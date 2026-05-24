// http_client_test.cpp — loopback gtest for bolt::api::http::Client (gateway P0).
//
// Spins a REAL App on an ephemeral cleartext HTTP/1.1 port and drives it with the
// outbound Client over a started IODispatcher + WorkerThreadPool. Exercises:
//   * GET → status + body byte-exact
//   * POST/PUT echo, randomized body sizes incl. > one recv chunk (multi-read
//     response reassembly through ResponseParser)
//   * path-param route, JSON route, response-header extraction
//   * 404 on an unregistered path
//   * keep-alive connection REUSE across a burst (idle_total() > 0 after)
//
// The Client::send() is a coroutine that suspends on async I/O and resumes on a
// worker thread, so a free `drive` coroutine captures the result + a done flag,
// and do_send() blocks (bounded) until completion.

#include "boltapi/app.h"
#include "boltapi/core/coro_task.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/http/client.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <random>
#include <string>
#include <thread>

namespace api  = bolt::api;
namespace core = bolt::api::core;
namespace net  = bolt::api::net;
namespace http = bolt::api::http;
namespace sys  = bolt::api::net::sys;

namespace {

// Pick a free loopback port via the OS (bind :0, read it back, release). Each
// test case runs in its OWN process under gtest_discover_tests + `ctest -j`, so a
// per-process counter would collide; an OS-assigned ephemeral port is unique
// across processes. The probe socket is only bound (never connected), so there is
// no TIME_WAIT to block the App's immediate rebind.
std::uint16_t pick_free_port() noexcept {
    sys::startup();
    const int s = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (s < 0) return 0;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = 0;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        sys::close_socket(s);
        return 0;
    }
    socklen_t len = sizeof(a);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    const std::uint16_t p = ntohs(a.sin_port);
    sys::close_socket(s);
    return p;
}

// Free coroutine (params copied into the frame; req's string_views must outlive
// the await — do_send keeps the backing strings alive until `done`).
core::coro_task<void> drive(http::Client* client, std::string host, std::uint16_t port,
                            http::ClientRequest req, http::ClientResponse* out,
                            std::atomic<bool>* done) {
    *out = co_await client->send(host, port, req);
    done->store(true, std::memory_order_release);
}

class HttpClientTest : public ::testing::Test {
protected:
    // Run one request to completion (bounded wait). Returns the response.
    http::ClientResponse do_send(const http::ClientRequest& req) {
        http::ClientResponse out;
        std::atomic<bool> done{false};
        auto task = drive(client_.get(), "127.0.0.1", port_, req, &out, &done);
        task.resume();  // kick to first suspension; resumes on a worker thereafter
        for (int i = 0; i < 10000 && !done.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        EXPECT_TRUE(done.load()) << "send did not complete in time";
        return out;
    }

    void SetUp() override {
        sys::startup();
        port_ = pick_free_port();
        ASSERT_NE(port_, 0) << "failed to obtain a free port";
        app_.get("/ping", [](api::Request&, api::Response& res) { res.ok().text("pong"); });
        app_.post("/echo", [](api::Request& req, api::Response& res) { res.ok().send(req.body()); });
        app_.put("/echo", [](api::Request& req, api::Response& res) { res.ok().send(req.body()); });
        app_.get("/users/{id}", [](api::Request& req, api::Response& res) {
            res.ok().text(std::string(req.path_param_view("id")));
        });
        app_.get("/json", [](api::Request&, api::Response& res) {
            res.ok().json("{\"k\":\"v\"}");
        });
        ASSERT_EQ(app_.start_background("127.0.0.1", port_), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        pool_ = std::make_unique<core::WorkerThreadPool>(static_cast<std::size_t>(2));
        pool_->start();
        net::IODispatcherConfig dc;
        dc.num_io_threads = 1;
        dc.worker_pool = pool_.get();
        disp_ = std::make_unique<net::IODispatcher>(dc);
        disp_->start();
        client_ = std::make_unique<http::Client>(disp_.get());
    }

    void TearDown() override {
        if (client_) client_->close_idle();
        if (disp_) disp_->stop();
        if (pool_) pool_->stop();
        app_.stop();
        client_.reset();
        disp_.reset();
        pool_.reset();
    }

    std::uint16_t port_ = 0;
    api::App app_;
    std::unique_ptr<core::WorkerThreadPool> pool_;
    std::unique_ptr<net::IODispatcher>      disp_;
    std::unique_ptr<http::Client>           client_;
};

TEST_F(HttpClientTest, GetReturnsStatusAndBody) {
    http::ClientRequest req;
    req.method = "GET";
    req.path = "/ping";
    const http::ClientResponse r = do_send(req);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "pong");
}

TEST_F(HttpClientTest, NotFoundIs404) {
    http::ClientRequest req;
    req.method = "GET";
    req.path = "/does-not-exist";
    const http::ClientResponse r = do_send(req);
    ASSERT_TRUE(r.ok);             // transport ok — a complete HTTP response
    EXPECT_EQ(r.status, 404);
}

TEST_F(HttpClientTest, PathParamEchoed) {
    http::ClientRequest req;
    req.method = "GET";
    req.path = "/users/42";
    const http::ClientResponse r = do_send(req);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "42");
}

TEST_F(HttpClientTest, JsonRouteHasContentType) {
    http::ClientRequest req;
    req.method = "GET";
    req.path = "/json";
    const http::ClientResponse r = do_send(req);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "{\"k\":\"v\"}");
    EXPECT_EQ(r.header("content-type"), "application/json");
}

TEST_F(HttpClientTest, PostEchoByteExactRandomizedSizes) {
    std::mt19937 rng(0xB0117AB1u);
    const std::size_t sizes[] = {0, 5, 100, 5000, 40000};  // 40k spans many recv chunks
    for (std::size_t sz : sizes) {
        std::string body;
        body.reserve(sz);
        for (std::size_t i = 0; i < sz; ++i) {
            body.push_back(static_cast<char>('A' + (rng() % 26)));
        }
        http::ClientRequest req;
        req.method = "POST";
        req.path = "/echo";
        req.body = body;
        req.content_type = "text/plain";
        const http::ClientResponse r = do_send(req);
        ASSERT_TRUE(r.ok) << "size=" << sz;
        EXPECT_EQ(r.status, 200) << "size=" << sz;
        EXPECT_EQ(r.body, body) << "size=" << sz;  // byte-exact echo
    }
}

TEST_F(HttpClientTest, PutEchoWorks) {
    http::ClientRequest req;
    req.method = "PUT";
    req.path = "/echo";
    req.body = "hello-put";
    req.content_type = "text/plain";
    const http::ClientResponse r = do_send(req);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "hello-put");
}

TEST_F(HttpClientTest, KeepAliveConnectionIsReusedAcrossBurst) {
    // A burst of sequential keep-alive requests should recycle the connection:
    // every response is correct AND at least one idle connection is pooled after.
    constexpr int kN = 50;
    for (int i = 0; i < kN; ++i) {
        http::ClientRequest req;
        req.method = "GET";
        req.path = "/ping";
        const http::ClientResponse r = do_send(req);
        ASSERT_TRUE(r.ok) << "iter " << i;
        ASSERT_EQ(r.status, 200) << "iter " << i;
        ASSERT_EQ(r.body, "pong") << "iter " << i;
    }
    // After a keep-alive burst the pool holds the recycled connection.
    EXPECT_GE(client_->idle_total(), static_cast<std::size_t>(1));
}

}  // namespace
