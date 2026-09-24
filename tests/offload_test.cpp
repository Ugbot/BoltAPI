// offload_test.cpp — App::offload keeps the I/O thread serving while a
// handler's blocking work runs on a worker (G2ETL-52).
//
// A real App on a cleartext port: /slow offloads a wait on a gate, /fast is a
// plain sync route. While /slow is parked, /fast must answer; /slow must then
// complete with the body its worker wrote and resume on its original thread.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19262;

std::atomic<bool>            g_gate{false};
std::atomic<bool>            g_slow_entered{false};
std::atomic<bool>            g_same_thread{false};
std::atomic<bool>            g_worker_thread_differs{false};
std::atomic<int>             g_mw_after{0};
std::atomic<bool>            g_inline_same_thread{false};

struct Reply {
    int status = 0;
    std::string body;
    bool ok = false;
};

Reply get(const char* path) {
    Reply out;
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return out;
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return out;
    }
    std::string req = "GET ";
    req += path;
    req += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    std::size_t sent = 0;
    while (sent < req.size()) {
        ssize_t n = sys::send_bytes(fd, req.data() + sent, req.size() - sent);
        if (n <= 0) break;
        sent += static_cast<std::size_t>(n);
    }
    std::string buf;
    char tmp[4096];
    for (int i = 0; i < 1024; ++i) {
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
    }
    sys::close_socket(fd);
    const std::size_t he = buf.find("\r\n\r\n");
    if (he == std::string::npos) return out;
    const std::size_t sp = buf.find(' ');
    out.status = std::atoi(buf.c_str() + sp + 1);
    out.body = buf.substr(he + 4);
    out.ok = true;
    return out;
}

class Offload : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();
        api::App* app = app_;
        app_->use_async([](api::Request&, api::Response&, api::Next next)
                            -> api::chain_task {
            co_await next();
            g_mw_after.fetch_add(1, std::memory_order_relaxed);
        });
        app_->get("/fast", [](api::Request&, api::Response& res) {
            res.ok().text("FAST");
        });
        app_->get_async("/slow", [app](api::Request&, api::Response& res)
                                     -> api::core::coro_task<void> {
            const std::thread::id before = std::this_thread::get_id();
            std::string body;
            co_await app->offload([&body, before]() {
                g_worker_thread_differs.store(
                    std::this_thread::get_id() != before);
                g_slow_entered.store(true);
                for (int i = 0; i < 1000 && !g_gate.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                body = "SLOW";
            });
            g_same_thread.store(std::this_thread::get_id() == before);
            res.ok().text(body);
        });
        app_->get_async("/inline", [app](api::Request&, api::Response& res)
                                       -> api::core::coro_task<void> {
            const std::thread::id before = std::this_thread::get_id();
            std::string body;
            co_await app->offload([&body, before]() {
                g_inline_same_thread.store(std::this_thread::get_id() == before);
                body = "INLINE";
            });
            res.ok().text(body);
        });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }

    static void TearDownTestSuite() {
        if (app_) {
            app_->stop();
            delete app_;
            app_ = nullptr;
        }
    }

    static api::App* app_;
};

api::App* Offload::app_ = nullptr;

TEST_F(Offload, OtherRequestsServedWhileWorkBlocks) {
    Reply slow;
    std::thread t([&slow]() { slow = get("/slow"); });
    for (int i = 0; i < 500 && !g_slow_entered.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    ASSERT_TRUE(g_slow_entered.load());

    const auto t0 = std::chrono::steady_clock::now();
    const Reply fast = get("/fast");
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    ASSERT_TRUE(fast.ok);
    EXPECT_EQ(fast.status, 200);
    EXPECT_EQ(fast.body, "FAST");
    EXPECT_LT(ms, 2000);
    EXPECT_FALSE(g_gate.load());

    g_gate.store(true);
    t.join();
    ASSERT_TRUE(slow.ok);
    EXPECT_EQ(slow.status, 200);
    EXPECT_EQ(slow.body, "SLOW");
    EXPECT_TRUE(g_worker_thread_differs.load());
    EXPECT_TRUE(g_same_thread.load());
    EXPECT_EQ(g_mw_after.load(), 2);
}

// dispatch_http3 must finish in one resume, so an offload under it runs its
// work inline on the calling thread instead of suspending (G2ETL-59).
TEST_F(Offload, SyncHttp3DispatchRunsWorkInline) {
    api::http::CoroHttpRequest req{};
    req.method = "GET";
    req.path   = "/inline";
    const api::http::CoroHttpResponse resp = app_->dispatch_http3(req);
    EXPECT_EQ(resp.status, 200);
    EXPECT_EQ(resp.body, "INLINE");
    EXPECT_TRUE(g_inline_same_thread.load());
    EXPECT_FALSE(api::detail::t_sync_dispatch);
}

}  // namespace
