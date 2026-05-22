// sse_test.cpp — gtest end-to-end coverage for coroutine SSE through bolt::api::App.
//
// Spins a REAL App (background threads) on an ephemeral cleartext HTTP/1.1 port
// with app.sse_coro("/events", ...) streaming N named events, then drives it
// from a raw client socket:
//   * GET /events with Accept: text/event-stream
//   * assert the response carries Content-Type: text/event-stream
//   * read and assert the N expected event:/data: frames arrive in order
// All reads are bounded by a wall-clock deadline so the test cannot hang.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace api  = bolt::api;
namespace core = bolt::api::core;
namespace net  = bolt::api::net;
namespace http = bolt::api::http;
namespace sys  = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19281;
constexpr int kNumEvents = 5;

int connect_client() {
    sys::startup();
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return -1;
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return -1;
    }
    return fd;
}

void set_recv_timeout(int fd, int ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(ms);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

bool send_all(int fd, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = sys::send_bytes(fd, data.data() + sent, data.size() - sent);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

class Sse : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        app_ = new api::App();
        app_->get("/health", [](api::Request&, api::Response& res) {
            res.ok().text("up");
        });
        app_->sse_coro("/events",
            [](net::IODispatcher& io, int fd, const http::CoroHttpRequest&)
                -> core::coro_task<void> {
                http::SSEWriter sse(io, fd);
                for (int i = 0; i < kNumEvents; ++i) {
                    bool ok = co_await sse.send_event(
                        "tick", "event-" + std::to_string(i),
                        std::to_string(i));
                    if (!ok) co_return;
                }
                co_return;
            });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }
    static void TearDownTestSuite() {
        if (app_) { app_->stop(); delete app_; app_ = nullptr; }
    }
    static api::App* app_;
};
api::App* Sse::app_ = nullptr;

// ---------------------------------------------------------------------------
TEST_F(Sse, StreamsOrderedEvents) {
    int fd = connect_client();
    ASSERT_GE(fd, 0);
    set_recv_timeout(fd, 400);

    std::string req =
        "GET /events HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: text/event-stream\r\n"
        "\r\n";
    ASSERT_TRUE(send_all(fd, req));

    // Read until we have all N events' data: lines (or deadline).
    std::string buf;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool got_headers = false;
    while (std::chrono::steady_clock::now() < deadline) {
        char tmp[2048];
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n > 0) {
            buf.append(tmp, static_cast<std::size_t>(n));
        } else if (n == 0) {
            break;  // server closed after streaming
        }
        if (!got_headers && buf.find("\r\n\r\n") != std::string::npos) {
            got_headers = true;
        }
        // Stop once we've seen the last event's data line.
        if (buf.find("data: event-" + std::to_string(kNumEvents - 1)) !=
            std::string::npos) {
            break;
        }
    }

    ASSERT_TRUE(got_headers) << "no SSE response headers; got: " << buf;
    const std::size_t hdr_end = buf.find("\r\n\r\n");
    const std::string headers = buf.substr(0, hdr_end);

    // Content-Type must be text/event-stream (case-insensitive header name).
    bool has_ct = headers.find("text/event-stream") != std::string::npos;
    EXPECT_TRUE(has_ct) << "missing event-stream content type:\n" << headers;

    // Body holds the SSE frames. Assert each event appears in order with the
    // expected event: and data: lines.
    const std::string body = buf.substr(hdr_end + 4);
    std::size_t scan = 0;
    for (int i = 0; i < kNumEvents; ++i) {
        const std::string ev_line = "event: tick";
        const std::string data_line = "data: event-" + std::to_string(i);
        std::size_t ev = body.find(ev_line, scan);
        ASSERT_NE(ev, std::string::npos)
            << "missing event line " << i << " in body:\n" << body;
        std::size_t dl = body.find(data_line, ev);
        ASSERT_NE(dl, std::string::npos)
            << "missing data line " << i << " in body:\n" << body;
        scan = dl + data_line.size();  // enforce in-order
    }

    sys::close_socket(fd);
}

}  // namespace
