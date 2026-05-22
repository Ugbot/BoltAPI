// middleware_test.cpp — gtest coverage for the bolt::api coroutine middleware
// onion, driven through a REAL App over a cleartext HTTP/1.1 socket.
//
// Covers:
//   * chain order: two middlewares wrap the handler, appending a pre-marker
//     before next() and a post-marker after — proving onion (LIFO post)
//     semantics with the handler in the middle.
//   * short-circuit: a middleware that writes 401 and does NOT call next()
//     stops the handler from ever running (and the happy path with the token
//     proves the handler does run when next() IS called).
//   * sync + async mix: a sync use() middleware and an async use_async()
//     middleware cooperate in one chain.
//
// Each scenario uses its own App on its own port so middleware sets don't bleed.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

namespace api  = bolt::api;
namespace core = bolt::api::core;
namespace sys  = bolt::api::net::sys;

namespace {

struct Resp {
    int status = 0;
    std::string headers;
    std::string body;
    bool ok = false;
};

std::string hdr_ci(const std::string& headers, const char* name) {
    std::string lname = name;
    for (char& c : lname) c = static_cast<char>(std::tolower((unsigned char)c));
    std::size_t pos = headers.find("\r\n");
    if (pos == std::string::npos) return {};
    pos += 2;
    while (pos < headers.size()) {
        std::size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            for (char& c : key) c = static_cast<char>(std::tolower((unsigned char)c));
            if (key == lname) {
                std::string v = line.substr(colon + 1);
                std::size_t b = 0, e = v.size();
                while (b < e && (v[b] == ' ' || v[b] == '\t')) ++b;
                while (e > b && (v[e - 1] == ' ' || v[e - 1] == '\t')) --e;
                return v.substr(b, e - b);
            }
        }
        pos = eol + 2;
    }
    return {};
}

// Send one request (Connection: close) with optional extra headers + body.
Resp request(uint16_t port, const std::string& method, const std::string& path,
             const std::string& extra_headers = {}, const std::string& body = {}) {
    Resp out;
    sys::startup();
    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return out;

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return out;
    }

    std::string raw = method + " " + path + " HTTP/1.1\r\nHost: x\r\n";
    raw += extra_headers;  // each line must end with CRLF
    raw += "Connection: close\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;

    std::size_t sent = 0;
    while (sent < raw.size()) {
        ssize_t n = sys::send_bytes(fd, raw.data() + sent, raw.size() - sent);
        if (n <= 0) break;
        sent += static_cast<std::size_t>(n);
    }

    std::string buf;
    char tmp[4096];
    for (;;) {
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (buf.size() > (1u << 20)) break;
    }
    sys::close_socket(fd);

    std::size_t he = buf.find("\r\n\r\n");
    if (he == std::string::npos) return out;
    out.headers = buf.substr(0, he);
    out.body = buf.substr(he + 4);
    std::size_t sp1 = out.headers.find(' ');
    if (sp1 != std::string::npos) out.status = std::atoi(out.headers.c_str() + sp1 + 1);
    std::string cl = hdr_ci(out.headers, "Content-Length");
    if (!cl.empty()) {
        long long n = std::stoll(cl);
        if (n >= 0 && out.body.size() > static_cast<std::size_t>(n)) {
            out.body.resize(static_cast<std::size_t>(n));
        }
    }
    out.ok = true;
    return out;
}

void wait_listen() {
    std::this_thread::sleep_for(std::chrono::milliseconds(350));
}

}  // namespace

// ---------------------------------------------------------------------------
// Chain order: two middlewares wrap the handler. Each appends a pre-marker
// before next() and a post-marker after. Onion runs pre in registration order,
// post in reverse (LIFO), handler in the middle. Trace is accumulated in the
// response X-Trace header so it round-trips to the client.
// ---------------------------------------------------------------------------
TEST(Middleware, ChainOrderOnion) {
    constexpr uint16_t kPort = 19311;
    api::App app;

    app.use_async([](api::Request&, api::Response& res, api::Next next)
                      -> core::coro_task<void> {
        res.raw().headers["X-Trace"] += "mw0-pre;";
        co_await next();
        res.raw().headers["X-Trace"] += "mw0-post;";
        co_return;
    });
    app.use_async([](api::Request&, api::Response& res, api::Next next)
                      -> core::coro_task<void> {
        res.raw().headers["X-Trace"] += "mw1-pre;";
        co_await next();
        res.raw().headers["X-Trace"] += "mw1-post;";
        co_return;
    });
    app.get("/order", [](api::Request&, api::Response& res) {
        res.raw().headers["X-Trace"] += "handler;";
        res.ok().text("done");
    });

    ASSERT_EQ(app.start_background("127.0.0.1", kPort), 0);
    wait_listen();

    Resp r = request(kPort, "GET", "/order");
    app.stop();

    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "done");
    EXPECT_EQ(hdr_ci(r.headers, "X-Trace"),
              "mw0-pre;mw1-pre;handler;mw1-post;mw0-post;");
}

// ---------------------------------------------------------------------------
// Short-circuit: an auth middleware writes 401 and does NOT call next(). The
// handler must never run. The happy path (correct token) proves next() lets the
// handler run exactly once.
// ---------------------------------------------------------------------------
TEST(Middleware, ShortCircuitDeniesHandler) {
    constexpr uint16_t kPort = 19312;
    api::App app;

    static std::atomic<int> g_handler_calls{0};
    g_handler_calls.store(0);

    app.use_async([](api::Request& req, api::Response& res, api::Next next)
                      -> core::coro_task<void> {
        if (req.header("X-Token") != "secret") {
            res.status(401).text("denied");
            co_return;  // short-circuit: handler never invoked
        }
        co_await next();
        co_return;
    });

    app.get("/secure", [](api::Request&, api::Response& res) {
        g_handler_calls.fetch_add(1);
        res.ok().text("secret-data");
    });

    ASSERT_EQ(app.start_background("127.0.0.1", kPort), 0);
    wait_listen();

    // No token -> 401, handler not run.
    Resp denied = request(kPort, "GET", "/secure");
    EXPECT_TRUE(denied.ok);
    EXPECT_EQ(denied.status, 401);
    EXPECT_EQ(denied.body, "denied");
    EXPECT_EQ(g_handler_calls.load(), 0);

    // With token -> 200, handler runs once.
    Resp allowed = request(kPort, "GET", "/secure", "X-Token: secret\r\n");
    app.stop();

    EXPECT_TRUE(allowed.ok);
    EXPECT_EQ(allowed.status, 200);
    EXPECT_EQ(allowed.body, "secret-data");
    EXPECT_EQ(g_handler_calls.load(), 1);
}

// ---------------------------------------------------------------------------
// Sync + async mix: a sync use() middleware sets markers around next(), an async
// use_async() middleware sets a marker, then the handler runs. Order proves the
// sync->async->handler->sync-post pipeline.
// ---------------------------------------------------------------------------
TEST(Middleware, SyncAndAsyncMix) {
    constexpr uint16_t kPort = 19313;
    api::App app;

    // Sync middleware (auto-wrapped to async via to_async()).
    app.use([](api::Request&, api::Response& res, std::function<void()> next) {
        res.raw().headers["X-Mix"] += "sync;";
        next();
        res.raw().headers["X-Mix"] += "sync-post;";
    });

    // Async middleware.
    app.use_async([](api::Request&, api::Response& res, api::Next next)
                      -> core::coro_task<void> {
        res.raw().headers["X-Mix"] += "async;";
        co_await next();
        co_return;
    });

    app.get("/mix", [](api::Request&, api::Response& res) {
        res.raw().headers["X-Mix"] += "handler;";
        res.ok().text("mixed");
    });

    ASSERT_EQ(app.start_background("127.0.0.1", kPort), 0);
    wait_listen();

    Resp r = request(kPort, "GET", "/mix");
    app.stop();

    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "mixed");
    EXPECT_EQ(hdr_ci(r.headers, "X-Mix"), "sync;async;handler;sync-post;");
}
