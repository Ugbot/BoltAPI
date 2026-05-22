// Engine end-to-end test for the forked CoroUnifiedServer.
//
// Spins up a real cleartext HTTP/1.1 server on a high port, then opens a raw
// TCP client socket (winsock on Windows, BSD sockets on POSIX), sends two
// requests across two HTTP methods (GET + POST) to two different paths, and
// asserts the responses contain the expected status + bodies.
//
// Plain main(): returns 0 on success, 1 on failure. No gtest.

#include "boltapi/server/coro_unified_server.h"
#include "boltapi/net/sys_compat.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

using bolt::api::http::CoroUnifiedServer;
using bolt::api::http::CoroUnifiedServerConfig;
using bolt::api::http::CoroHttpRequest;
using bolt::api::http::CoroHttpResponse;
namespace core = bolt::api::core;
namespace sys  = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 18793;  // high, unlikely-busy port
constexpr const char* kPingBody = "PONG-12345";
constexpr const char* kEchoPrefix = "ECHO:";

int g_failures = 0;

void check(bool cond, const char* what) {
    if (!cond) {
        std::fprintf(stderr, "[e2e] FAIL: %s\n", what);
        ++g_failures;
    } else {
        std::fprintf(stderr, "[e2e] ok:   %s\n", what);
    }
}

// Open a blocking client socket to 127.0.0.1:kPort, send `request`, read the
// full response until the peer closes (Connection: close). Returns the raw
// response text, or empty string on connection failure.
std::string round_trip(const std::string& request) {
    sys::startup();

    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) {
        std::fprintf(stderr, "[e2e] client socket() failed\n");
        return {};
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr, "[e2e] client connect() failed\n");
        sys::close_socket(fd);
        return {};
    }

    // Send the full request.
    size_t total_sent = 0;
    while (total_sent < request.size()) {
        ssize_t n = sys::send_bytes(fd, request.data() + total_sent,
                                    request.size() - total_sent);
        if (n <= 0) break;
        total_sent += static_cast<size_t>(n);
    }

    // Read until close or buffer cap.
    std::string response;
    char buf[4096];
    for (;;) {
        ssize_t n = sys::recv_bytes(fd, buf, sizeof(buf));
        if (n <= 0) break;
        response.append(buf, static_cast<size_t>(n));
        if (response.size() > (1u << 20)) break;  // safety cap
    }

    sys::close_socket(fd);
    return response;
}

}  // namespace

int main() {
    sys::startup();

    CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_http1_cleartext = true;
    config.http1_port = kPort;
    config.host = "127.0.0.1";
    config.num_io_threads = 1;
    config.num_workers = 2;
    config.enable_signal_handlers = false;  // tests must not hijack signals

    CoroUnifiedServer server(config);

    server.set_handler([](const CoroHttpRequest& req) -> core::coro_task<CoroHttpResponse> {
        CoroHttpResponse resp;
        resp.status = 200;
        resp.status_message = "OK";
        resp.headers["Content-Type"] = "text/plain";

        if (req.method == "POST") {
            // Echo the body back with a known prefix (exercises a 2nd verb +
            // randomized-ish input the caller supplies).
            resp.body = std::string(kEchoPrefix) + req.body;
        } else {
            resp.body = kPingBody;
        }
        co_return resp;
    });

    if (server.start_background() != 0) {
        std::fprintf(stderr, "[e2e] FAIL: server.start_background() returned non-zero\n");
        return 1;
    }

    // Give the accept loop a moment to bind/listen.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // ---- Test 1: GET /ping ----
    {
        std::string req =
            "GET /ping HTTP/1.1\r\n"
            "Host: x\r\n"
            "Connection: close\r\n"
            "\r\n";
        std::string resp = round_trip(req);
        check(!resp.empty(), "GET /ping got a response");
        check(resp.find("200") != std::string::npos, "GET /ping response contains 200");
        check(resp.find(kPingBody) != std::string::npos, "GET /ping response contains PONG body");
    }

    // ---- Test 2: POST /echo with a body (second verb, second path) ----
    {
        const std::string payload = std::string("rand-7f3a-payload-") +
                                     '\x01' + '\x02' + "data";
        std::string req =
            "POST /echo HTTP/1.1\r\n"
            "Host: x\r\n"
            "Content-Length: " + std::to_string(payload.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" + payload;
        std::string resp = round_trip(req);
        check(!resp.empty(), "POST /echo got a response");
        check(resp.find("200") != std::string::npos, "POST /echo response contains 200");
        check(resp.find(std::string(kEchoPrefix) + payload) != std::string::npos,
              "POST /echo response echoes body");
    }

    server.stop();

    if (g_failures == 0) {
        std::fprintf(stderr, "[e2e] SUCCESS: all checks passed\n");
        return 0;
    }
    std::fprintf(stderr, "[e2e] FAILURE: %d check(s) failed\n", g_failures);
    return 1;
}
