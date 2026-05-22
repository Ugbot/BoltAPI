// throughput_bench.cpp — end-to-end HTTP/1.1 throughput micro-benchmark.
//
// Spins a real bolt::api::App on loopback cleartext HTTP/1.1, then fires a
// bounded number of keep-alive requests from a few client threads over
// persistent connections, measuring aggregate req/s and mean per-request
// latency. This is a benchmark, NOT a ctest: it is bounded and best-effort —
// it prints numbers and exits 0 even on partial completion.
//
// No third-party load tool: raw sockets + std::thread + std::chrono.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort           = 19311;
constexpr int      kClientThreads  = 4;
constexpr int      kReqsPerThread  = 20000;   // bounded total = threads * this
constexpr long long kTotalReqs     =
    static_cast<long long>(kClientThreads) * kReqsPerThread;

std::atomic<long long> g_ok{0};
std::atomic<long long> g_fail{0};
std::atomic<long long> g_latency_ns{0};

// One persistent keep-alive connection firing `count` pipelined-serial requests
// (send one, read one, repeat) against /bench. Accumulates latency + counts.
void client_worker() {
    sys::startup();

    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) { g_fail.fetch_add(kReqsPerThread); return; }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        g_fail.fetch_add(kReqsPerThread);
        return;
    }

    // Keep-alive GET; no Connection: close so the socket is reused.
    static const char kReq[] =
        "GET /bench HTTP/1.1\r\nHost: x\r\n\r\n";
    const std::size_t kReqLen = sizeof(kReq) - 1;

    char rbuf[4096];

    for (int i = 0; i < kReqsPerThread; ++i) {
        const auto t0 = std::chrono::steady_clock::now();

        std::size_t sent = 0;
        bool send_ok = true;
        while (sent < kReqLen) {
            ssize_t n = sys::send_bytes(fd, kReq + sent, kReqLen - sent);
            if (n <= 0) { send_ok = false; break; }
            sent += static_cast<std::size_t>(n);
        }
        if (!send_ok) { g_fail.fetch_add(1); break; }

        // Read one complete response. Our handler returns a small fixed body so
        // we read until we see the header terminator + the declared body bytes.
        std::string buf;
        std::size_t header_end = std::string::npos;
        long long content_length = -1;
        bool resp_ok = false;
        for (;;) {
            if (header_end != std::string::npos && content_length >= 0) {
                const std::size_t have = buf.size() - (header_end + 4);
                if (have >= static_cast<std::size_t>(content_length)) {
                    resp_ok = true;
                    break;
                }
            }
            ssize_t n = sys::recv_bytes(fd, rbuf, sizeof(rbuf));
            if (n <= 0) break;
            buf.append(rbuf, static_cast<std::size_t>(n));
            if (header_end == std::string::npos) {
                header_end = buf.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    // Find Content-Length (case-insensitive enough for our own
                    // server's canonical "Content-Length:" header).
                    std::size_t cl = buf.find("Content-Length:");
                    if (cl == std::string::npos) cl = buf.find("content-length:");
                    if (cl != std::string::npos && cl < header_end) {
                        content_length = std::atoll(buf.c_str() + cl + 15);
                    } else {
                        content_length = 0;  // assume empty body
                    }
                }
            }
            if (buf.size() > (1u << 16)) break;  // safety
        }

        const auto t1 = std::chrono::steady_clock::now();
        if (resp_ok) {
            g_ok.fetch_add(1, std::memory_order_relaxed);
            g_latency_ns.fetch_add(
                std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count(),
                std::memory_order_relaxed);
        } else {
            g_fail.fetch_add(1, std::memory_order_relaxed);
            break;  // connection broken — stop this worker
        }
    }

    sys::close_socket(fd);
}

}  // namespace

int main() {
    std::printf("== bolt::api::App throughput benchmark ==\n");
    std::printf("client threads=%d  reqs/thread=%d  total=%lld  (keep-alive)\n\n",
                kClientThreads, kReqsPerThread, kTotalReqs);

    sys::startup();

    // Build the App with a couple of routes; the bench hits the static one.
    api::App app;
    app.get("/bench", [](api::Request&, api::Response& res) {
        res.ok().text("ok");
    });
    app.get("/users/{id}", [](api::Request& req, api::Response& res) {
        res.ok().text(std::string(req.path_param("id")));
    });

    if (app.start_background("127.0.0.1", kPort) != 0) {
        std::printf("FAILED to start App on 127.0.0.1:%u\n", kPort);
        return 0;  // bench: do not hard-fail CI
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    const auto wall0 = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(kClientThreads);
    for (int i = 0; i < kClientThreads; ++i) threads.emplace_back(client_worker);
    for (auto& t : threads) t.join();

    const auto wall1 = std::chrono::steady_clock::now();
    app.stop();

    const double wall_s =
        std::chrono::duration_cast<std::chrono::duration<double>>(wall1 - wall0)
            .count();
    const long long ok = g_ok.load();
    const long long fail = g_fail.load();
    const double rps = wall_s > 0.0 ? static_cast<double>(ok) / wall_s : 0.0;
    const double mean_lat_us =
        ok > 0 ? (static_cast<double>(g_latency_ns.load()) / static_cast<double>(ok))
                     / 1000.0
               : 0.0;

    std::printf("[results]\n");
    std::printf("  completed       %lld ok, %lld failed\n", ok, fail);
    std::printf("  wall time       %.3f s\n", wall_s);
    std::printf("  throughput      %.0f req/s\n", rps);
    std::printf("  mean latency    %.2f us/req\n", mean_lat_us);
    return 0;
}
