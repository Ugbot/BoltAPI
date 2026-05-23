// body_throughput_bench.cpp — body-path throughput, exercises the request-body
// buffer (slot-pool default vs bolt::Arena when BOLTAPI_USE_BOLT_ARENA=ON).
//
// The plain throughput_bench uses GET with no body, so it never touches the
// body buffer. This bench POSTs a body large enough to exceed the connection's
// stack buffer and force a RequestBodyBuffer acquire() every request — which is
// exactly the path the Arena swap changes. Echo handler returns the body, so we
// also move it back out. Reports req/s and MiB/s. Bench, not a ctest.

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

constexpr uint16_t  kPort          = 19347;
constexpr int       kClientThreads = 4;
constexpr int       kReqsPerThread = 5000;
constexpr std::size_t kBodyBytes   = 32 * 1024;  // > stack buf -> hits body arena
constexpr long long kTotalReqs =
    static_cast<long long>(kClientThreads) * kReqsPerThread;

std::atomic<long long> g_ok{0};
std::atomic<long long> g_fail{0};
std::atomic<long long> g_latency_ns{0};

std::string make_request() {
    std::string body(kBodyBytes, 'x');
    std::string req;
    req.reserve(kBodyBytes + 128);
    req += "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: ";
    req += std::to_string(kBodyBytes);
    req += "\r\n\r\n";
    req += body;
    return req;
}

void client_worker(const std::string& req) {
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

    const char* rp = req.data();
    const std::size_t rlen = req.size();
    std::vector<char> rbuf(64 * 1024);

    for (int i = 0; i < kReqsPerThread; ++i) {
        const auto t0 = std::chrono::steady_clock::now();

        std::size_t sent = 0;
        bool send_ok = true;
        while (sent < rlen) {
            ssize_t n = sys::send_bytes(fd, rp + sent, rlen - sent);
            if (n <= 0) { send_ok = false; break; }
            sent += static_cast<std::size_t>(n);
        }
        if (!send_ok) { g_fail.fetch_add(1); break; }

        // Read one full response: headers + Content-Length body (the echo).
        std::string buf;
        std::size_t header_end = std::string::npos;
        long long content_length = -1;
        bool resp_ok = false;
        for (;;) {
            if (header_end != std::string::npos && content_length >= 0) {
                const std::size_t have = buf.size() - (header_end + 4);
                if (have >= static_cast<std::size_t>(content_length)) { resp_ok = true; break; }
            }
            ssize_t n = sys::recv_bytes(fd, rbuf.data(), rbuf.size());
            if (n <= 0) break;
            buf.append(rbuf.data(), static_cast<std::size_t>(n));
            if (header_end == std::string::npos) {
                header_end = buf.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    std::size_t cl = buf.find("Content-Length:");
                    if (cl == std::string::npos) cl = buf.find("content-length:");
                    content_length = (cl != std::string::npos && cl < header_end)
                                         ? std::atoll(buf.c_str() + cl + 15) : 0;
                }
            }
            if (buf.size() > (kBodyBytes + (1u << 16))) break;  // safety
        }

        const auto t1 = std::chrono::steady_clock::now();
        if (resp_ok) {
            g_ok.fetch_add(1, std::memory_order_relaxed);
            g_latency_ns.fetch_add(
                std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count(),
                std::memory_order_relaxed);
        } else {
            g_fail.fetch_add(1, std::memory_order_relaxed);
            break;
        }
    }
    sys::close_socket(fd);
}

}  // namespace

int main() {
#if defined(BOLTAPI_USE_BOLT_ARENA) && BOLTAPI_USE_BOLT_ARENA
    const char* mode = "bolt::Arena (BOLTAPI_USE_BOLT_ARENA=ON)";
#else
    const char* mode = "slot-pool (default)";
#endif
    std::printf("== body-path throughput benchmark ==\n");
    std::printf("body buffer mode: %s\n", mode);
    std::printf("client threads=%d  reqs/thread=%d  total=%lld  body=%zu B (keep-alive)\n\n",
                kClientThreads, kReqsPerThread, kTotalReqs, kBodyBytes);

    sys::startup();
    api::App app;
    app.post("/echo", [](api::Request& req, api::Response& res) {
        res.ok().body(req.body());  // echo the request body back
    });
    if (app.start_background("127.0.0.1", kPort) != 0) {
        std::printf("FAILED to start App on 127.0.0.1:%u\n", kPort);
        return 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    const std::string req = make_request();
    const auto wall0 = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;
    threads.reserve(kClientThreads);
    for (int i = 0; i < kClientThreads; ++i) threads.emplace_back(client_worker, std::cref(req));
    for (auto& t : threads) t.join();
    const auto wall1 = std::chrono::steady_clock::now();
    app.stop();

    const double wall_s =
        std::chrono::duration_cast<std::chrono::duration<double>>(wall1 - wall0).count();
    const long long ok = g_ok.load();
    const double rps = wall_s > 0.0 ? static_cast<double>(ok) / wall_s : 0.0;
    const double mibps = wall_s > 0.0
        ? (static_cast<double>(ok) * static_cast<double>(kBodyBytes) * 2.0)
              / (1024.0 * 1024.0) / wall_s
        : 0.0;  // x2: body in + echo out
    const double mean_lat_us =
        ok > 0 ? (static_cast<double>(g_latency_ns.load()) / static_cast<double>(ok)) / 1000.0 : 0.0;

    std::printf("[results]\n");
    std::printf("  completed       %lld ok, %lld failed\n", ok, g_fail.load());
    std::printf("  wall time       %.3f s\n", wall_s);
    std::printf("  throughput      %.0f req/s\n", rps);
    std::printf("  body bandwidth  %.0f MiB/s (in+out)\n", mibps);
    std::printf("  mean latency    %.2f us/req\n", mean_lat_us);
    return 0;
}
