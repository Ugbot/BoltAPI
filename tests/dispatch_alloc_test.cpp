// dispatch_alloc_test.cpp — measures + gates HEAP ALLOCATIONS PER REQUEST on the
// full HTTP/1.1 dispatch+response path (parse -> router -> middleware -> handler ->
// serialize -> write). Allocation counting is deterministic regardless of CPU load,
// so this is reliable even on a busy box (unlike throughput timing).
//
// A real App runs on loopback; a RAW, FIXED-BUFFER client (zero per-request client
// allocations) fires many keep-alive GETs on one connection. The global operator new
// counter runs on all threads, so after warmup the per-request delta is dominated by
// the SERVER's per-request allocations. The test prints allocs/req and asserts a
// ceiling (tightened as Phase 1 lands).

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

namespace {
std::atomic<std::uint64_t> g_alloc_count{0};
}

void* operator new(std::size_t n) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (n == 0) n = 1;
    void* p = std::malloc(n);
    if (!p) std::abort();
    return p;
}
void* operator new[](std::size_t n) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (n == 0) n = 1;
    void* p = std::malloc(n);
    if (!p) std::abort();
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace {

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

constexpr std::uint16_t kPort = 19511;

// Raw keep-alive client using FIXED stack buffers — zero per-request client allocs.
// Sends one GET, reads one Content-Length-framed response. Returns false on error.
bool one_request(int fd, const char* req, std::size_t req_len, char* rbuf,
                 std::size_t rcap) {
    std::size_t sent = 0;
    while (sent < req_len) {
        ssize_t n = sys::send_bytes(fd, req + sent, req_len - sent);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    // Read until we have headers + the declared Content-Length body.
    std::size_t have = 0;
    long long content_length = -1;
    std::size_t header_end = 0;
    for (;;) {
        if (header_end != 0 && content_length >= 0 &&
            have >= header_end + static_cast<std::size_t>(content_length)) {
            return true;
        }
        if (have >= rcap) return false;  // response too big for fixed buffer
        ssize_t n = sys::recv_bytes(fd, rbuf + have, rcap - have);
        if (n <= 0) return false;
        have += static_cast<std::size_t>(n);
        if (header_end == 0) {
            // find "\r\n\r\n"
            for (std::size_t i = 3; i < have; ++i) {
                if (rbuf[i - 3] == '\r' && rbuf[i - 2] == '\n' &&
                    rbuf[i - 1] == '\r' && rbuf[i] == '\n') {
                    header_end = i + 1;
                    break;
                }
            }
            if (header_end != 0) {
                // crude Content-Length scan within the header block
                const char* cl = nullptr;
                for (std::size_t i = 0; i + 15 < header_end; ++i) {
                    if (std::strncmp(rbuf + i, "Content-Length:", 15) == 0) { cl = rbuf + i + 15; break; }
                }
                content_length = cl ? std::atoll(cl) : 0;
            }
        }
    }
}

}  // namespace

TEST(DispatchAlloc, AllocationsPerRequestOnResponsePath) {
    sys::startup();

    api::App app;
    app.get("/p", [](api::Request&, api::Response& res) { res.ok().text("Hello, World!"); });
    ASSERT_EQ(app.start_background("127.0.0.1", kPort), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    static const char kReq[] = "GET /p HTTP/1.1\r\nHost: x\r\n\r\n";
    const std::size_t kReqLen = sizeof(kReq) - 1;
    char rbuf[8192];

    // Warmup: excludes one-time allocs (thread pools, frame-arena pool block,
    // connection buffers, capacity growth).
    for (int i = 0; i < 2000; ++i) {
        ASSERT_TRUE(one_request(fd, kReq, kReqLen, rbuf, sizeof(rbuf))) << "warmup iter " << i;
    }

    constexpr int kIters = 20000;
    const std::uint64_t start = g_alloc_count.load(std::memory_order_relaxed);
    for (int i = 0; i < kIters; ++i) {
        ASSERT_TRUE(one_request(fd, kReq, kReqLen, rbuf, sizeof(rbuf))) << "iter " << i;
    }
    const std::uint64_t delta = g_alloc_count.load(std::memory_order_relaxed) - start;
    const double per_req = static_cast<double>(delta) / kIters;

    sys::close_socket(fd);
    app.stop();

    std::printf("\n[dispatch-alloc] allocations/request (server, steady state) = %.2f"
                "  (%llu allocs / %d reqs)\n\n",
                per_req, static_cast<unsigned long long>(delta), kIters);

    // Ceiling history:
    //   - Phase 1: 7 -> 3 (resp_str reuse + to_chars + branchless headers +
    //     removed the dispatch wrapper + conn_read/conn_write frames).
    //   - Phase 3 slice D-part-2: 3 -> 2. The dispatch coroutine frame (~3840 B)
    //     is now arena-backed: App::dispatch_coro_ returns
    //     http::dispatch_task<T> (not core::coro_task<T>), whose promise
    //     operator new draws from FrameArenaPool instead of `::operator new`.
    // Remaining 2 are the ~32 B Content-Type header value and one ~16 B alloc;
    // further reductions await a no-alloc header store.
    EXPECT_LE(per_req, 2.0) << "allocs/request on the dispatch+response path";
}
