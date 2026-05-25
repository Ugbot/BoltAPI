// no_alloc_test.cpp — proves the router + http1-parser hot paths are
// allocation-free (TigerStyle / HFT mechanical sympathy).
//
// We install a global operator new / new[] / delete / delete[] that bumps a
// thread-safe atomic counter. A scoped guard snapshots the counter, runs the
// hot path many times, and asserts the delta is exactly zero. Warmup runs
// first so any one-time lazy init (none expected on these paths) is excluded.
//
// SCOPE NOTE: this test covers Router::match() (static + param + wildcard + miss)
// and HTTP1Parser in isolation. The App MIDDLEWARE chain is now ALSO allocation-
// free (handle-driven onion + a Disruptor-style per-request frame-arena pool, no
// shared_ptr / no per-link std::function) — that is gated separately in
// middleware_alloc_test.cpp. (The top-level dispatch coroutine frame is still one
// heap frame per request; eliminating it is a separate item.)

#include "boltapi/router.h"
#include "boltapi/http/http1_parser.h"
#include "util/http_fuzz.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Global allocation counter. Thread-safe (relaxed atomics — we only need an
// accurate total, not ordering). Replacing the global operator new/delete is
// well-defined and affects the whole program for this test binary.
// ---------------------------------------------------------------------------
namespace {
std::atomic<std::uint64_t> g_alloc_count{0};
std::atomic<std::uint64_t> g_free_count{0};
}  // namespace

void* operator new(std::size_t n) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (n == 0) n = 1;
    void* p = std::malloc(n);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t n) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (n == 0) n = 1;
    void* p = std::malloc(n);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void* p) noexcept {
    if (p) { g_free_count.fetch_add(1, std::memory_order_relaxed); std::free(p); }
}
void operator delete[](void* p) noexcept {
    if (p) { g_free_count.fetch_add(1, std::memory_order_relaxed); std::free(p); }
}
// Sized-deallocation overloads (C++14+): route through the unsized form so the
// counter stays consistent regardless of which the compiler selects.
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete[](p); }

namespace {

namespace api = bolt::api;

// RAII snapshot of the allocation counter over a scope.
struct AllocGuard {
    std::uint64_t start = g_alloc_count.load(std::memory_order_relaxed);
    std::uint64_t delta() const noexcept {
        return g_alloc_count.load(std::memory_order_relaxed) - start;
    }
};

// Build a representative router: static + param + wildcard across verbs.
void build_router(api::Router& r) {
    r.add(api::Method::Get,  "/health");
    r.add(api::Method::Get,  "/api/v1/status");
    r.add(api::Method::Post, "/api/v1/login");
    r.add(api::Method::Get,  "/users/{id}");
    r.add(api::Method::Get,  "/users/{id}/posts/{pid}");
    r.add(api::Method::Put,  "/users/{id}");
    r.add(api::Method::Get,  "/files/*");
    r.build();
}

// A volatile sink prevents the optimizer from eliding match() / parse() calls.
volatile std::uint32_t g_sink = 0;

}  // namespace

// ---------------------------------------------------------------------------
// Sanity: the counter actually observes a heap allocation (guards against the
// instrumentation silently no-op'ing, which would make the zero asserts vacuous).
// ---------------------------------------------------------------------------
TEST(NoAlloc, CounterObservesAllocation) {
    AllocGuard g;
    // Force a heap allocation the optimizer cannot remove.
    auto* p = new std::uint64_t(0xDEADBEEF);
    g_sink ^= static_cast<std::uint32_t>(*p);
    delete p;
    EXPECT_GE(g.delta(), 1u) << "global operator new instrumentation is not active";
}

// ---------------------------------------------------------------------------
// Router::match() — static hits, param hits, wildcard, and misses must all be
// allocation-free. Build the router OUTSIDE the measured region (build() does
// allocate, by design — it owns the arena/trie).
// ---------------------------------------------------------------------------
TEST(NoAlloc, RouterMatchIsAllocationFree) {
    api::Router r;
    build_router(r);

    // Concrete paths kept alive for the whole measured region; match() returns
    // string_views into these, so no allocation should ever be needed.
    const std::string p_static_a = "/health";
    const std::string p_static_b = "/api/v1/status";
    const std::string p_param_a  = "/users/4242";
    const std::string p_param_b  = "/users/7/posts/99";
    const std::string p_wild     = "/files/a/b/c/deep/tail.txt";
    const std::string p_miss     = "/no/such/route/here";

    // Warmup (excluded from the assertion).
    for (int i = 0; i < 1000; ++i) {
        g_sink ^= r.match(api::Method::Get,  p_static_a).route_id;
        g_sink ^= r.match(api::Method::Get,  p_param_a).route_id;
        g_sink ^= r.match(api::Method::Get,  p_wild).route_id;
        g_sink ^= r.match(api::Method::Get,  p_miss).route_id;
    }

    constexpr int kIters = 200000;
    AllocGuard g;
    for (int i = 0; i < kIters; ++i) {
        api::MatchResult m1 = r.match(api::Method::Get,  p_static_a);
        api::MatchResult m2 = r.match(api::Method::Post, p_static_b);  // method-miss (status is GET-only)
        api::MatchResult m3 = r.match(api::Method::Get,  p_param_a);
        api::MatchResult m4 = r.match(api::Method::Get,  p_param_b);
        api::MatchResult m5 = r.match(api::Method::Get,  p_wild);
        api::MatchResult m6 = r.match(api::Method::Get,  p_miss);
        g_sink ^= m1.route_id ^ m2.route_id ^ m3.route_id ^
                  m4.route_id ^ m5.route_id ^ m6.route_id ^ m3.param_count;
    }
    EXPECT_EQ(g.delta(), 0u)
        << "Router::match() allocated on the hot path (" << g.delta()
        << " allocations across " << kIters << " iterations)";
}

// ---------------------------------------------------------------------------
// Randomized match() driver — vary param values across many seeds; still zero.
// ---------------------------------------------------------------------------
TEST(NoAlloc, RouterMatchRandomizedIsAllocationFree) {
    api::Router r;
    build_router(r);

    boltapi::test::FuzzRng rng{0xA110C0DEu};
    // Pre-generate concrete paths so string construction is outside the region.
    std::vector<std::string> paths;
    paths.reserve(512);
    for (int i = 0; i < 512; ++i) {
        const std::string id  = std::to_string(rng.in_range(1, 1000000));
        const std::string pid = std::to_string(rng.in_range(1, 1000000));
        switch (rng.below(4)) {
            case 0:  paths.push_back("/users/" + id); break;
            case 1:  paths.push_back("/users/" + id + "/posts/" + pid); break;
            case 2:  paths.push_back("/files/" + id + "/" + pid + "/x"); break;
            default: paths.push_back("/health"); break;
        }
    }

    // Warmup.
    for (const auto& p : paths) g_sink ^= r.match(api::Method::Get, p).route_id;

    AllocGuard g;
    for (int rep = 0; rep < 200; ++rep) {
        for (const auto& p : paths) {
            api::MatchResult m = r.match(api::Method::Get, p);
            g_sink ^= m.route_id ^ m.param_count;
            for (std::uint32_t k = 0; k < m.param_count; ++k) {
                g_sink ^= static_cast<std::uint32_t>(m.params[k].value.size());
            }
        }
    }
    EXPECT_EQ(g.delta(), 0u)
        << "randomized Router::match() allocated (" << g.delta() << ")";
}

// ---------------------------------------------------------------------------
// HTTP1Parser — parsing a full request into a stack-resident HTTP1Request
// (std::array headers, string_views into the input) must not touch the heap.
// ---------------------------------------------------------------------------
TEST(NoAlloc, Http1ParserIsAllocationFree) {
    using bolt::api::http::HTTP1Parser;
    using bolt::api::http::HTTP1Request;

    // Several representative raw requests (caller-owned buffers).
    const std::string reqs[] = {
        "GET /health HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
        "GET /users/42?expand=true HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n",
        "POST /api/v1/login HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
        "Content-Type: application/json\r\n\r\nhello",
        "PUT /users/7 HTTP/1.1\r\nHost: x\r\nX-Trace: abc-123\r\n"
        "Content-Length: 3\r\n\r\nfoo",
    };
    constexpr int kReqs = static_cast<int>(sizeof(reqs) / sizeof(reqs[0]));

    // Warmup: parse each once (parser is stack-only; reset() between requests).
    for (int i = 0; i < kReqs; ++i) {
        HTTP1Parser parser;
        HTTP1Request out;
        std::size_t consumed = 0;
        int rc = parser.parse(reinterpret_cast<const std::uint8_t*>(reqs[i].data()),
                              reqs[i].size(), out, consumed);
        g_sink ^= static_cast<std::uint32_t>(rc) ^
                  static_cast<std::uint32_t>(out.header_count);
    }

    constexpr int kIters = 50000;
    AllocGuard g;
    for (int it = 0; it < kIters; ++it) {
        for (int i = 0; i < kReqs; ++i) {
            HTTP1Parser parser;            // value type — lives on the stack
            HTTP1Request out;              // std::array headers — stack-resident
            std::size_t consumed = 0;
            int rc = parser.parse(
                reinterpret_cast<const std::uint8_t*>(reqs[i].data()),
                reqs[i].size(), out, consumed);
            g_sink ^= static_cast<std::uint32_t>(rc) ^
                      static_cast<std::uint32_t>(out.header_count) ^
                      static_cast<std::uint32_t>(consumed) ^
                      static_cast<std::uint32_t>(out.path.size());
        }
    }
    EXPECT_EQ(g.delta(), 0u)
        << "HTTP1Parser allocated on the parse path (" << g.delta()
        << " allocations across " << (kIters * kReqs) << " parses)";
}
