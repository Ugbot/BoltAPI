// middleware_alloc_test.cpp — proves the middleware onion is ALLOCATION-FREE on
// the steady-state request path (TigerStyle / LMAX-Disruptor memory model).
//
// The chain is driven by borrowed value handles (Next) — no shared_ptr, no
// per-link std::function — and every coroutine FRAME is bump-allocated from a
// per-request arena acquired from a pre-allocated pool (a Disruptor-style ring:
// pre-allocated slots, lock-free claim/publish). So after warmup (which triggers
// the one-time pool block + the registration-time std::function targets), running
// the chain N times must allocate EXACTLY ZERO times on the global heap.
//
// We drive the REAL ChainCtx/Next/chain_task machinery directly (no sockets), so
// this gates the production chain, not a mock.

#include "boltapi/middleware.h"
#include "boltapi/http/frame_arena.h"
#include "boltapi/request.h"
#include "boltapi/response.h"
#include "boltapi/server/coro_unified_server.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

// ---------------------------------------------------------------------------
// Global allocation counter (same pattern as no_alloc_test).
// ---------------------------------------------------------------------------
namespace {
std::atomic<std::uint64_t> g_alloc_count{0};
}  // namespace

// abort (not throw) on OOM: the suite builds -fno-exceptions on Clang/GCC.
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

namespace api  = bolt::api;
namespace http = bolt::api::http;

struct AllocGuard {
    std::uint64_t start = g_alloc_count.load(std::memory_order_relaxed);
    std::uint64_t delta() const noexcept {
        return g_alloc_count.load(std::memory_order_relaxed) - start;
    }
};

// Volatile sink: reading the heap value through it defeats the compiler's
// allocation-elision (C++14 [expr.new]/10) so the sanity check below is real.
volatile std::uint32_t g_sink = 0;

// A middleware that bumps a pre/post counter around next() — NO allocation.
api::AsyncMiddleware mk(int* pre, int* post) {
    return [pre, post](api::Request& req, api::Response& res, api::Next next)
               -> api::chain_task {
        ++(*pre);
        co_await next();
        ++(*post);
        co_return;
    };
}

// Terminal: bump a hit counter (read via the ctx) — NO allocation.
api::chain_task alloc_terminal(api::Request&, api::Response& res, api::Next next) {
    auto* hits = static_cast<int*>(const_cast<void*>(next.ctx()->terminal_ctx));
    ++(*hits);
    res.ok();
    co_return;
}

// Drive a (synchronous) chain to completion.
void drive(api::ChainCtx& ctx) {
    api::chain_task t = api::Next(&ctx, 0)();
    t.resume();
    while (!t.done()) t.resume();
}

}  // namespace

// Sanity: the instrumentation actually observes allocations.
TEST(MiddlewareAlloc, CounterObservesAllocation) {
    AllocGuard g;
    // Direct ::operator new call (NOT a new-expression) — exempt from C++14
    // allocation elision, so Clang/MSVC -O2 cannot optimize it away; the side
    // effect (counter increment) is observed via delta() below.
    void* p = ::operator new(64);
    g_sink ^= static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(p) & 0xFFu);
    ::operator delete(p);
    EXPECT_GE(g.delta(), 1u) << "global operator new instrumentation is not active";
}

// The headline gate: driving the chain N times allocates ZERO on the global heap.
TEST(MiddlewareAlloc, ChainIsAllocationFree) {
    int pre[3] = {0, 0, 0};
    int post[3] = {0, 0, 0};
    int hits = 0;

    // Registration-time std::function targets allocate HERE (outside the region).
    std::array<api::AsyncMiddleware, 3> mws = {mk(&pre[0], &post[0]),
                                               mk(&pre[1], &post[1]),
                                               mk(&pre[2], &post[2])};

    bolt::api::http::CoroHttpRequest  creq;   // default: empty views, 0 headers
    bolt::api::http::CoroHttpResponse cresp;
    cresp.status = 200;
    api::Request  req(creq, nullptr, 0);
    api::Response res(cresp);

    api::ChainCtx ctx;
    ctx.middleware   = mws.data();
    ctx.count        = static_cast<std::uint32_t>(mws.size());
    ctx.req          = &req;
    ctx.res          = &res;
    ctx.terminal     = &alloc_terminal;
    ctx.terminal_ctx = &hits;

    // Warmup: triggers the one-time pool block alloc + any lazy init.
    for (int i = 0; i < 200; ++i) {
        ctx.frames = http::frame_pool_acquire();
        drive(ctx);
        http::frame_pool_release(ctx.frames);
    }
    ASSERT_EQ(hits, 200);  // terminal ran every time (chain actually executed)

    constexpr int kIters = 100000;
    AllocGuard g;
    for (int i = 0; i < kIters; ++i) {
        ctx.frames = http::frame_pool_acquire();
        drive(ctx);
        http::frame_pool_release(ctx.frames);
    }
    EXPECT_EQ(g.delta(), 0u)
        << "middleware chain allocated on the hot path (" << g.delta()
        << " allocations across " << kIters << " runs)";

    // Onion executed fully: each middleware's pre + post ran every iteration.
    const int total = 200 + kIters;
    EXPECT_EQ(hits, total);
    for (int k = 0; k < 3; ++k) {
        EXPECT_EQ(pre[k], total);
        EXPECT_EQ(post[k], total);
    }
}

// Short-circuit (a middleware that does NOT call next()) is also allocation-free.
TEST(MiddlewareAlloc, ShortCircuitIsAllocationFree) {
    int reached_inner = 0;
    int hits = 0;
    std::array<api::AsyncMiddleware, 2> mws = {
        // Outer: short-circuits (never calls next()).
        [](api::Request&, api::Response& res, api::Next) -> api::chain_task {
            res.status(401);
            co_return;  // no next()
        },
        // Inner: would bump if reached (it must NOT be).
        [&reached_inner](api::Request&, api::Response&, api::Next next) -> api::chain_task {
            ++reached_inner;
            co_await next();
            co_return;
        }};

    bolt::api::http::CoroHttpRequest  creq;
    bolt::api::http::CoroHttpResponse cresp;
    cresp.status = 200;
    api::Request  req(creq, nullptr, 0);
    api::Response res(cresp);

    api::ChainCtx ctx;
    ctx.middleware = mws.data();
    ctx.count = 2;
    ctx.req = &req;
    ctx.res = &res;
    ctx.terminal = &alloc_terminal;
    ctx.terminal_ctx = &hits;

    for (int i = 0; i < 200; ++i) {
        ctx.frames = http::frame_pool_acquire();
        drive(ctx);
        http::frame_pool_release(ctx.frames);
    }

    constexpr int kIters = 100000;
    AllocGuard g;
    for (int i = 0; i < kIters; ++i) {
        ctx.frames = http::frame_pool_acquire();
        drive(ctx);
        http::frame_pool_release(ctx.frames);
    }
    EXPECT_EQ(g.delta(), 0u) << "short-circuit path allocated (" << g.delta() << ")";
    EXPECT_EQ(reached_inner, 0);          // inner never ran
    EXPECT_EQ(hits, 0);                   // terminal never ran
    EXPECT_EQ(res.status_code(), 401);
}
