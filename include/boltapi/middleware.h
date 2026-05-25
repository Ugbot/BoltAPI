// boltapi/middleware.h — the coroutine middleware onion (handle-driven).
//
// A request flows through a chain of middleware, each of which may run code
// before AND after the rest of the chain by awaiting next():
//
//     co_await mw0(req, res, [&]{ co_await mw1(req, res, [&]{ ... handler ... }); });
//
// Calling next() proceeds inward to the next link; NOT calling next()
// short-circuits (e.g. an auth middleware that writes 401 and returns without
// awaiting next() prevents the handler from ever running).
//
// TigerStyle / game-engine memory model (NO smart pointers, NO per-request heap):
//   * `Next` is a tiny VALUE HANDLE — a borrowed `ChainCtx*` + a link index. It is
//     copied by value (two words); it allocates nothing. (The old design folded
//     the chain with one `std::make_shared<Next>` + one `std::function` per link
//     PER REQUEST — banned: shared_ptr churn on the hot path.)
//   * `ChainCtx` lives on the dispatch coroutine's frame for the request and is
//     borrowed (non-owning) by every `Next`. The middleware live in a contiguous
//     array (`App::middleware_`); the chain indexes into it.
//   * `Next::operator()` is NOT itself a coroutine — it returns the next link's
//     task directly, so there is no per-link driver frame.
//   * The terminal (the matched route handler) is reached via a plain function
//     pointer + opaque ctx — no `std::function`, no allocation.
//
// The middleware coroutine FRAMES themselves are allocated from a per-request
// frame arena (a pre-allocated pool / ring — see frame_arena.h) via `chain_task`,
// so the steady-state request path performs no heap allocation for the chain.
#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/http/frame_arena.h"
#include "boltapi/request.h"
#include "boltapi/response.h"

#include <cassert>
#include <cstdint>
#include <functional>

namespace bolt::api {

struct ChainCtx;

// Free a chain coroutine frame: arena frames (in the pool block) are reclaimed by
// the per-request release/reset, so deletion is a no-op; the rare global-new
// fallback (pool exhausted) is freed normally. Contextless by necessity (operator
// delete has no access to the per-request arena) — the pool range-check resolves it.
inline void chain_free_frame(void* p) noexcept {
    if (p == nullptr) return;
    if (http::frame_pool_owns(p)) return;  // arena memory: reclaimed on release
    ::operator delete(p);                   // global fallback allocation
}

// ---------------------------------------------------------------------------
// chain_task — the coroutine task used by every middleware link + the terminal.
// Identical surface to core::coro_task<void>, but its FRAME is allocated from the
// per-request frame arena reached through the `Next` parameter (param-passing
// promise `operator new`). All chain coroutines therefore share one bump arena
// and free nothing individually (the arena is released as a unit per request).
// ---------------------------------------------------------------------------
class Next;  // fwd (carries the arena pointer into operator new)

class chain_task {
public:
    struct promise_type {
        std::coroutine_handle<> continuation_{};

        chain_task get_return_object() noexcept {
            return chain_task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() noexcept { return {}; }

        struct final_awaiter {
            bool await_ready() const noexcept { return false; }
            std::coroutine_handle<> await_suspend(
                std::coroutine_handle<promise_type> h) noexcept {
                auto cont = h.promise().continuation_;
                return cont ? cont : std::noop_coroutine();
            }
            void await_resume() noexcept {}
        };
        final_awaiter final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::abort(); }  // -fno-exceptions

        // Frame allocation: pull from the per-request arena carried by `Next`.
        // Every chain coroutine has `Next` as its LAST parameter; the compiler
        // forwards the coroutine's parameters here (a lambda may prepend its
        // closure object, so we take the final argument generically). Falls back
        // to global new ONLY if the pool is exhausted (range-checked in operator
        // delete, so the fallback is still freed correctly).
        template <typename... Args>
        static void* operator new(std::size_t n, Args&... args) noexcept;
        static void  operator delete(void* p) noexcept { chain_free_frame(p); }
        static void  operator delete(void* p, std::size_t) noexcept { chain_free_frame(p); }
    };

    chain_task() noexcept = default;
    explicit chain_task(std::coroutine_handle<promise_type> h) noexcept : handle_(h) {}
    chain_task(chain_task&& o) noexcept : handle_(std::exchange(o.handle_, nullptr)) {}
    chain_task& operator=(chain_task&& o) noexcept {
        if (this != &o) {
            if (handle_) handle_.destroy();
            handle_ = std::exchange(o.handle_, nullptr);
        }
        return *this;
    }
    chain_task(const chain_task&) = delete;
    chain_task& operator=(const chain_task&) = delete;
    ~chain_task() { if (handle_) handle_.destroy(); }

    bool resume() {
        if (!handle_ || handle_.done()) return false;
        handle_.resume();
        return !handle_.done();
    }
    bool done() const noexcept { return !handle_ || handle_.done(); }

    struct awaiter {
        std::coroutine_handle<promise_type> h_;
        bool await_ready() const noexcept { return !h_ || h_.done(); }
        std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
            h_.promise().continuation_ = awaiting;
            return h_;
        }
        void await_resume() const noexcept {}
    };
    awaiter operator co_await() && noexcept { return awaiter{handle_}; }

private:
    std::coroutine_handle<promise_type> handle_{};
};

// ---------------------------------------------------------------------------
// Next — borrowed value handle into the chain (no allocation, no smart pointer).
// ---------------------------------------------------------------------------
class Next {
public:
    Next() noexcept = default;
    Next(const ChainCtx* ctx, std::uint32_t index) noexcept : ctx_(ctx), index_(index) {}

    chain_task operator()() const;            // defined after ChainCtx

    const ChainCtx* ctx() const noexcept { return ctx_; }
    std::uint32_t   index() const noexcept { return index_; }

private:
    const ChainCtx* ctx_   = nullptr;
    std::uint32_t   index_ = 0;
};

// Extract the trailing Next from a chain coroutine's forwarded parameters (Next
// is always the last parameter; a lambda closure object, if present, is first).
namespace detail {
inline const Next& chain_last_next(const Next& n) noexcept { return n; }
template <typename T0, typename... Rest>
inline const Next& chain_last_next(const T0&, const Rest&... rest) noexcept {
    return chain_last_next(rest...);
}
}  // namespace detail

// Async middleware: may co_await next() and run post-processing afterwards.
using AsyncMiddleware = std::function<chain_task(Request&, Response&, Next)>;

// Sync middleware: receives a plain std::function next() it may call (or not).
using Middleware = std::function<void(Request&, Response&, std::function<void()>)>;

// Terminal (the matched route handler) reached via a function pointer — no
// std::function, no allocation. It takes the same (Request&, Response&, Next)
// signature as a middleware so every chain coroutine shares one frame allocator;
// it reads its opaque payload (the RouteEntry) from `next.ctx()->terminal_ctx`.
using ChainTerminalFn = chain_task (*)(Request&, Response&, Next);

// ---------------------------------------------------------------------------
// ChainCtx — per-request, borrowed by every Next. Lives on the dispatch frame.
// All members are NON-OWNING. `frames` is the per-request frame arena (acquired
// from the pool by the dispatcher) that backs every chain coroutine frame.
// ---------------------------------------------------------------------------
struct ChainCtx {
    const AsyncMiddleware* middleware   = nullptr;  // contiguous array
    std::uint32_t          count        = 0;
    Request*               req          = nullptr;
    Response*              res          = nullptr;
    ChainTerminalFn        terminal     = nullptr;
    const void*            terminal_ctx = nullptr;
    http::FrameArena*      frames       = nullptr;   // backs chain_task frames
};

// operator(): NOT a coroutine — returns the next link's task directly (no per-link
// driver frame). Awaiting it runs the remainder of the chain; not awaiting it
// short-circuits.
inline chain_task Next::operator()() const {
    assert(ctx_ != nullptr && "Next: null chain ctx");
    assert(index_ <= ctx_->count && "Next: index past chain end");
    if (index_ < ctx_->count) {
        return ctx_->middleware[index_](*ctx_->req, *ctx_->res, Next(ctx_, index_ + 1));
    }
    return ctx_->terminal(*ctx_->req, *ctx_->res, Next(ctx_, index_));
}

// Promise frame allocation: arena via the (trailing) Next handle, else global.
template <typename... Args>
void* chain_task::promise_type::operator new(std::size_t n, Args&... args) noexcept {
    const Next& next = detail::chain_last_next(args...);
    if (const ChainCtx* c = next.ctx()) {
        if (c->frames != nullptr) {
            if (void* p = c->frames->allocate(n)) return p;  // arena hit
        }
    }
    return ::operator new(n, std::nothrow);  // pool exhausted/overflow: global
}

// ---------------------------------------------------------------------------
// Adapt a sync Middleware into an AsyncMiddleware.
//
// The sync middleware sees a synchronous next() shim that drives the (lazy)
// continuation to completion inline. Correct because chain links never truly
// suspend on I/O under a *sync* middleware in v1; a deeper link that DOES suspend
// must use the async form.
// ---------------------------------------------------------------------------
inline AsyncMiddleware to_async(Middleware sync) {
    return [sync = std::move(sync)](Request& req, Response& res, Next next)
               -> chain_task {
        std::function<void()> sync_next = [&]() {
            chain_task t = next();
            t.resume();
            while (!t.done()) { if (!t.resume()) break; }
        };
        sync(req, res, sync_next);
        co_return;
    };
}

}  // namespace bolt::api
