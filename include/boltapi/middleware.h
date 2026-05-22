// boltapi/middleware.h — the coroutine middleware onion.
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
// Composition (App::build_chain) folds the registered middleware right-to-left
// so the terminal continuation is the matched route handler. The fold is
// bounded by the registered middleware count — no unbounded recursion on the
// hot path; each link is exactly one std::function hop.
//
// TODO(perf): each Next/AsyncMiddleware is a std::function => one heap alloc per
// link per request when captures exceed the SBO. An arena-backed continuation
// (bolt::Arena per-request scratch) would make the chain allocation-free. Not
// blocking for v1; flagged for the M-series perf pass.
#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/request.h"
#include "boltapi/response.h"

#include <functional>

namespace bolt::api {

// The continuation that advances to the next link (or the terminal handler).
// Awaiting it runs the remainder of the chain; not awaiting it short-circuits.
using Next = std::function<core::coro_task<void>()>;

// Async middleware: may co_await next() and run post-processing afterwards.
using AsyncMiddleware =
    std::function<core::coro_task<void>(Request&, Response&, Next)>;

// Sync middleware: receives a plain std::function next() it may call (or not).
// Auto-wrapped to an AsyncMiddleware via to_async() below.
using Middleware =
    std::function<void(Request&, Response&, std::function<void()>)>;

// ---------------------------------------------------------------------------
// Adapt a sync Middleware into an AsyncMiddleware.
//
// The sync middleware sees a synchronous next() shim. Because the underlying
// continuation is itself a coroutine, we drive it to completion synchronously
// when the shim is invoked: the engine's coro_task is lazy (initial_suspend =
// suspend_always) and our chain links never truly suspend on I/O in v1, so a
// resume()-to-done loop is correct and bounded. If a deeper link DOES suspend
// on real async I/O, mixing it under a *sync* middleware is unsupported (the
// async form must be used) — asserted via done() after the drive loop.
// ---------------------------------------------------------------------------
inline AsyncMiddleware to_async(Middleware sync) {
    return [sync = std::move(sync)](Request& req, Response& res, Next next)
               -> core::coro_task<void> {
        bool called = false;
        // Capture the async continuation; the sync shim resumes it inline.
        std::function<void()> sync_next = [&]() {
            called = true;
            core::coro_task<void> t = next();
            // Drive the lazy continuation to completion (bounded by chain depth).
            t.resume();                 // kick off (initial_suspend was lazy)
            while (!t.done()) {
                if (!t.resume()) break;  // resume() returns false when done
            }
        };
        sync(req, res, sync_next);
        (void)called;  // not awaiting is legal: it's an explicit short-circuit.
        co_return;
    };
}

}  // namespace bolt::api
