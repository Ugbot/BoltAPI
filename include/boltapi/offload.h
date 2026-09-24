// boltapi/offload.h — run blocking handler work off the I/O thread.
//
// With inline_resume (the IODispatcher default) every handler runs on the
// single I/O thread, so a handler that blocks for seconds stalls every other
// connection. `co_await app.offload(work)` from an async route or async
// middleware runs `work` on a worker-pool blocking thread and resumes the
// awaiting coroutine back on I/O thread 0, leaving the reactor free meanwhile.
//
// Resuming on thread 0 is only correct when that thread owns the connection:
// a single I/O thread, or a shared-engine backend (IOCP). Otherwise `work`
// runs inline — the same gate Response::stream's offloaded producer uses.
//
// Every middleware between the dispatcher and the awaiting coroutine must be
// async (App::use_async): a sync middleware's next() shim cannot survive a
// genuine suspension. The synchronous HTTP/3 entry (App::dispatch_http3)
// cannot either, so it marks its thread and an offload there runs inline.
#pragma once

#include "boltapi/net/io_dispatcher.h"

#include <cassert>
#include <cstdio>
#include <coroutine>
#include <functional>
#include <utility>

namespace bolt::api {

namespace detail {
// True while App::dispatch_http3 drives a dispatch to completion in one resume.
inline thread_local bool t_sync_dispatch = false;
}  // namespace detail

class Offload {
public:
    Offload(net::IODispatcher* io, std::function<void()> work) noexcept
        : io_(io), work_(std::move(work)) {
        assert(work_ != nullptr && "offload: empty work");
    }

    bool await_ready() {
        if (can_offload()) return false;
        work_();
        return true;
    }

    void await_suspend(std::coroutine_handle<> h) {
        assert(h && "offload: null continuation");
        assert(io_ != nullptr && io_->worker_pool() != nullptr);
        // The future is discarded: a packaged_task future never blocks in its
        // destructor, and completion is signalled by the post below.
        (void)io_->worker_pool()->submit_blocking([this, h]() {
            work_();
            // Refused only when the dispatcher is stopping: the connection is
            // being torn down, so report instead of resuming off-thread.
            if (!io_->post_to_io_thread(0, h)) {
                std::fprintf(stderr, "boltapi offload: resume dropped "
                                     "(I/O thread not accepting posts)\n");
            }
        });
    }

    void await_resume() const noexcept {}

private:
    bool can_offload() const noexcept {
        if (detail::t_sync_dispatch) return false;
        if (io_ == nullptr || io_->worker_pool() == nullptr) return false;
        return io_->io_thread_count() == 1 || !io_->per_thread_engines();
    }

    net::IODispatcher*    io_;
    std::function<void()> work_;
};

}  // namespace bolt::api
