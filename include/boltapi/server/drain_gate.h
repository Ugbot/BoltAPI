#pragma once

// Connection drain gate for CoroUnifiedServer graceful shutdown: an active
// connection count plus the mutex/condvar that shutdown waiters block on.
//
// A notifier must take and release the mutex between publishing the state a
// waiter checks and calling notify_all. Otherwise the notify can land after
// the waiter evaluated its predicate but before it blocked, and is lost: the
// waiter then sleeps to its deadline (G2CHK-1303).

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>

#include "boltapi/core/coro_task.h"

namespace bolt::api::http {

// Test seam: called with the mutex held, after a waiter's predicate failed and
// before it blocks. nullptr in production.
using DrainGateWaitHook = void (*)(void* ctx);

class DrainGate {
public:
    using Clock = std::chrono::steady_clock;

    void open_one() noexcept {
        uint64_t prev = active_.fetch_add(1, std::memory_order_relaxed);
        assert(prev < UINT64_MAX);
        (void)prev;
    }

    // Returns true when this close took the count to zero.
    bool close_one() noexcept {
        uint64_t prev = active_.fetch_sub(1, std::memory_order_acq_rel);
        assert(prev > 0);
        return prev == 1;
    }

    // Wake every waiter after the caller published the state they wait on.
    // Passing through the mutex orders this after any waiter's predicate
    // check, so the notify cannot fall into its check-to-block window.
    void wake() noexcept {
        { std::lock_guard<std::mutex> lock(mutex_); }
        shutdown_cv_.notify_all();
    }

    uint64_t active() const noexcept {
        return active_.load(std::memory_order_acquire);
    }

    bool wait_drained(Clock::time_point deadline) noexcept {
        return wait_until(deadline, [this]() noexcept { return active() == 0; });
    }

    // Wait for pred() under the gate mutex. The caller must not hold it.
    template <typename Pred>
    bool wait_until(Clock::time_point deadline, Pred pred) noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        assert(lock.owns_lock());
        while (!pred()) {
            if (wait_hook_ != nullptr) wait_hook_(wait_hook_ctx_);
            if (shutdown_cv_.wait_until(lock, deadline) == std::cv_status::timeout) {
                return pred();
            }
        }
        return true;
    }

    void set_wait_hook(DrainGateWaitHook hook, void* ctx) noexcept {
        assert(hook != nullptr || ctx == nullptr);
        std::lock_guard<std::mutex> lock(mutex_);
        wait_hook_ = hook;
        wait_hook_ctx_ = ctx;
    }

private:
    std::mutex mutex_;
    std::condition_variable shutdown_cv_;
    DrainGateWaitHook wait_hook_ = nullptr;
    void* wait_hook_ctx_ = nullptr;
    alignas(core::kCacheLineSize) std::atomic<uint64_t> active_{0};
};

}  // namespace bolt::api::http
