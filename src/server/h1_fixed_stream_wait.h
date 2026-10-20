#pragma once
#include "h1_fixed_stream.h"

namespace bolt::api::http {

// The final arming->parked CAS is the last shared/frame access on a suspended
// path. A shared-engine completion may resume on another reactor immediately.
// While arming, a producer can notify but can NEVER post the coroutine handle.
// Hook is a compile-time test seam; production instantiates an empty callable.
template <class WhileArming>
bool h1_fixed_stream_suspend(H1FixedStreamSlot* state, bool completion_only,
                             std::coroutine_handle<> handle,
                             WhileArming while_arming) noexcept {
    using Phase = H1FixedStreamSlot::WaitPhase;
    assert(handle != nullptr);
    assert(state->busy.load(std::memory_order_relaxed));
    state->waiter.store(handle.address(), std::memory_order_relaxed);
    const Phase before = state->wait_phase.exchange(Phase::kArming,
                                                    std::memory_order_acq_rel);
    assert(before == Phase::kIdle || before == Phase::kNotified);
    (void)before;
    while_arming();
    if (state->done.load(std::memory_order_acquire) ||
        (!completion_only && state->pending.load(std::memory_order_acquire) != 0)) {
        state->waiter.store(nullptr, std::memory_order_relaxed);
        state->wait_phase.store(Phase::kIdle, std::memory_order_release);
        return false;  // arming/notified: no producer owns a resume
    }
    Phase expected = Phase::kArming;
    if (state->wait_phase.compare_exchange_strong(expected, Phase::kParked,
            std::memory_order_acq_rel, std::memory_order_acquire)) return true;
    // No access after a successful park; notification during arming cannot post.
    assert(expected == Phase::kNotified);
    state->waiter.store(nullptr, std::memory_order_relaxed);
    state->wait_phase.store(Phase::kIdle, std::memory_order_release);
    return false;
}

struct H1FixedStreamReady {
    H1FixedStreamSlot* slot;
    bool completion_only = false;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(std::coroutine_handle<> handle) const noexcept {
        // Snapshot every awaiter field before any publication. The helper's
        // successful park is followed only by returns, never by a this access.
        H1FixedStreamSlot* const state = slot;
        const bool completion = completion_only;
        return h1_fixed_stream_suspend(state, completion, handle, []() noexcept {});
    }
    void await_resume() const noexcept {}
};
}  // namespace bolt::api::http
