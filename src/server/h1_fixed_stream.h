#pragma once
// Private cleartext H1 fixed-stream handoff. Storage is allocated at server
// startup; the producer and reactor retain separate references to each slot.
// Exactly one copied slice can be pending. Only the reactor touches the socket.
#include "boltapi/http/fixed_stream_limits.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/net/sys_compat.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <coroutine>
#include <cstring>
#include <functional>
#include <cstdio>
#include <new>
#include <string_view>

namespace bolt::api::http {

struct H1FixedStreamSlot {
    static constexpr int32_t kCancelled = -1;
    enum class WaitPhase : uint8_t { kIdle, kArming, kNotified, kParked };
    enum class StartPhase : uint8_t { kWaiting, kRun, kCancel };
    using Sink = std::function<void(std::string_view)>;
    using Producer = std::function<void(const Sink&)>;
    alignas(64) std::atomic<bool> busy{false};
    std::atomic<uint32_t> references{0};
    std::atomic<int32_t> pending{0};
    std::atomic<bool> done{false};
    std::atomic<void*> waiter{nullptr};
    std::atomic<WaitPhase> wait_phase{WaitPhase::kIdle};
    std::atomic<StartPhase> start_phase{StartPhase::kWaiting};
    Producer producer;
    net::IODispatcher* io = nullptr;
    std::atomic<std::size_t> io_thread_index{0};
    std::atomic<int> active_fd{-1};  // -2 temporarily claims shutdown vs close
    uint64_t declared = 0;
    uint64_t produced = 0;  // producer-owned; read only after done.acquire
    bool overrun = false;  // producer-owned; read only after done.acquire
    alignas(64) char bytes[kFixedStreamSliceBytes];

    void release() noexcept {
        const uint32_t before = references.fetch_sub(1, std::memory_order_acq_rel);
        assert(before > 0);
        assert(before <= 2);
        if (before == 1) busy.store(false, std::memory_order_release);
    }

    // This is called only with a retained producer/consumer reference, so even
    // an immediate coroutine resume cannot recycle the slot underneath it.
    void wake() noexcept {
        assert(io != nullptr);
        assert(busy.load(std::memory_order_relaxed));
        WaitPhase phase = wait_phase.load(std::memory_order_acquire);
        while (phase != WaitPhase::kNotified) {
            const WaitPhase next = phase == WaitPhase::kParked
                ? WaitPhase::kIdle : WaitPhase::kNotified;
            if (!wait_phase.compare_exchange_weak(phase, next,
                    std::memory_order_acq_rel, std::memory_order_acquire)) continue;
            if (phase != WaitPhase::kParked) return;  // arming: never resume
            void* address = waiter.load(std::memory_order_relaxed);
            assert(address != nullptr);
            if (!io->post_to_io_thread(io_thread_index.load(std::memory_order_relaxed),
                    std::coroutine_handle<>::from_address(address))) {
                // Retain the exact parked waiter on refusal; never discard
                // ownership or resume on a foreign thread. Normal server stop
                // keeps reactors accepting completion posts until slots drain.
                wait_phase.store(WaitPhase::kParked, std::memory_order_release);
                cancel();
                std::fprintf(stderr, "[boltapi] fixed-stream resume refused; waiter retained\n");
            }
            return;
        }
    }

    void cancel() noexcept {
        assert(busy.load(std::memory_order_relaxed));
        assert(references.load(std::memory_order_relaxed) > 0);
        pending.store(kCancelled, std::memory_order_release);
        pending.notify_one();
        start_phase.store(StartPhase::kCancel, std::memory_order_release);
        start_phase.notify_one();
    }

    void run_producer() noexcept {
        assert(producer != nullptr);
        assert(references.load(std::memory_order_relaxed) == 2);
        StartPhase start = start_phase.load(std::memory_order_acquire);
        while (start == StartPhase::kWaiting) {
            start_phase.wait(start, std::memory_order_acquire);
            start = start_phase.load(std::memory_order_acquire);
        }
        if (start == StartPhase::kRun) {
            Sink sink = [this](std::string_view source) { emit(source); };
            producer(sink);
        }
        producer = nullptr;  // context dies before completion is published
        done.store(true, std::memory_order_release);
        wake();
        release();  // final worker access, even if the consumer already returned
    }

    // Normal completion remains the sole fd-close owner. A shutdown task may
    // claim the fd briefly; do not close/recycle it until that syscall returns.
    void deactivate_fd() noexcept {
        int fd = active_fd.load(std::memory_order_acquire);
        assert(fd >= -2);
        assert(busy.load(std::memory_order_relaxed));
        for (;;) {
            if (fd == -2) {
                active_fd.wait(-2, std::memory_order_acquire);
                fd = active_fd.load(std::memory_order_acquire);
            } else if (active_fd.compare_exchange_weak(fd, -1,
                    std::memory_order_acq_rel, std::memory_order_acquire)) break;
        }
        assert(active_fd.load(std::memory_order_relaxed) == -1);
    }

    void emit(std::string_view source) noexcept {
        assert(produced <= declared);
        assert(io != nullptr);
        if (source.empty() || overrun || pending.load(std::memory_order_acquire) < 0)
            return;
        if (source.size() > declared - produced) { overrun = true; return; }
        for (std::size_t off = 0; off < source.size();) {
            if (pending.load(std::memory_order_acquire) < 0) return;
            const std::size_t take = std::min(source.size() - off, sizeof(bytes));
            std::memcpy(bytes, source.data() + off, take);
            int32_t empty = 0;
            if (!pending.compare_exchange_strong(empty, static_cast<int32_t>(take),
                    std::memory_order_acq_rel, std::memory_order_acquire)) return;
            wake();
            int32_t state = pending.load(std::memory_order_acquire);
            while (state > 0) {
                pending.wait(state, std::memory_order_acquire);
                state = pending.load(std::memory_order_acquire);
            }
            if (state < 0) return;
            produced += take;
            off += take;
        }
        assert(produced <= declared);
    }
};

class H1FixedStreamPool {
public:
    explicit H1FixedStreamPool(std::size_t count) noexcept : count_(count) {
        assert(count > 0);
        assert(count <= kFixedStreamMaxSlots);
        slots_ = new (std::nothrow) H1FixedStreamSlot[count];
    }
    ~H1FixedStreamPool() { delete[] slots_; }
    H1FixedStreamPool(const H1FixedStreamPool&) = delete;
    H1FixedStreamPool& operator=(const H1FixedStreamPool&) = delete;
    bool valid() const noexcept { return slots_ != nullptr; }

    H1FixedStreamSlot* acquire(net::IODispatcher& io, std::size_t owner,
                              uint64_t length) noexcept {
        assert(slots_ != nullptr);
        assert(count_ <= kFixedStreamMaxSlots);
        assert(owner < io.io_thread_count());
        if (stopping_.load(std::memory_order_acquire)) return nullptr;
        for (std::size_t i = 0; i < count_; ++i) {
            H1FixedStreamSlot& slot = slots_[i];
            bool free = false;
            if (!slot.busy.compare_exchange_strong(free, true,
                    std::memory_order_acquire)) continue;
            slot.references.store(1, std::memory_order_relaxed);
            slot.pending.store(0, std::memory_order_relaxed);
            slot.done.store(false, std::memory_order_relaxed);
            slot.waiter.store(nullptr, std::memory_order_relaxed);
            slot.wait_phase.store(H1FixedStreamSlot::WaitPhase::kIdle, std::memory_order_relaxed);
            slot.start_phase.store(H1FixedStreamSlot::StartPhase::kWaiting, std::memory_order_relaxed);
            assert(slot.producer == nullptr);
            slot.io = &io;
            slot.io_thread_index.store(owner, std::memory_order_relaxed);
            slot.active_fd.store(-1, std::memory_order_relaxed);
            slot.declared = length;
            slot.produced = 0;
            slot.overrun = false;
            // close the race with cancel_all after the first stopping check
            if (stopping_.load(std::memory_order_acquire)) {
                slot.cancel();
                slot.release();
                return nullptr;
            }
            return &slot;
        }
        return nullptr;
    }

    // Called after accepting has stopped and before joining I/O/workers. The
    // backing bytes outlive both: a final I/O drain never sees producer scratch.
    void cancel_all() noexcept {
        assert(slots_ != nullptr);
        assert(count_ <= kFixedStreamMaxSlots);
        stopping_.store(true, std::memory_order_release);
        for (std::size_t i = 0; i < count_; ++i) {
            // Slots persist until pool destruction; cancellation does not read
            // other slot fields, so it can race acquisition and final release.
            slots_[i].pending.store(H1FixedStreamSlot::kCancelled,
                                    std::memory_order_release);
            slots_[i].pending.notify_one();
            slots_[i].start_phase.store(H1FixedStreamSlot::StartPhase::kCancel,
                                        std::memory_order_release);
            slots_[i].start_phase.notify_one();
        }
    }

    void shutdown_on_reactor(net::IODispatcher& io, std::size_t index) noexcept {
        assert(io.current_io_thread_index() == index);
        assert(stopping_.load(std::memory_order_acquire));
        for (std::size_t i = 0; i < count_; ++i) {
            H1FixedStreamSlot& slot = slots_[i];
            int fd = slot.active_fd.load(std::memory_order_acquire);
            if (fd < 0 || slot.io_thread_index.load(std::memory_order_relaxed) != index)
                continue;
            if (!slot.active_fd.compare_exchange_strong(fd, -2,
                    std::memory_order_acq_rel, std::memory_order_acquire)) continue;
#ifdef _WIN32
            const int result = ::shutdown(static_cast<SOCKET>(fd), SD_BOTH);
#else
            const int result = ::shutdown(fd, SHUT_RDWR);
#endif
            // A reset peer may already be disconnected. Its pending write still
            // completes as an error; the ordinary connection path owns close.
            if (result != 0) std::fprintf(stderr,
                "[boltapi] fixed-stream shutdown: peer already disconnected\n");
            slot.active_fd.store(fd, std::memory_order_release);
            slot.active_fd.notify_one();
        }
    }

    bool idle() const noexcept {
        assert(slots_ != nullptr);
        assert(count_ <= kFixedStreamMaxSlots);
        for (std::size_t i = 0; i < count_; ++i)
            if (slots_[i].busy.load(std::memory_order_acquire)) return false;
        return true;
    }

private:
    H1FixedStreamSlot* slots_ = nullptr;
    std::size_t count_;
    std::atomic<bool> stopping_{false};
};

}  // namespace bolt::api::http
