// boltapi/http/frame_arena.h — per-request coroutine-frame allocator pool.
//
// A game-engine "frame allocator": a fixed pool of bump arenas carved from ONE
// pre-allocated contiguous block. The middleware chain (middleware.h) allocates
// every coroutine frame for a request from a single arena acquired from this pool,
// then releases it (reset) when the request's chain completes. No per-request
// malloc on the steady path; no smart pointers; bounded, pre-allocated memory.
//
// Why a pool of arenas (not one thread_local arena): a chain can SUSPEND (an async
// handler awaiting I/O), at which point the worker thread runs a DIFFERENT request's
// chain. Each in-flight chain therefore needs its OWN arena. The pool hands out an
// arena per chain (lock-free ring free-list) and takes it back when the chain ends.
//
// operator delete is contextless, so it can't find "which arena" — instead the
// whole pool is ONE contiguous block, and `frame_pool_owns(p)` range-checks it:
// arena frames are reclaimed by the per-request reset (delete is a no-op for them),
// while the rare global-new fallback (pool exhausted) is freed normally.
//
// TigerStyle: fixed capacity (named constants), bounded loops, >=2 asserts/fn,
// no exceptions, no per-request heap allocation, explicit teardown.
#pragma once

#include "boltapi/core/worker_pool.h"  // core::MPMCQueue (lock-free ring)

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>

namespace bolt::api::http {

// Bounds (explicit, bounded). The block is kArenas * kArenaBytes, allocated once.
inline constexpr std::uint32_t kFrameArenaCount = 256;     // max concurrent chains (pow2 for the ring)
inline constexpr std::size_t   kFrameArenaBytes = 8192;    // per-chain frame budget
inline constexpr std::size_t   kFrameAlign      = alignof(std::max_align_t);

static_assert((kFrameArenaCount & (kFrameArenaCount - 1)) == 0,
              "kFrameArenaCount must be a power of two (ring capacity)");
static_assert(kFrameArenaBytes % kFrameAlign == 0,
              "kFrameArenaBytes must be a multiple of kFrameAlign so arenas stay aligned");

// One bump arena over a [base, base+cap) span of the pool block. NOT thread-safe:
// exactly one chain owns an arena at a time (acquired exclusively; a suspended
// coroutine is not executing, so no concurrent access to a single arena).
class FrameArena {
public:
    FrameArena() noexcept = default;

    void init(std::byte* base, std::size_t cap) noexcept {
        assert(base != nullptr && "FrameArena::init: null base");
        assert(cap > 0 && "FrameArena::init: zero cap");
        base_ = base;
        cap_  = cap;
        off_  = 0;
    }

    // Bump-allocate `n` bytes, aligned. Returns nullptr on overflow (caller falls
    // back to global new). Bounded: a single compare; never grows.
    void* allocate(std::size_t n) noexcept {
        assert(base_ != nullptr && "FrameArena::allocate: uninitialized");
        const std::size_t aligned = (off_ + (kFrameAlign - 1)) & ~(kFrameAlign - 1);
        if (aligned + n > cap_) return nullptr;   // overflow: caller uses global new
        void* p = base_ + aligned;
        off_ = aligned + n;
        assert(off_ <= cap_ && "FrameArena: offset past capacity");
        return p;
    }

    void reset() noexcept { off_ = 0; }

private:
    std::byte*  base_ = nullptr;
    std::size_t cap_  = 0;
    std::size_t off_  = 0;
};

// The pool: one contiguous block + a lock-free ring of free arena indices.
class FrameArenaPool {
public:
    FrameArenaPool() {
        block_ = static_cast<std::byte*>(
            ::operator new(kTotalBytes, std::align_val_t(kFrameAlign)));
        end_ = block_ + kTotalBytes;
        for (std::uint32_t i = 0; i < kFrameArenaCount; ++i) {
            arenas_[i].init(block_ + static_cast<std::size_t>(i) * kFrameArenaBytes,
                            kFrameArenaBytes);
            const bool pushed = free_.try_push(i);
            assert(pushed && "FrameArenaPool: ring smaller than arena count");
            (void)pushed;
        }
        assert(block_ != nullptr && "FrameArenaPool: block alloc failed");
    }

    ~FrameArenaPool() {
        ::operator delete(block_, std::align_val_t(kFrameAlign));
    }

    FrameArenaPool(const FrameArenaPool&) = delete;
    FrameArenaPool& operator=(const FrameArenaPool&) = delete;

    // Acquire an exclusive arena (reset). Returns nullptr when the pool is
    // exhausted (caller's frames then fall back to global new — still correct).
    FrameArena* acquire() noexcept {
        std::optional<std::uint32_t> idx = free_.try_pop();
        if (!idx) return nullptr;
        assert(*idx < kFrameArenaCount && "acquire: bad index");
        arenas_[*idx].reset();
        return &arenas_[*idx];
    }

    // Return an arena to the pool (reset). Safe to call with nullptr.
    void release(FrameArena* a) noexcept {
        if (a == nullptr) return;
        const std::ptrdiff_t i = a - arenas_;
        assert(i >= 0 && i < static_cast<std::ptrdiff_t>(kFrameArenaCount) &&
               "release: arena not from this pool");
        a->reset();
        const bool pushed = free_.try_push(static_cast<std::uint32_t>(i));
        assert(pushed && "release: ring full (double release?)");
        (void)pushed;
    }

    // Is `p` inside the pool block? (Range check for the contextless operator
    // delete: true => arena frame, reclaimed by reset; false => global fallback.)
    bool owns(const void* p) const noexcept {
        return p >= block_ && p < end_;
    }

private:
    static constexpr std::size_t kTotalBytes =
        static_cast<std::size_t>(kFrameArenaCount) * kFrameArenaBytes;

    std::byte* block_ = nullptr;
    std::byte* end_   = nullptr;
    FrameArena arenas_[kFrameArenaCount]{};
    core::MPMCQueue<std::uint32_t, kFrameArenaCount> free_{};
};

// Process-wide pool (lazy, thread-safe init). One block for the whole process.
inline FrameArenaPool& frame_pool() noexcept {
    static FrameArenaPool pool;
    return pool;
}

inline FrameArena* frame_pool_acquire() noexcept { return frame_pool().acquire(); }
inline void        frame_pool_release(FrameArena* a) noexcept { frame_pool().release(a); }
inline bool        frame_pool_owns(const void* p) noexcept { return frame_pool().owns(p); }

}  // namespace bolt::api::http
