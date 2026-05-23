#pragma once
/**
 * @file body_buffer_arena.h
 * @brief Thread-local request-body buffer provider for HTTP request bodies.
 *
 * Two implementations live behind the BOLTAPI_USE_BOLT_ARENA compile flag; the
 * PUBLIC API (BodyBufferArena::Handle, acquire(size_t)->Handle,
 * thread_body_arena(), thread_body_arena_reset()) is identical in both so that
 * RequestBodyBuffer and all callers compile unchanged.
 *
 *   BOLTAPI_USE_BOLT_ARENA == 0 (DEFAULT)
 *   -------------------------------------
 *   Slot-pool. Pre-allocates reusable buffers in two tiers to avoid per-request
 *   heap allocation:
 *     Tier 1: 4 × 64KB  = 256KB per thread  (typical bulk API payloads)
 *     Tier 2: 2 × 1MB   = 2MB per thread    (large bulk imports)
 *   Bodies exceeding Tier 2 fall back to a one-off heap allocation (< 0.1% of
 *   requests). Handle is a move-only RAII view that releases its slot on
 *   destruction; thread_body_arena_reset() is a no-op (reclamation is per-slot).
 *
 *   BOLTAPI_USE_BOLT_ARENA == 1 (opt-in, risk-gated)
 *   ------------------------------------------------
 *   Bump allocator: each acquire(n) carves n bytes (align 64) from a
 *   thread-local bolt::Arena. The arena grows on demand and frees nothing until
 *   thread_body_arena_reset() resets the whole arena. The returned Handle is a
 *   NON-OWNING view (data + capacity); Handle::release() is a NO-OP — memory is
 *   reclaimed only by the per-request reset, NEVER per handle. A heap fallback
 *   is used only if Arena::allocate returns nullptr (block table exhausted).
 *
 *   CRITICAL (arena mode): thread_body_arena_reset() must be called only when no
 *   live body view points into the arena (use-after-reset is the hazard). Call
 *   sites guard this; see src/server/coro_unified_server.cpp.
 *
 * Thread-local: no locks or atomics needed (coroutines on same thread are
 * cooperative).
 */

#include <cstdint>
#include <cstddef>
#include <memory>
#include <array>
#include <cstring>

#ifndef BOLTAPI_USE_BOLT_ARENA
#define BOLTAPI_USE_BOLT_ARENA 0
#endif

#if BOLTAPI_USE_BOLT_ARENA
#include <atomic>
#include "bolt/bolt_arena.h"
// bolt_arena.h -> bolt_port.h pulls in <windows.h> on Win32, which leaks
// preprocessor macros that collide with the engine's scoped enums:
//   NO_ERROR (winerror.h) -> http2::ErrorCode::NO_ERROR
//   ERROR    (wingdi.h)   -> core::LogLevel::ERROR
//   DELETE   (winnt.h)    -> http Method::DELETE
// Undef the known collisions so downstream engine headers parse identically to
// the default (no-windows.h) build. Local to the opt-in arena path.
#ifdef NO_ERROR
#undef NO_ERROR
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DELETE
#undef DELETE
#endif
#endif

namespace bolt::api {
namespace http {

#if BOLTAPI_USE_BOLT_ARENA
// ===========================================================================
// Bolt-native bump-allocator implementation (opt-in, risk-gated).
// ===========================================================================

class BodyBufferArena {
public:
    // Tier constants retained for API/source compatibility (callers may read
    // them); they have no functional role in the bump-allocator path.
    static constexpr size_t TIER1_SIZE  = 64 * 1024;
    static constexpr size_t TIER1_COUNT = 4;
    static constexpr size_t TIER2_SIZE  = 1024 * 1024;
    static constexpr size_t TIER2_COUNT = 2;
    static constexpr size_t TOTAL_SLOTS = TIER1_COUNT + TIER2_COUNT;

    /**
     * Non-owning view over arena-bumped memory. Move-only to preserve the
     * default path's value semantics. Destruction does NOT free the bytes (they
     * belong to the arena, reclaimed in bulk by reset()) but DOES decrement the
     * owning arena's live-view count so reset() can know when it is safe.
     * For the rare heap-fallback case the Handle owns the allocation directly
     * (and carries no arena back-pointer).
     */
    class Handle {
    public:
        Handle() noexcept = default;

        Handle(uint8_t* data, size_t capacity, BodyBufferArena* arena) noexcept
            : data_(data), capacity_(capacity), arena_(arena) {}

        ~Handle() { release(); }

        Handle(Handle&& o) noexcept
            : data_(o.data_), capacity_(o.capacity_), arena_(o.arena_),
              heap_buf_(std::move(o.heap_buf_)) {
            o.data_ = nullptr;
            o.capacity_ = 0;
            o.arena_ = nullptr;
        }

        Handle& operator=(Handle&& o) noexcept {
            if (this != &o) {
                release();
                data_ = o.data_;
                capacity_ = o.capacity_;
                arena_ = o.arena_;
                heap_buf_ = std::move(o.heap_buf_);
                o.data_ = nullptr;
                o.capacity_ = 0;
                o.arena_ = nullptr;
            }
            return *this;
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        uint8_t* data() const noexcept { return data_; }
        size_t capacity() const noexcept { return capacity_; }
        explicit operator bool() const noexcept { return data_ != nullptr; }

    private:
        friend class BodyBufferArena;

        static Handle from_heap(std::unique_ptr<uint8_t[]> buf, size_t cap) noexcept {
            Handle h;
            h.heap_buf_ = std::move(buf);
            h.data_ = h.heap_buf_.get();
            h.capacity_ = cap;
            return h;  // arena_ stays null: pure heap ownership
        }

        // Arena-backed views do NOT free bytes here (the arena reclaims them via
        // reset()); they only retire their live-view reservation so a later
        // reset() on the owning arena becomes safe. Heap-fallback frees its buf.
        void release() noexcept {
            if (arena_) {
                arena_->retire_view();
                arena_ = nullptr;
            }
            data_ = nullptr;
            capacity_ = 0;
            heap_buf_.reset();
        }

        uint8_t* data_ = nullptr;
        size_t capacity_ = 0;
        BodyBufferArena* arena_ = nullptr;       // null for heap fallback
        std::unique_ptr<uint8_t[]> heap_buf_;    // only set for heap fallback
    };

    BodyBufferArena() = default;

    /**
     * Bump-allocate `needed` bytes (align 64) from this arena. Falls back to a
     * one-off heap allocation only if the arena cannot satisfy the request
     * (block table exhausted / OOM). Arena-backed handles reserve a live view.
     */
    Handle acquire(size_t needed) noexcept {
        if (needed == 0) needed = 1;  // never hand back a zero-capacity view
        void* p = arena_.allocate(needed, 64);
        if (p) {
            live_views_.fetch_add(1, std::memory_order_acq_rel);
            return Handle(static_cast<uint8_t*>(p), needed, this);
        }
        // Arena exhausted — heap fallback (Handle owns it; no live-view reserve).
        auto buf = std::make_unique<uint8_t[]>(needed);
        return Handle::from_heap(std::move(buf), needed);
    }

    /**
     * Reset the arena, reclaiming every outstanding view in one O(1) step —
     * but ONLY when no Handle still references it. Under the engine's
     * any-worker coroutine resumption, a body view acquired from this arena may
     * still be live on another in-flight coroutine; resetting then would be a
     * use-after-reset. We therefore make reset a safe no-op while live views
     * remain, and reclaim on the first reset call that observes a quiescent
     * arena (which is the common case at request teardown, where the request's
     * own Handle has just been released).
     */
    void reset() noexcept {
        if (live_views_.load(std::memory_order_acquire) == 0) {
            arena_.reset();
        }
    }

    /// Diagnostics: number of arena-backed views currently outstanding.
    size_t slots_in_use() const noexcept {
        return live_views_.load(std::memory_order_relaxed);
    }

private:
    friend class Handle;

    void retire_view() noexcept {
        live_views_.fetch_sub(1, std::memory_order_acq_rel);
    }

    // 64KB initial block keeps small-body workloads in one block; grows on
    // demand for large bodies. reset() keeps blocks for reuse.
    bolt::Arena arena_{bolt::ArenaConfig{
        /*initial_block_size=*/64 * 1024,
        /*max_block_size=*/64 * 1024 * 1024,
        /*alignment=*/64,
        /*poison_on_reset=*/false}};

    // Outstanding arena-backed Handle count. Atomic because a Handle acquired on
    // one worker thread may be released on another after a coroutine migrates.
    std::atomic<size_t> live_views_{0};
};

/// Thread-local accessor — one arena per worker thread, created on first use.
inline BodyBufferArena& thread_body_arena() {
    thread_local BodyBufferArena arena;
    return arena;
}

/// Reset the calling thread's body arena, reclaiming its per-request body
/// buffers in O(1). Self-guarding: it reclaims only when the thread's arena has
/// no outstanding Handle (the common quiescent case at request teardown) and is
/// otherwise a safe no-op, so it cannot use-after-reset a view still live on a
/// migrated coroutine. Cheap to call unconditionally per request.
inline void thread_body_arena_reset() noexcept {
    thread_body_arena().reset();
}

#else
// ===========================================================================
// Default slot-pool implementation (unchanged — byte-for-byte semantics).
// ===========================================================================

class BodyBufferArena {
public:
    static constexpr size_t TIER1_SIZE  = 64 * 1024;      // 64KB
    static constexpr size_t TIER1_COUNT = 4;
    static constexpr size_t TIER2_SIZE  = 1024 * 1024;    // 1MB
    static constexpr size_t TIER2_COUNT = 2;
    static constexpr size_t TOTAL_SLOTS = TIER1_COUNT + TIER2_COUNT;

    /**
     * RAII handle — automatically releases buffer back to arena on destruction.
     * Move-only. Default-constructed handle is empty (operator bool() == false).
     */
    class Handle {
    public:
        Handle() noexcept = default;

        Handle(uint8_t* data, size_t capacity, BodyBufferArena* arena, int slot) noexcept
            : data_(data), capacity_(capacity), arena_(arena), slot_(slot) {}

        ~Handle() { release(); }

        // Move-only
        Handle(Handle&& o) noexcept
            : data_(o.data_), capacity_(o.capacity_), arena_(o.arena_),
              slot_(o.slot_), heap_buf_(std::move(o.heap_buf_)) {
            o.data_ = nullptr;
            o.arena_ = nullptr;
            o.slot_ = -1;
        }

        Handle& operator=(Handle&& o) noexcept {
            if (this != &o) {
                release();
                data_ = o.data_;
                capacity_ = o.capacity_;
                arena_ = o.arena_;
                slot_ = o.slot_;
                heap_buf_ = std::move(o.heap_buf_);
                o.data_ = nullptr;
                o.arena_ = nullptr;
                o.slot_ = -1;
            }
            return *this;
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        uint8_t* data() const noexcept { return data_; }
        size_t capacity() const noexcept { return capacity_; }
        explicit operator bool() const noexcept { return data_ != nullptr; }

    private:
        friend class BodyBufferArena;

        // Heap-fallback constructor: Handle owns the allocation directly
        static Handle from_heap(std::unique_ptr<uint8_t[]> buf, size_t cap) noexcept {
            Handle h;
            h.heap_buf_ = std::move(buf);
            h.data_ = h.heap_buf_.get();
            h.capacity_ = cap;
            return h;
        }

        void release() noexcept {
            if (arena_ && slot_ >= 0) {
                arena_->release_slot(slot_);
            }
            data_ = nullptr;
            arena_ = nullptr;
            slot_ = -1;
            heap_buf_.reset();
        }

        uint8_t* data_ = nullptr;
        size_t capacity_ = 0;
        BodyBufferArena* arena_ = nullptr;
        int slot_ = -1;
        std::unique_ptr<uint8_t[]> heap_buf_;  // only set for heap fallback
    };

    BodyBufferArena() {
        for (size_t i = 0; i < TIER1_COUNT; i++) {
            slots_[i].data = std::make_unique<uint8_t[]>(TIER1_SIZE);
            slots_[i].capacity = TIER1_SIZE;
        }
        for (size_t i = 0; i < TIER2_COUNT; i++) {
            size_t idx = TIER1_COUNT + i;
            slots_[idx].data = std::make_unique<uint8_t[]>(TIER2_SIZE);
            slots_[idx].capacity = TIER2_SIZE;
        }
    }

    /**
     * Acquire the smallest available buffer that fits `needed` bytes.
     * Returns RAII Handle that auto-releases on destruction.
     * Falls back to heap allocation if pool is exhausted or needed > TIER2_SIZE.
     */
    Handle acquire(size_t needed) noexcept {
        // Best-fit: find smallest available slot >= needed
        int best = -1;
        size_t best_cap = SIZE_MAX;
        for (size_t i = 0; i < TOTAL_SLOTS; i++) {
            if (!slots_[i].in_use && slots_[i].capacity >= needed
                && slots_[i].capacity < best_cap) {
                best = static_cast<int>(i);
                best_cap = slots_[i].capacity;
            }
        }
        if (best >= 0) {
            slots_[best].in_use = true;
            return Handle(slots_[best].data.get(), slots_[best].capacity, this, best);
        }
        // Pool exhausted or request too large — heap fallback
        auto buf = std::make_unique<uint8_t[]>(needed);
        return Handle::from_heap(std::move(buf), needed);
    }

    /**
     * Query how many slots are currently in use (for diagnostics/testing).
     */
    size_t slots_in_use() const noexcept {
        size_t count = 0;
        for (size_t i = 0; i < TOTAL_SLOTS; i++) {
            if (slots_[i].in_use) count++;
        }
        return count;
    }

private:
    friend class Handle;

    struct Slot {
        std::unique_ptr<uint8_t[]> data;
        size_t capacity = 0;
        bool in_use = false;
    };

    std::array<Slot, TOTAL_SLOTS> slots_{};

    void release_slot(int idx) noexcept {
        if (idx >= 0 && static_cast<size_t>(idx) < TOTAL_SLOTS) {
            slots_[idx].in_use = false;
        }
    }
};

/// Thread-local accessor — one arena per worker thread, created on first use.
inline BodyBufferArena& thread_body_arena() {
    thread_local BodyBufferArena arena;
    return arena;
}

/// Reset hook — NO-OP in the slot-pool path (reclamation is per-slot via the
/// Handle destructor). Present so callers compile identically in both modes.
inline void thread_body_arena_reset() noexcept {}

#endif  // BOLTAPI_USE_BOLT_ARENA

}  // namespace http
}  // namespace bolt::api
