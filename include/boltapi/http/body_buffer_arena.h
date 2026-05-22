#pragma once
/**
 * @file body_buffer_arena.h
 * @brief Thread-local tiered body buffer pool for HTTP request bodies.
 *
 * Pre-allocates reusable buffers in two tiers to avoid per-request heap allocation
 * when reading large HTTP request bodies (e.g., ES bulk API payloads).
 *
 * Tier 1: 4 × 64KB  = 256KB per thread  (typical bulk API payloads)
 * Tier 2: 2 × 1MB   = 2MB per thread    (large bulk imports)
 * Total:  ~2.25MB per worker thread
 *
 * For bodies exceeding Tier 2 capacity, a one-off heap allocation is used.
 * This is rare in practice (< 0.1% of requests).
 *
 * Modeled on the existing BufferPool pattern in http1_connection.cpp.
 * Thread-local: no locks or atomics needed (coroutines on same thread are cooperative).
 */

#include <cstdint>
#include <cstddef>
#include <memory>
#include <array>
#include <cstring>

namespace bolt::api {
namespace http {

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

}  // namespace http
}  // namespace bolt::api
