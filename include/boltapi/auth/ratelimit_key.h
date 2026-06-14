// boltapi/auth/ratelimit_key.h — bounded-key token-bucket rate limiter.
//
// Generalization of bolt::api::RateLimiter (which is per-IP-only): this one
// keys on an arbitrary `string_view` (e.g. an email for login lockout, an
// API-key prefix for per-key throttling). Fixed-capacity SwissTable-backed
// bucket map; LRU eviction when full so a flood of unique keys can't
// starve the table.
//
// Lock-free single-writer / multi-reader CAS update of each bucket; the
// hash table's entry-claim path uses a per-slot seqlock so the steady-state
// fast path stays wait-free. No allocations after construction.
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bolt::api::auth {

class RateLimitKey {
public:
    static constexpr size_t kSlots          = 4096;     // power of two
    static constexpr size_t kMaxKeyBytes    = 64;
    static constexpr uint32_t kMaxProbe     = 32;       // bounded linear probe

    struct Config {
        uint32_t capacity         = 5;     // burst
        uint32_t refill_per_sec   = 1;     // sustained rate
    };

    RateLimitKey() noexcept;
    RateLimitKey(const RateLimitKey&)            = delete;
    RateLimitKey& operator=(const RateLimitKey&) = delete;

    // Attempt to consume one token for `key` under the given config.
    // Returns true if a token was available (request allowed), false if
    // rate-limited. Allocation-free.
    bool consume(std::string_view key, const Config& cfg) noexcept;

    // Reset a key's bucket (e.g. on successful login after lockout).
    void reset(std::string_view key) noexcept;

    // Number of slots currently occupied (rough; reader-side estimate).
    size_t size() const noexcept { return size_.load(std::memory_order_relaxed); }

private:
    struct alignas(64) Slot {
        std::atomic<uint64_t> seq{0};       // even = stable, odd = writer in
        std::atomic<uint64_t> last_use_ns{0};
        uint8_t               key_len = 0;
        char                  key[kMaxKeyBytes];
        std::atomic<uint32_t> tokens_x1000{0};   // milli-tokens for sub-int refill
        std::atomic<uint64_t> last_refill_ns{0};
    };

    uint64_t now_ns() const noexcept {
        return uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // Hash + slot resolution. swiss_mix style — same shape as the existing
    // bolt::SwissTable but inlined here to keep this header self-contained.
    static uint64_t hash_key(std::string_view key) noexcept;
    size_t          slot_index(uint64_t h, uint32_t probe) const noexcept {
        return size_t((h + probe) & (kSlots - 1));
    }

    bool slot_match(const Slot& s, std::string_view key) const noexcept;
    void slot_init (Slot& s, std::string_view key, uint64_t now,
                    const Config& cfg) noexcept;

    Slot                       slots_[kSlots];
    std::atomic<size_t>        size_{0};
};

}  // namespace bolt::api::auth
