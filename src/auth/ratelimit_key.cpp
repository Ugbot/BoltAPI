// boltapi/auth/ratelimit_key.cpp — bounded-key bucket limiter.

#include "boltapi/auth/ratelimit_key.h"

#include <cassert>
#include <cstring>

namespace bolt::api::auth {

namespace {

// MurmurHash-3 finalizer, adequate for hashing short keys. Matches the
// "swiss_mix" pattern used elsewhere in the codebase but inlined to keep
// the header dep-free.
uint64_t mix64(uint64_t x) noexcept {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

}  // namespace

uint64_t RateLimitKey::hash_key(std::string_view key) noexcept {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : key) { h ^= uint8_t(c); h *= 0x100000001b3ULL; }
    return mix64(h);
}

bool RateLimitKey::slot_match(const Slot& s, std::string_view key) const noexcept {
    if (s.key_len != uint8_t(key.size())) return false;
    return std::memcmp(s.key, key.data(), key.size()) == 0;
}

void RateLimitKey::slot_init(Slot& s, std::string_view key, uint64_t now,
                             const Config& cfg) noexcept {
    s.key_len = uint8_t(key.size());
    std::memcpy(s.key, key.data(), key.size());
    s.tokens_x1000  .store(cfg.capacity * 1000u, std::memory_order_relaxed);
    s.last_refill_ns.store(now,                   std::memory_order_relaxed);
    s.last_use_ns   .store(now,                   std::memory_order_relaxed);
}

RateLimitKey::RateLimitKey() noexcept {
    // Zero-init via aggregate; key_len starts at 0 so slots are "empty".
    for (size_t i = 0; i < kSlots; ++i) {
        slots_[i].key_len = 0;
        slots_[i].seq.store(0, std::memory_order_relaxed);
        slots_[i].last_use_ns.store(0, std::memory_order_relaxed);
        slots_[i].tokens_x1000.store(0, std::memory_order_relaxed);
        slots_[i].last_refill_ns.store(0, std::memory_order_relaxed);
    }
}

bool RateLimitKey::consume(std::string_view key, const Config& cfg) noexcept {
    assert(!key.empty());
    if (key.size() > kMaxKeyBytes) return true;  // unbounded key: fail-open
    if (cfg.capacity == 0)         return false; // hard cap of zero = deny all

    const uint64_t h = hash_key(key);
    const uint64_t now = now_ns();

    // First pass: look for an existing entry.
    for (uint32_t p = 0; p < kMaxProbe; ++p) {
        Slot& s = slots_[slot_index(h, p)];
        const uint64_t seq = s.seq.load(std::memory_order_acquire);
        if ((seq & 1u) != 0) continue;  // writer in progress; treat as miss-for-now
        if (s.key_len != 0 && slot_match(s, key)) {
            // Refill: add (now - last) * rate tokens, capped at capacity.
            const uint64_t last = s.last_refill_ns.load(std::memory_order_relaxed);
            const uint64_t dt_ns = now - last;
            const uint32_t add = uint32_t((dt_ns * cfg.refill_per_sec) / 1'000'000'000u);
            if (add > 0) {
                uint32_t cur = s.tokens_x1000.load(std::memory_order_relaxed);
                uint32_t nxt = cur + add * 1000u;
                if (nxt > cfg.capacity * 1000u) nxt = cfg.capacity * 1000u;
                s.tokens_x1000.store(nxt, std::memory_order_relaxed);
                s.last_refill_ns.store(now, std::memory_order_relaxed);
            }
            // CAS one milli-bucket out.
            uint32_t cur = s.tokens_x1000.load(std::memory_order_relaxed);
            while (cur >= 1000u) {
                if (s.tokens_x1000.compare_exchange_weak(cur, cur - 1000u,
                        std::memory_order_acquire, std::memory_order_relaxed)) {
                    s.last_use_ns.store(now, std::memory_order_relaxed);
                    return true;
                }
            }
            s.last_use_ns.store(now, std::memory_order_relaxed);
            return false;
        }
    }

    // Second pass: claim the LRU empty/oldest slot. Writer-side seqlock bump.
    size_t   victim_idx = slot_index(h, 0);
    uint64_t oldest     = UINT64_MAX;
    for (uint32_t p = 0; p < kMaxProbe; ++p) {
        const size_t   i = slot_index(h, p);
        const Slot&    s = slots_[i];
        if (s.key_len == 0) { victim_idx = i; oldest = 0; break; }  // empty wins
        const uint64_t u = s.last_use_ns.load(std::memory_order_relaxed);
        if (u < oldest)   { oldest = u; victim_idx = i; }
    }
    Slot& v = slots_[victim_idx];
    uint64_t expected = v.seq.load(std::memory_order_relaxed);
    if ((expected & 1u) != 0) return true;  // someone else writing — fail-open this tick
    if (!v.seq.compare_exchange_strong(expected, expected + 1,
            std::memory_order_acq_rel, std::memory_order_relaxed)) {
        return true;  // contended; fail-open
    }
    const bool was_empty = (v.key_len == 0);
    slot_init(v, key, now, cfg);
    v.tokens_x1000.fetch_sub(1000u, std::memory_order_relaxed);  // one immediate consume
    v.seq.store(expected + 2, std::memory_order_release);
    if (was_empty) size_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void RateLimitKey::reset(std::string_view key) noexcept {
    if (key.empty() || key.size() > kMaxKeyBytes) return;
    const uint64_t h = hash_key(key);
    for (uint32_t p = 0; p < kMaxProbe; ++p) {
        Slot& s = slots_[slot_index(h, p)];
        const uint64_t seq = s.seq.load(std::memory_order_acquire);
        if ((seq & 1u) != 0) continue;
        if (s.key_len != 0 && slot_match(s, key)) {
            uint64_t expected = seq;
            if (s.seq.compare_exchange_strong(expected, seq + 1,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                s.key_len = 0;
                s.tokens_x1000.store(0, std::memory_order_relaxed);
                s.seq.store(seq + 2, std::memory_order_release);
                size_.fetch_sub(1, std::memory_order_relaxed);
            }
            return;
        }
    }
}

}  // namespace bolt::api::auth
