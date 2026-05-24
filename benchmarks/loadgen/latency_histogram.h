// latency_histogram.h — hand-rolled log-linear latency histogram.
//
// An HdrHistogram-style histogram (log-spaced octaves, linear sub-buckets within
// each octave) with FIXED static storage and NO allocation — the right shape for
// the load generator: one histogram per connection, recorded into serially (a
// connection only ever has one request in flight), then merged once at the end.
//
// Zero third-party deps (no HdrHistogram vendored): just <bit>/<cstdint>. The
// resolution is ~1.5% (64 sub-buckets/octave); the range spans 1 ns .. 2^40 ns
// (~1100 s), which brackets every realistic request latency.
//
// TigerStyle: bounded (fixed kCells), no recursion, >=2 asserts per non-trivial
// fn, no allocation, no side effects in asserts.
#pragma once

#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>

namespace bolt::bench {

class LatencyHistogram {
public:
    // 64 linear sub-buckets per octave (~1.5% relative error); 40 octaves cover
    // 2^40 ns (~1100 s). counts_ is 40*64*8 B = 20 KiB — fine per connection.
    static constexpr int         kSubBucketBits  = 6;
    static constexpr std::size_t kSubBucketCount = std::size_t{1} << kSubBucketBits;  // 64
    static constexpr int         kBucketCount    = 40;
    static constexpr std::size_t kCells          = kBucketCount * kSubBucketCount;    // 2560

    // Record one latency sample (nanoseconds). Bounded: index is clamped into range.
    void record(std::uint64_t ns) noexcept {
        const std::size_t idx = index_for(ns);
        assert(idx < kCells);
        assert(total_ < UINT64_MAX);  // bounded-count invariant
        counts_[idx] += 1;
        total_ += 1;
    }

    // Fold `other` into this (per-cell sum). Used to merge per-connection
    // histograms into one before reporting.
    void merge(const LatencyHistogram& other) noexcept {
        assert(this != &other);
        assert(other.total_ <= UINT64_MAX - total_);
        for (std::size_t i = 0; i < kCells; ++i) counts_[i] += other.counts_[i];
        total_ += other.total_;
    }

    std::uint64_t total_count() const noexcept { return total_; }

    // Lower-edge value of the bucket holding the p-th percentile (p in (0,100]).
    // Single bounded forward scan — no recursion.
    std::uint64_t percentile(double p) const noexcept {
        assert(p > 0.0 && p <= 100.0);
        assert(total_ <= UINT64_MAX);
        if (total_ == 0) return 0;
        // rank = ceil(p/100 * total), clamped to [1, total].
        std::uint64_t rank = static_cast<std::uint64_t>((p / 100.0) * static_cast<double>(total_) + 0.999999);
        if (rank == 0) rank = 1;
        if (rank > total_) rank = total_;
        std::uint64_t cum = 0;
        for (std::size_t i = 0; i < kCells; ++i) {
            cum += counts_[i];
            if (cum >= rank) return value_at(i);
        }
        return value_at(kCells - 1);
    }

    std::uint64_t min() const noexcept {
        assert(total_ <= UINT64_MAX);
        for (std::size_t i = 0; i < kCells; ++i) {
            if (counts_[i] != 0) return value_at(i);
        }
        return 0;
    }

    std::uint64_t max() const noexcept {
        assert(total_ <= UINT64_MAX);
        for (std::size_t i = kCells; i-- > 0;) {
            if (counts_[i] != 0) return value_at(i);
        }
        return 0;
    }

private:
    // Map a nanosecond value to a cell index. Monotonic in `ns`; clamped so a
    // garbage/huge value can never index out of bounds.
    static std::size_t index_for(std::uint64_t ns) noexcept {
        if (ns == 0) ns = 1;
        int e = 63 - std::countl_zero(ns);     // floor(log2(ns)), in [0,63]
        if (e >= kBucketCount) e = kBucketCount - 1;
        const int shift = (e > kSubBucketBits) ? (e - kSubBucketBits) : 0;
        const std::uint64_t base = std::uint64_t{1} << e;
        std::uint64_t s = (ns - base) >> shift;
        if (s >= kSubBucketCount) s = kSubBucketCount - 1;  // safety when e clamped
        const std::size_t idx = static_cast<std::size_t>(e) * kSubBucketCount + static_cast<std::size_t>(s);
        assert(idx < kCells);
        return idx;
    }

    // Lower-edge nanosecond value represented by a cell index.
    static std::uint64_t value_at(std::size_t idx) noexcept {
        assert(idx < kCells);
        const int e = static_cast<int>(idx / kSubBucketCount);
        const std::uint64_t s = idx % kSubBucketCount;
        const int shift = (e > kSubBucketBits) ? (e - kSubBucketBits) : 0;
        return (std::uint64_t{1} << e) + (s << shift);
    }

    std::uint64_t counts_[kCells] = {};
    std::uint64_t total_ = 0;
};

}  // namespace bolt::bench
