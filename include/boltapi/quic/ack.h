// boltapi/quic/ack.h — QUIC received-packet ACK range tracking (RFC 9000 §19.3).
//
// PORTED/RESHAPED from the ACK-range building logic in FasterAPI's
// quic_packet_number_space.h RecvTracker and quic_ack_tracker.{h,cpp}. This
// header carries ONLY the data structure that turns the set of received packet
// numbers into ACK ranges (gap/range encoding) for an AckFrame. The loss timers,
// RTT estimation and congestion coupling from the FasterAPI source are NOT
// ported here (those belong to the later RFC 9002 loss-recovery phase).
//
// Reshaped to Bolt Tiger Style: namespace bolt::api::quic, named bounds, >=2
// asserts per function, noexcept, no allocation (fixed-capacity range array, no
// std::vector / std::unordered_map), no exceptions.
//
// Representation: a sorted, coalesced set of inclusive [start, end] ranges of
// received packet numbers, newest-largest first is reconstructed at build time.
// Bounded by kMaxTrackedRanges; when full, the lowest (oldest) range is dropped
// — matching QUIC's "an endpoint MAY limit ACK range count" guidance.
//
// Dependency-free; compiles UNCONDITIONALLY (covered by the default suite).

#pragma once

#include "boltapi/quic/frames.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace bolt::api::quic {

// Max distinct (non-contiguous) received ranges we retain. Bounded so the
// ACK frame we emit can never exceed kMaxAckRanges additional ranges.
inline constexpr std::size_t kMaxTrackedRanges = kMaxAckRanges;

// ----------------------------------------------------------------------------
// AckRangeTracker — record received packet numbers, build an AckFrame.
// ----------------------------------------------------------------------------
class AckRangeTracker {
public:
    AckRangeTracker() noexcept = default;

    void reset() noexcept {
        count_ = 0;
        assert(count_ == 0 && "reset must clear ranges");
        assert(is_sorted_descending() && "empty set is trivially sorted");
    }

    std::size_t range_count() const noexcept {
        assert(count_ <= kMaxTrackedRanges && "range count overflow");
        return count_;
    }

    bool empty() const noexcept {
        assert(count_ <= kMaxTrackedRanges);
        return count_ == 0;
    }

    // Largest received packet number, or returns false if none recorded.
    bool largest(std::uint64_t& out) const noexcept {
        assert(count_ <= kMaxTrackedRanges && "range count overflow");
        if (count_ == 0) return false;
        out = ranges_[0].end;  // ranges_ kept in descending order
        return true;
    }

    // Record one received packet number. Coalesces into adjacent ranges; inserts
    // a new range otherwise (descending by start). Idempotent for duplicates.
    void record(std::uint64_t pn) noexcept {
        assert(pn <= (1ULL << 62) - 1 && "received PN exceeds 2^62-1");
        assert(count_ <= kMaxTrackedRanges && "range count overflow");

        // Find the first range whose start <= pn (descending order scan).
        std::size_t i = 0;
        while (i < count_ && ranges_[i].start > pn) {
            ++i;
        }

        // Already covered?
        if (i < count_ && pn >= ranges_[i].start && pn <= ranges_[i].end) {
            return;
        }

        // Extend the range above (ranges_[i-1]) downward if pn == its start-1.
        const bool join_above = (i > 0) && (pn + 1 == ranges_[i - 1].start);
        // Extend the range below (ranges_[i]) upward if pn == its end+1.
        const bool join_below = (i < count_) && (pn == ranges_[i].end + 1);

        if (join_above && join_below) {
            // Merge ranges_[i-1] and ranges_[i] across pn.
            ranges_[i - 1].start = ranges_[i].start;
            remove_at(i);
            return;
        }
        if (join_above) {
            ranges_[i - 1].start = pn;
            return;
        }
        if (join_below) {
            ranges_[i].end = pn;
            return;
        }

        insert_at(i, Range{pn, pn});
    }

    // Build an ACK frame from the tracked ranges. `ack_delay` is supplied by the
    // caller (already in the peer's units). Returns false if nothing to ack.
    bool build_ack_frame(AckFrame& ack, std::uint64_t ack_delay) const noexcept {
        assert(count_ <= kMaxTrackedRanges && "range count overflow");
        if (count_ == 0) return false;

        ack.has_ecn = false;
        ack.ack_delay = ack_delay;
        ack.largest_acked = ranges_[0].end;
        // First ACK range = (largest - smallest) of the top range.
        ack.first_ack_range = ranges_[0].end - ranges_[0].start;

        ack.range_count = 0;
        std::uint64_t prev_smallest = ranges_[0].start;
        for (std::size_t i = 1; i < count_; ++i) {
            // Gap = (prev_smallest - 1) - largest_of_this_range - 1.
            assert(prev_smallest > ranges_[i].end + 1 && "ranges not disjoint");
            const std::uint64_t gap = prev_smallest - ranges_[i].end - 2;
            const std::uint64_t rlen = ranges_[i].end - ranges_[i].start;
            ack.ranges[ack.range_count].gap = gap;
            ack.ranges[ack.range_count].length = rlen;
            ++ack.range_count;
            prev_smallest = ranges_[i].start;
        }
        assert(ack.range_count + 1 == count_ && "ack range/range mismatch");
        assert(ack.range_count <= kMaxAckRanges && "emitted ACK range overflow");
        return true;
    }

private:
    struct Range {
        std::uint64_t start = 0;  // inclusive
        std::uint64_t end = 0;    // inclusive
    };

    bool is_sorted_descending() const noexcept {
        for (std::size_t i = 1; i < count_; ++i) {
            if (ranges_[i - 1].start <= ranges_[i].end) return false;
        }
        return true;
    }

    void insert_at(std::size_t idx, Range r) noexcept {
        assert(idx <= count_ && "insert index out of range");
        if (count_ == kMaxTrackedRanges) {
            // Full: drop the lowest (oldest) range to make room, unless the new
            // range itself is the lowest (then just ignore it).
            if (idx == count_) return;
            --count_;  // drop ranges_[count_-1] (smallest)
        }
        for (std::size_t j = count_; j > idx; --j) {
            ranges_[j] = ranges_[j - 1];
        }
        ranges_[idx] = r;
        ++count_;
        assert(count_ <= kMaxTrackedRanges && "range overflow after insert");
        assert(is_sorted_descending() && "ranges unsorted after insert");
    }

    void remove_at(std::size_t idx) noexcept {
        assert(idx < count_ && "remove index out of range");
        for (std::size_t j = idx; j + 1 < count_; ++j) {
            ranges_[j] = ranges_[j + 1];
        }
        --count_;
        assert(count_ < kMaxTrackedRanges + 1 && "range underflow");
        assert(is_sorted_descending() && "ranges unsorted after remove");
    }

    Range ranges_[kMaxTrackedRanges]{};  // descending by start
    std::size_t count_ = 0;
};

}  // namespace bolt::api::quic
