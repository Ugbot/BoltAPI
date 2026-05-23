// boltapi/quic/loss.h — RFC 9002 loss recovery + NewReno congestion control.
//
// ADAPTED from FasterAPI src/cpp/http/quic/quic_ack_tracker.h (AckTracker, the
// RFC 9002 loss-detection + RTT logic) and quic_congestion.h
// (NewRenoCongestionControl), reshaped to Bolt Tiger Style: namespace
// bolt::api::quic, >=2 asserts per function, named bounds, noexcept, no
// allocation (the FasterAPI std::unordered_map<pn,SentPacket> + std::vector
// scratch are replaced by a fixed-capacity per-space sent-packet ring), no
// recursion on the packet hot path, no exceptions, <70-line functions.
//
// This replaces the wave-4 "rewind unacked CRYPTO on tick" stand-in in
// connection.h. The connection records every ack-eliciting packet it sends
// (which retransmittable frames it carried) into a SentPacketTracker; on each
// inbound ACK it samples RTT, frees acked packets, and detects loss by the
// RFC 9002 packet- and time-thresholds; on a PTO/loss it re-frames the lost
// frames into FRESH packet numbers (never reusing a PN).
//
// Header-only, dependency-free apart from the QUIC primitives. Compiles
// UNCONDITIONALLY so the default ctest suite covers it.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "boltapi/quic/pn_space.h"

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style: every limit explicit + asserted).
// ----------------------------------------------------------------------------

// Per-PN-space sent-packet history. A loopback stream transfer of a few MB at
// ~1100 payload bytes/packet keeps far fewer than this in flight at once; the
// ring drops the oldest (which is either acked or already declared lost) when
// it wraps, matching RFC 9002's "an implementation MAY bound its state". Kept
// modest so the three per-space rings fit comfortably in the connection object.
inline constexpr std::size_t kMaxSentPackets = 256;

// What retransmittable content a sent packet carried, so loss recovery can
// re-frame exactly those bytes into a new packet. CRYPTO and STREAM ranges are
// tracked as (level/stream, offset, length); a packet may carry several.
inline constexpr std::size_t kMaxFrameRangesPerPacket = 4;

// RFC 9002 §6.1.1 / §6.1.2 loss-detection constants.
inline constexpr std::uint64_t kPacketThreshold = 3;        // §6.1.1 kPacketThreshold
inline constexpr std::uint64_t kTimeThresholdNum = 9;       // 9/8 = 1.125 (§6.1.2)
inline constexpr std::uint64_t kTimeThresholdDen = 8;
inline constexpr std::uint64_t kGranularityUs = 1000;       // 1 ms (§6.1.2 kGranularity)
inline constexpr std::uint64_t kInitialRttUs = 333000;      // §6.2.2 kInitialRtt 333 ms
inline constexpr std::uint64_t kMaxPtoBackoffShift = 6;     // cap exponential PTO backoff

// A retransmittable byte range carried by a sent packet. `is_crypto` selects
// whether `id` is a TLS level (CRYPTO) or a stream id (STREAM); `fin` is the
// STREAM FIN flag for that range.
struct FrameRange {
    bool is_crypto = false;
    bool fin = false;
    std::uint64_t id = 0;       // TLS level (crypto) or stream id (stream)
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

// One in-flight packet's bookkeeping (RFC 9002 §A.1 sent_packets entry).
struct SentPacketInfo {
    std::uint64_t packet_number = 0;
    std::uint64_t time_sent_us = 0;
    std::uint64_t size = 0;              // on-wire bytes (for cwnd accounting)
    bool ack_eliciting = false;
    bool in_flight = false;             // still counted in bytes_in_flight
    bool acked = false;
    bool lost = false;
    std::size_t range_count = 0;
    FrameRange ranges[kMaxFrameRangesPerPacket]{};
};

// ============================================================================
// NewRenoCongestion — RFC 9002 §7 NewReno. Scalar state, branchless-friendly.
// ============================================================================
class NewRenoCongestion {
public:
    static constexpr std::uint64_t kMaxDatagram = 1200;          // §7.2 max_datagram_size
    static constexpr std::uint64_t kInitialWindow = 10 * 1200;   // §7.2 (min(10*MSS,...))
    static constexpr std::uint64_t kMinimumWindow = 2 * 1200;    // §7.2 kMinimumWindow

    NewRenoCongestion() noexcept
        : cwnd_(kInitialWindow), ssthresh_(UINT64_MAX), bytes_in_flight_(0),
          recovery_start_us_(0) {
        assert(cwnd_ == kInitialWindow && "cwnd init");
        assert(ssthresh_ == UINT64_MAX && "ssthresh init (slow start)");
    }

    bool in_slow_start() const noexcept {
        assert(cwnd_ >= kMinimumWindow && "cwnd below floor");
        return cwnd_ < ssthresh_;
    }

    // RFC 9002 §7.8: a packet is in a recovery period if it was sent before the
    // recovery start time.
    bool in_recovery(std::uint64_t sent_time_us) const noexcept {
        assert(recovery_start_us_ <= UINT64_MAX && "recovery time");
        return recovery_start_us_ != 0 && sent_time_us <= recovery_start_us_;
    }

    void on_packet_sent(std::uint64_t bytes) noexcept {
        assert(bytes > 0 && "sent zero bytes");
        bytes_in_flight_ += bytes;
        assert(bytes_in_flight_ >= bytes && "bif overflow");
    }

    // RFC 9002 §7.3.1 (slow start) / §7.3.2 (congestion avoidance).
    void on_packet_acked(std::uint64_t bytes, std::uint64_t sent_time_us) noexcept {
        assert(bytes > 0 && "acked zero bytes");
        sub_in_flight(bytes);
        if (in_recovery(sent_time_us)) return;  // §7.3.2: no increase in recovery
        if (in_slow_start()) {
            cwnd_ += bytes;                      // exponential
        } else {
            cwnd_ += (kMaxDatagram * bytes) / cwnd_;  // ~+1 MSS per RTT
        }
        assert(cwnd_ >= kMinimumWindow && "cwnd underflow on ack");
    }

    // RFC 9002 §7.6.2: enter a recovery period; halve cwnd to ssthresh.
    void on_congestion_event(std::uint64_t sent_time_us,
                             std::uint64_t now_us) noexcept {
        assert(now_us >= sent_time_us && "time goes backward");
        if (in_recovery(sent_time_us)) return;  // already recovering
        recovery_start_us_ = now_us;
        ssthresh_ = cwnd_ / 2;
        if (ssthresh_ < kMinimumWindow) ssthresh_ = kMinimumWindow;
        cwnd_ = ssthresh_;
        assert(cwnd_ >= kMinimumWindow && "cwnd below floor after loss");
    }

    void on_packet_lost(std::uint64_t bytes) noexcept {
        assert(bytes > 0 && "lost zero bytes");
        sub_in_flight(bytes);
    }

    // RFC 9002 §7.6: persistent congestion collapses cwnd to the minimum.
    void on_persistent_congestion() noexcept {
        cwnd_ = kMinimumWindow;
        recovery_start_us_ = 0;
        assert(cwnd_ == kMinimumWindow && "pc collapse");
        assert(recovery_start_us_ == 0 && "pc clears recovery");
    }

    // RFC 9002 §7.5: can send if in-flight + bytes fits the window.
    bool can_send(std::uint64_t bytes) const noexcept {
        assert(bytes <= kMaxDatagram * 64 && "absurd send size");
        return bytes_in_flight_ + bytes <= cwnd_;
    }

    std::uint64_t cwnd() const noexcept { return cwnd_; }
    std::uint64_t ssthresh() const noexcept { return ssthresh_; }
    std::uint64_t bytes_in_flight() const noexcept { return bytes_in_flight_; }

    // RFC 9002 §6.4 / §9.3: when Initial/Handshake keys are discarded their
    // packets leave flight. We clear in-flight accounting at handshake
    // confirmation (1-RTT data has not yet been sent at that point).
    void reset_in_flight() noexcept {
        bytes_in_flight_ = 0;
        assert(bytes_in_flight_ == 0 && "in-flight reset");
    }

private:
    void sub_in_flight(std::uint64_t bytes) noexcept {
        assert(bytes > 0 && "sub zero");
        bytes_in_flight_ = (bytes_in_flight_ >= bytes) ? bytes_in_flight_ - bytes : 0;
    }

    std::uint64_t cwnd_;
    std::uint64_t ssthresh_;
    std::uint64_t bytes_in_flight_;
    std::uint64_t recovery_start_us_;
};

// ============================================================================
// RttEstimator — RFC 9002 §5 latest/min/smoothed RTT + rttvar + PTO.
// ============================================================================
class RttEstimator {
public:
    RttEstimator() noexcept
        : latest_(0), smoothed_(kInitialRttUs), rttvar_(kInitialRttUs / 2),
          min_(UINT64_MAX), have_sample_(false) {
        assert(smoothed_ == kInitialRttUs && "srtt init");
        assert(rttvar_ == kInitialRttUs / 2 && "rttvar init");
    }

    // RFC 9002 §5.3: update on a new RTT sample, adjusting for ack delay.
    void on_rtt_sample(std::uint64_t rtt_us, std::uint64_t ack_delay_us) noexcept {
        assert(rtt_us > 0 && "zero rtt sample");
        latest_ = rtt_us;
        if (rtt_us < min_) min_ = rtt_us;
        if (!have_sample_) {
            smoothed_ = rtt_us;
            rttvar_ = rtt_us / 2;
            have_sample_ = true;
            return;
        }
        // Only subtract ack delay if it keeps the adjusted RTT >= min_rtt.
        std::uint64_t adjusted = rtt_us;
        if (rtt_us >= min_ + ack_delay_us) adjusted = rtt_us - ack_delay_us;
        const std::uint64_t diff =
            (adjusted > smoothed_) ? adjusted - smoothed_ : smoothed_ - adjusted;
        rttvar_ = (3 * rttvar_ + diff) / 4;          // beta = 1/4
        smoothed_ = (7 * smoothed_ + adjusted) / 8;  // alpha = 1/8
        assert(smoothed_ > 0 && "srtt collapsed");
    }

    // RFC 9002 §6.2.1: PTO = smoothed_rtt + max(4*rttvar, granularity) +
    // max_ack_delay, scaled by 2^backoff.
    std::uint64_t pto(std::uint64_t max_ack_delay_us,
                      std::uint32_t backoff) const noexcept {
        assert(backoff <= 32 && "absurd pto backoff");
        std::uint64_t var = 4 * rttvar_;
        if (var < kGranularityUs) var = kGranularityUs;
        const std::uint32_t shift =
            (backoff > kMaxPtoBackoffShift) ? static_cast<std::uint32_t>(kMaxPtoBackoffShift)
                                            : backoff;
        const std::uint64_t base = smoothed_ + var + max_ack_delay_us;
        assert(base > 0 && "pto base zero");
        return base << shift;
    }

    std::uint64_t latest() const noexcept { return latest_; }
    std::uint64_t smoothed() const noexcept { return smoothed_; }
    std::uint64_t rttvar() const noexcept { return rttvar_; }
    std::uint64_t min_rtt() const noexcept { return have_sample_ ? min_ : 0; }
    bool have_sample() const noexcept { return have_sample_; }

private:
    std::uint64_t latest_;
    std::uint64_t smoothed_;
    std::uint64_t rttvar_;
    std::uint64_t min_;
    bool have_sample_;
};

// ============================================================================
// SentPacketTracker — bounded per-space ring of in-flight packets. Records what
// each ack-eliciting packet carried so the connection can re-frame on loss.
// ============================================================================
class SentPacketTracker {
public:
    SentPacketTracker() noexcept = default;

    // Record a sent packet. Overwrites the oldest slot when the ring is full.
    // If that evicted slot was still in flight, its byte count is reported in
    // *evicted_in_flight so the caller can reconcile congestion accounting (a
    // bounded ring must never leak bytes_in_flight on wrap).
    SentPacketInfo& record(std::uint64_t pn, std::uint64_t now_us,
                           std::uint64_t size, bool ack_eliciting,
                           std::uint64_t* evicted_in_flight = nullptr) noexcept {
        assert(size <= 1500 && "sent packet too big");
        assert(count_ <= kMaxSentPackets && "tracker overflow");
        if (evicted_in_flight) *evicted_in_flight = 0;
        const std::size_t idx = head_;
        head_ = (head_ + 1) % kMaxSentPackets;
        if (count_ < kMaxSentPackets) {
            ++count_;
        } else {
            // Ring full: ring_[idx] is the oldest live entry being evicted.
            if (ring_[idx].in_flight && evicted_in_flight)
                *evicted_in_flight = ring_[idx].size;
            tail_ = (tail_ + 1) % kMaxSentPackets;
        }
        SentPacketInfo& s = ring_[idx];
        s = SentPacketInfo{};
        s.packet_number = pn;
        s.time_sent_us = now_us;
        s.size = size;
        s.ack_eliciting = ack_eliciting;
        s.in_flight = ack_eliciting;  // only ack-eliciting packets count in flight
        if (pn >= next_expected_) next_expected_ = pn + 1;
        return s;
    }

    std::size_t count() const noexcept {
        assert(count_ <= kMaxSentPackets && "count overflow");
        return count_;
    }

    // Iterate the live entries. Index 0..count()-1 maps oldest..newest.
    SentPacketInfo& at(std::size_t i) noexcept {
        assert(i < count_ && "tracker index oob");
        return ring_[(tail_ + i) % kMaxSentPackets];
    }
    const SentPacketInfo& at(std::size_t i) const noexcept {
        assert(i < count_ && "tracker index oob");
        return ring_[(tail_ + i) % kMaxSentPackets];
    }

    // Find a live, not-yet-acked packet by number. Returns nullptr if absent.
    SentPacketInfo* find_unacked(std::uint64_t pn) noexcept {
        assert(count_ <= kMaxSentPackets && "count overflow");
        for (std::size_t i = 0; i < count_; ++i) {
            SentPacketInfo& s = at(i);
            if (s.packet_number == pn && !s.acked && !s.lost) return &s;
        }
        return nullptr;
    }

    bool any_ack_eliciting_in_flight() const noexcept {
        for (std::size_t i = 0; i < count_; ++i) {
            const SentPacketInfo& s = at(i);
            if (s.in_flight && s.ack_eliciting) return true;
        }
        return false;
    }

    // Earliest time_sent among in-flight ack-eliciting packets (for PTO base).
    bool earliest_in_flight_time(std::uint64_t& out) const noexcept {
        bool found = false;
        for (std::size_t i = 0; i < count_; ++i) {
            const SentPacketInfo& s = at(i);
            if (s.in_flight && s.ack_eliciting && (!found || s.time_sent_us < out)) {
                out = s.time_sent_us;
                found = true;
            }
        }
        return found;
    }

private:
    SentPacketInfo ring_[kMaxSentPackets]{};
    std::size_t head_ = 0;   // next write slot
    std::size_t tail_ = 0;   // oldest live slot
    std::size_t count_ = 0;
    std::uint64_t next_expected_ = 0;
};

}  // namespace bolt::api::quic
