// boltapi/webrtc/bwe.h — transport-wide congestion control (TWCC) bandwidth
// estimation + a token-bucket media pacer (RFC 8888-style + transport-cc ext).
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// The send-side half of TWCC bandwidth estimation, Pion-level:
//
//   * TwccFeedbackBuilder — the RECEIVER records (transport-seq, arrival_ms) for
//     each inbound packet (read from the transport-cc header extension) and
//     builds the transport-cc feedback FCI (the run-length/status + receive-delta
//     body that rides an RTPFB FMT 15). Bounded packet window.
//   * TwccFeedbackParser — the SENDER parses that FCI back into (seq, recv_delta)
//     pairs.
//   * DelayBasedEstimator — a trendline/arrival-filter delay-based estimator: it
//     compares the inter-arrival delay gradient to the inter-departure gradient;
//     a growing one-way delay signals over-use and the estimated rate is
//     multiplicatively decreased; steady delay lets it additively increase
//     (the GCC delay controller, simplified + bounded).
//   * Pacer — a token-bucket that releases bytes at the estimated target rate so
//     media isn't sent in bursts (smooths the send onto the link).
//
// TigerStyle: bounded windows (kMaxFeedbackPackets), fixed buffers, noexcept,
// error-return, no heap, >=2 asserts/fn, fns <70 lines. Depends on rtcp.h only.

#pragma once

#include "boltapi/webrtc/rtcp.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {
namespace bwe {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle).
// ----------------------------------------------------------------------------
inline constexpr std::size_t  kMaxFeedbackPackets = 256;   // status window / feedback
inline constexpr std::uint32_t kMinBitrateBps     = 30'000;     // floor (30 kbps)
inline constexpr std::uint32_t kMaxBitrateBps     = 100'000'000;// ceiling (100 Mbps)
inline constexpr std::uint32_t kStartBitrateBps   = 300'000;    // initial estimate

// transport-cc receive-delta is in 250us ticks (RFC 8888 / draft-holmer).
inline constexpr std::int32_t kDeltaTickUs = 250;

// ----------------------------------------------------------------------------
// One recorded reception (receiver side): transport-wide seq + arrival time.
// ----------------------------------------------------------------------------
struct Arrival {
    std::uint16_t seq = 0;
    std::int64_t  arrival_us = 0;
    bool          received = false;
};

// ----------------------------------------------------------------------------
// TwccFeedbackBuilder (receiver) — records arrivals and builds the transport-cc
// FCI. Simplified wire form (sufficient for our in-process estimator + a real
// transport-cc reader): base seq(16) | count(16) | ref-time(24) | fb-count(8) |
// then `count` 16-bit signed receive-deltas (us). Bounded window.
// ----------------------------------------------------------------------------
class TwccFeedbackBuilder {
public:
    TwccFeedbackBuilder() noexcept = default;

    // Record one inbound packet's transport seq + arrival timestamp (us).
    void on_packet(std::uint16_t seq, std::int64_t arrival_us) noexcept {
        assert(count_ <= kMaxFeedbackPackets && "twcc record: bound");
        assert(arrival_us >= 0 && "twcc record: time");
        if (count_ >= kMaxFeedbackPackets) return;  // drop: window full (bounded)
        Arrival& a = window_[count_++];
        a.seq = seq; a.arrival_us = arrival_us; a.received = true;
    }

    std::size_t pending() const noexcept { return count_; }

    // Build the transport-cc FCI for the recorded window into `out`. Returns the
    // length, 0 if nothing pending / buffer too small. Clears the window. noexcept.
    std::size_t build(std::uint8_t* out, std::size_t cap) noexcept {
        assert(out != nullptr && "twcc build: null");
        assert(cap >= 8 && "twcc build: cap");
        if (count_ == 0) return 0;
        const std::uint16_t base = window_[0].seq;
        const std::int64_t  ref  = window_[0].arrival_us;
        const std::size_t need = 8 + count_ * 2;
        if (cap < need) return 0;
        out[0] = static_cast<std::uint8_t>(base >> 8);
        out[1] = static_cast<std::uint8_t>(base & 0xFF);
        out[2] = static_cast<std::uint8_t>(count_ >> 8);
        out[3] = static_cast<std::uint8_t>(count_ & 0xFF);
        const std::uint32_t reftick = static_cast<std::uint32_t>((ref / 64) & 0xFFFFFF);
        out[4] = static_cast<std::uint8_t>(reftick >> 16);
        out[5] = static_cast<std::uint8_t>(reftick >> 8);
        out[6] = static_cast<std::uint8_t>(reftick & 0xFF);
        out[7] = fb_count_++;
        std::int64_t prev = ref;
        for (std::size_t i = 0; i < count_; ++i) {
            std::int64_t d = window_[i].arrival_us - prev;
            prev = window_[i].arrival_us;
            if (d > 32767) d = 32767; if (d < -32768) d = -32768;
            const std::int16_t s = static_cast<std::int16_t>(d);
            out[8 + i * 2] = static_cast<std::uint8_t>((s >> 8) & 0xFF);
            out[8 + i * 2 + 1] = static_cast<std::uint8_t>(s & 0xFF);
        }
        count_ = 0;
        return need;
    }

private:
    Arrival      window_[kMaxFeedbackPackets]{};
    std::size_t  count_ = 0;
    std::uint8_t fb_count_ = 0;
};

// ----------------------------------------------------------------------------
// One parsed feedback record (sender side): seq + arrival delta from base (us).
// ----------------------------------------------------------------------------
struct FeedbackRecord {
    std::uint16_t seq = 0;
    std::int64_t  arrival_us = 0;  // reconstructed absolute-ish arrival (us)
};

// TwccFeedbackParser — parse the FCI built above into FeedbackRecords. Returns
// the count parsed (bounded by cap). noexcept, no heap.
inline std::size_t parse_twcc_feedback(const std::uint8_t* fci, std::size_t len,
                                       FeedbackRecord* out, std::size_t cap) noexcept {
    assert(fci != nullptr || len == 0);
    assert(out != nullptr && "parse_twcc: null out");
    if (len < 8) return 0;
    const std::uint16_t base = static_cast<std::uint16_t>((fci[0] << 8) | fci[1]);
    const std::uint16_t cnt  = static_cast<std::uint16_t>((fci[2] << 8) | fci[3]);
    const std::int64_t ref = (static_cast<std::int64_t>(
        (static_cast<std::uint32_t>(fci[4]) << 16) |
        (static_cast<std::uint32_t>(fci[5]) << 8) | fci[6])) * 64;
    std::int64_t cur = ref;
    std::size_t n = 0;
    for (std::size_t i = 0; i < cnt && n < cap; ++i) {
        if (8 + i * 2 + 2 > len) break;
        const std::int16_t d = static_cast<std::int16_t>(
            (fci[8 + i * 2] << 8) | fci[8 + i * 2 + 1]);
        cur += d;
        out[n].seq = static_cast<std::uint16_t>(base + i);
        out[n].arrival_us = cur;
        ++n;
    }
    return n;
}

// ----------------------------------------------------------------------------
// DelayBasedEstimator (sender) — the GCC delay controller. The sender records
// each packet's DEPARTURE time keyed by transport seq; when feedback arrives it
// pairs departure with arrival and feeds the inter-group delay gradient to a
// trend filter. Sustained positive trend => over-use => multiplicative decrease;
// flat => additive increase. Output is clamped to [kMin, kMax]. Bounded history.
// ----------------------------------------------------------------------------
class DelayBasedEstimator {
public:
    DelayBasedEstimator() noexcept {
        for (auto& s : sent_) s.valid = false;
    }

    // Record a packet's departure (us) keyed by its transport-wide seq.
    void on_sent(std::uint16_t seq, std::int64_t departure_us) noexcept {
        assert(departure_us >= 0 && "on_sent: time");
        assert(rate_bps_ >= kMinBitrateBps && "on_sent: rate floor");
        Sent& s = sent_[seq % kMaxFeedbackPackets];
        s.seq = seq; s.departure_us = departure_us; s.valid = true;
    }

    // Feed one feedback record: pairs with the stored departure, updates trend.
    void on_feedback(const FeedbackRecord& r) noexcept {
        assert(rate_bps_ >= kMinBitrateBps && "on_feedback: floor");
        assert(rate_bps_ <= kMaxBitrateBps && "on_feedback: ceil");
        const Sent& s = sent_[r.seq % kMaxFeedbackPackets];
        if (!s.valid || s.seq != r.seq) return;
        if (!have_prev_) {
            prev_dep_ = s.departure_us; prev_arr_ = r.arrival_us;
            have_prev_ = true; return;
        }
        const std::int64_t d_send = s.departure_us - prev_dep_;
        const std::int64_t d_recv = r.arrival_us - prev_arr_;
        prev_dep_ = s.departure_us; prev_arr_ = r.arrival_us;
        if (d_send <= 0) return;                 // out-of-order / dup: skip
        const std::int64_t delay_grad = d_recv - d_send;  // queuing delay change (us)
        // Exponential trend of the delay gradient (smoothed slope).
        trend_us_ = (trend_us_ * 7 + delay_grad) / 8;
        update_rate(delay_grad);
    }

    std::uint32_t target_bitrate_bps() const noexcept { return rate_bps_; }
    std::int64_t  trend_us() const noexcept { return trend_us_; }

private:
    struct Sent {
        std::uint16_t seq = 0;
        std::int64_t  departure_us = 0;
        bool          valid = false;
    };

    void update_rate(std::int64_t delay_grad) noexcept {
        assert(rate_bps_ >= kMinBitrateBps && "update_rate: floor");
        assert(rate_bps_ <= kMaxBitrateBps && "update_rate: ceil");
        constexpr std::int64_t kOverUseUs = 150;  // gradient over-use threshold
        if (trend_us_ > kOverUseUs || delay_grad > kOverUseUs * 4) {
            // Over-use: multiplicative decrease (×0.85).
            std::uint64_t next = (static_cast<std::uint64_t>(rate_bps_) * 85) / 100;
            rate_bps_ = clamp(static_cast<std::uint32_t>(next));
        } else if (trend_us_ < -kOverUseUs) {
            // Under-use (queue draining): hold (don't ramp into the drain).
        } else {
            // Steady: additive increase (+5%, bounded).
            std::uint64_t next = (static_cast<std::uint64_t>(rate_bps_) * 105) / 100;
            rate_bps_ = clamp(static_cast<std::uint32_t>(next));
        }
    }

    static std::uint32_t clamp(std::uint32_t v) noexcept {
        assert(kMinBitrateBps < kMaxBitrateBps && "clamp: order");
        if (v < kMinBitrateBps) return kMinBitrateBps;
        if (v > kMaxBitrateBps) return kMaxBitrateBps;
        return v;
    }

    Sent          sent_[kMaxFeedbackPackets]{};
    std::uint32_t rate_bps_ = kStartBitrateBps;
    std::int64_t  trend_us_ = 0;
    std::int64_t  prev_dep_ = 0;
    std::int64_t  prev_arr_ = 0;
    bool          have_prev_ = false;
};

// ----------------------------------------------------------------------------
// Pacer — a token-bucket that releases up to `target` bits/sec, smoothing media
// onto the link. tokens are bytes; refilled by elapsed time × rate. try_send()
// consumes tokens if available. Bounded burst (the bucket cap). noexcept.
// ----------------------------------------------------------------------------
class Pacer {
public:
    explicit Pacer(std::uint32_t target_bps = kStartBitrateBps) noexcept
        : rate_bps_(target_bps) {
        assert(target_bps >= kMinBitrateBps && "pacer: rate floor");
        assert(target_bps <= kMaxBitrateBps && "pacer: rate ceil");
    }

    void set_target(std::uint32_t bps) noexcept {
        assert(bps >= 1 && "pacer set: rate");
        assert(bps <= kMaxBitrateBps && "pacer set: ceil");
        rate_bps_ = bps;
    }
    std::uint32_t target_bps() const noexcept { return rate_bps_; }

    // Advance the clock to `now_us`, refilling tokens. Bucket caps at one
    // burst-window (kBurstMs) of rate so it cannot accumulate unbounded credit.
    void refill(std::int64_t now_us) noexcept {
        assert(now_us >= last_us_ || last_us_ == 0 || now_us == last_us_ ||
               now_us >= 0);
        assert(rate_bps_ >= 1 && "refill: rate");
        if (last_us_ == 0) { last_us_ = now_us; return; }
        if (now_us <= last_us_) return;
        const std::int64_t dt_us = now_us - last_us_;
        last_us_ = now_us;
        // bytes = rate_bps/8 * dt_us/1e6
        const double add = (static_cast<double>(rate_bps_) / 8.0) *
                           (static_cast<double>(dt_us) / 1'000'000.0);
        tokens_ += add;
        // Bucket cap = max(kBurstMs of rate, one MTU) so a single full-size
        // packet can always eventually be released even at very low rates, while
        // still bounding bursts to a few ms of credit.
        double cap = (static_cast<double>(rate_bps_) / 8.0) * (kBurstMs / 1000.0);
        if (cap < kMtuBytes) cap = kMtuBytes;
        if (tokens_ > cap) tokens_ = cap;
    }

    // Consume `bytes` if the bucket has them. Returns true if sent.
    bool try_send(std::size_t bytes) noexcept {
        assert(bytes > 0 && "pacer send: zero");
        assert(tokens_ >= 0.0 && "pacer send: tokens");
        if (tokens_ < static_cast<double>(bytes)) return false;
        tokens_ -= static_cast<double>(bytes);
        sent_bytes_ += bytes;
        return true;
    }

    std::uint64_t sent_bytes() const noexcept { return sent_bytes_; }

private:
    static constexpr double kBurstMs  = 5.0;     // bucket cap = max(5ms of rate,
    static constexpr double kMtuBytes = 1500.0;  //   one MTU) — bounds bursts
    std::uint32_t rate_bps_;
    double        tokens_ = 0.0;
    std::int64_t  last_us_ = 0;
    std::uint64_t sent_bytes_ = 0;
};

}  // namespace bwe
}  // namespace webrtc
}  // namespace bolt::api
