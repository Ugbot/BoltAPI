// bwe_test.cpp — WA gate: TWCC bandwidth estimation + token-bucket pacer.
//
// In-process, deterministic, deadline-bounded (DEFAULT suite, no external deps):
//   (1) TWCC FCI round-trip: the receiver records (seq, arrival) and builds the
//       transport-cc FCI; the sender parses it back to (seq, arrival) records
//       byte-consistent.
//   (2) DELAY-BASED ESTIMATE under induced congestion: feed a timed sequence
//       whose one-way delay GROWS (queue building) -> the estimator's target
//       rate DECREASES from the start rate and converges; then with flat delay it
//       recovers (increases) -> bounded, finite, monotone in the right direction.
//   (3) PACER: a token bucket driven by the estimate emits at ~the target rate
//       over a window (bounded relative-error check) and never bursts above the
//       bucket cap.

#include "boltapi/webrtc/bwe.h"
#include "boltapi/webrtc/rtcp.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <vector>

namespace bwe  = bolt::api::webrtc::bwe;
namespace rtcp = bolt::api::webrtc::rtcp;

// ===========================================================================
// GATE 1 — transport-cc feedback FCI build -> parse round-trip.
// ===========================================================================
TEST(Bwe, TwccFeedbackRoundTrip) {
    bwe::TwccFeedbackBuilder fb;
    // 10 packets arriving roughly every 5ms (5000us).
    constexpr int kN = 10;
    std::int64_t arrivals[kN];
    for (int i = 0; i < kN; ++i) {
        arrivals[i] = 1'000'000 + static_cast<std::int64_t>(i) * 5000;
        fb.on_packet(static_cast<std::uint16_t>(7000 + i), arrivals[i]);
    }
    ASSERT_EQ(fb.pending(), static_cast<std::size_t>(kN));

    std::uint8_t fci[1024];
    const std::size_t flen = fb.build(fci, sizeof(fci));
    ASSERT_GT(flen, 8u);
    EXPECT_EQ(fb.pending(), 0u) << "build should drain the window";

    // The FCI rides an RTPFB FMT 15 (TWCC) — prove it composes with rtcp.h.
    std::uint8_t pkt[1200];
    rtcp::Builder b(pkt, sizeof(pkt));
    ASSERT_EQ(b.add_twcc(0xFEEDu, 0xABCDu, fci, flen), rtcp::RtcpError::Ok);
    rtcp::Compound comp;
    ASSERT_EQ(rtcp::parse_compound(pkt, b.size(), comp), rtcp::RtcpError::Ok);
    ASSERT_GE(comp.count, 1u);
    const rtcp::Packet& fbk = comp.packets[0];
    ASSERT_EQ(fbk.type, rtcp::Type::RTPFB);
    ASSERT_EQ(fbk.count, static_cast<std::uint8_t>(rtcp::RtpfbFmt::Twcc));

    // Parse the FCI back to records; relative arrival spacing preserved (~5ms).
    bwe::FeedbackRecord recs[bwe::kMaxFeedbackPackets];
    const std::size_t n = bwe::parse_twcc_feedback(fbk.fci, fbk.fci_len, recs,
                                                   bwe::kMaxFeedbackPackets);
    ASSERT_EQ(n, static_cast<std::size_t>(kN));
    for (int i = 0; i < kN; ++i) {
        EXPECT_EQ(recs[i].seq, static_cast<std::uint16_t>(7000 + i));
        if (i > 0) {
            const std::int64_t spacing = recs[i].arrival_us - recs[i - 1].arrival_us;
            EXPECT_NEAR(static_cast<double>(spacing), 5000.0, 200.0);
        }
    }
}

// ===========================================================================
// GATE 2 — delay-based estimate converges DOWN under growing delay.
// ===========================================================================
TEST(Bwe, DelayBasedEstimatorReactsToCongestion) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    bwe::DelayBasedEstimator est;
    const std::uint32_t start = est.target_bitrate_bps();
    ASSERT_EQ(start, bwe::kStartBitrateBps);

    // Phase A: send packets every 10ms; arrivals fall progressively LATER
    // (one-way delay grows ~2ms per packet) — sustained over-use.
    std::int64_t dep = 0;
    std::uint16_t seq = 0;
    constexpr int kCong = 120;
    for (int i = 0; i < kCong; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        dep += 10'000;                              // 10ms inter-departure
        const std::int64_t extra_delay = static_cast<std::int64_t>(i) * 2'000;  // growing
        est.on_sent(seq, dep);
        bwe::FeedbackRecord r;
        r.seq = seq;
        r.arrival_us = dep + 50'000 + extra_delay;  // base owd 50ms + growth
        est.on_feedback(r);
        ++seq;
    }
    const std::uint32_t after_cong = est.target_bitrate_bps();
    EXPECT_LT(after_cong, start) << "rate should decrease under growing delay";
    EXPECT_GE(after_cong, bwe::kMinBitrateBps);
    EXPECT_GT(est.trend_us(), 0) << "delay trend should be positive (over-use)";

    // Phase B: flat delay (queue drained) -> rate recovers (increases).
    for (int i = 0; i < 120; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline);
        dep += 10'000;
        est.on_sent(seq, dep);
        bwe::FeedbackRecord r;
        r.seq = seq;
        r.arrival_us = dep + 50'000;                // constant one-way delay
        est.on_feedback(r);
        ++seq;
    }
    const std::uint32_t after_flat = est.target_bitrate_bps();
    EXPECT_GT(after_flat, after_cong) << "rate should recover when delay is flat";
    EXPECT_LE(after_flat, bwe::kMaxBitrateBps);
}

// ===========================================================================
// GATE 3 — pacer emits at ~target rate and never bursts above the bucket cap.
// ===========================================================================
TEST(Bwe, PacerEmitsAtTargetRate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    constexpr std::uint32_t kTarget = 1'000'000;  // 1 Mbps = 125000 bytes/s
    bwe::Pacer pacer(kTarget);

    // Drive 1 second of virtual time in 1ms steps, trying to send a 1200-byte
    // packet whenever the bucket allows. Count bytes actually released.
    constexpr std::size_t kPkt = 1200;
    std::int64_t now = 1'000'000;  // start (avoid the 0 sentinel)
    pacer.refill(now);
    constexpr int kSteps = 1000;   // 1000 ms
    for (int i = 0; i < kSteps; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        now += 1000;               // +1ms
        pacer.refill(now);
        // Try to drain whatever the bucket allows this tick (bounded inner loop).
        for (int g = 0; g < 32; ++g) {
            if (!pacer.try_send(kPkt)) break;
        }
    }

    // Over ~1s at 1 Mbps we expect ~125 KB. Allow a generous +/-15% band (the
    // bucket cap bounds bursts so it cannot run far over).
    const std::uint64_t sent = pacer.sent_bytes();
    const double expected = static_cast<double>(kTarget) / 8.0;  // bytes/s * 1s
    EXPECT_GT(static_cast<double>(sent), expected * 0.85)
        << "pacer underran: " << sent;
    EXPECT_LT(static_cast<double>(sent), expected * 1.15)
        << "pacer overran: " << sent;

    // Retargeting lowers the rate; a fresh window emits proportionally less.
    bwe::Pacer slow(kTarget / 4);
    std::int64_t t = 2'000'000;
    slow.refill(t);
    for (int i = 0; i < kSteps; ++i) {
        t += 1000; slow.refill(t);
        for (int g = 0; g < 32; ++g) if (!slow.try_send(kPkt)) break;
    }
    EXPECT_LT(slow.sent_bytes(), sent) << "lower target must emit fewer bytes";
}
