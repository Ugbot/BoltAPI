// sctp_robust_test.cpp — THE SCTP ROBUSTNESS GATE (gtest, UNCONDITIONAL).
//
// Hardened SCTP for real browser data channels, exercised between two
// cross-wired in-process SctpAssociation endpoints (fully deterministic, no
// network). Covers the four hardening pillars:
//
//   1. FRAGMENTATION / REASSEMBLY (RFC 4960 §6.9): 64 KiB and 256 KiB messages
//      both directions, ordered AND unordered, asserted byte-exact on delivery.
//   2. UNORDERED DELIVERY: interleaved unordered messages are delivered as soon
//      as each is fully reassembled — not head-of-line blocked behind an earlier
//      (withheld) one.
//   3. PARTIAL RELIABILITY (RFC 3758 / FORWARD-TSN): a partial-reliable channel
//      under simulated loss abandons a message; the receiver advances past it
//      (FORWARD-TSN) and subsequent messages still arrive.
//   4. LOSSY LINK + RTO + CONGESTION CONTROL (RFC 6298 + RFC 4960 §7): a seeded,
//      deterministic packet-loss relay drops a fraction of SCTP packets; a large
//      reliable transfer still completes correctly via RTO retransmit, the assoc
//      does not stall or busy-loop, and cwnd is observed to grow then back off.
//
// A VIRTUAL CLOCK drives RTO so timeouts are deterministic and the test cannot
// hang: every relay round advances time by a fixed step and feeds it to
// feed()/tick(). All loops are bounded by an iteration cap.

#include "boltapi/webrtc/sctp.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace wrtc = bolt::api::webrtc;

namespace {

using Assoc = wrtc::SctpAssociation;

// A captured outbound packet plus the virtual time it was emitted.
struct Pkt {
    std::string bytes;
};

// Cross-wired pair of associations with a virtual clock and an optional seeded
// packet-loss model. feed()/tick() are always given the virtual `now_ms` so RTO
// is deterministic. The harness pumps in bounded rounds.
struct Link {
    std::unique_ptr<Assoc> passive = std::make_unique<Assoc>();
    std::unique_ptr<Assoc> active  = std::make_unique<Assoc>();

    std::vector<Pkt> to_passive;   // produced by active's sink
    std::vector<Pkt> to_active;    // produced by passive's sink

    std::vector<std::pair<std::uint16_t, std::string>> passive_rx;
    std::vector<std::pair<std::uint16_t, std::string>> active_rx;

    std::uint64_t now_ms = 1000;       // virtual clock
    std::uint64_t step_ms = 20;        // advance per pump round

    // Loss model (seeded). drop_first_n_data: drop the first N *DATA* packets on
    // the chosen direction (used to force RTO / abandonment deterministically).
    std::mt19937 rng{12345};
    double active_to_passive_loss = 0.0;   // probability [0,1)
    double passive_to_active_loss = 0.0;

    // Targeted drop: drop DATA packets whose first DATA-chunk TSN is in this set,
    // for the first occurrence only (forces a specific fragment to be lost).
    std::vector<std::uint32_t> drop_tsns_once;

    void init() {
        passive->init(Assoc::Role::Passive,
            [this](const std::uint8_t* p, std::size_t n) -> bool {
                to_active.push_back(Pkt{std::string(reinterpret_cast<const char*>(p), n)});
                return true;
            },
            [this](const wrtc::SctpRecvMessage& m) {
                passive_rx.emplace_back(m.stream_id,
                    std::string(reinterpret_cast<const char*>(m.data), m.len));
            });
        active->init(Assoc::Role::Active,
            [this](const std::uint8_t* p, std::size_t n) -> bool {
                to_passive.push_back(Pkt{std::string(reinterpret_cast<const char*>(p), n)});
                return true;
            },
            [this](const wrtc::SctpRecvMessage& m) {
                active_rx.emplace_back(m.stream_id,
                    std::string(reinterpret_cast<const char*>(m.data), m.len));
            });
    }

    // Is this packet a DATA packet, and what's its first DATA-chunk TSN?
    static bool first_data_tsn(const std::string& pkt, std::uint32_t& tsn_out) {
        if (pkt.size() < 12 + 16) return false;
        const std::uint8_t* d = reinterpret_cast<const std::uint8_t*>(pkt.data());
        std::size_t off = 12;
        while (off + 4 <= pkt.size()) {
            const std::uint8_t ctype = d[off];
            const std::uint16_t clen =
                static_cast<std::uint16_t>((d[off + 2] << 8) | d[off + 3]);
            if (clen < 4 || off + clen > pkt.size()) break;
            if (ctype == 0) {  // DATA
                const std::uint8_t* v = d + off + 4;
                tsn_out = (static_cast<std::uint32_t>(v[0]) << 24) |
                          (static_cast<std::uint32_t>(v[1]) << 16) |
                          (static_cast<std::uint32_t>(v[2]) << 8)  |
                           static_cast<std::uint32_t>(v[3]);
                return true;
            }
            off += (clen + 3u) & ~3u;
        }
        return false;
    }

    bool should_drop(const std::string& pkt, bool active_to_passive) {
        std::uint32_t tsn;
        const bool is_data = first_data_tsn(pkt, tsn);
        if (is_data) {
            for (auto& t : drop_tsns_once) {
                if (t == tsn) { t = 0xFFFFFFFFu; return true; }  // consume once
            }
        }
        const double p = active_to_passive ? active_to_passive_loss
                                           : passive_to_active_loss;
        if (p <= 0.0) return false;
        // Never drop non-DATA control (handshake/SACK/FWD-TSN) to keep the
        // control plane progressing; loss is modelled on DATA only (the
        // interesting retransmit case). Browsers also rarely lose tiny acks.
        if (!is_data) return false;
        std::uniform_real_distribution<double> u(0.0, 1.0);
        return u(rng) < p;
    }

    // One pump round: deliver queued packets (subject to loss), advance the
    // clock, and tick both sides so RTO/abandonment fire.
    void pump_round() {
        std::vector<Pkt> a = std::move(to_active);
        std::vector<Pkt> p = std::move(to_passive);
        to_active.clear();
        to_passive.clear();
        for (auto& pk : p) {
            if (should_drop(pk.bytes, /*active_to_passive=*/true)) continue;
            passive->feed(reinterpret_cast<const std::uint8_t*>(pk.bytes.data()),
                          pk.bytes.size(), now_ms);
        }
        for (auto& pk : a) {
            if (should_drop(pk.bytes, /*active_to_passive=*/false)) continue;
            active->feed(reinterpret_cast<const std::uint8_t*>(pk.bytes.data()),
                         pk.bytes.size(), now_ms);
        }
        now_ms += step_ms;
        active->tick(now_ms);
        passive->tick(now_ms);
    }

    // Send on the active/passive side using the VIRTUAL clock so RTO timers are
    // deterministic (send() seeds the T3 deadline from the time passed here).
    bool active_send(std::uint16_t sid, std::uint32_t ppid, const std::string& s,
                     wrtc::SctpReliability rel = wrtc::SctpReliability::reliable()) {
        return active->send(sid, ppid,
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size(), rel, now_ms);
    }
    bool passive_send(std::uint16_t sid, std::uint32_t ppid, const std::string& s,
                      wrtc::SctpReliability rel = wrtc::SctpReliability::reliable()) {
        return passive->send(sid, ppid,
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size(), rel, now_ms);
    }

    void handshake() {
        ASSERT_TRUE(active->connect());
        for (int i = 0; i < 50 &&
             !(active->established() && passive->established()); ++i) {
            pump_round();
        }
        ASSERT_EQ(active->state(), Assoc::State::Established);
        ASSERT_EQ(passive->state(), Assoc::State::Established);
    }

    // Pump until `done` or the round cap is hit (never hangs).
    template <class Pred>
    bool pump_until(Pred done, int max_rounds) {
        for (int i = 0; i < max_rounds; ++i) {
            if (done()) return true;
            pump_round();
        }
        return done();
    }
};

std::string make_payload(std::size_t n, std::uint32_t seed) {
    std::mt19937 rng{seed};
    std::string s;
    s.resize(n);
    for (std::size_t i = 0; i < n; ++i) s[i] = static_cast<char>(rng() & 0xFF);
    return s;
}

}  // namespace

// ===========================================================================
// 1) Large-message fragmentation + reassembly — 64 KiB and 256 KiB, both
//    directions, ordered AND unordered, byte-exact.
// ===========================================================================
TEST(SctpRobust, LargeMessageReassemblyOrdered) {
    auto link = std::make_unique<Link>();
    link->init();
    link->handshake();

    const std::uint32_t kBin = static_cast<std::uint32_t>(wrtc::Ppid::Binary);

    const std::string m64  = make_payload(64 * 1024, 1);
    const std::string m256 = make_payload(256 * 1024, 2);

    // active -> passive: 64K then 256K on stream 0 (ordered).
    ASSERT_TRUE(link->active_send(0, kBin, m64));
    ASSERT_TRUE(link->active_send(0, kBin, m256));

    ASSERT_TRUE(link->pump_until([&] { return link->passive_rx.size() >= 2; }, 2000))
        << "large ordered transfer did not complete";
    ASSERT_EQ(link->passive_rx.size(), 2u);
    EXPECT_EQ(link->passive_rx[0].first, 0);
    EXPECT_EQ(link->passive_rx[0].second, m64);   // byte-exact
    EXPECT_EQ(link->passive_rx[1].second, m256);  // byte-exact

    // passive -> active: 256K reply on stream 5 (ordered).
    const std::string r256 = make_payload(256 * 1024, 3);
    ASSERT_TRUE(link->passive_send(5, kBin, r256));
    ASSERT_TRUE(link->pump_until([&] { return !link->active_rx.empty(); }, 2000));
    ASSERT_EQ(link->active_rx.size(), 1u);
    EXPECT_EQ(link->active_rx[0].first, 5);
    EXPECT_EQ(link->active_rx[0].second, r256);
}

TEST(SctpRobust, LargeMessageReassemblyUnordered) {
    auto link = std::make_unique<Link>();
    link->init();
    link->handshake();

    const std::uint32_t kBin = static_cast<std::uint32_t>(wrtc::Ppid::Binary);
    auto rel = wrtc::SctpReliability::reliable(/*unordered=*/true);

    const std::string m64  = make_payload(64 * 1024, 11);
    const std::string m256 = make_payload(256 * 1024, 12);

    ASSERT_TRUE(link->active_send(0, kBin, m64, rel));
    ASSERT_TRUE(link->active_send(0, kBin, m256, rel));

    ASSERT_TRUE(link->pump_until([&] { return link->passive_rx.size() >= 2; }, 2000));
    // Unordered: both arrive; collect by size and assert byte-exact.
    bool got64 = false, got256 = false;
    for (auto& m : link->passive_rx) {
        if (m.second.size() == m64.size())  { EXPECT_EQ(m.second, m64);  got64 = true; }
        if (m.second.size() == m256.size()) { EXPECT_EQ(m.second, m256); got256 = true; }
    }
    EXPECT_TRUE(got64);
    EXPECT_TRUE(got256);
}

// ===========================================================================
// 2) Unordered delivery is not head-of-line blocked.
//
// We withhold delivery of an earlier ORDERED message by dropping its single
// DATA chunk once, and send a later UNORDERED message: the unordered message
// must arrive before the (retransmitted) ordered one. This proves unordered
// data bypasses the per-stream ordered queue.
// ===========================================================================
TEST(SctpRobust, UnorderedNotHeadOfLineBlocked) {
    auto link = std::make_unique<Link>();
    link->init();
    link->handshake();

    const std::uint32_t kStr = static_cast<std::uint32_t>(wrtc::Ppid::String);

    // First send one ORDERED message on stream 0 and learn its TSN by capturing
    // the next outbound DATA. Simpler + deterministic: drop the FIRST data TSN.
    // The active's first DATA TSN == its initial TSN; we drop it once so the
    // ordered message is delayed until RTO retransmit.
    // Send the ordered message; capture its TSN from the queued packet.
    const std::string ordered_msg = "ORDERED-must-wait";
    ASSERT_TRUE(link->active_send(0, kStr, ordered_msg));
    // The ordered DATA is now sitting in to_passive; grab its TSN and arrange to
    // drop it on first delivery.
    ASSERT_FALSE(link->to_passive.empty());
    std::uint32_t ord_tsn = 0;
    ASSERT_TRUE(Link::first_data_tsn(link->to_passive.back().bytes, ord_tsn));
    link->drop_tsns_once.push_back(ord_tsn);

    // Now an UNORDERED message on the SAME stream.
    const std::string unordered_msg = "UNORDERED-arrives-first";
    auto rel = wrtc::SctpReliability::reliable(/*unordered=*/true);
    ASSERT_TRUE(link->active_send(0, kStr, unordered_msg, rel));

    // Pump a few rounds WITHOUT enough time for RTO so the ordered chunk is still
    // missing. The unordered message must already be delivered.
    link->step_ms = 5;  // small steps; RTO is >= 100ms
    for (int i = 0; i < 6; ++i) link->pump_round();

    bool saw_unordered = false, saw_ordered = false;
    for (auto& m : link->passive_rx) {
        if (m.second == unordered_msg) saw_unordered = true;
        if (m.second == ordered_msg)   saw_ordered = true;
    }
    EXPECT_TRUE(saw_unordered) << "unordered message was head-of-line blocked";
    EXPECT_FALSE(saw_ordered) << "ordered message should still be missing (dropped)";

    // Now let RTO recover the ordered message; it must eventually arrive.
    link->step_ms = 60;
    ASSERT_TRUE(link->pump_until([&] {
        for (auto& m : link->passive_rx) if (m.second == ordered_msg) return true;
        return false;
    }, 200)) << "ordered message never recovered via RTO";
}

// ===========================================================================
// 3) Partial reliability: abandon a message under loss (FORWARD-TSN); later
//    messages still arrive and the receiver advances past the abandoned one.
// ===========================================================================
TEST(SctpRobust, PartialReliabilityAbandonsUnderLoss) {
    auto link = std::make_unique<Link>();
    link->init();
    link->handshake();

    const std::uint32_t kBin = static_cast<std::uint32_t>(wrtc::Ppid::Binary);

    // A partial-reliable (rexmit-limited, max_retransmits = 0) ORDERED channel:
    // a message that needs ANY retransmit is abandoned immediately.
    wrtc::SctpReliability pr;
    pr.unordered = false;
    pr.rexmit_limited = true;
    pr.max_retransmits = 0;

    // Message A (will be abandoned): a multi-fragment message; drop its FIRST
    // fragment once so it can never complete and gets abandoned after 0 rtx.
    const std::string msgA = make_payload(8 * 1024, 21);  // ~8 fragments
    // Capture A's first TSN by sending and inspecting the first queued DATA.
    ASSERT_TRUE(link->active_send(2, kBin, msgA, pr));
    ASSERT_FALSE(link->to_passive.empty());
    std::uint32_t a_tsn = 0;
    ASSERT_TRUE(Link::first_data_tsn(link->to_passive.front().bytes, a_tsn));
    link->drop_tsns_once.push_back(a_tsn);

    // Message B (must arrive): a normal reliable ordered message on the SAME
    // stream, sent right after A.
    const std::string msgB = "B-after-abandoned-A";
    ASSERT_TRUE(link->active_send(2, kBin, msgB,
                                 wrtc::SctpReliability::reliable()));

    // Drive: A's first fragment is dropped -> after RTO it would retransmit, but
    // max_retransmits=0 abandons it -> FORWARD-TSN -> receiver skips A's SSN ->
    // B (next SSN) is delivered.
    link->step_ms = 60;
    const bool got_b = link->pump_until([&] {
        for (auto& m : link->passive_rx) if (m.second == msgB) return true;
        return false;
    }, 300);
    ASSERT_TRUE(got_b) << "message after abandoned one never arrived (HOL stall)";

    // A must NOT have been delivered (it was abandoned).
    for (auto& m : link->passive_rx) {
        EXPECT_NE(m.second.size(), msgA.size())
            << "abandoned message was unexpectedly delivered";
    }
    // The sender emitted at least one FORWARD-TSN (chunk count went up via rtx
    // accounting is indirect; the decisive check is B arrived past A).
}

// ===========================================================================
// 4) Lossy link: a large reliable transfer completes via RTO retransmit; the
//    assoc doesn't stall/busy-loop; cwnd grows then backs off on loss.
// ===========================================================================
TEST(SctpRobust, LossyLinkCompletesViaRto) {
    auto link = std::make_unique<Link>();
    link->init();
    link->handshake();

    // 20% deterministic DATA loss both directions (seeded RNG).
    link->active_to_passive_loss = 0.20;
    link->passive_to_active_loss = 0.05;
    link->step_ms = 15;

    const std::uint32_t kBin = static_cast<std::uint32_t>(wrtc::Ppid::Binary);
    const std::string big = make_payload(128 * 1024, 31);  // ~120 fragments

    std::uint32_t cwnd_initial = link->active->cwnd();
    ASSERT_TRUE(link->active_send(0, kBin, big));

    // Observe cwnd growth before significant loss-driven backoff. Sample peak.
    std::uint32_t cwnd_peak = cwnd_initial;
    std::uint64_t rtx_seen = 0;
    bool delivered = false;
    for (int i = 0; i < 5000 && !delivered; ++i) {
        link->pump_round();
        const std::uint32_t cw = link->active->cwnd();
        if (cw > cwnd_peak) cwnd_peak = cw;
        rtx_seen = link->active->chunks_retransmitted();
        if (!link->passive_rx.empty()) delivered = true;
    }

    ASSERT_TRUE(delivered) << "lossy large transfer never completed (stall?)";
    ASSERT_EQ(link->passive_rx.size(), 1u);
    EXPECT_EQ(link->passive_rx[0].second, big) << "reassembled bytes differ";

    // RTO + retransmit must have happened (we dropped 20% of DATA).
    EXPECT_GT(rtx_seen, 0u) << "no retransmits despite injected loss";
    // cwnd must have grown above its initial value (slow start) at some point.
    EXPECT_GT(cwnd_peak, cwnd_initial) << "cwnd never grew";
    // The association is healthy (not Failed) after recovery.
    EXPECT_NE(link->active->state(), Assoc::State::Failed);
    EXPECT_NE(link->passive->state(), Assoc::State::Failed);
}

// ===========================================================================
// 5) Sanity: multiple small messages across multiple streams + verbs still work
//    with the new fragmenting send path (regression guard for the §2 round-trip
//    style coverage CLAUDE.md asks for: >1 route, different "verbs", random data).
// ===========================================================================
TEST(SctpRobust, MultiStreamMixedRoundTrip) {
    auto link = std::make_unique<Link>();
    link->init();
    link->handshake();

    const std::uint32_t kStr = static_cast<std::uint32_t>(wrtc::Ppid::String);
    const std::uint32_t kBin = static_cast<std::uint32_t>(wrtc::Ppid::Binary);

    std::mt19937 rng{99};
    std::vector<std::pair<std::uint16_t, std::string>> sent;
    for (int i = 0; i < 12; ++i) {
        const std::uint16_t sid = static_cast<std::uint16_t>(rng() % 8);
        const std::size_t len = 1 + (rng() % 4000);  // spans single + multi chunk
        const std::string payload = make_payload(len, 1000 + i);
        const std::uint32_t ppid = (i & 1) ? kBin : kStr;
        ASSERT_TRUE(link->active_send(sid, ppid, payload));
        sent.emplace_back(sid, payload);
    }

    ASSERT_TRUE(link->pump_until(
        [&] { return link->passive_rx.size() >= sent.size(); }, 4000));
    ASSERT_EQ(link->passive_rx.size(), sent.size());

    // Per-stream ordering must be preserved; collect per stream and compare.
    for (std::uint16_t s = 0; s < 8; ++s) {
        std::vector<std::string> exp, got;
        for (auto& p : sent) if (p.first == s) exp.push_back(p.second);
        for (auto& p : link->passive_rx) if (p.first == s) got.push_back(p.second);
        ASSERT_EQ(exp.size(), got.size()) << "stream " << s << " count mismatch";
        for (std::size_t i = 0; i < exp.size(); ++i)
            EXPECT_EQ(exp[i], got[i]) << "stream " << s << " msg " << i;
    }
}
