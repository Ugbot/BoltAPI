// simulcast_test.cpp — WA gate: Simulcast (RFC 8851/8852) + SVC passthrough.
//
// In-process, deterministic, deadline-bounded (DEFAULT suite, no external deps):
//   (1) SIMULCAST SDP: a real-shaped offer with 3 rids (q;h;f) + the RID header
//       extension is parsed; negotiate_media echoes the rids + ext id; the answer
//       round-trips through our parser carrying a=rid recv x3 + a=simulcast:recv.
//   (2) SIMULCAST DEMUX: inbound RTP carrying the rtp-stream-id (RID) header
//       extension demuxes into 3 per-encoding streams of a SimulcastTrack, each
//       with its own SSRC, byte-exact, over randomized rounds (seeded RNG).
//   (3) SVC passthrough: an SvcRelay classifies (spatial,temporal) from the
//       Dependency Descriptor extension and drops layers above a target without
//       decoding — keep/drop counts match the induced layer pattern.
//
// Bounded by an iteration cap + wall-clock deadline (no hang).

#include "boltapi/webrtc/sdp.h"
#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/track.h"
#include "boltapi/webrtc/interceptor.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace sdp  = bolt::api::webrtc;
namespace rtp  = bolt::api::webrtc::rtp;
namespace wrtc = bolt::api::webrtc;

namespace {

// A representative Chrome simulcast video offer: 3 send rids (q;h;f), the RID
// header extension, BUNDLE + rtcp-mux.
const char* kSimulcastOffer =
    "v=0\r\n"
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0\r\n"
    "a=msid-semantic: WMS\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp-mux\r\n"
    "a=mid:0\r\n"
    "a=ice-ufrag:abcd\r\n"
    "a=ice-pwd:0123456789abcdef0123456789\r\n"
    "a=fingerprint:sha-256 AB:CD:EF:00:11:22\r\n"
    "a=setup:actpass\r\n"
    "a=sendonly\r\n"
    "a=rtpmap:96 VP8/90000\r\n"
    "a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
    "a=rid:q send\r\n"
    "a=rid:h send\r\n"
    "a=rid:f send\r\n"
    "a=simulcast:send q;h;f\r\n";

constexpr std::uint8_t kRidExtId = 2;

}  // namespace

// ===========================================================================
// GATE 1 — simulcast SDP: parse 3 rids, negotiate, build answer, round-trip.
// ===========================================================================
TEST(Simulcast, OfferThreeRidsNegotiateAndAnswer) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    sdp::SdpSession offer;
    ASSERT_EQ(sdp::parse(kSimulcastOffer, offer), sdp::SdpError::Ok);
    ASSERT_EQ(offer.media_count, 1u);
    const sdp::SdpMedia& m = offer.media[0];
    ASSERT_TRUE(m.has_simulcast());
    EXPECT_EQ(m.rid_extmap_id(), kRidExtId);

    std::string_view rids[wrtc::kMaxRids];
    const std::size_t nr = m.rids(rids, wrtc::kMaxRids);
    ASSERT_EQ(nr, 3u);
    EXPECT_EQ(rids[0], "q");
    EXPECT_EQ(rids[1], "h");
    EXPECT_EQ(rids[2], "f");

    sdp::MediaNegotiation neg;
    ASSERT_EQ(sdp::negotiate_media(offer, neg), sdp::SdpError::Ok);
    ASSERT_EQ(neg.media_count, 1u);
    ASSERT_EQ(neg.media[0].rid_count, 3u);
    EXPECT_EQ(neg.media[0].rid_ext_id, kRidExtId);

    sdp::MediaAnswerParams ap;
    ap.ice_ufrag = "wxyz";
    ap.ice_pwd = "fedcba9876543210fedcba9876";
    ap.fingerprint_sha256 = "11:22:33:44:55:66";
    ap.negotiation = &neg;
    std::string answer;
    ASSERT_EQ(sdp::build_media_answer(ap, answer), sdp::SdpError::Ok);
    ASSERT_LT(std::chrono::steady_clock::now(), deadline);

    // The answer carries the RID extmap + a=rid recv x3 + a=simulcast:recv.
    EXPECT_NE(answer.find("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"),
              std::string::npos);
    EXPECT_NE(answer.find("a=rid:q recv"), std::string::npos);
    EXPECT_NE(answer.find("a=rid:h recv"), std::string::npos);
    EXPECT_NE(answer.find("a=rid:f recv"), std::string::npos);
    EXPECT_NE(answer.find("a=simulcast:recv q;h;f"), std::string::npos);

    // Round-trips through our parser with the simulcast preserved.
    sdp::SdpSession reparsed;
    ASSERT_EQ(sdp::parse(answer, reparsed), sdp::SdpError::Ok);
    ASSERT_EQ(reparsed.media_count, 1u);
    EXPECT_TRUE(reparsed.media[0].has_simulcast());
    std::string_view rr[wrtc::kMaxRids];
    EXPECT_EQ(reparsed.media[0].rids(rr, wrtc::kMaxRids), 3u);
}

// ===========================================================================
// GATE 2 — simulcast demux: inbound RTP with the RID header ext -> 3 encodings.
// ===========================================================================
TEST(Simulcast, RidHeaderExtensionDemuxesThreeEncodings) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    wrtc::SimulcastTrack track;
    track.init(wrtc::MediaKind::kVideo, kRidExtId);

    const char* rid_names[3] = {"q", "h", "f"};
    const std::uint32_t ssrcs[3] = {0x1111u, 0x2222u, 0x3333u};

    std::mt19937 rng(0x51AB2025u);
    std::uniform_int_distribution<int> len_d(8, 200);
    std::uniform_int_distribution<int> byte_d(0, 255);

    std::size_t expect_pkts[3] = {0, 0, 0};
    constexpr int kRounds = 60;
    for (int i = 0; i < kRounds; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        const int layer = i % 3;
        const std::size_t plen = static_cast<std::size_t>(len_d(rng));
        std::vector<std::uint8_t> payload(plen);
        for (auto& b : payload) b = static_cast<std::uint8_t>(byte_d(rng));

        // Build the RID one-byte header extension carrying rid_names[layer].
        rtp::Header h{};
        h.payload_type = 96;
        h.sequence = static_cast<std::uint16_t>(100 + i);
        h.timestamp = 9000u + static_cast<std::uint32_t>(i) * 90u;
        h.ssrc = ssrcs[layer];
        rtp::Extension e{};
        e.id = kRidExtId;
        e.value = reinterpret_cast<const std::uint8_t*>(rid_names[layer]);
        e.length = static_cast<std::uint16_t>(std::strlen(rid_names[layer]));
        std::uint8_t extbuf[16];
        ASSERT_GT(rtp::build_one_byte_extensions(h, &e, 1, extbuf, sizeof(extbuf)), 0u);

        std::uint8_t raw[1500];
        std::size_t rlen = 0;
        ASSERT_EQ(rtp::serialize(h, payload.data(), payload.size(), 0, raw,
                                 sizeof(raw), rlen), rtp::RtpError::Ok);

        rtp::Packet pkt;
        ASSERT_EQ(rtp::parse(raw, rlen, pkt), rtp::RtpError::Ok);
        // RID extension carried through parse.
        char rid_check[wrtc::kMaxRidLen + 1];
        ASSERT_GT(rtp::rid_value(pkt.header, kRidExtId, rid_check, sizeof(rid_check)),
                  0u);
        EXPECT_STREQ(rid_check, rid_names[layer]);

        wrtc::SimulcastTrack::Encoding* enc = track.demux(pkt, rlen);
        ASSERT_NE(enc, nullptr);
        EXPECT_STREQ(enc->rid, rid_names[layer]);
        EXPECT_EQ(enc->ssrc, ssrcs[layer]);
        ++expect_pkts[layer];
    }

    // Exactly 3 encodings, each bound to its own SSRC + correct packet counts.
    ASSERT_EQ(track.encoding_count(), 3u);
    for (int l = 0; l < 3; ++l) {
        wrtc::SimulcastTrack::Encoding* enc = track.encoding_by_rid(rid_names[l]);
        ASSERT_NE(enc, nullptr);
        EXPECT_EQ(enc->ssrc, ssrcs[l]);
        EXPECT_EQ(enc->packets, expect_pkts[l]);
    }
}

// ===========================================================================
// GATE 3 — SVC passthrough: classify (spatial,temporal) from the Dependency
// Descriptor ext and drop layers above a target without decoding.
// ===========================================================================
TEST(Simulcast, SvcRelayDropsLayersAboveTarget) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    constexpr std::uint8_t kDdExtId = 4;

    wrtc::SvcRelay relay(kDdExtId);
    relay.set_target(/*max_spatial=*/1, /*max_temporal=*/1);  // keep S<=1, T<=1

    std::mt19937 rng(0x5C402025u);
    std::uniform_int_distribution<int> byte_d(0, 255);

    std::size_t expect_keep = 0, expect_drop = 0;
    constexpr int kRounds = 64;
    for (int i = 0; i < kRounds; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline);
        const std::uint8_t spatial  = static_cast<std::uint8_t>(i % 3);   // 0..2
        const std::uint8_t temporal = static_cast<std::uint8_t>((i / 3) % 3);

        rtp::Header h{};
        h.payload_type = 98;
        h.sequence = static_cast<std::uint16_t>(500 + i);
        h.ssrc = 0xABCDu;
        // Dependency Descriptor ext: byte1 low nibble = (spatial<<4)|temporal.
        std::uint8_t dd[2] = {0x80, static_cast<std::uint8_t>((spatial << 4) | temporal)};
        rtp::Extension e{kDdExtId, dd, 2};
        std::uint8_t extbuf[16];
        ASSERT_GT(rtp::build_one_byte_extensions(h, &e, 1, extbuf, sizeof(extbuf)), 0u);

        std::uint8_t pl[32];
        for (auto& b : pl) b = static_cast<std::uint8_t>(byte_d(rng));
        std::uint8_t raw[1500];
        std::size_t rlen = 0;
        ASSERT_EQ(rtp::serialize(h, pl, sizeof(pl), 0, raw, sizeof(raw), rlen),
                  rtp::RtpError::Ok);
        rtp::Packet pkt;
        ASSERT_EQ(rtp::parse(raw, rlen, pkt), rtp::RtpError::Ok);

        wrtc::RtcpSink sink;
        const bool keep = relay.on_inbound_rtp(pkt, raw, rlen, sink);
        if (spatial <= 1 && temporal <= 1) { EXPECT_TRUE(keep); ++expect_keep; }
        else { EXPECT_FALSE(keep); ++expect_drop; }
    }

    EXPECT_EQ(relay.forwarded(), expect_keep);
    EXPECT_EQ(relay.dropped(), expect_drop);
    EXPECT_EQ(relay.seen(), static_cast<std::size_t>(kRounds));
    EXPECT_GT(expect_drop, 0u) << "test should induce some dropped layers";
}
