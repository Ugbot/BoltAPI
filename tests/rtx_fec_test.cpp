// rtx_fec_test.cpp — WA gate: RTX (RFC 4588) + RED/ULPFEC (RFC 2198 / 5109).
//
// In-process, deterministic, deadline-bounded (DEFAULT suite, no external deps):
//   (1) RTX: send media packets through the RtxInterceptor (caches them); an
//       inbound Generic NACK for seq N produces an RTX packet whose OSN==N, on
//       the rtx SSRC/PT; parse_rtx reconstructs the original payload BYTE-EXACT.
//       Randomized payloads (seeded RNG), multiple seqs incl. a BLP bitmask.
//   (2) FEC: build a ULPFEC packet over a group of media packets, DROP one, and
//       RECOVER it byte-exact from the FEC packet + survivors. Randomized over
//       many group sizes / which-one-dropped (seeded RNG).

#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"
#include "boltapi/webrtc/interceptor.h"
#include "boltapi/webrtc/fec.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace rtp  = bolt::api::webrtc::rtp;
namespace rtcp = bolt::api::webrtc::rtcp;
namespace fec  = bolt::api::webrtc::fec;
namespace wrtc = bolt::api::webrtc;

namespace {

constexpr std::uint32_t kMediaSsrc = 0x0ABCDEF0u;
constexpr std::uint8_t  kMediaPt   = 96;
constexpr std::uint32_t kRtxSsrc   = 0x0FEDCBA0u;
constexpr std::uint8_t  kRtxPt     = 97;

// Captured RTX packets emitted by the interceptor's RtpSink.
struct RtxCapture {
    std::vector<std::vector<std::uint8_t>> packets;
    static bool sink(void* ctx, const std::uint8_t* data, std::size_t len) noexcept {
        auto* self = static_cast<RtxCapture*>(ctx);
        self->packets.emplace_back(data, data + len);
        return true;
    }
};

std::size_t build_media(std::uint8_t* buf, std::size_t cap, std::uint16_t seq,
                        std::uint32_t ts, const std::uint8_t* pl, std::size_t plen) {
    rtp::Header h{};
    h.payload_type = kMediaPt;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = kMediaSsrc;
    std::size_t w = 0;
    EXPECT_EQ(rtp::serialize(h, pl, plen, 0, buf, cap, w), rtp::RtpError::Ok);
    return w;
}

}  // namespace

// ===========================================================================
// GATE 1 — RTX: NACK for seq N -> RTX packet with OSN==N reconstructs original.
// ===========================================================================
TEST(Rtx, NackProducesRtxPacketByteExact) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    wrtc::RtxInterceptor rtx(kMediaSsrc, kMediaPt, kRtxSsrc, kRtxPt);
    RtxCapture cap;
    wrtc::RtpSink sink; sink.fn = &RtxCapture::sink; sink.ctx = &cap;
    rtx.set_rtx_sink(sink);

    std::mt19937 rng(0x57A72025u);
    std::uniform_int_distribution<int> len_d(8, 240);
    std::uniform_int_distribution<int> byte_d(0, 255);

    // Send a window of media packets through the outbound hook (RTX caches them).
    constexpr std::uint16_t kBase = 5000;
    constexpr int kN = 20;
    std::vector<std::vector<std::uint8_t>> payloads(kN);
    for (int i = 0; i < kN; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        const std::size_t plen = static_cast<std::size_t>(len_d(rng));
        payloads[i].resize(plen);
        for (auto& b : payloads[i]) b = static_cast<std::uint8_t>(byte_d(rng));
        std::uint8_t raw[1500];
        const std::size_t rlen = build_media(
            raw, sizeof(raw), static_cast<std::uint16_t>(kBase + i),
            7000u + static_cast<std::uint32_t>(i), payloads[i].data(),
            payloads[i].size());
        rtp::Packet pkt;
        ASSERT_EQ(rtp::parse(raw, rlen, pkt), rtp::RtpError::Ok);
        rtx.on_outbound_rtp(pkt, raw, rlen);
    }

    // Inbound NACK: PID = kBase+3, BLP names kBase+4 and kBase+6 too.
    const std::uint16_t pid = kBase + 3;
    const std::uint16_t blp = (1u << 0) | (1u << 2);  // +1 (=4), +3 (=6)
    rtcp::NackBlock nb{pid, blp};
    std::uint8_t rbuf[256];
    rtcp::Builder b(rbuf, sizeof(rbuf));
    ASSERT_EQ(b.add_nack(0xFEEDu, kMediaSsrc, &nb, 1), rtcp::RtcpError::Ok);
    rtcp::Compound comp;
    ASSERT_EQ(rtcp::parse_compound(rbuf, b.size(), comp), rtcp::RtcpError::Ok);

    wrtc::RtcpSink rsink;  // unused; RTX uses its RtpSink
    rtx.on_inbound_rtcp(comp, rsink);

    // 3 RTX packets emitted (seq 5003, 5004, 5006), each reconstructs byte-exact.
    ASSERT_EQ(cap.packets.size(), 3u);
    EXPECT_EQ(rtx.retransmits(), 3u);
    const std::uint16_t want[3] = {static_cast<std::uint16_t>(kBase + 3),
                                   static_cast<std::uint16_t>(kBase + 4),
                                   static_cast<std::uint16_t>(kBase + 6)};
    int matched = 0;
    for (const auto& rp : cap.packets) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline);
        rtp::Packet rxp;
        ASSERT_EQ(rtp::parse(rp.data(), rp.size(), rxp), rtp::RtpError::Ok);
        EXPECT_EQ(rxp.header.payload_type, kRtxPt);
        EXPECT_EQ(rxp.header.ssrc, kRtxSsrc);
        ASSERT_GE(rxp.payload_len, 2u);
        const std::uint16_t osn =
            static_cast<std::uint16_t>((rxp.payload[0] << 8) | rxp.payload[1]);

        std::uint8_t orig[1500];
        std::size_t oseq = 0;
        const std::size_t olen = rtx.parse_rtx(rxp, orig, sizeof(orig), &oseq);
        ASSERT_GT(olen, 0u);
        EXPECT_EQ(oseq, osn);
        rtp::Packet origp;
        ASSERT_EQ(rtp::parse(orig, olen, origp), rtp::RtpError::Ok);
        EXPECT_EQ(origp.header.ssrc, kMediaSsrc);
        EXPECT_EQ(origp.header.payload_type, kMediaPt);
        EXPECT_EQ(origp.header.sequence, osn);

        // Find which seq this was and assert byte-exact payload.
        for (int k = 0; k < 3; ++k) {
            if (osn == want[k]) {
                const int idx = static_cast<int>(osn - kBase);
                ASSERT_GE(idx, 0); ASSERT_LT(idx, kN);
                std::vector<std::uint8_t> got(origp.payload,
                                              origp.payload + origp.payload_len);
                EXPECT_EQ(got, payloads[idx]);
                ++matched;
            }
        }
    }
    EXPECT_EQ(matched, 3);
}

// ===========================================================================
// GATE 2 — FEC: a group with one dropped packet is RECOVERED byte-exact.
// ===========================================================================
TEST(Fec, RecoverDroppedPacketByteExact) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    std::mt19937 rng(0xFEC2025u);
    std::uniform_int_distribution<int> len_d(16, 400);
    std::uniform_int_distribution<int> byte_d(0, 255);

    constexpr int kTrials = 50;
    for (int t = 0; t < kTrials; ++t) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        std::uniform_int_distribution<int> grp_d(2, static_cast<int>(fec::kMaxFecGroup));
        const std::size_t group = static_cast<std::size_t>(grp_d(rng));
        const std::uint16_t base = static_cast<std::uint16_t>(2000 + t * 32);

        // Build `group` media members with randomized payloads.
        std::vector<std::vector<std::uint8_t>> pls(group);
        std::vector<fec::Member> members(group);
        for (std::size_t i = 0; i < group; ++i) {
            const std::size_t plen = static_cast<std::size_t>(len_d(rng));
            pls[i].resize(plen);
            for (auto& bb : pls[i]) bb = static_cast<std::uint8_t>(byte_d(rng));
            members[i].sequence = static_cast<std::uint16_t>(base + i);
            members[i].payload_type = kMediaPt;
            members[i].timestamp = 1000u + static_cast<std::uint32_t>(i) * 90u;
            members[i].ssrc = kMediaSsrc;
            members[i].payload = pls[i].data();
            members[i].payload_len = pls[i].size();
        }

        // Build the FEC packet over the whole group.
        std::uint8_t fecbuf[2048];
        std::size_t feclen = 0;
        ASSERT_EQ(fec::build_fec(members.data(), group, fecbuf, sizeof(fecbuf),
                                 &feclen), fec::FecError::Ok);
        ASSERT_GT(feclen, fec::kFecHeaderLen + fec::kFecLevel0Len);

        // Drop one member (deterministic per trial), survivors are the rest.
        const std::size_t drop = static_cast<std::size_t>(t) % group;
        std::vector<fec::Member> survivors;
        for (std::size_t i = 0; i < group; ++i)
            if (i != drop) survivors.push_back(members[i]);

        std::uint8_t out[2048];
        std::uint16_t rseq = 0; std::uint8_t rpt = 0; std::uint32_t rts = 0;
        std::size_t olen = 0;
        ASSERT_EQ(fec::recover(fecbuf, feclen, survivors.data(), survivors.size(),
                               &rseq, &rpt, &rts, out, sizeof(out), &olen),
                  fec::FecError::Ok)
            << "trial " << t << " group " << group << " drop " << drop;

        // Recovered fields + payload match the dropped member byte-exact.
        EXPECT_EQ(rseq, members[drop].sequence);
        EXPECT_EQ(rpt, members[drop].payload_type);
        EXPECT_EQ(rts, members[drop].timestamp);
        ASSERT_EQ(olen, members[drop].payload_len);
        std::vector<std::uint8_t> got(out, out + olen);
        EXPECT_EQ(got, pls[drop]) << "trial " << t;
    }
}

// ===========================================================================
// GATE 3 — FEC: two missing is NOT recoverable (XOR recovers exactly one).
// ===========================================================================
TEST(Fec, TwoMissingNotRecoverable) {
    fec::Member m[3];
    std::uint8_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    std::uint8_t bb[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    std::uint8_t cc[8] = {17, 18, 19, 20, 21, 22, 23, 24};
    const std::uint8_t* pls[3] = {a, bb, cc};
    for (int i = 0; i < 3; ++i) {
        m[i].sequence = static_cast<std::uint16_t>(100 + i);
        m[i].payload_type = kMediaPt;
        m[i].timestamp = 5u;
        m[i].ssrc = kMediaSsrc;
        m[i].payload = pls[i];
        m[i].payload_len = 8;
    }
    std::uint8_t fbuf[256]; std::size_t flen = 0;
    ASSERT_EQ(fec::build_fec(m, 3, fbuf, sizeof(fbuf), &flen), fec::FecError::Ok);

    // Only one survivor -> two missing -> NotRecoverable.
    std::uint8_t out[256]; std::uint16_t s = 0; std::uint8_t p = 0; std::uint32_t ts = 0;
    std::size_t olen = 0;
    EXPECT_EQ(fec::recover(fbuf, flen, &m[0], 1, &s, &p, &ts, out, sizeof(out),
                           &olen), fec::FecError::NotRecoverable);
}
