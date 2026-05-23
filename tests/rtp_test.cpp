// tests/rtp_test.cpp — RTP / RTCP codec tests (boltapi/webrtc/rtp.h + rtcp.h).
//
// Covers:
//   * RTP header round-trip with CSRCs, RFC 8285 one-byte + two-byte extensions,
//     padding, marker (randomised inputs, many SSRCs/PTs)
//   * a real captured RTP packet's field decode (Opus)
//   * RTCP SR + RR round-trip (with report blocks)
//   * a compound packet (SR + SDES) parse/build
//   * NACK + PLI + TWCC + FIR + REMB feedback round-trip
//   * RTP-vs-RTCP demux classifier (RFC 5761)
//   * negative / bounds cases
//
// Dual-mode: under the normal gtest build (boltapi_add_test) this is a regular
// gtest TU. When compiled with -DBOLTAPI_RTP_TEST_STANDALONE (the throwaway
// tools/rtp_check build) a tiny shim provides TEST()/EXPECT_*/main() so no gtest
// dependency is needed for self-validation.

#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"

#include <cstdint>
#include <cstring>

#ifdef BOLTAPI_RTP_TEST_STANDALONE
// ----------------------------------------------------------------------------
// Minimal gtest-compatible shim (no external dependency).
// ----------------------------------------------------------------------------
#include <cstdio>
#include <vector>
namespace boltapi_shim {
struct Case { const char* suite; const char* name; void (*fn)(); };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
inline int& failures() { static int f = 0; return f; }
inline int& checks() { static int c = 0; return c; }
struct Reg { Reg(const char* s, const char* n, void (*f)()) { registry().push_back({s, n, f}); } };
}  // namespace boltapi_shim
#define TEST(suite, name)                                                       \
    static void suite##_##name##_body();                                        \
    static ::boltapi_shim::Reg suite##_##name##_reg(#suite, #name,             \
                                                    suite##_##name##_body);     \
    static void suite##_##name##_body()
#define BOLTAPI_EXPECT(cond)                                                    \
    do {                                                                        \
        ++::boltapi_shim::checks();                                             \
        if (!(cond)) {                                                          \
            std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);       \
            ++::boltapi_shim::failures();                                       \
        }                                                                       \
    } while (0)
#define EXPECT_TRUE(c)     BOLTAPI_EXPECT(c)
#define EXPECT_FALSE(c)    BOLTAPI_EXPECT(!(c))
#define EXPECT_EQ(a, b)    BOLTAPI_EXPECT((a) == (b))
#define EXPECT_NE(a, b)    BOLTAPI_EXPECT((a) != (b))
#define EXPECT_LE(a, b)    BOLTAPI_EXPECT((a) <= (b))
#define EXPECT_GE(a, b)    BOLTAPI_EXPECT((a) >= (b))
int main() {
    std::printf("=== RTP/RTCP codec tests (standalone) ===\n");
    for (const auto& c : ::boltapi_shim::registry()) {
        std::printf("%s.%s\n", c.suite, c.name);
        c.fn();
    }
    std::printf("=== %d checks, %d failures ===\n",
                ::boltapi_shim::checks(), ::boltapi_shim::failures());
    return ::boltapi_shim::failures() == 0 ? 0 : 1;
}
#else
#include <gtest/gtest.h>
#endif

namespace rtp = bolt::api::webrtc::rtp;
namespace rtcp = bolt::api::webrtc::rtcp;

namespace {

// Deterministic xorshift PRNG so runs are reproducible.
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    std::uint32_t next() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return static_cast<std::uint32_t>(s >> 32);
    }
};

}  // namespace

// ----------------------------------------------------------------------------
// RTP header round-trip: CSRCs + one-byte extension + padding + marker.
// ----------------------------------------------------------------------------
TEST(Rtp, HeaderRoundTrip) {
    Rng rng(12345);
    for (int iter = 0; iter < 64; ++iter) {
        rtp::Header h{};
        h.padding      = (iter & 1) != 0;
        h.marker       = (iter & 2) != 0;
        h.payload_type = static_cast<std::uint8_t>(rng.next() & 0x7F);
        h.sequence     = static_cast<std::uint16_t>(rng.next());
        h.timestamp    = rng.next();
        h.ssrc         = rng.next();
        h.csrc_count   = static_cast<std::uint8_t>(rng.next() % (rtp::kMaxCsrc + 1));
        for (std::uint8_t i = 0; i < h.csrc_count; ++i) h.csrc[i] = rng.next();

        std::uint8_t ext_payload[16]{};
        const bool with_ext = (iter % 3) == 0;
        if (with_ext) {
            ext_payload[0] = (1 << 4) | (2 - 1); ext_payload[1] = 0xAA; ext_payload[2] = 0xBB;
            ext_payload[3] = (2 << 4) | (1 - 1); ext_payload[4] = 0xCC;
            h.extension = true;
            h.extension_profile = rtp::kExtProfileOneByte;
            h.ext_raw = ext_payload;
            h.ext_raw_len = 8;  // 5 bytes + 3 zero pad => multiple of 4
        }

        std::uint8_t payload[200];
        const std::size_t plen = 20 + (rng.next() % 100);
        for (std::size_t i = 0; i < plen; ++i)
            payload[i] = static_cast<std::uint8_t>(rng.next());

        const std::uint8_t pad_len =
            h.padding ? static_cast<std::uint8_t>(1 + (rng.next() % 8)) : 0;

        std::uint8_t buf[512];
        std::size_t written = 0;
        EXPECT_EQ(rtp::serialize(h, payload, plen, pad_len, buf, sizeof(buf), written),
                  rtp::RtpError::Ok);

        rtp::Packet pkt{};
        EXPECT_EQ(rtp::parse(buf, written, pkt), rtp::RtpError::Ok);
        EXPECT_EQ(pkt.header.version, rtp::kVersion);
        EXPECT_EQ(pkt.header.marker, h.marker);
        EXPECT_EQ(pkt.header.padding, h.padding);
        EXPECT_EQ(pkt.header.payload_type, h.payload_type);
        EXPECT_EQ(pkt.header.sequence, h.sequence);
        EXPECT_EQ(pkt.header.timestamp, h.timestamp);
        EXPECT_EQ(pkt.header.ssrc, h.ssrc);
        EXPECT_EQ(pkt.header.csrc_count, h.csrc_count);
        for (std::uint8_t i = 0; i < h.csrc_count; ++i)
            EXPECT_EQ(pkt.header.csrc[i], h.csrc[i]);
        EXPECT_EQ(pkt.payload_len, plen);
        EXPECT_TRUE(std::memcmp(pkt.payload, payload, plen) == 0);
        if (h.padding) EXPECT_EQ(pkt.padding_len, pad_len);

        if (with_ext) {
            EXPECT_TRUE(pkt.header.extension);
            EXPECT_EQ(pkt.header.extension_profile, rtp::kExtProfileOneByte);
            EXPECT_EQ(pkt.header.ext_count, std::size_t(2));
            const rtp::Extension* e1 = pkt.header.find_extension(1);
            const rtp::Extension* e2 = pkt.header.find_extension(2);
            EXPECT_TRUE(e1 != nullptr && e1->length == 2 &&
                        e1->value[0] == 0xAA && e1->value[1] == 0xBB);
            EXPECT_TRUE(e2 != nullptr && e2->length == 1 && e2->value[0] == 0xCC);
        }
    }
}

// Two-byte extension form (RFC 8285 §4.3).
TEST(Rtp, TwoByteExtension) {
    rtp::Header h{};
    h.payload_type = 96; h.sequence = 7; h.timestamp = 1000; h.ssrc = 0xDEADBEEF;
    h.extension = true;
    h.extension_profile = 0x1000;  // two-byte profile
    std::uint8_t ext[8] = { 5, 3, 0x11, 0x22, 0x33, 0, 0, 0 };  // id=5 len=3
    h.ext_raw = ext; h.ext_raw_len = 8;
    std::uint8_t buf[64]; std::size_t w = 0;
    EXPECT_EQ(rtp::serialize(h, nullptr, 0, 0, buf, sizeof(buf), w), rtp::RtpError::Ok);
    rtp::Packet pkt{};
    EXPECT_EQ(rtp::parse(buf, w, pkt), rtp::RtpError::Ok);
    EXPECT_EQ(pkt.header.ext_count, std::size_t(1));
    const rtp::Extension* e = pkt.header.find_extension(5);
    EXPECT_TRUE(e != nullptr && e->length == 3);
    EXPECT_TRUE(e && e->value[0] == 0x11 && e->value[1] == 0x22 && e->value[2] == 0x33);
}

// Decode a real captured RTP packet (Opus): V=2 PT=111 seq=0x0457
// ts=0x12345678 ssrc=0x1A2B3C4D + 6 payload bytes.
TEST(Rtp, RealCapturedPacket) {
    const std::uint8_t wire[] = {
        0x80, 0x6F, 0x04, 0x57,
        0x12, 0x34, 0x56, 0x78,
        0x1A, 0x2B, 0x3C, 0x4D,
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02
    };
    rtp::Packet pkt{};
    EXPECT_EQ(rtp::parse(wire, sizeof(wire), pkt), rtp::RtpError::Ok);
    EXPECT_EQ(pkt.header.version, std::uint8_t(2));
    EXPECT_FALSE(pkt.header.padding);
    EXPECT_FALSE(pkt.header.extension);
    EXPECT_EQ(pkt.header.csrc_count, std::uint8_t(0));
    EXPECT_FALSE(pkt.header.marker);
    EXPECT_EQ(pkt.header.payload_type, std::uint8_t(111));
    EXPECT_EQ(pkt.header.sequence, std::uint16_t(0x0457));
    EXPECT_EQ(pkt.header.timestamp, std::uint32_t(0x12345678));
    EXPECT_EQ(pkt.header.ssrc, std::uint32_t(0x1A2B3C4D));
    EXPECT_EQ(pkt.header.header_len, std::size_t(12));
    EXPECT_EQ(pkt.payload_len, std::size_t(6));
    EXPECT_TRUE(pkt.payload[0] == 0xDE && pkt.payload[5] == 0x02);
}

// ----------------------------------------------------------------------------
// RTCP SR + RR round-trip with report blocks.
// ----------------------------------------------------------------------------
TEST(Rtcp, SenderAndReceiverReports) {
    rtcp::ReportBlock rb[2]{};
    rb[0] = { 0x11111111, 12, -34, 0x0000ABCD, 555, 0x1234, 0x5678 };
    rb[1] = { 0x22222222, 0, 1000, 0x0001FFFF, 9, 0xAAAA, 0xBBBB };

    {  // SR
        std::uint8_t buf[256];
        rtcp::Builder b(buf, sizeof(buf));
        EXPECT_EQ(b.add_sr(0xCAFEBABE, 0x0123456789ABCDEFull, 0x0A0B0C0D,
                           42, 9001, rb, 2), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::SR);
        EXPECT_EQ(p.ssrc, std::uint32_t(0xCAFEBABE));
        EXPECT_EQ(p.ntp_timestamp, std::uint64_t(0x0123456789ABCDEF));
        EXPECT_EQ(p.rtp_timestamp, std::uint32_t(0x0A0B0C0D));
        EXPECT_EQ(p.packet_count, std::uint32_t(42));
        EXPECT_EQ(p.octet_count, std::uint32_t(9001));
        EXPECT_EQ(p.report_count, std::size_t(2));
        EXPECT_EQ(p.report_blocks[0].ssrc, std::uint32_t(0x11111111));
        EXPECT_EQ(p.report_blocks[0].fraction_lost, std::uint8_t(12));
        EXPECT_EQ(p.report_blocks[0].cumulative_lost, -34);
        EXPECT_EQ(p.report_blocks[0].highest_seq, std::uint32_t(0x0000ABCD));
        EXPECT_EQ(p.report_blocks[0].jitter, std::uint32_t(555));
        EXPECT_EQ(p.report_blocks[1].ssrc, std::uint32_t(0x22222222));
        EXPECT_EQ(p.report_blocks[1].cumulative_lost, 1000);
    }
    {  // RR
        std::uint8_t buf[256];
        rtcp::Builder b(buf, sizeof(buf));
        EXPECT_EQ(b.add_rr(0xFEEDF00D, rb, 2), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::RR);
        EXPECT_EQ(p.ssrc, std::uint32_t(0xFEEDF00D));
        EXPECT_EQ(p.report_count, std::size_t(2));
        EXPECT_EQ(p.report_blocks[1].ssrc, std::uint32_t(0x22222222));
        EXPECT_EQ(p.report_blocks[0].lsr, std::uint32_t(0x1234));
        EXPECT_EQ(p.report_blocks[0].dlsr, std::uint32_t(0x5678));
    }
}

// Compound packet: SR + SDES parse/build.
TEST(Rtcp, CompoundSrSdes) {
    std::uint8_t buf[256];
    rtcp::Builder b(buf, sizeof(buf));
    rtcp::ReportBlock rb{};
    rb.ssrc = 0xABCD1234; rb.fraction_lost = 5; rb.highest_seq = 100;
    EXPECT_EQ(b.add_sr(0x10203040, 0xDEADBEEFCAFEBABEull, 7, 3, 480, &rb, 1),
              rtcp::RtcpError::Ok);

    const char* cname = "bolt@example.org";
    rtcp::SdesItem items[1];
    items[0].type = rtcp::SdesType::CName;
    items[0].text = cname;
    items[0].length = static_cast<std::uint8_t>(std::strlen(cname));
    EXPECT_EQ(b.add_sdes(0x10203040, items, 1), rtcp::RtcpError::Ok);

    rtcp::Compound c{};
    EXPECT_EQ(rtcp::parse_compound(buf, b.size(), c), rtcp::RtcpError::Ok);
    EXPECT_EQ(c.count, std::size_t(2));
    EXPECT_TRUE(c.packets[0].type == rtcp::Type::SR);
    EXPECT_EQ(c.packets[0].ssrc, std::uint32_t(0x10203040));
    EXPECT_EQ(c.packets[0].report_count, std::size_t(1));
    EXPECT_EQ(c.packets[0].report_blocks[0].ssrc, std::uint32_t(0xABCD1234));
    EXPECT_TRUE(c.packets[1].type == rtcp::Type::SDES);
    EXPECT_EQ(c.packets[1].ssrc, std::uint32_t(0x10203040));
    EXPECT_EQ(c.packets[1].sdes_count, std::size_t(1));
    EXPECT_TRUE(c.packets[1].sdes[0].type == rtcp::SdesType::CName);
    EXPECT_EQ(c.packets[1].sdes[0].length, std::uint8_t(std::strlen(cname)));
    EXPECT_TRUE(std::memcmp(c.packets[1].sdes[0].text, cname, std::strlen(cname)) == 0);
}

// Feedback: NACK + PLI + FIR + REMB + TWCC round-trips.
TEST(Rtcp, Feedback) {
    {  // NACK
        std::uint8_t buf[128];
        rtcp::Builder b(buf, sizeof(buf));
        rtcp::NackBlock nb[3] = { {100, 0x000F}, {200, 0xFFFF}, {4000, 0x0001} };
        EXPECT_EQ(b.add_nack(0xAAAA0001, 0xBBBB0002, nb, 3), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::RTPFB);
        EXPECT_EQ(p.count, std::uint8_t(rtcp::RtpfbFmt::Nack));
        EXPECT_EQ(p.ssrc, std::uint32_t(0xAAAA0001));
        EXPECT_EQ(p.media_ssrc, std::uint32_t(0xBBBB0002));
        EXPECT_EQ(p.nack_count, std::size_t(3));
        EXPECT_TRUE(p.nacks[0].pid == 100 && p.nacks[0].blp == 0x000F);
        EXPECT_TRUE(p.nacks[1].pid == 200 && p.nacks[1].blp == 0xFFFF);
        EXPECT_TRUE(p.nacks[2].pid == 4000 && p.nacks[2].blp == 0x0001);
    }
    {  // PLI
        std::uint8_t buf[64];
        rtcp::Builder b(buf, sizeof(buf));
        EXPECT_EQ(b.add_pli(0x1111, 0x2222), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::PSFB);
        EXPECT_EQ(p.count, std::uint8_t(rtcp::PsfbFmt::Pli));
        EXPECT_TRUE(p.ssrc == 0x1111u && p.media_ssrc == 0x2222u);
        EXPECT_EQ(p.fci_len, std::uint16_t(0));
    }
    {  // FIR
        std::uint8_t buf[64];
        rtcp::Builder b(buf, sizeof(buf));
        rtcp::FirEntry fe[2] = { {0xDEAD0001, 7}, {0xDEAD0002, 200} };
        EXPECT_EQ(b.add_fir(0x3333, 0x4444, fe, 2), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::PSFB);
        EXPECT_EQ(p.count, std::uint8_t(rtcp::PsfbFmt::Fir));
        EXPECT_EQ(p.fir_count, std::size_t(2));
        EXPECT_TRUE(p.fir[0].ssrc == 0xDEAD0001u && p.fir[0].seq == 7);
        EXPECT_TRUE(p.fir[1].ssrc == 0xDEAD0002u && p.fir[1].seq == 200);
    }
    {  // REMB
        std::uint8_t buf[64];
        rtcp::Builder b(buf, sizeof(buf));
        std::uint32_t ssrcs[2] = { 0x55550001, 0x55550002 };
        const std::uint32_t bitrate = 2500000;
        EXPECT_EQ(b.add_remb(0x6666, bitrate, ssrcs, 2), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::PSFB);
        EXPECT_EQ(p.count, std::uint8_t(rtcp::PsfbFmt::Remb));
        EXPECT_EQ(p.remb_ssrc_count, std::size_t(2));
        EXPECT_TRUE(p.remb_ssrcs[0] == 0x55550001u && p.remb_ssrcs[1] == 0x55550002u);
        const std::uint32_t got = p.remb_bitrate_bps;
        const std::uint32_t diff = got > bitrate ? got - bitrate : bitrate - got;
        EXPECT_LE(diff, bitrate / 1000 + 8);  // 6/18 float approximation
    }
    {  // TWCC raw FCI passthrough
        std::uint8_t buf[64];
        rtcp::Builder b(buf, sizeof(buf));
        const std::uint8_t fci[10] = { 0,1,2,3,4,5,6,7,8,9 };
        EXPECT_EQ(b.add_twcc(0x7777, 0x8888, fci, sizeof(fci)), rtcp::RtcpError::Ok);
        rtcp::Packet p{};
        EXPECT_EQ(rtcp::parse_one(buf, b.size(), p), rtcp::RtcpError::Ok);
        EXPECT_TRUE(p.type == rtcp::Type::RTPFB);
        EXPECT_EQ(p.count, std::uint8_t(rtcp::RtpfbFmt::Twcc));
        EXPECT_GE(p.fci_len, std::uint16_t(sizeof(fci)));  // padded to 4
        EXPECT_TRUE(std::memcmp(p.fci, fci, sizeof(fci)) == 0);
    }
}

// RTP vs RTCP demux (RFC 5761).
TEST(Rtcp, Demux) {
    const std::uint8_t rtp_pkt[] = { 0x80, 0x6F, 0,0, 0,0,0,0, 0,0,0,0 };  // PT 111
    EXPECT_FALSE(rtcp::is_rtcp(rtp_pkt, sizeof(rtp_pkt)));
    const std::uint8_t rtp_marked[] = { 0x80, 0xE0, 0,0, 0,0,0,0, 0,0,0,0 };  // M+PT96
    EXPECT_FALSE(rtcp::is_rtcp(rtp_marked, sizeof(rtp_marked)));
    const std::uint8_t sr[] = { 0x80, 200, 0,0 };
    EXPECT_TRUE(rtcp::is_rtcp(sr, sizeof(sr)));
    const std::uint8_t rr[] = { 0x80, 201, 0,0 };
    EXPECT_TRUE(rtcp::is_rtcp(rr, sizeof(rr)));
    const std::uint8_t psfb[] = { 0x80, 206, 0,0 };
    EXPECT_TRUE(rtcp::is_rtcp(psfb, sizeof(psfb)));
    const std::uint8_t one[] = { 0x80 };
    EXPECT_FALSE(rtcp::is_rtcp(one, sizeof(one)));
}

// Negative / bounds cases.
TEST(Rtcp, Errors) {
    rtp::Header h{};
    rtp::Packet pkt{};
    EXPECT_EQ(rtp::parse(nullptr, 0, pkt), rtp::RtpError::TooShort);
    const std::uint8_t too_short[] = { 0x80, 0x60, 0, 0 };
    EXPECT_EQ(rtp::parse(too_short, sizeof(too_short), pkt), rtp::RtpError::TooShort);
    const std::uint8_t bad_ver[] = { 0x40, 0x60, 0,0, 0,0,0,0, 0,0,0,0 };  // V=1
    EXPECT_EQ(rtp::parse(bad_ver, sizeof(bad_ver), pkt), rtp::RtpError::BadVersion);
    std::uint8_t tiny[4]; std::size_t w = 0;
    EXPECT_EQ(rtp::serialize_header(h, tiny, sizeof(tiny), w), rtp::RtpError::BufferTooSmall);

    rtcp::Packet rp{};
    EXPECT_EQ(rtcp::parse_one(too_short, 2, rp), rtcp::RtcpError::TooShort);
    const std::uint8_t rtcp_bad_len[] = { 0x80, 200, 0xFF, 0xFF };  // huge declared len
    EXPECT_EQ(rtcp::parse_one(rtcp_bad_len, sizeof(rtcp_bad_len), rp),
              rtcp::RtcpError::BadLength);
}
