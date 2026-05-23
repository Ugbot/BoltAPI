// media_track_test.cpp — WM5 MEDIA PIPELINE GATE (interceptors + Track + SRTP).
//
// In-process, deterministic, deadline-bounded. Exercises the WM5 surface that
// App::on_track / WebRtcPeerHub wire together — without needing the live
// transport — so it runs in the DEFAULT suite (no BOLTAPI_WITH_WEBRTC flag):
//
//   * Two srtp::SrtpSessions sharing a known master key/salt model one direction
//     of a DTLS-SRTP keying (sender.out <-> receiver.in). (The cross-stack live
//     keying is already proven by tests/dtls_srtp_test.cpp.)
//   * An audio MediaTrack + a video MediaTrack (DIFFERENT SSRCs) in a
//     TrackRegistry; an outbound RTP packet goes through the interceptor chain
//     (outbound hook) then SRTP-protect; the protected bytes are fed to the
//     inbound side (SRTP-unprotect -> RFC 5761 demux -> by-SSRC track lookup ->
//     deliver -> handler fires with the right SSRC/PT/payload, BYTE-EXACT).
//   * Interceptor: a deliberate inbound sequence GAP makes NackGenerator emit a
//     Generic NACK that we parse back via rtcp.h and assert the missing seq; the
//     ReportInterceptor tick() produces a parseable SR/RR compound.
//   * More than one track (audio AND video), randomized payloads (seeded RNG).
//
// Bounded by an iteration cap + a wall-clock deadline so it can never hang.

#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"
#include "boltapi/webrtc/interceptor.h"
#include "boltapi/webrtc/track.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace srtp = bolt::api::webrtc::srtp;
namespace rtp  = bolt::api::webrtc::rtp;
namespace rtcp = bolt::api::webrtc::rtcp;
namespace wrtc = bolt::api::webrtc;

namespace {

constexpr std::uint8_t  kAudioPt   = 111;        // opus-ish
constexpr std::uint8_t  kVideoPt   = 96;         // VP8-ish
constexpr std::uint32_t kAudioSsrc = 0x0A0A0A0Au;
constexpr std::uint32_t kVideoSsrc = 0x0B0B0B0Bu;

// A known master key + salt (CM profile: 16-byte key, 14-byte salt).
const std::uint8_t kMasterKey[16] = {
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39};
const std::uint8_t kMasterSalt[14] = {
    0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB,
    0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6};

// Build a valid RTP packet (12-byte header + payload) into `buf`.
std::size_t build_rtp(std::uint8_t* buf, std::size_t cap, std::uint8_t pt,
                      std::uint16_t seq, std::uint32_t ssrc, std::uint32_t ts,
                      const std::uint8_t* payload, std::size_t plen) {
    rtp::Header h{};
    h.payload_type = pt;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = ssrc;
    std::size_t written = 0;
    EXPECT_EQ(rtp::serialize(h, payload, plen, 0, buf, cap, written),
              rtp::RtpError::Ok);
    return written;
}

// A test harness modelling the hub's media path WITHOUT the live transport.
// Sender side: outbound interceptors -> SRTP protect -> "wire" (a byte vector).
// Receiver side: SRTP unprotect -> RFC5761 demux -> track deliver / RTCP hooks.
struct MediaHarness {
    srtp::SrtpSession tx;   // sender outbound
    srtp::SrtpSession rx;   // receiver inbound (same key as tx)

    wrtc::InterceptorChain  out_chain;          // sender outbound chain
    wrtc::InterceptorChain  in_chain;           // receiver inbound chain
    wrtc::ReportInterceptor reporter{0xFEEDu};  // sender SR/RR reporter
    wrtc::NackGenerator     nack_gen{0xCAFEu};  // receiver NACK generator
    wrtc::TrackRegistry     rx_tracks;          // receiver tracks (by SSRC)

    // Captured deliveries (handler fired): ssrc, pt, payload bytes.
    struct Delivered {
        std::uint32_t ssrc;
        std::uint8_t  pt;
        std::vector<std::uint8_t> payload;
    };
    std::vector<Delivered> delivered;

    // Captured RTCP emitted by the receiver inbound chain (e.g. NACK).
    std::vector<std::vector<std::uint8_t>> rtcp_out;

    bool init() {
        if (tx.init(srtp::Profile::kAesCm128HmacSha1_80, kMasterKey, 16,
                    kMasterSalt, 14) != srtp::Error::kOk)
            return false;
        if (rx.init(srtp::Profile::kAesCm128HmacSha1_80, kMasterKey, 16,
                    kMasterSalt, 14) != srtp::Error::kOk)
            return false;
        out_chain.add(&reporter);
        in_chain.add(&nack_gen);
        // Two inbound tracks with distinct SSRCs (pre-registered like SDP).
        rx_tracks.add(wrtc::MediaKind::kAudio, kAudioSsrc, kAudioPt, "opus");
        rx_tracks.add(wrtc::MediaKind::kVideo, kVideoSsrc, kVideoPt, "VP8");
        for (std::size_t i = 0; i < rx_tracks.size(); ++i) {
            rx_tracks.at(i)->set_deliver_sink(&MediaHarness::deliver_cb, this);
        }
        return true;
    }

    static void deliver_cb(void* ctx, wrtc::MediaTrack& t, const rtp::Packet& pkt,
                           const std::uint8_t* data, std::size_t len) noexcept {
        (void)data; (void)len;
        auto* self = static_cast<MediaHarness*>(ctx);
        Delivered d;
        d.ssrc = t.ssrc();
        d.pt = pkt.header.payload_type;
        d.payload.assign(pkt.payload, pkt.payload + pkt.payload_len);
        self->delivered.push_back(std::move(d));
    }

    // RtcpSink trampoline: capture the receiver's emitted RTCP.
    static bool rtcp_capture(void* ctx, const std::uint8_t* data,
                             std::size_t len) noexcept {
        auto* self = static_cast<MediaHarness*>(ctx);
        self->rtcp_out.emplace_back(data, data + len);
        return true;
    }

    // Sender: build, run outbound chain, SRTP-protect into `wire`.
    bool send(std::uint8_t pt, std::uint16_t seq, std::uint32_t ssrc,
              const std::uint8_t* payload, std::size_t plen,
              std::vector<std::uint8_t>& wire) {
        std::uint8_t raw[1500];
        const std::size_t rlen =
            build_rtp(raw, sizeof(raw), pt, seq, ssrc, 1000u + seq, payload, plen);
        if (rlen < rtp::kFixedHeaderSize) return false;
        rtp::Packet pkt;
        if (rtp::parse(raw, rlen, pkt) != rtp::RtpError::Ok) return false;
        out_chain.outbound_rtp(pkt, raw, rlen);
        std::uint8_t prot[1600];
        std::size_t prot_len = 0;
        if (tx.protect_rtp(raw, rlen, prot, sizeof(prot), &prot_len) !=
            srtp::Error::kOk)
            return false;
        wire.assign(prot, prot + prot_len);
        return true;
    }

    // Receiver: SRTP-unprotect, RFC5761 demux, run inbound chain, deliver.
    bool recv(const std::vector<std::uint8_t>& wire) {
        std::uint8_t plain[1600];
        std::size_t plain_len = 0;
        wrtc::RtcpSink sink; sink.fn = &MediaHarness::rtcp_capture; sink.ctx = this;
        if (rtcp::is_rtcp(wire.data(), wire.size())) {
            if (rx.unprotect_rtcp(wire.data(), wire.size(), plain, sizeof(plain),
                                  &plain_len) != srtp::Error::kOk)
                return false;
            rtcp::Compound c;
            if (rtcp::parse_compound(plain, plain_len, c) != rtcp::RtcpError::Ok)
                return false;
            in_chain.inbound_rtcp(c, sink);
            return true;
        }
        if (rx.unprotect_rtp(wire.data(), wire.size(), plain, sizeof(plain),
                             &plain_len) != srtp::Error::kOk)
            return false;
        rtp::Packet pkt;
        if (rtp::parse(plain, plain_len, pkt) != rtp::RtpError::Ok) return false;
        if (!in_chain.inbound_rtp(pkt, plain, plain_len, sink)) return true;
        wrtc::MediaTrack* t = rx_tracks.by_ssrc(pkt.header.ssrc);
        if (t == nullptr) t = rx_tracks.by_payload_type(pkt.header.payload_type);
        if (t == nullptr) return false;
        t->deliver(pkt, plain, plain_len);
        return true;
    }
};

}  // namespace

// ===========================================================================
// GATE 1 — two tracks (audio + video, distinct SSRCs), randomized payloads:
// outbound interceptors -> SRTP -> inbound SRTP -> RFC5761 demux -> correct
// track -> handler fires with the right SSRC/PT/payload, byte-exact.
// ===========================================================================
TEST(MediaTrack, TwoTracksRoundTripByteExact) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    MediaHarness h;
    ASSERT_TRUE(h.init());

    std::mt19937 rng(0xB01D2025u);                 // seeded, deterministic
    std::uniform_int_distribution<int> len_d(8, 240);
    std::uniform_int_distribution<int> byte_d(0, 255);

    constexpr int kRounds = 64;                      // bounded (no hang)
    std::vector<std::vector<std::uint8_t>> sent_audio, sent_video;

    for (int i = 0; i < kRounds; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "deadline";
        const bool video = (i % 2) == 1;
        const std::size_t plen = static_cast<std::size_t>(len_d(rng));
        std::vector<std::uint8_t> payload(plen);
        for (auto& b : payload) b = static_cast<std::uint8_t>(byte_d(rng));

        const std::uint8_t pt   = video ? kVideoPt   : kAudioPt;
        const std::uint32_t ssrc = video ? kVideoSsrc : kAudioSsrc;
        const std::uint16_t seq = static_cast<std::uint16_t>(1000 + i);

        std::vector<std::uint8_t> wire;
        ASSERT_TRUE(h.send(pt, seq, ssrc, payload.data(), payload.size(), wire));
        ASSERT_GT(wire.size(), 12u + payload.size());  // SRTP tag appended
        ASSERT_TRUE(h.recv(wire));
        (video ? sent_video : sent_audio).push_back(std::move(payload));
    }

    // Every packet delivered to the right track, byte-exact, in order per SSRC.
    ASSERT_EQ(h.delivered.size(), static_cast<std::size_t>(kRounds));
    std::size_t ai = 0, vi = 0;
    for (const auto& d : h.delivered) {
        if (d.ssrc == kAudioSsrc) {
            ASSERT_EQ(d.pt, kAudioPt);
            ASSERT_LT(ai, sent_audio.size());
            EXPECT_EQ(d.payload, sent_audio[ai++]);
        } else {
            ASSERT_EQ(d.ssrc, kVideoSsrc);
            ASSERT_EQ(d.pt, kVideoPt);
            ASSERT_LT(vi, sent_video.size());
            EXPECT_EQ(d.payload, sent_video[vi++]);
        }
    }
    EXPECT_EQ(ai, sent_audio.size());
    EXPECT_EQ(vi, sent_video.size());

    // Track counters reflect the delivered media.
    wrtc::MediaTrack* at = h.rx_tracks.by_ssrc(kAudioSsrc);
    wrtc::MediaTrack* vt = h.rx_tracks.by_ssrc(kVideoSsrc);
    ASSERT_NE(at, nullptr);
    ASSERT_NE(vt, nullptr);
    EXPECT_EQ(at->packets_recv(), sent_audio.size());
    EXPECT_EQ(vt->packets_recv(), sent_video.size());
    EXPECT_EQ(at->codec(), std::string("opus"));
    EXPECT_EQ(vt->codec(), std::string("VP8"));
    EXPECT_EQ(vt->kind(), wrtc::MediaKind::kVideo);
}

// ===========================================================================
// GATE 2 — interceptor NACK generator: a deliberate inbound sequence gap makes
// the receiver emit a Generic NACK; parse it via rtcp.h and assert the missing
// sequence number(s). Bounded.
// ===========================================================================
TEST(MediaTrack, NackGeneratorEmitsOnSequenceGap) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    MediaHarness h;
    ASSERT_TRUE(h.init());

    const std::uint8_t pl[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};

    // Send seq 100, then JUMP to 103 (104 - 3 missing: 101, 102) on the audio
    // SSRC. The NackGenerator runs on the receiver inbound chain.
    std::vector<std::uint8_t> w0, w1;
    ASSERT_TRUE(h.send(kAudioPt, 100, kAudioSsrc, pl, sizeof(pl), w0));
    ASSERT_TRUE(h.recv(w0));
    ASSERT_TRUE(std::chrono::steady_clock::now() < deadline);
    ASSERT_TRUE(h.send(kAudioPt, 103, kAudioSsrc, pl, sizeof(pl), w1));
    ASSERT_TRUE(h.recv(w1));

    // A NACK was emitted (captured via the inbound RtcpSink).
    ASSERT_GE(h.nack_gen.nacks_emitted(), 1u);
    ASSERT_FALSE(h.rtcp_out.empty()) << "no RTCP captured for the NACK";

    // Parse the captured RTCP; find the Generic NACK and assert 101 + 102 missing.
    bool found_101 = false, found_102 = false;
    for (const auto& buf : h.rtcp_out) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline);
        rtcp::Compound c;
        if (rtcp::parse_compound(buf.data(), buf.size(), c) != rtcp::RtcpError::Ok)
            continue;
        for (std::size_t i = 0; i < c.count; ++i) {
            const rtcp::Packet& p = c.packets[i];
            if (p.type != rtcp::Type::RTPFB) continue;
            if (p.count != static_cast<std::uint8_t>(rtcp::RtpfbFmt::Nack)) continue;
            EXPECT_EQ(p.media_ssrc, kAudioSsrc);
            for (std::size_t n = 0; n < p.nack_count; ++n) {
                const rtcp::NackBlock& nb = p.nacks[n];
                if (nb.pid == 101) found_101 = true;
                if (nb.pid == 102) found_102 = true;
                for (std::uint16_t bit = 0; bit < 16; ++bit) {
                    if ((nb.blp & (1u << bit)) == 0) continue;
                    const std::uint16_t s =
                        static_cast<std::uint16_t>(nb.pid + 1 + bit);
                    if (s == 101) found_101 = true;
                    if (s == 102) found_102 = true;
                }
            }
        }
    }
    EXPECT_TRUE(found_101) << "NACK did not list missing seq 101";
    EXPECT_TRUE(found_102) << "NACK did not list missing seq 102";
}

// ===========================================================================
// GATE 3 — RTCP SR/RR reporter tick() produces a parseable report. The sender
// reporter counts outbound RTP per SSRC and, on tick(), builds an SR per
// outbound SSRC (here we drive build_now for determinism) that parses back.
// ===========================================================================
TEST(MediaTrack, ReportInterceptorTickProducesParseableReport) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(10);
    MediaHarness h;
    ASSERT_TRUE(h.init());

    const std::uint8_t pl[16] = {0};
    // Send a few packets on both SSRCs so the reporter has outbound stats.
    for (int i = 0; i < 8; ++i) {
        ASSERT_LT(std::chrono::steady_clock::now(), deadline);
        std::vector<std::uint8_t> w;
        const bool video = (i % 2) == 1;
        ASSERT_TRUE(h.send(video ? kVideoPt : kAudioPt,
                           static_cast<std::uint16_t>(200 + i),
                           video ? kVideoSsrc : kAudioSsrc, pl, sizeof(pl), w));
    }

    // build_now is the deterministic test seam (ignores the interval).
    std::uint8_t buf[1500];
    std::size_t out_len = 0;
    const std::size_t n = h.reporter.build_now(buf, sizeof(buf), &out_len, 5000);
    ASSERT_GE(n, 1u) << "reporter produced no RTCP packets";
    ASSERT_GT(out_len, 0u);

    // The compound must parse and contain an SR for each outbound SSRC.
    rtcp::Compound c;
    ASSERT_EQ(rtcp::parse_compound(buf, out_len, c), rtcp::RtcpError::Ok);
    bool sr_audio = false, sr_video = false;
    for (std::size_t i = 0; i < c.count; ++i) {
        const rtcp::Packet& p = c.packets[i];
        if (p.type != rtcp::Type::SR) continue;
        if (p.ssrc == kAudioSsrc) { sr_audio = true; EXPECT_GT(p.packet_count, 0u); }
        if (p.ssrc == kVideoSsrc) { sr_video = true; EXPECT_GT(p.packet_count, 0u); }
    }
    EXPECT_TRUE(sr_audio) << "no SR for the audio SSRC";
    EXPECT_TRUE(sr_video) << "no SR for the video SSRC";

    // The tick() path also fires once the interval elapses (now_ms past 0).
    wrtc::RtcpSink sink; sink.fn = &MediaHarness::rtcp_capture; sink.ctx = &h;
    const std::size_t emitted = h.reporter.tick(10000, sink);
    EXPECT_GE(emitted, 1u);
    EXPECT_GE(h.reporter.reports_built(), 1u);
}
