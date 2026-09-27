// media — inbound media from a peer, down the path WebRtcPeerHub::feed_media
// runs: SRTP/SRTCP unprotect, RTP/RTCP parse, the transport-cc extension, the
// interceptor chain (NACK generator/responder, RTX, reports, SVC relay) and
// the track registry. Also the FEC and TWCC-feedback decoders.
//
// Byte 0: bit0 GCM profile, bit1 RTX instead of NACK-resend, bit2 SVC relay.
// Then up to 16 records: {kind, u16 len, bytes}. Kinds 2/4 are protected by a
// sender session first, so they reach decryption and parsing past the tag.
#include "fuzz_util.h"

#include "boltapi/webrtc/bwe.h"
#include "boltapi/webrtc/fec.h"
#include "boltapi/webrtc/interceptor.h"
#include "boltapi/webrtc/rtcp.h"
#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/track.h"

#include <memory>
#include <vector>

namespace wr = bolt::api::webrtc;
namespace sr = bolt::api::webrtc::srtp;

namespace {

constexpr std::size_t kScratch = 2048;
constexpr int kMaxRecords = 16;
constexpr std::uint32_t kMediaSsrc = 0x11111111u;
constexpr std::uint32_t kRtxSsrc = 0x22222222u;

bool sink_fn(void*, const std::uint8_t* data, std::size_t len) noexcept {
    FUZZ_CHECK(data != nullptr || len == 0);
    return true;
}

struct Media {
    sr::SrtpSession in, out;
    wr::InterceptorChain chain;
    wr::NackGenerator nack_gen{0x42};
    wr::NackResponder nack_resp;
    wr::ReportInterceptor reporter{0x42};
    std::unique_ptr<wr::RtxInterceptor> rtx;
    std::unique_ptr<wr::SvcRelay> svc;
    wr::bwe::TwccFeedbackBuilder twcc;
    wr::TrackRegistry tracks;
};

void deliver_rtp(Media& m, const std::uint8_t* plain, std::size_t n, const wr::RtcpSink& sink) {
    wr::rtp::Packet pkt;
    if (wr::rtp::parse(plain, n, pkt) != wr::rtp::RtpError::Ok) return;
    FUZZ_CHECK(pkt.payload_len <= n);
    std::uint16_t tseq = 0;
    if (wr::rtp::transport_cc_seq(pkt.header, 3, &tseq)) m.twcc.on_packet(tseq, 1000);
    std::uint32_t ast = 0;
    (void)wr::rtp::abs_send_time(pkt.header, 2, &ast);
    if (!m.chain.inbound_rtp(pkt, plain, n, sink)) return;
    wr::MediaTrack* t = m.tracks.by_ssrc(pkt.header.ssrc);
    if (t == nullptr) {
        t = m.tracks.add(wr::MediaKind::kVideo, pkt.header.ssrc, pkt.header.payload_type, "VP8");
    }
    if (t != nullptr) t->deliver(pkt, plain, n);
    m.chain.outbound_rtp(pkt, plain, n);
}

void deliver_rtcp(Media& m, const std::uint8_t* plain, std::size_t n, const wr::RtcpSink& sink) {
    wr::rtcp::Compound c;
    if (wr::rtcp::parse_compound(plain, n, c) != wr::rtcp::RtcpError::Ok) return;
    FUZZ_CHECK(c.count <= wr::rtcp::kMaxPackets);
    m.chain.inbound_rtcp(c, sink);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    boltapi_fuzz::Input in(data, size);
    const std::uint8_t flags = in.u8();
    auto m = std::make_unique<Media>();
    const sr::Profile prof = (flags & 1) ? sr::Profile::kAeadAes128Gcm
                                         : sr::Profile::kAesCm128HmacSha1_80;
    std::uint8_t key[sr::kMasterKeyLen];
    std::uint8_t salt[sr::kMasterSaltLen];
    for (std::size_t i = 0; i < sizeof(key); ++i) key[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = 0; i < sizeof(salt); ++i) salt[i] = static_cast<std::uint8_t>(0x80 + i);
    FUZZ_CHECK(m->in.init(prof, key, sizeof(key), salt, sizeof(salt)) == sr::Error::kOk);
    FUZZ_CHECK(m->out.init(prof, key, sizeof(key), salt, sizeof(salt)) == sr::Error::kOk);
    wr::RtcpSink sink;
    sink.fn = &sink_fn;
    wr::RtpSink rsink;
    rsink.fn = &sink_fn;
    m->chain.add(&m->nack_gen);
    if (flags & 2) {
        m->rtx = std::make_unique<wr::RtxInterceptor>(kMediaSsrc, 96, kRtxSsrc, 97);
        m->rtx->set_rtx_sink(rsink);
        m->chain.add(m->rtx.get());
    } else {
        m->nack_resp.set_resend_sink(rsink);
        m->chain.add(&m->nack_resp);
    }
    m->chain.add(&m->reporter);
    if (flags & 4) {
        m->svc = std::make_unique<wr::SvcRelay>(5);
        m->chain.add(m->svc.get());
    }

    static std::uint8_t wire[kScratch + 64];
    static std::uint8_t plain[kScratch + 64];
    for (int k = 0; k < kMaxRecords && !in.empty(); ++k) {
        const std::uint8_t kind = in.u8() % 8;
        std::size_t got = 0;
        const std::uint8_t* raw = in.take(in.u16() % (kScratch + 1), &got);
        std::vector<std::uint8_t> pkt(raw, raw + got);   // exact size for ASan
        pkt.reserve(1);
        std::size_t n = 0;
        switch (kind) {
            case 0: deliver_rtp(*m, pkt.data(), pkt.size(), sink); break;
            case 1: deliver_rtcp(*m, pkt.data(), pkt.size(), sink); break;
            case 2:
                if (m->out.protect_rtp(pkt.data(), pkt.size(), wire, sizeof(wire), &n) !=
                    sr::Error::kOk) break;
                pkt.assign(wire, wire + n);
                [[fallthrough]];
            case 3:
                if (m->in.unprotect_rtp(pkt.data(), pkt.size(), plain, kScratch, &n) ==
                    sr::Error::kOk) {
                    FUZZ_CHECK(n <= pkt.size());
                    std::vector<std::uint8_t> p(plain, plain + n);
                    p.reserve(1);
                    deliver_rtp(*m, p.data(), p.size(), sink);
                }
                break;
            case 4:
                if (m->out.protect_rtcp(pkt.data(), pkt.size(), wire, sizeof(wire), &n) !=
                    sr::Error::kOk) break;
                pkt.assign(wire, wire + n);
                [[fallthrough]];
            case 5:
                if (m->in.unprotect_rtcp(pkt.data(), pkt.size(), plain, kScratch, &n) ==
                    sr::Error::kOk) {
                    FUZZ_CHECK(n <= pkt.size());
                    std::vector<std::uint8_t> p(plain, plain + n);
                    p.reserve(1);
                    deliver_rtcp(*m, p.data(), p.size(), sink);
                }
                break;
            case 6: {
                wr::fec::Member members[2];
                members[0].sequence = 7;
                members[0].payload = pkt.data();
                members[0].payload_len = pkt.size() / 2;
                std::uint16_t seq = 0;
                std::uint8_t pt = 0;
                std::uint32_t ts = 0;
                (void)wr::fec::recover(pkt.data(), pkt.size(), members, 1, &seq, &pt, &ts,
                                       plain, kScratch, &n);
                break;
            }
            default: {
                wr::bwe::FeedbackRecord recs[64];
                const std::size_t r = wr::bwe::parse_twcc_feedback(pkt.data(), pkt.size(),
                                                                    recs, 64);
                FUZZ_CHECK(r <= 64);
                break;
            }
        }
        (void)m->chain.tick(1000u * static_cast<std::uint64_t>(k + 1), sink);
        std::uint8_t fb[512];
        if (m->twcc.pending() > 0) (void)m->twcc.build(fb, sizeof(fb));
    }
    return 0;
}
