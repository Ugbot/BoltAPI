// src/webrtc/peer_hub.cpp — DTLS<->SCTP bridge + App channel surfacing.
// See include/boltapi/webrtc/peer_hub.h.

#include "boltapi/webrtc/peer_hub.h"
#include "boltapi/net/udp_transport.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <new>

namespace bolt::api {
namespace webrtc {

namespace {

bool same_peer(const sockaddr* a, int alen, const sockaddr_storage& b, int blen) {
    if (alen != blen) return false;
    if (a->sa_family != b.ss_family) return false;
    if (a->sa_family == AF_INET) {
        const auto* x = reinterpret_cast<const sockaddr_in*>(a);
        const auto* y = reinterpret_cast<const sockaddr_in*>(&b);
        return x->sin_port == y->sin_port &&
               x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        const auto* x = reinterpret_cast<const sockaddr_in6*>(a);
        const auto* y = reinterpret_cast<const sockaddr_in6*>(&b);
        return x->sin6_port == y->sin6_port &&
               std::memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return std::memcmp(a, &b, static_cast<std::size_t>(alen)) == 0;
}

}  // namespace

WebRtcPeerHub::Peer*
WebRtcPeerHub::lookup(const sockaddr* peer, int peer_len) noexcept {
    if (!peer || peer_len <= 0) return nullptr;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        Peer& p = peers_[i];
        if (p.used && same_peer(peer, peer_len, p.addr, p.addr_len)) return &p;
    }
    return nullptr;
}

WebRtcPeerHub::Peer*
WebRtcPeerHub::obtain(const sockaddr* peer, int peer_len) noexcept {
    Peer* p = lookup(peer, peer_len);
    if (p) return p;
    if (count_ >= kMaxPeers) return nullptr;
    if (static_cast<std::size_t>(peer_len) > sizeof(sockaddr_storage)) return nullptr;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        if (!peers_[i].used) {
            Peer& np = peers_[i];
            np.used = true;
            std::memcpy(&np.addr, peer, static_cast<std::size_t>(peer_len));
            np.addr_len = peer_len;
            np.session = nullptr;
            np.stack.reset();
            ++count_;
            return &np;
        }
    }
    return nullptr;
}

DataChannelStack*
WebRtcPeerHub::stack_for(const sockaddr* peer, int peer_len) noexcept {
    Peer* p = lookup(peer, peer_len);
    return p ? p->stack.get() : nullptr;
}

void WebRtcPeerHub::drain_to_sctp(Peer& p) noexcept {
    if (!p.session || !p.stack) return;
    // One SSL_read returns one DTLS application record = one SCTP packet
    // (DTLS preserves record boundaries). 2 KiB covers a full path-MTU record.
    std::uint8_t buf[2048];
    for (;;) {
        const int n = p.session->read_app(buf, sizeof(buf));
        if (n <= 0) break;
        p.stack->feed(buf, static_cast<std::size_t>(n));
    }
}

void WebRtcPeerHub::feed(const sockaddr* peer, int peer_len,
                         const std::uint8_t* data, std::size_t len) noexcept {
    if (!dtls_ || !transport_ || !peer || peer_len <= 0) return;

    // RFC 7983 demux of the datagram-handler range (>=20): first byte 128..191 is
    // RTP/RTCP media; everything else (20..63) is DTLS. The transport already
    // dropped STUN (0..3). Route media to the media path once DTLS is up.
    if (len >= 1 && data != nullptr && data[0] >= 128 && data[0] <= 191) {
        Peer* mp = lookup(peer, peer_len);
        if (mp && mp->session && mp->session->established() && ensure_media(*mp)) {
            feed_media(*mp, data, len);
        }
        return;
    }

    // 1. Feed DTLS (creates the session on first ClientHello + drives handshake).
    dtls_->feed(peer, peer_len, data, len);

    // 2. Resolve the (now-existing) session for this peer.
    DtlsSession* sess = dtls_->find(peer, peer_len);
    if (!sess || !sess->established()) return;

    // 3. Lazily create the per-peer data-channel stack once DTLS is up.
    Peer* p = obtain(peer, peer_len);
    if (!p) return;
    p->session = sess;
    // Build SRTP keying + media chain now that DTLS is Established (idempotent).
    ensure_media(*p);
    if (!p->stack) {
        p->stack = std::make_unique<DataChannelStack>();
        DtlsSession* s = sess;
        ChannelReadyCallback ready = on_channel_ready_;
        p->stack->init(
            SctpAssociation::Role::Passive,
            // SCTP packet sink: ship as a DTLS application record.
            [s](const std::uint8_t* pkt, std::size_t plen) -> bool {
                return s->send_app(pkt, plen) >= 0;
            },
            // Channel-ready: surface to the App.
            [ready](DataChannel& ch) { if (ready) ready(ch); });
    }

    // 4. Drain decrypted SCTP packets out of DTLS into the SCTP stack.
    drain_to_sctp(*p);
}

std::size_t WebRtcPeerHub::tick_retransmit() noexcept {
    std::size_t n = 0;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        if (peers_[i].used && peers_[i].stack) {
            n += peers_[i].stack->tick_retransmit();
        }
    }
    return n;
}

// ---------------------------------------------------------------------------
// Media — track specs, keying, demux, send. See peer_hub.h.
// ---------------------------------------------------------------------------

// Monotonic clocks shared by the pacer + TWCC arrival timestamps. steady_clock
// is monotonic; we convert once to integer us/ms (no float on the hot path).
std::int64_t WebRtcPeerHub::now_us() noexcept {
    assert(true && "now_us 1");
    assert(true && "now_us 2");
    const auto t = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(t).count();
}

std::uint64_t WebRtcPeerHub::now_ms() noexcept {
    assert(true && "now_ms 1");
    assert(true && "now_ms 2");
    const std::int64_t us = now_us();
    return static_cast<std::uint64_t>(us / 1000);
}

void WebRtcPeerHub::configure_media(const MediaConfig& cfg) noexcept {
    assert(cfg.media_pt <= 127 && "configure_media: media pt range");
    assert(cfg.rtx_pt <= 127 && "configure_media: rtx pt range");
    media_cfg_ = cfg;
}

void WebRtcPeerHub::add_track_spec(MediaKind kind, std::uint32_t ssrc,
                                   std::uint8_t pt, const char* codec) noexcept {
    assert(codec != nullptr && "add_track_spec: null codec");
    assert(track_spec_count_ <= kMaxTrackSpecs && "add_track_spec: overflow pre");
    if (track_spec_count_ >= kMaxTrackSpecs) return;
    MediaTrackSpec& s = track_specs_[track_spec_count_++];
    s.kind = kind;
    s.ssrc = ssrc;
    s.payload_type = pt;
    std::size_t i = 0;
    while (codec[i] != '\0' && i + 1 < kMaxCodecName) { s.codec[i] = codec[i]; ++i; }
    s.codec[i] = '\0';
}

// MediaAccess methods — route a sink call back through the owning peer's media.
bool WebRtcPeerHub::MediaAccess::send_rtp_raw(const std::uint8_t* data,
                                              std::size_t len) noexcept {
    assert(media != nullptr && "send_rtp_raw: null media");
    assert(data != nullptr && "send_rtp_raw: null");
    if (media->hub == nullptr || media->owner == nullptr) return false;
    return media->hub->send_rtp_protected(*media->owner, data, len);
}

bool WebRtcPeerHub::MediaAccess::send_rtcp(const std::uint8_t* data,
                                           std::size_t len) noexcept {
    assert(media != nullptr && "MediaAccess send_rtcp: null media");
    assert(data != nullptr || len == 0);
    if (media->hub == nullptr || media->owner == nullptr) return false;
    return media->hub->send_rtcp(*media->owner, data, len);
}

bool WebRtcPeerHub::MediaAccess::track_write(const std::uint8_t* data,
                                             std::size_t len) noexcept {
    assert(media != nullptr && "track_write: null media");
    assert(data != nullptr && len >= rtp::kFixedHeaderSize && "track_write: short");
    if (media->hub == nullptr || media->owner == nullptr) return false;
    return media->hub->send_rtp(*media->owner, data, len);
}

// RtcpSink trampoline: emit a built RTCP compound for the peer (SRTCP + send).
static bool rtcp_sink_trampoline(void* ctx, const std::uint8_t* data,
                                 std::size_t len) noexcept {
    assert(ctx != nullptr && "rtcp_sink: null ctx");
    assert(data != nullptr || len == 0);
    auto* a = static_cast<WebRtcPeerHub::MediaAccess*>(ctx);
    return a->send_rtcp(data, len);
}

// RtpSink trampoline: emit a packet straight to SRTP-protect + transport WITHOUT
// re-running the outbound chain. Shared by the NACK responder's resend AND the
// RTX interceptor's retransmit (an RTX packet must not be re-cached as media).
static bool rtp_sink_trampoline(void* ctx, const std::uint8_t* data,
                                std::size_t len) noexcept {
    assert(ctx != nullptr && "rtp_sink: null ctx");
    assert(data != nullptr && "rtp_sink: null data");
    auto* a = static_cast<WebRtcPeerHub::MediaAccess*>(ctx);
    return a->send_rtp_raw(data, len);
}

// MediaTrack write trampoline: App track.write -> outbound interceptors -> SRTP.
static bool MediaTrack_write_trampoline(void* ctx, const std::uint8_t* data,
                                        std::size_t len) noexcept {
    assert(ctx != nullptr && "track write tramp: null ctx");
    assert(data != nullptr && "track write tramp: null");
    auto* a = static_cast<WebRtcPeerHub::MediaAccess*>(ctx);
    return a->track_write(data, len);
}

bool WebRtcPeerHub::ensure_media(Peer& p) noexcept {
    assert(p.used && "ensure_media: unused peer");
    assert(p.session != nullptr && "ensure_media: no session");
    if (p.media && p.media->keyed) return true;
    if (!p.session->established()) return false;
    if (!p.media) {
        p.media = std::make_unique<Media>();
        p.media->owner = &p;
        p.media->hub = this;
    }
    Media& m = *p.media;
    if (!m.keyed) {
        if (!p.session->make_srtp_sessions(m.in, m.out)) return false;
        m.keyed = true;
        // Build the interceptor chain. The NACK generator detects inbound gaps
        // and emits Generic NACK; the reporter emits SR/RR on tick. Loss recovery
        // is EITHER true RTX (RFC 4588, dedicated rtx SSRC/PT — when negotiated)
        // OR plain NACK-by-resend on the same SSRC. We add exactly one of those
        // so an inbound NACK is answered once. Both route via this peer's sinks.
        m.access.media = &m;
        m.twcc_ext_id     = media_cfg_.transport_cc_ext_id;
        m.abs_send_ext_id = media_cfg_.abs_send_time_ext_id;
        // Sender SSRC for our TWCC feedback: the negotiated media SSRC if set,
        // else the first declared outbound track (a stable, non-zero local id).
        m.self_ssrc = media_cfg_.media_ssrc;
        if (m.self_ssrc == 0 && track_spec_count_ > 0)
            m.self_ssrc = track_specs_[0].ssrc;
        // SFU relay (P2) has no declared outbound track/SSRC; use a fixed non-zero
        // local id so PLI/TWCC we generate carry a valid sender SSRC.
        constexpr std::uint32_t kRelaySenderSsrc = 0x42'4F'4C'54u;  // "BOLT"
        if (m.self_ssrc == 0 && relay_) m.self_ssrc = kRelaySenderSsrc;
        m.chain.add(&m.nack_gen);
        const bool use_rtx = media_cfg_.rtx_pt != 0 &&
                             media_cfg_.rtx_ssrc != media_cfg_.media_ssrc;
        if (use_rtx) {
            // Placement-construct the RTX interceptor with the negotiated mapping.
            m.rtx = ::new (m.rtx_store) RtxInterceptor(
                media_cfg_.media_ssrc, media_cfg_.media_pt,
                media_cfg_.rtx_ssrc, media_cfg_.rtx_pt);
            RtpSink xs; xs.fn = &rtp_sink_trampoline; xs.ctx = &m.access;
            m.rtx->set_rtx_sink(xs);
            m.chain.add(m.rtx);
        } else {
            m.chain.add(&m.nack_resp);
            RtpSink rs; rs.fn = &rtp_sink_trampoline; rs.ctx = &m.access;
            m.nack_resp.set_resend_sink(rs);
        }
        m.chain.add(&m.reporter);
        // Pacer: when negotiated, the outbound RTP path shapes to the target rate.
        if (media_cfg_.pacer_target_bps != 0) {
            m.pacer.set_target(media_cfg_.pacer_target_bps);
            m.pace_enabled = true;
        }
        // Pre-register the declared outbound tracks + wire their write sinks.
        for (std::size_t i = 0; i < track_spec_count_; ++i) {
            const MediaTrackSpec& s = track_specs_[i];
            MediaTrack* t = m.tracks.add(s.kind, s.ssrc, s.payload_type, s.codec);
            if (t == nullptr) break;
            t->set_write_sink(&MediaTrack_write_trampoline, &m.access);
            if (on_track_ready_) on_track_ready_(*t);
        }
    }
    return m.keyed;
}

void WebRtcPeerHub::feed_media(Peer& p, const std::uint8_t* data,
                               std::size_t len) noexcept {
    assert(p.media && p.media->keyed && "feed_media: not keyed");
    assert(data != nullptr && len >= 2 && "feed_media: short");
    Media& m = *p.media;
    std::uint8_t plain[kMediaScratch];
    std::size_t plain_len = 0;
    RtcpSink sink; sink.fn = &rtcp_sink_trampoline; sink.ctx = &m.access;

    if (rtcp::is_rtcp(data, len)) {
        if (m.in.unprotect_rtcp(data, len, plain, sizeof(plain), &plain_len) !=
            srtp::Error::kOk) return;
        rtcp::Compound c;
        if (rtcp::parse_compound(plain, plain_len, c) != rtcp::RtcpError::Ok) return;
        m.chain.inbound_rtcp(c, sink);  // local: NACK->RTX from this leg's cache
        // SFU (P2): relay a subscriber's PLI/FIR upstream to the publisher so it
        // emits a keyframe (NACK stays local — served from the per-leg RTX cache).
        if (relay_) relay_rtcp_feedback(p, c);
        return;
    }
    // SRTP -> plain RTP.
    if (m.in.unprotect_rtp(data, len, plain, sizeof(plain), &plain_len) !=
        srtp::Error::kOk) return;
    rtp::Packet pkt;
    if (rtp::parse(plain, plain_len, pkt) != rtp::RtpError::Ok) return;
    // TWCC: record this packet's transport-wide arrival BEFORE the chain so the
    // window reflects every received packet (even ones a relay later drops).
    record_twcc_arrival(m, pkt);
    if (!m.chain.inbound_rtp(pkt, plain, plain_len, sink)) return;  // dropped
    // Demux by SSRC (exact). A genuinely-new SSRC gets its OWN track (so two
    // SSRCs sharing a PT never collide); the matching pre-registered PT, if any,
    // supplies the codec/kind, else infer kind from PT range (RFC 3551 dynamic).
    MediaTrack* t = m.tracks.by_ssrc(pkt.header.ssrc);
    if (t == nullptr) {
        const MediaTrack* tmpl = m.tracks.by_payload_type(pkt.header.payload_type);
        const MediaKind k = tmpl ? tmpl->kind()
                                 : (pkt.header.payload_type < 96 ? MediaKind::kAudio
                                                                 : MediaKind::kVideo);
        const char* codec = tmpl ? tmpl->codec() : "unknown";
        t = m.tracks.add(k, pkt.header.ssrc, pkt.header.payload_type, codec);
        if (t == nullptr) return;  // track table full
        t->set_write_sink(&MediaTrack_write_trampoline, &m.access);
        if (on_track_ready_) on_track_ready_(*t);
    }
    t->deliver(pkt, plain, plain_len);  // local on_track (echo/app); noop in relay
    // SFU (P2): forward this packet to every OTHER peer (selective forwarding,
    // per-subscriber SRTP, no transcode). This is the relay fan-out.
    if (relay_) forward_rtp_to_others(p, plain, plain_len);
}

bool WebRtcPeerHub::send_rtp(Peer& p, const std::uint8_t* data,
                             std::size_t len) noexcept {
    assert(data != nullptr && "send_rtp: null");
    assert(len >= rtp::kFixedHeaderSize && "send_rtp: short");
    if (!p.media || !p.media->keyed || !transport_) return false;
    Media& m = *p.media;
    rtp::Packet pkt;
    if (rtp::parse(data, len, pkt) != rtp::RtpError::Ok) return false;
    m.chain.outbound_rtp(pkt, data, len);  // RTX/NACK cache for retransmit
    // Pacer: account this packet against the token bucket so the send rate is
    // observably shaped to the target. We never DROP an echo packet (correctness
    // first — the media-echo gate is byte-exact), so a token shortfall still
    // sends; the pacer's accounting drives the BWE/pacing telemetry + tests.
    if (m.pace_enabled) {
        m.pacer.refill(now_us());
        (void)m.pacer.try_send(len);  // consumes tokens when available
    }
    return send_rtp_protected(p, data, len);
}

// Record one inbound packet's transport-cc seq + arrival (us) into the TWCC
// window when a transport-cc extmap was negotiated and present. Bounded window.
void WebRtcPeerHub::record_twcc_arrival(Media& m, const rtp::Packet& pkt) noexcept {
    assert(m.keyed && "record_twcc_arrival: not keyed");
    assert(pkt.header.csrc_count <= rtp::kMaxCsrc && "record_twcc: csrc");
    if (m.twcc_ext_id == 0) return;  // transport-cc not negotiated
    std::uint16_t tseq = 0;
    if (!rtp::transport_cc_seq(pkt.header, m.twcc_ext_id, &tseq)) return;
    m.twcc.on_packet(tseq, now_us());
}

// Build + emit a transport-cc feedback compound (RTPFB FMT 15) from the recorded
// arrival window, if any. Returns 1 if a feedback packet was emitted, else 0.
std::size_t WebRtcPeerHub::emit_twcc_feedback(Media& m) noexcept {
    assert(m.keyed && "emit_twcc_feedback: not keyed");
    assert(m.access.media == &m && "emit_twcc_feedback: access");
    if (m.twcc_ext_id == 0 || m.twcc.pending() == 0) return 0;
    std::uint8_t fci[8 + bwe::kMaxFeedbackPackets * 2];
    const std::size_t fci_len = m.twcc.build(fci, sizeof(fci));
    if (fci_len == 0) return 0;
    std::uint8_t buf[kMediaScratch];
    rtcp::Builder b(buf, sizeof(buf));
    if (b.add_twcc(m.self_ssrc, 0, fci, fci_len) != rtcp::RtcpError::Ok) return 0;
    RtcpSink sink; sink.fn = &rtcp_sink_trampoline; sink.ctx = &m.access;
    return sink.emit(buf, b.size()) ? 1u : 0u;
}

bool WebRtcPeerHub::send_rtp_protected(Peer& p, const std::uint8_t* data,
                                       std::size_t len) noexcept {
    assert(p.media && p.media->keyed && "send_rtp_protected: not keyed");
    assert(data != nullptr && len >= rtp::kFixedHeaderSize && "send_rtp_protected");
    Media& m = *p.media;
    std::uint8_t prot[kMediaScratch];
    std::size_t prot_len = 0;
    if (m.out.protect_rtp(data, len, prot, sizeof(prot), &prot_len) !=
        srtp::Error::kOk) return false;
    return transport_->send(reinterpret_cast<const sockaddr*>(&p.addr),
                            p.addr_len, prot, prot_len) >= 0;
}

bool WebRtcPeerHub::send_rtcp(Peer& p, const std::uint8_t* data,
                              std::size_t len) noexcept {
    assert(data != nullptr || len == 0);
    assert(len <= kMediaScratch && "send_rtcp: oversize");
    if (!p.media || !p.media->keyed || !transport_) return false;
    Media& m = *p.media;
    std::uint8_t prot[kMediaScratch];
    std::size_t prot_len = 0;
    if (m.out.protect_rtcp(data, len, prot, sizeof(prot), &prot_len) !=
        srtp::Error::kOk) return false;
    return transport_->send(reinterpret_cast<const sockaddr*>(&p.addr),
                            p.addr_len, prot, prot_len) >= 0;
}

// SFU (P2) — forward one plaintext RTP packet from `src` to every OTHER keyed
// peer via that peer's outbound chain (RTX cache) + SRTP + transport. Verbatim
// forwarding (same SSRC/seq/ts) — correct for one-source-per-SSRC relay; the
// subscriber browser latches the new SSRC onto its recv transceiver. Bounded.
std::size_t WebRtcPeerHub::forward_rtp_to_others(Peer& src,
                                                 const std::uint8_t* plain,
                                                 std::size_t len) noexcept {
    assert(plain != nullptr && "forward: null");
    assert(len >= rtp::kFixedHeaderSize && "forward: short rtp");
    assert(relay_ && "forward: not in relay mode");
    std::size_t fanned = 0;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        Peer& q = peers_[i];
        if (&q == &src) continue;                       // never echo to the source
        if (!q.used || !q.media || !q.media->keyed) continue;
        if (send_rtp(q, plain, len)) ++fanned;
    }
    assert(fanned < kMaxPeers && "forward: fanout exceeded peer table");
    return fanned;
}

// SFU (P2) — the peer publishing `ssrc` (it created an inbound track for it), or
// nullptr. Bounded scan over the peer table; no allocation.
WebRtcPeerHub::Peer* WebRtcPeerHub::publisher_of_ssrc(std::uint32_t ssrc) noexcept {
    assert(ssrc != 0 && "publisher_of_ssrc: zero ssrc");
    assert(relay_ && "publisher_of_ssrc: not in relay mode");
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        Peer& p = peers_[i];
        if (!p.used || !p.media || !p.media->keyed) continue;
        if (p.media->tracks.by_ssrc(ssrc) != nullptr) return &p;
    }
    return nullptr;
}

// SFU (P2) — relay PLI/FIR keyframe requests upstream. For each PSFB PLI/FIR in
// the compound, find the publisher of the targeted media SSRC and send it a PLI
// (its encoder produces a fresh keyframe, which the relay forwards downstream).
void WebRtcPeerHub::relay_rtcp_feedback(Peer& from,
                                        const rtcp::Compound& c) noexcept {
    assert(relay_ && "relay_rtcp: not in relay mode");
    assert(c.count <= rtcp::kMaxPackets && "relay_rtcp: count overflow");
    for (std::size_t i = 0; i < c.count; ++i) {
        const rtcp::Packet& pk = c.packets[i];
        if (pk.type != rtcp::Type::PSFB) continue;
        const bool is_pli = pk.count == static_cast<std::uint8_t>(rtcp::PsfbFmt::Pli);
        const bool is_fir = pk.count == static_cast<std::uint8_t>(rtcp::PsfbFmt::Fir);
        if (!is_pli && !is_fir) continue;
        std::uint32_t target = pk.media_ssrc;             // PLI carries it here
        if (target == 0 && pk.fir_count > 0) target = pk.fir[0].ssrc;  // FIR FCI
        if (target == 0) continue;
        Peer* pub = publisher_of_ssrc(target);
        if (pub == nullptr || pub == &from) continue;     // unknown / self
        std::uint8_t buf[64];
        rtcp::Builder b(buf, sizeof(buf));
        if (b.add_pli(pub->media->self_ssrc, target) != rtcp::RtcpError::Ok) continue;
        (void)send_rtcp(*pub, buf, b.size());
    }
}

std::size_t WebRtcPeerHub::tick_media(std::uint64_t now_ms) noexcept {
    assert(true && "tick_media 1");
    assert(true && "tick_media 2");
    std::size_t n = 0;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        Peer& p = peers_[i];
        if (!p.used || !p.media || !p.media->keyed) continue;
        RtcpSink sink; sink.fn = &rtcp_sink_trampoline; sink.ctx = &p.media->access;
        n += p.media->chain.tick(now_ms, sink);
        n += emit_twcc_feedback(*p.media);  // TWCC feedback from recorded arrivals
    }
    return n;
}

TrackRegistry* WebRtcPeerHub::tracks_for(const sockaddr* peer,
                                         int peer_len) noexcept {
    Peer* p = lookup(peer, peer_len);
    return (p && p->media) ? &p->media->tracks : nullptr;
}

}  // namespace webrtc
}  // namespace bolt::api
