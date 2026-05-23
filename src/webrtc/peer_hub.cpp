// src/webrtc/peer_hub.cpp — DTLS<->SCTP bridge + App channel surfacing.
// See include/boltapi/webrtc/peer_hub.h.

#include "boltapi/webrtc/peer_hub.h"
#include "boltapi/net/udp_transport.h"

#include <cassert>
#include <cstring>

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

// RtpSink trampoline: re-emit a cached RTP packet (NACK responder resend).
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
        // Build the interceptor chain (NACK gen + responder + reporter). The
        // NACK responder resends via the RTP sink; the chain emits RTCP via the
        // RTCP sink. Both trampolines route back through this peer's media.
        m.access.media = &m;
        m.chain.add(&m.nack_gen);
        m.chain.add(&m.nack_resp);
        m.chain.add(&m.reporter);
        RtpSink rs; rs.fn = &rtp_sink_trampoline; rs.ctx = &m.access;
        m.nack_resp.set_resend_sink(rs);
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
        m.chain.inbound_rtcp(c, sink);
        return;
    }
    // SRTP -> plain RTP.
    if (m.in.unprotect_rtp(data, len, plain, sizeof(plain), &plain_len) !=
        srtp::Error::kOk) return;
    rtp::Packet pkt;
    if (rtp::parse(plain, plain_len, pkt) != rtp::RtpError::Ok) return;
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
    t->deliver(pkt, plain, plain_len);
}

bool WebRtcPeerHub::send_rtp(Peer& p, const std::uint8_t* data,
                             std::size_t len) noexcept {
    assert(data != nullptr && "send_rtp: null");
    assert(len >= rtp::kFixedHeaderSize && "send_rtp: short");
    if (!p.media || !p.media->keyed || !transport_) return false;
    Media& m = *p.media;
    rtp::Packet pkt;
    if (rtp::parse(data, len, pkt) != rtp::RtpError::Ok) return false;
    m.chain.outbound_rtp(pkt, data, len);  // e.g. cache for NACK responder
    return send_rtp_protected(p, data, len);
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

std::size_t WebRtcPeerHub::tick_media(std::uint64_t now_ms) noexcept {
    assert(true && "tick_media 1");
    assert(true && "tick_media 2");
    std::size_t n = 0;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        Peer& p = peers_[i];
        if (!p.used || !p.media || !p.media->keyed) continue;
        RtcpSink sink; sink.fn = &rtcp_sink_trampoline; sink.ctx = &p.media->access;
        n += p.media->chain.tick(now_ms, sink);
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
