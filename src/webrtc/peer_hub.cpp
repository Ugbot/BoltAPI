// src/webrtc/peer_hub.cpp — DTLS<->SCTP bridge + App channel surfacing.
// See include/boltapi/webrtc/peer_hub.h.

#include "boltapi/webrtc/peer_hub.h"
#include "boltapi/net/udp_transport.h"

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

    // 1. Feed DTLS (creates the session on first ClientHello + drives handshake).
    dtls_->feed(peer, peer_len, data, len);

    // 2. Resolve the (now-existing) session for this peer.
    DtlsSession* sess = dtls_->find(peer, peer_len);
    if (!sess || !sess->established()) return;

    // 3. Lazily create the per-peer data-channel stack once DTLS is up.
    Peer* p = obtain(peer, peer_len);
    if (!p) return;
    p->session = sess;
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

}  // namespace webrtc
}  // namespace bolt::api
