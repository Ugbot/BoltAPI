// boltapi/webrtc/peer_hub.h — bridges the DTLS layer to per-peer data-channel
// stacks and surfaces channels to App-registered handlers.
//
// ============================================================================
// ROLE
// ============================================================================
// This is the glue between DtlsSessionManager (the secure record layer) and
// DataChannelStack (SCTP + DCEP + channels). It is wired as the UdpTransport's
// datagram handler (first byte 20..63 -> DTLS). For each inbound DTLS datagram:
//
//   1. feed it to the peer's DtlsSession (handshake or app-data).
//   2. once the session is Established, lazily create a DataChannelStack for the
//      peer whose SCTP packet sink is DtlsSession::send_app (SCTP rides as DTLS
//      application records — RFC 8261). The stack is the SCTP PASSIVE answerer.
//   3. drain DtlsSession::read_app() (decrypted SCTP packets) into the stack's
//      feed(); the stack runs the SCTP handshake + DCEP and, on a new channel,
//      invokes the registered App handler (by label, with "" as a wildcard).
//
// App handlers get (label, data, len) on each message and may echo by calling
// back into the channel — the hub exposes the just-opened channel to the App via
// a ChannelOpenCallback so the App can attach on_message that does channel work.
//
// TigerStyle: bounded per-peer table, noexcept hot paths, explicit teardown.
// Compiled UNCONDITIONALLY (no engine deps beyond DTLS/SCTP which are also
// unconditional); only App *start* wiring is gated by BOLTAPI_WITH_WEBRTC.

#pragma once

#include "boltapi/net/sys_compat.h"
#include "boltapi/webrtc/dtls.h"
#include "boltapi/webrtc/data_channel.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace bolt::api {
namespace net { class UdpTransport; }
namespace webrtc {

// ----------------------------------------------------------------------------
// WebRtcPeerHub — owns the per-peer DataChannelStacks layered over DTLS.
// ----------------------------------------------------------------------------
class WebRtcPeerHub {
public:
    // Called when a data channel is established for a peer, so the owner can
    // attach message/open/close callbacks (matching the channel's label to a
    // registered handler). The DataChannelStack/peer index is opaque to callers.
    using ChannelReadyCallback = std::function<void(DataChannel& ch)>;

    WebRtcPeerHub(DtlsSessionManager& dtls, net::UdpTransport& transport) noexcept
        : dtls_(&dtls), transport_(&transport) {}
    ~WebRtcPeerHub() = default;

    WebRtcPeerHub(const WebRtcPeerHub&) = delete;
    WebRtcPeerHub& operator=(const WebRtcPeerHub&) = delete;

    void set_channel_ready(ChannelReadyCallback cb) noexcept {
        on_channel_ready_ = std::move(cb);
    }

    // The transport datagram handler: feed DTLS, then drive SCTP. noexcept,
    // safe on malformed input.
    void feed(const sockaddr* peer, int peer_len, const std::uint8_t* data,
              std::size_t len) noexcept;

    // Drive retransmits across all peer stacks (call from a timer if desired).
    std::size_t tick_retransmit() noexcept;

    std::size_t peer_count() const noexcept { return count_; }

    // Test/introspection: the stack for a given peer (nullptr if none).
    DataChannelStack* stack_for(const sockaddr* peer, int peer_len) noexcept;

private:
    static constexpr std::size_t kMaxPeers = 64;

    struct Peer {
        bool used = false;
        sockaddr_storage addr{};
        int addr_len = 0;
        DtlsSession* session = nullptr;  // borrowed from the DtlsSessionManager
        std::unique_ptr<DataChannelStack> stack;
    };

    Peer* lookup(const sockaddr* peer, int peer_len) noexcept;
    Peer* obtain(const sockaddr* peer, int peer_len) noexcept;
    void  drain_to_sctp(Peer& p) noexcept;

    DtlsSessionManager* dtls_      = nullptr;  // borrowed
    net::UdpTransport*  transport_ = nullptr;  // borrowed
    ChannelReadyCallback on_channel_ready_;

    Peer        peers_[kMaxPeers];
    std::size_t count_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
