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
#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"
#include "boltapi/webrtc/interceptor.h"
#include "boltapi/webrtc/track.h"

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

    // Called when a media track is established for a peer (created on the first
    // inbound RTP for a new SSRC, or pre-registered). The owner attaches the
    // App on_track handler via MediaTrack::set_deliver_sink. Mirrors the
    // channel-ready callback for data channels.
    using TrackReadyCallback = std::function<void(MediaTrack& track)>;

    // A media track the App declared up-front (from negotiated SDP). The hub
    // pre-registers these so the App can write outbound media before any inbound
    // RTP arrives. Bounded list supplied by the owner.
    struct MediaTrackSpec {
        MediaKind     kind = MediaKind::kAudio;
        std::uint32_t ssrc = 0;
        std::uint8_t  payload_type = 0;
        char          codec[kMaxCodecName] = {0};
    };

    WebRtcPeerHub(DtlsSessionManager& dtls, net::UdpTransport& transport) noexcept
        : dtls_(&dtls), transport_(&transport) {}
    ~WebRtcPeerHub() = default;

    WebRtcPeerHub(const WebRtcPeerHub&) = delete;
    WebRtcPeerHub& operator=(const WebRtcPeerHub&) = delete;

    void set_channel_ready(ChannelReadyCallback cb) noexcept {
        on_channel_ready_ = std::move(cb);
    }

    void set_track_ready(TrackReadyCallback cb) noexcept {
        on_track_ready_ = std::move(cb);
    }

    // Declare the outbound media tracks (negotiated SSRC/PT/codec). Pre-registered
    // on each peer when SRTP keying is ready, so the App can write media. Bounded
    // by kMaxTracks; extra specs are dropped. Call before traffic flows.
    void add_track_spec(MediaKind kind, std::uint32_t ssrc, std::uint8_t pt,
                        const char* codec) noexcept;

    // The transport datagram handler: feed DTLS, then drive SCTP. noexcept,
    // safe on malformed input.
    void feed(const sockaddr* peer, int peer_len, const std::uint8_t* data,
              std::size_t len) noexcept;

    // Drive retransmits across all peer stacks (call from a timer if desired).
    std::size_t tick_retransmit() noexcept;

    // Drive the media interceptor tick() across all peers (periodic SR/RR etc.).
    // Returns the total RTCP packets emitted. Call from a timer if desired.
    std::size_t tick_media(std::uint64_t now_ms) noexcept;

    std::size_t peer_count() const noexcept { return count_; }

    // Test/introspection: the stack for a given peer (nullptr if none).
    DataChannelStack* stack_for(const sockaddr* peer, int peer_len) noexcept;

    // Test/introspection: the track registry for a given peer (nullptr if none).
    TrackRegistry* tracks_for(const sockaddr* peer, int peer_len) noexcept;

private:
    static constexpr std::size_t kMaxPeers       = 64;
    static constexpr std::size_t kMaxTrackSpecs  = kMaxTracks;
    static constexpr std::size_t kMediaScratch   = 2048;  // one MTU + SRTP slack

    struct Peer;   // fwd
    struct Media;  // fwd

public:
    // MediaAccess — the opaque `ctx` handed to the C-style sink trampolines
    // (RtpSink/RtcpSink/MediaTrack::WriteFn). Holds a back-pointer to the peer's
    // Media so a trampoline can route SRTP-protect + transport->send. Stable
    // address (lives inside Media), so function-pointer sinks stay valid. Public
    // only so the file-scope sink trampolines in peer_hub.cpp can read it; not
    // part of the intended API surface.
    struct MediaAccess {
        Media* media = nullptr;
        bool send_rtp_raw(const std::uint8_t* data, std::size_t len) noexcept;
        bool send_rtcp(const std::uint8_t* data, std::size_t len) noexcept;
        bool track_write(const std::uint8_t* data, std::size_t len) noexcept;
    };

private:
    // Per-peer media state: role-mapped SRTP sessions + interceptor chain (with
    // its built-ins) + the track registry. Heap-allocated once per peer (NOT on
    // the packet path) so the Peer table stays small.
    struct Media {
        srtp::SrtpSession in;
        srtp::SrtpSession out;
        bool              keyed = false;
        InterceptorChain  chain;
        NackGenerator     nack_gen{0};
        NackResponder     nack_resp;
        ReportInterceptor reporter{0};
        TrackRegistry     tracks;
        MediaAccess       access{};         // ctx for the sink trampolines
        Peer*             owner = nullptr;  // back-pointer for the sinks
        WebRtcPeerHub*    hub   = nullptr;  // for the C-style sink callbacks
    };

    struct Peer {
        bool used = false;
        sockaddr_storage addr{};
        int addr_len = 0;
        DtlsSession* session = nullptr;  // borrowed from the DtlsSessionManager
        std::unique_ptr<DataChannelStack> stack;
        std::unique_ptr<Media> media;     // lazily built when SRTP keying is ready
    };

    Peer* lookup(const sockaddr* peer, int peer_len) noexcept;
    Peer* obtain(const sockaddr* peer, int peer_len) noexcept;
    void  drain_to_sctp(Peer& p) noexcept;

    // Media wiring. Build the SRTP sessions + interceptor chain + track specs for
    // a peer once DTLS is Established (idempotent). Returns true if media is ready.
    bool  ensure_media(Peer& p) noexcept;
    // Handle one inbound media datagram (first byte 128..191): SRTCP/SRTP demux.
    void  feed_media(Peer& p, const std::uint8_t* data, std::size_t len) noexcept;
    // Send one RTP packet for a peer: interceptors(outbound) -> SRTP -> transport.
    bool  send_rtp(Peer& p, const std::uint8_t* data, std::size_t len) noexcept;
    // SRTP-protect + transport->send, WITHOUT re-running the outbound interceptor
    // chain (used by the NACK responder resend so a resend isn't re-cached).
    bool  send_rtp_protected(Peer& p, const std::uint8_t* data,
                             std::size_t len) noexcept;
    // Send one already-built RTCP compound for a peer: SRTCP-protect -> transport.
    bool  send_rtcp(Peer& p, const std::uint8_t* data, std::size_t len) noexcept;

    DtlsSessionManager* dtls_      = nullptr;  // borrowed
    net::UdpTransport*  transport_ = nullptr;  // borrowed
    ChannelReadyCallback on_channel_ready_;
    TrackReadyCallback   on_track_ready_;

    // Outbound track declarations (negotiated). Pre-registered per peer.
    MediaTrackSpec track_specs_[kMaxTrackSpecs]{};
    std::size_t    track_spec_count_ = 0;

    Peer        peers_[kMaxPeers];
    std::size_t count_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
