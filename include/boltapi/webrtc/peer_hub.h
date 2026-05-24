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
#include "boltapi/webrtc/bwe.h"
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

    // Negotiated media options fed from the signaling answer (app.cpp). All knobs
    // default to "off" so an unconfigured hub behaves exactly as before (the
    // existing media-echo path). Applied when a peer's media chain is built.
    struct MediaConfig {
        // RTX (RFC 4588): one media<->rtx mapping. When rtx_pt != 0 the live
        // outbound chain caches media for `media_ssrc`/`media_pt` and answers an
        // inbound Generic NACK with a true RTX packet on rtx_ssrc/rtx_pt (OSN
        // prefix). rtx_pt == 0 disables RTX (falls back to NACK-by-resend).
        std::uint32_t media_ssrc = 0;
        std::uint8_t  media_pt   = 0;
        std::uint32_t rtx_ssrc   = 0;
        std::uint8_t  rtx_pt     = 0;
        // a=extmap ids (1..14, 0 = not negotiated). transport-cc drives TWCC
        // arrival recording + feedback; abs-send-time is recorded for the pacer.
        std::uint8_t  transport_cc_ext_id = 0;
        std::uint8_t  abs_send_time_ext_id = 0;
        // Pacer target (bits/sec). 0 = no pacing (send immediately).
        std::uint32_t pacer_target_bps = 0;
    };

    // Apply the negotiated media options. Idempotent; takes effect for peers whose
    // media is built AFTER this call (call right after negotiating the answer).
    void configure_media(const MediaConfig& cfg) noexcept;

    // SFU relay mode (P2): when ON, each inbound RTP packet from one peer is
    // FORWARDED to every OTHER keyed peer (per-subscriber SRTP, no transcode), and
    // a subscriber's PLI/FIR is relayed upstream to the publisher of that SSRC so
    // keyframes flow. OFF (default) keeps the single-peer echo/track behavior.
    // Idempotent; safe to toggle before traffic flows.
    void set_relay(bool on) noexcept { relay_ = on; }
    bool relay() const noexcept { return relay_; }

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

    // A monotonic microsecond clock for the pacer / TWCC arrival timestamps. One
    // implementation, used on both the I/O thread and the tick timer.
    static std::int64_t now_us() noexcept;
    static std::uint64_t now_ms() noexcept;

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
        // WA live-wire: RTX (RFC 4588) — present only when negotiated (rtx_pt!=0).
        // Stored as raw storage + a placement-constructed pointer so the Media
        // ctor stays trivial and we never default-construct an invalid RtxInterceptor
        // (its ctor asserts rtx_ssrc != media_ssrc). No heap on the packet path.
        alignas(RtxInterceptor) unsigned char rtx_store[sizeof(RtxInterceptor)]{};
        RtxInterceptor*   rtx = nullptr;
        bwe::TwccFeedbackBuilder twcc;   // receiver-side arrival window
        bwe::Pacer        pacer{bwe::kStartBitrateBps};
        bool              pace_enabled = false;
        std::uint8_t      twcc_ext_id = 0;   // transport-cc a=extmap id (0=off)
        std::uint8_t      abs_send_ext_id = 0;
        std::uint32_t     self_ssrc = 0;     // our SSRC for TWCC feedback sender id
        TrackRegistry     tracks;
        MediaAccess       access{};         // ctx for the sink trampolines
        Peer*             owner = nullptr;  // back-pointer for the sinks
        WebRtcPeerHub*    hub   = nullptr;  // for the C-style sink callbacks

        ~Media() noexcept { if (rtx != nullptr) { rtx->~RtxInterceptor(); rtx = nullptr; } }
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
    // Record an inbound packet's transport-cc seq (if present) for TWCC feedback.
    void  record_twcc_arrival(Media& m, const rtp::Packet& pkt) noexcept;
    // Build + emit one TWCC feedback compound from the recorded window (if any).
    std::size_t emit_twcc_feedback(Media& m) noexcept;

    // SFU (P2) — forward one plaintext RTP packet from `src` to every OTHER keyed
    // peer (per-subscriber SRTP-protect + send via their outbound chain). Returns
    // the number of subscribers the packet was forwarded to. Bounded by kMaxPeers.
    std::size_t forward_rtp_to_others(Peer& src, const std::uint8_t* plain,
                                      std::size_t len) noexcept;
    // SFU (P2) — relay a subscriber's PLI/FIR upstream: for each PSFB PLI/FIR in
    // the compound, find the peer publishing that media SSRC and send it a PLI so
    // it emits a keyframe. NACK is served locally (per-leg RTX cache), not relayed.
    void relay_rtcp_feedback(Peer& from, const rtcp::Compound& c) noexcept;
    // SFU (P2) — the peer currently publishing `ssrc` (a track in its registry),
    // or nullptr. Used to route PLI/FIR upstream. Bounded scan over kMaxPeers.
    Peer* publisher_of_ssrc(std::uint32_t ssrc) noexcept;

    DtlsSessionManager* dtls_      = nullptr;  // borrowed
    net::UdpTransport*  transport_ = nullptr;  // borrowed
    ChannelReadyCallback on_channel_ready_;
    TrackReadyCallback   on_track_ready_;

    // Outbound track declarations (negotiated). Pre-registered per peer.
    MediaTrackSpec track_specs_[kMaxTrackSpecs]{};
    std::size_t    track_spec_count_ = 0;

    // Negotiated media options (RTX/TWCC/abs-send-time/pacer). Applied per peer
    // when its media chain is built. Defaults => off (legacy echo behavior).
    MediaConfig    media_cfg_{};

    // SFU relay mode (P2). false => single-peer echo/track (legacy). See set_relay.
    bool           relay_ = false;

    Peer        peers_[kMaxPeers];
    std::size_t count_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
