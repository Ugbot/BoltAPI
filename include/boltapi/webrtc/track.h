// boltapi/webrtc/track.h — MediaTrack: the App-facing media (audio/video) handle.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A MediaTrack is the media analogue of a DataChannel: a per-SSRC handle for one
// negotiated media stream. The App receives inbound tracks via App::on_track and
// sends media by calling track.write(rtp_packet). It carries the immutable
// identity of the stream — kind (audio/video), SSRC, codec name, payload type —
// and a write sink the media layer (peer_hub) binds to "interceptors ->
// SRTP-protect -> UdpTransport".
//
// FLOW (mirrors data_channel.h):
//   inbound:  SRTP-unprotect -> RFC5761 demux -> TrackRegistry::track_for(ssrc/pt)
//             -> MediaTrack::deliver(rtp) -> App on_track handler.
//   outbound: App track.write(rtp) -> WriteSink(interceptors -> SRTP -> UDP).
//
// TigerStyle: bounded TrackRegistry (kMaxTracks), fixed-size codec name, no heap
// on the write/deliver path, noexcept, no exceptions, >=2 asserts/fn. The write
// sink is a plain function pointer + ctx (no std::function on the hot path).

#pragma once

#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/sdp.h"   // for webrtc::MediaKind (kAudio/kVideo) + kMaxRids

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kMaxTracks      = 16;  // per-peer media tracks
inline constexpr std::size_t kMaxCodecName   = 24;  // "VP8"/"opus"/"H264"/...
inline constexpr std::size_t kMaxEncodings   = kMaxRids;  // simulcast layers/track

// MediaKind (kAudio/kVideo) is defined in sdp.h (WM4); MediaTrack reuses it so a
// negotiated SdpMedia kind maps straight onto a track with no conversion.

inline const char* media_kind_name(MediaKind k) noexcept {
    assert(static_cast<int>(k) <= 1 && "media_kind_name: range");
    assert(true && "media_kind_name");
    return k == MediaKind::kVideo ? "video" : "audio";
}

// ----------------------------------------------------------------------------
// MediaTrack — one media stream (per SSRC + payload type).
// ----------------------------------------------------------------------------
class MediaTrack {
public:
    // Write sink: emit one full RTP packet [data, data+len). The media layer
    // binds this to interceptors -> SRTP-protect -> UdpTransport. Plain fn ptr.
    using WriteFn = bool (*)(void* ctx, const std::uint8_t* data,
                             std::size_t len) noexcept;

    // Inbound delivery callback to the App: (track, parsed RTP, raw, len).
    using DeliverFn = void (*)(void* ctx, MediaTrack& track,
                               const rtp::Packet& pkt, const std::uint8_t* data,
                               std::size_t len) noexcept;

    MediaTrack() noexcept = default;
    MediaTrack(const MediaTrack&) = delete;
    MediaTrack& operator=(const MediaTrack&) = delete;

    // Bind the immutable identity. `codec` is copied into a fixed buffer.
    void init(MediaKind kind, std::uint32_t ssrc, std::uint8_t payload_type,
              const char* codec) noexcept {
        assert(codec != nullptr && "track init: null codec");
        assert(payload_type <= 127 && "track init: pt range");
        kind_ = kind;
        ssrc_ = ssrc;
        payload_type_ = payload_type;
        std::size_t n = 0;
        while (codec[n] != '\0' && n + 1 < kMaxCodecName) {
            codec_[n] = codec[n];
            ++n;
        }
        codec_[n] = '\0';
        used_ = true;
    }

    // Bind the outbound write sink (peer_hub -> interceptors -> SRTP -> UDP).
    void set_write_sink(WriteFn fn, void* ctx) noexcept {
        assert(fn != nullptr && "set_write_sink: null fn");
        assert(used_ && "set_write_sink before init");
        write_fn_ = fn;
        write_ctx_ = ctx;
    }

    // Bind the inbound delivery callback (peer_hub -> App on_track handler).
    void set_deliver_sink(DeliverFn fn, void* ctx) noexcept {
        assert(fn != nullptr && "set_deliver_sink: null fn");
        assert(used_ && "set_deliver_sink before init");
        deliver_fn_ = fn;
        deliver_ctx_ = ctx;
    }

    // App-facing send: write one RTP packet out. The packet's SSRC/PT should
    // match the track (the App built it via rtp::serialize). Returns false if no
    // sink is bound or the sink rejected the packet. noexcept, no heap.
    bool write(const std::uint8_t* data, std::size_t len) noexcept {
        assert(data != nullptr && "track write: null");
        assert(len >= rtp::kFixedHeaderSize && "track write: short");
        if (write_fn_ == nullptr) return false;
        ++packets_sent_;
        bytes_sent_ += len;
        return write_fn_(write_ctx_, data, len);
    }

    // Internal: media layer calls this on an inbound RTP packet for this track.
    void deliver(const rtp::Packet& pkt, const std::uint8_t* data,
                 std::size_t len) noexcept {
        assert(data != nullptr && "track deliver: null");
        assert(len >= rtp::kFixedHeaderSize && "track deliver: short");
        ++packets_recv_;
        bytes_recv_ += len;
        if (deliver_fn_ != nullptr) deliver_fn_(deliver_ctx_, *this, pkt, data, len);
    }

    bool          in_use() const noexcept { return used_; }
    MediaKind     kind() const noexcept { return kind_; }
    std::uint32_t ssrc() const noexcept { return ssrc_; }
    std::uint8_t  payload_type() const noexcept { return payload_type_; }
    const char*   codec() const noexcept { return codec_; }

    std::uint64_t packets_sent() const noexcept { return packets_sent_; }
    std::uint64_t packets_recv() const noexcept { return packets_recv_; }
    std::uint64_t bytes_sent()   const noexcept { return bytes_sent_; }
    std::uint64_t bytes_recv()   const noexcept { return bytes_recv_; }

private:
    MediaKind     kind_ = MediaKind::kAudio;
    std::uint32_t ssrc_ = 0;
    std::uint8_t  payload_type_ = 0;
    char          codec_[kMaxCodecName]{};
    bool          used_ = false;

    WriteFn   write_fn_ = nullptr;
    void*     write_ctx_ = nullptr;
    DeliverFn deliver_fn_ = nullptr;
    void*     deliver_ctx_ = nullptr;

    std::uint64_t packets_sent_ = 0;
    std::uint64_t packets_recv_ = 0;
    std::uint64_t bytes_sent_   = 0;
    std::uint64_t bytes_recv_   = 0;
};

// ----------------------------------------------------------------------------
// TrackRegistry — a bounded fixed-capacity table of MediaTracks for one peer.
// Inbound RTP is demuxed by SSRC (primary) with a payload-type fallback for the
// first packet of an SSRC that wasn't pre-registered from the SDP. No heap.
// ----------------------------------------------------------------------------
class TrackRegistry {
public:
    TrackRegistry() noexcept = default;
    TrackRegistry(const TrackRegistry&) = delete;
    TrackRegistry& operator=(const TrackRegistry&) = delete;

    // Register a track (e.g. from a negotiated m-line). Returns the slot, or
    // nullptr if the table is full. If an entry with the same SSRC exists it is
    // returned (idempotent).
    MediaTrack* add(MediaKind kind, std::uint32_t ssrc, std::uint8_t pt,
                    const char* codec) noexcept {
        assert(codec != nullptr && "registry add: null codec");
        assert(count_ <= kMaxTracks && "registry overflow precondition");
        MediaTrack* existing = by_ssrc(ssrc);
        if (existing != nullptr) return existing;
        if (count_ >= kMaxTracks) return nullptr;
        MediaTrack* slot = &tracks_[count_++];
        slot->init(kind, ssrc, pt, codec);
        return slot;
    }

    // Find a track by SSRC (exact). nullptr if absent.
    MediaTrack* by_ssrc(std::uint32_t ssrc) noexcept {
        assert(count_ <= kMaxTracks && "by_ssrc: count");
        assert(true && "by_ssrc");
        for (std::size_t i = 0; i < count_; ++i) {
            if (tracks_[i].in_use() && tracks_[i].ssrc() == ssrc) return &tracks_[i];
        }
        return nullptr;
    }

    // Find a track by payload type (first match). Used as a fallback when an
    // inbound SSRC is new but its PT matches a negotiated track. nullptr if none.
    MediaTrack* by_payload_type(std::uint8_t pt) noexcept {
        assert(pt <= 127 && "by_payload_type: range");
        assert(count_ <= kMaxTracks);
        for (std::size_t i = 0; i < count_; ++i) {
            if (tracks_[i].in_use() && tracks_[i].payload_type() == pt)
                return &tracks_[i];
        }
        return nullptr;
    }

    std::size_t size() const noexcept { return count_; }
    MediaTrack* at(std::size_t i) noexcept {
        assert(i < count_ && "registry at: oob");
        assert(tracks_[i].in_use());
        return &tracks_[i];
    }

private:
    MediaTrack  tracks_[kMaxTracks]{};
    std::size_t count_ = 0;
};

// ----------------------------------------------------------------------------
// SimulcastTrack (WA) — one logical video track carrying multiple simulcast
// ENCODINGS (RFC 8851/8852), each identified by a RID string and demuxed from
// the RID header extension (RFC 8852, urn:...:sdes:rtp-stream-id). The peer
// sends each layer as its own RTP stream (own SSRC + own seq space); the first
// packet of a layer binds RID -> SSRC. Per-encoding packet/byte counters let the
// App pick a layer to relay (a real SFU forwards exactly one encoding). Bounded:
// kMaxEncodings, fixed RID/codec buffers, no heap on the demux path.
// ----------------------------------------------------------------------------
class SimulcastTrack {
public:
    struct Encoding {
        char          rid[kMaxRidLen + 1]{};   // restriction id (NUL-terminated)
        std::uint32_t ssrc = 0;                // learned from the first packet
        bool          ssrc_bound = false;
        std::uint64_t packets = 0;
        std::uint64_t bytes = 0;
        bool          used = false;
    };

    SimulcastTrack() noexcept = default;
    SimulcastTrack(const SimulcastTrack&) = delete;
    SimulcastTrack& operator=(const SimulcastTrack&) = delete;

    // Declare identity + the RID header-extension id (from the SDP). `rid_ext_id`
    // is the a=extmap id of the RID extension (1..14). Pre-registering rids from
    // the SDP is optional — they are also learned lazily on the first packet.
    void init(MediaKind kind, std::uint8_t rid_ext_id) noexcept {
        assert(rid_ext_id >= 1 && rid_ext_id <= 14 && "simulcast init: ext id");
        assert(static_cast<int>(kind) <= 1 && "simulcast init: kind");
        kind_ = kind;
        rid_ext_id_ = rid_ext_id;
        used_ = true;
    }

    // Pre-register a RID from the SDP (so layer order is deterministic). Returns
    // the encoding slot, or nullptr if full / not initialised.
    Encoding* add_rid(const char* rid) noexcept {
        assert(rid != nullptr && "add_rid: null");
        assert(used_ && "add_rid before init");
        return encoding_for_rid(rid);
    }

    // Demux one inbound RTP packet into its per-encoding stream by RID. Binds
    // RID -> SSRC on first sight; updates that encoding's counters. Returns the
    // Encoding it was routed to, or nullptr if the packet carried no RID ext and
    // no SSRC match (caller may then treat it as a plain track). No allocation.
    Encoding* demux(const rtp::Packet& pkt, std::size_t len) noexcept {
        assert(used_ && "simulcast demux before init");
        assert(len >= rtp::kFixedHeaderSize && "simulcast demux: short");
        char rid[kMaxRidLen + 1];
        const std::size_t n = rtp::rid_value(pkt.header, rid_ext_id_, rid,
                                             sizeof(rid));
        Encoding* e = nullptr;
        if (n > 0) e = encoding_for_rid(rid);
        else       e = encoding_for_ssrc(pkt.header.ssrc);
        if (e == nullptr) return nullptr;
        if (!e->ssrc_bound) { e->ssrc = pkt.header.ssrc; e->ssrc_bound = true; }
        ++e->packets;
        e->bytes += len;
        return e;
    }

    bool          in_use() const noexcept { return used_; }
    MediaKind     kind() const noexcept { return kind_; }
    std::uint8_t  rid_ext_id() const noexcept { return rid_ext_id_; }
    std::size_t   encoding_count() const noexcept { return count_; }
    const Encoding* encoding_at(std::size_t i) const noexcept {
        assert(i < count_ && "encoding_at: oob");
        assert(encodings_[i].used && "encoding_at: unused");
        return &encodings_[i];
    }
    Encoding* encoding_by_rid(const char* rid) noexcept {
        assert(rid != nullptr && "encoding_by_rid: null");
        assert(used_ && "encoding_by_rid: init");
        for (std::size_t i = 0; i < count_; ++i)
            if (encodings_[i].used && std::strcmp(encodings_[i].rid, rid) == 0)
                return &encodings_[i];
        return nullptr;
    }

private:
    Encoding* encoding_for_rid(const char* rid) noexcept {
        assert(rid != nullptr && "encoding_for_rid: null");
        assert(count_ <= kMaxEncodings && "encoding_for_rid: bound");
        for (std::size_t i = 0; i < count_; ++i)
            if (encodings_[i].used && std::strcmp(encodings_[i].rid, rid) == 0)
                return &encodings_[i];
        if (count_ >= kMaxEncodings) return nullptr;
        Encoding& e = encodings_[count_++];
        e.used = true;
        std::size_t k = 0;
        while (rid[k] != '\0' && k < kMaxRidLen) { e.rid[k] = rid[k]; ++k; }
        e.rid[k] = '\0';
        return &e;
    }

    Encoding* encoding_for_ssrc(std::uint32_t ssrc) noexcept {
        assert(count_ <= kMaxEncodings && "encoding_for_ssrc: bound");
        assert(used_ && "encoding_for_ssrc: init");
        for (std::size_t i = 0; i < count_; ++i)
            if (encodings_[i].used && encodings_[i].ssrc_bound &&
                encodings_[i].ssrc == ssrc)
                return &encodings_[i];
        return nullptr;
    }

    MediaKind    kind_ = MediaKind::kVideo;
    std::uint8_t rid_ext_id_ = 0;
    bool         used_ = false;
    Encoding     encodings_[kMaxEncodings]{};
    std::size_t  count_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
