// boltapi/webrtc/sdp.h — SDP (RFC 4566 / RFC 8866) parse + generate for WebRTC
// data-channel signaling.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A bounded, allocation-light SDP codec covering exactly what a browser WebRTC
// data-channel offer/answer needs. ADAPTED from FasterAPI's line-by-line parser
// (src/cpp/webrtc/sdp_parser.{h,cpp}) but reshaped to satisfy Bolt's TigerStyle
// / -fno-exceptions discipline:
//
//   * parse() takes a std::string_view and fills a FIXED-CAPACITY structure.
//     All string fields are zero-copy string_views INTO the caller's source
//     buffer (which must outlive the parsed structure). No std::unordered_map,
//     no std::stoi (uses std::from_chars — noexcept), no throwing.
//   * generate() appends into a std::string (no std::ostringstream).
//   * Everything is noexcept; malformed input returns SdpError, never throws.
//
// This codec is compiled UNCONDITIONALLY into the boltapi library (it has no
// engine deps and zero runtime cost unless used), so the default test suite
// exercises it. Only protocol/transport WIRING lives behind BOLTAPI_WITH_WEBRTC.
//
// SDP shape for a data channel (representative Chrome offer):
//   v=0
//   o=- 4611731400430051336 2 IN IP4 127.0.0.1
//   s=-
//   t=0 0
//   a=group:BUNDLE 0
//   a=msid-semantic: WMS
//   m=application 9 UDP/DTLS/SCTP webrtc-datachannel
//   c=IN IP4 0.0.0.0
//   a=ice-ufrag:abcd
//   a=ice-pwd:0123456789abcdef0123456789
//   a=fingerprint:sha-256 AB:CD:...
//   a=setup:actpass
//   a=mid:0
//   a=sctp-port:5000
//   a=max-message-size:262144
//   a=candidate:... (optional, trickle or in-SDP)
//
// TigerStyle: fixed capacities + asserts, zero-copy views, no exceptions.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api {
namespace webrtc {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle: explicit, asserted). A data-channel SDP is small; these
// caps are generous for a single m=application section plus typical attributes.
// ----------------------------------------------------------------------------
inline constexpr std::size_t kSdpMaxMediaSections   = 4;    // BUNDLE of a few m-lines
// A real Chrome audio+video offer carries ~10 codecs * (rtpmap+fmtp+rtcp-fb*4)
// plus extmap/ssrc per m-line, so the per-section attribute cap must be generous
// (still fixed/bounded — TigerStyle, no growth). 128 covers Chrome/Firefox.
inline constexpr std::size_t kSdpMaxAttrsPerSection = 128;  // a= lines per scope
inline constexpr std::size_t kSdpMaxFormatsPerMedia = 32;   // m= PT tokens (audio lists many)
inline constexpr std::size_t kSdpMaxCandidates      = 16;   // a=candidate lines / media

// Media (audio/video) negotiation bounds (WM4). kMaxMediaSections = audio +
// video + (optional) application; kMaxCodecsPerSection bounds the negotiated
// codec set we emit per m-line. Both fixed — no unbounded vectors.
inline constexpr std::size_t kMaxMediaSections    = kSdpMaxMediaSections;
inline constexpr std::size_t kMaxCodecsPerSection = 16;

// WA — simulcast (RFC 8851 a=simulcast + RFC 8852 a=rid). A simulcast track
// offers up to kMaxRids alternative encodings keyed by a short restriction id
// (the "rid"); each is carried as a separate RTP stream tagged with the RID
// header extension (urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id). Both bounded
// (TigerStyle: fixed capacity, no growth).
inline constexpr std::size_t kMaxRids    = 4;   // alt encodings per simulcast m-line
inline constexpr std::size_t kMaxRidLen  = 16;  // a RID is a short token (RFC 8852)

// ----------------------------------------------------------------------------
// Result codes — no exceptions.
// ----------------------------------------------------------------------------
enum class SdpError : std::uint8_t {
    Ok = 0,
    Empty,            // input was empty
    MalformedLine,    // a line lacked the "x=" type/equals shape
    BadMediaLine,     // m= line couldn't be tokenised
    BadNumber,        // a numeric field (port etc.) failed from_chars
    Overflow,         // a fixed-capacity bound was exceeded
};

// ----------------------------------------------------------------------------
// SdpAttribute — one a= line. Either a flag (value empty) or name:value.
// Both key and value are zero-copy views into the source buffer.
// ----------------------------------------------------------------------------
struct SdpAttribute {
    std::string_view key;    // e.g. "ice-ufrag", "setup", "candidate"
    std::string_view value;  // e.g. "abcd"; empty for flag attributes
};

// ----------------------------------------------------------------------------
// SdpMedia — one m= section plus its attributes.
// ----------------------------------------------------------------------------
struct SdpMedia {
    std::string_view media_type;   // "application", "audio", "video"
    std::uint16_t    port = 0;
    std::string_view protocol;     // "UDP/DTLS/SCTP", "UDP/TLS/RTP/SAVPF", ...
    std::string_view connection;   // c= line for this media (may be empty)

    std::string_view formats[kSdpMaxFormatsPerMedia]{};  // e.g. "webrtc-datachannel"
    std::size_t      format_count = 0;

    SdpAttribute attrs[kSdpMaxAttrsPerSection]{};
    std::size_t  attr_count = 0;

    // Convenience lookups for the WebRTC-relevant attributes. Return empty view
    // when absent. Linear scan over a tiny fixed array (no hashing).
    std::string_view attr(std::string_view key) const noexcept;
    bool has_attr(std::string_view key) const noexcept;

    // WebRTC field accessors (thin wrappers over attr()).
    std::string_view ice_ufrag()    const noexcept { return attr("ice-ufrag"); }
    std::string_view ice_pwd()      const noexcept { return attr("ice-pwd"); }
    std::string_view fingerprint()  const noexcept { return attr("fingerprint"); }
    std::string_view setup()        const noexcept { return attr("setup"); }
    std::string_view mid()          const noexcept { return attr("mid"); }
    // sctp-port as a parsed integer; false (out unchanged) if absent/malformed.
    bool sctp_port(std::uint16_t* out) const noexcept;
    bool max_message_size(std::uint32_t* out) const noexcept;

    // ---- Media (audio/video) accessors (WM4) ------------------------------
    // Media direction (RFC 4566 §6): one of sendrecv/recvonly/sendonly/inactive.
    // Defaults to "sendrecv" when no direction attribute is present.
    std::string_view direction() const noexcept;

    // a=rtpmap:<pt> <encoding>/<clock>[/<chans>] for a given payload type. The
    // returned view is the encoding part ("opus/48000/2", "VP8/90000"), empty if
    // no rtpmap line names `pt`. There can be one rtpmap per PT, so we scan all.
    std::string_view rtpmap_for(std::uint8_t pt) const noexcept;
    // a=fmtp:<pt> <params> for `pt` (the params view), empty if absent.
    std::string_view fmtp_for(std::uint8_t pt) const noexcept;

    // The payload types from the m= format list, parsed as integers, into `out`
    // (capacity `cap`). Returns the count written (bounded by cap & format_count).
    std::size_t payload_types(std::uint8_t* out, std::size_t cap) const noexcept;

    // True if a=rtcp-mux is present (RTP+RTCP on one port — always for WebRTC).
    bool rtcp_mux() const noexcept { return has_attr("rtcp-mux"); }
    // First a=ssrc:<id> ... value (the "<id> cname:.." string), empty if absent.
    std::string_view ssrc() const noexcept { return attr("ssrc"); }

    // ---- Simulcast (WA: RFC 8851 / RFC 8852) ------------------------------
    // True if this m-line carries a=simulcast (a simulcast offer/answer).
    bool has_simulcast() const noexcept { return has_attr("simulcast"); }
    // The a=simulcast:<...> value (e.g. "send q;h;f" / "recv q;h;f"), empty if
    // none. Caller parses the direction + alternative list (see parse_rids()).
    std::string_view simulcast() const noexcept { return attr("simulcast"); }
    // Collect the rids declared by a=rid:<id> ... lines into `out` (each a view
    // into the source buffer), up to `cap`. Returns the count written. The order
    // is the SDP order (matches the simulcast layer list order). No allocation.
    std::size_t rids(std::string_view* out, std::size_t cap) const noexcept;
    // The id of the a=extmap line whose URI is the RID (rtp-stream-id) extension,
    // or 0 if no such extmap is present. Used to demux inbound layers by RID.
    std::uint8_t rid_extmap_id() const noexcept;
};

// ----------------------------------------------------------------------------
// SdpSession — the whole parsed description.
// ----------------------------------------------------------------------------
struct SdpSession {
    std::string_view version;       // v=
    std::string_view origin;        // o=
    std::string_view session_name;  // s=
    std::string_view connection;    // session-level c=
    std::string_view timing;        // t=

    SdpAttribute session_attrs[kSdpMaxAttrsPerSection]{};
    std::size_t   session_attr_count = 0;

    SdpMedia    media[kSdpMaxMediaSections]{};
    std::size_t media_count = 0;

    std::string_view session_attr(std::string_view key) const noexcept;
    bool has_session_attr(std::string_view key) const noexcept;

    // First media section whose media_type == "application" (the data channel),
    // or nullptr if none. Const-correct overloads.
    const SdpMedia* application_media() const noexcept;
};

// ----------------------------------------------------------------------------
// parse — fill `out` from `sdp`. Views point into `sdp`; it must outlive `out`.
// Returns SdpError::Ok on success. Never throws, never allocates.
// ----------------------------------------------------------------------------
SdpError parse(std::string_view sdp, SdpSession& out) noexcept;

// ----------------------------------------------------------------------------
// generate — serialise `session` by appending CRLF-terminated lines into `out`.
// `out` is NOT cleared (append semantics); clear it first if you want a fresh
// document. Returns SdpError::Ok. Allocation is whatever std::string growth
// does — acceptable here (generate is not a per-packet hot path).
// ----------------------------------------------------------------------------
SdpError generate(const SdpSession& session, std::string& out);

// ----------------------------------------------------------------------------
// AnswerParams — the inputs Bolt (the answerer) needs to build a data-channel
// SDP answer. The browser is the offerer; Bolt answers setup:passive (DTLS
// server). All views/strings are copied into the generated string at build
// time, so they need only outlive the build_answer call.
// ----------------------------------------------------------------------------
struct AnswerParams {
    std::string_view origin_session_id = "4611731400430051336";  // o= sess-id
    std::string_view mid               = "0";                    // must echo offer
    std::string_view ice_ufrag;        // our local ICE ufrag (required)
    std::string_view ice_pwd;          // our local ICE pwd (required)
    std::string_view fingerprint_sha256;  // hex "AB:CD:..." (no algo prefix)
    std::string_view setup             = "passive";  // we are DTLS server
    std::uint16_t    sctp_port         = 5000;
    std::uint32_t    max_message_size  = 262144;
    bool             ice_lite          = false;  // emit a=ice-lite at session level

    // Host (and later srflx) ICE candidate lines, WITHOUT the leading "a=" but
    // WITH the "candidate:" token — i.e. exactly IceCandidate::to_string()
    // output. Emitted as `a=candidate:...` lines under the m=application section.
    // Views must outlive the build_answer call. Empty => no a=candidate lines.
    const std::string_view* candidates = nullptr;
    std::size_t             candidate_count = 0;
};

// build_answer — emit a complete data-channel answer SDP into `out` (cleared
// first). Requires ufrag/pwd/fingerprint to be non-empty (asserted). Returns
// SdpError::Ok, or SdpError::MalformedLine if a required field is empty.
SdpError build_answer(const AnswerParams& p, std::string& out);

// ===========================================================================
// WM4 — media (audio + video) SDP negotiation.
// ===========================================================================

// Media kinds we negotiate (relay/echo, no transcode — WEBRTC_MEDIA_PLAN §M4).
enum class MediaKind : std::uint8_t { kAudio = 0, kVideo = 1 };

// One negotiated codec kept in the answer: the offer's payload type plus the
// rtpmap encoding string and (optional) fmtp params, all zero-copy views into
// the offer buffer (which must outlive the answer build).
struct NegotiatedCodec {
    std::uint8_t     pt = 0;        // payload type (echoed from the offer)
    std::string_view rtpmap;        // "opus/48000/2", "VP8/90000", ...
    std::string_view fmtp;          // fmtp params (may be empty)
};

// One negotiated media section (audio or video): the common codecs kept, the
// mid (echoed from the offer), and the direction we answer with.
struct NegotiatedMedia {
    MediaKind        kind = MediaKind::kAudio;
    std::string_view mid;                       // echoed from the offer m-line
    std::string_view direction = "recvonly";    // our answer direction
    NegotiatedCodec  codecs[kMaxCodecsPerSection]{};
    std::size_t      codec_count = 0;

    // WA — simulcast: the rids offered for this m-line (echoed from a=rid lines)
    // and the RID header-extension id we answer with. When rid_count > 0 the
    // answer emits a=rid:<id> recv lines + an a=simulcast:recv <list> line + an
    // a=extmap for the RID extension. rid_count == 0 means no simulcast.
    std::string_view rids[kMaxRids]{};
    std::size_t      rid_count = 0;
    std::uint8_t     rid_ext_id = 0;            // a=extmap id for the RID ext (0=absent)
};

// The result of intersecting an offer against Bolt's supported codec set: the
// per-m-line negotiated codecs (BUNDLE all onto one transport). Fixed capacity.
struct MediaNegotiation {
    NegotiatedMedia media[kMaxMediaSections]{};
    std::size_t     media_count = 0;
};

// WA — the RFC 8852 RID header-extension URI and the RFC 8888 / abs-send-time +
// transport-cc URIs. These are the extmap URIs we recognize/emit. Constants so
// both the SDP layer and the RTP-extension demux agree on one spelling.
inline constexpr std::string_view kRidExtUri =
    "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
inline constexpr std::string_view kTransportCcExtUri =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
inline constexpr std::string_view kAbsSendTimeExtUri =
    "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

// negotiate_media — intersect the parsed `offer`'s audio/video m-lines against
// Bolt's supported codecs (audio: Opus/PCMU/PCMA; video: VP8/VP9/H264), keeping
// only the common ones (offer's PTs, in offer order). Non-audio/video sections
// (e.g. m=application) are ignored here. Returns SdpError::Ok (or Overflow if a
// bound is exceeded). noexcept, no allocation, fully bounded.
SdpError negotiate_media(const SdpSession& offer, MediaNegotiation& out) noexcept;

// MediaAnswerParams — inputs to build a media (audio+video) SDP answer. Bolt is
// the answerer (DTLS server, setup:passive, ice-lite). All m-lines BUNDLE onto
// one ICE/DTLS transport with rtcp-mux. The negotiated codecs come from
// negotiate_media(); ufrag/pwd/fingerprint identify the transport.
struct MediaAnswerParams {
    std::string_view origin_session_id = "4611731400430051336";
    std::string_view ice_ufrag;            // required
    std::string_view ice_pwd;              // required
    std::string_view fingerprint_sha256;   // hex "AB:CD:.." (no algo prefix)
    std::string_view setup = "passive";    // we are the DTLS server
    bool             ice_lite = true;      // emit a=ice-lite (session level)
    const MediaNegotiation* negotiation = nullptr;  // required, non-empty
};

// build_media_answer — emit a complete audio+video answer SDP into `out`
// (cleared first), BUNDLE + rtcp-mux, one m-line per negotiated section with the
// agreed PTs only, a=rtpmap/a=fmtp echoed, setup:passive, ice-lite. Requires
// ufrag/pwd/fingerprint + a non-empty negotiation. Returns SdpError::Ok, or
// SdpError::MalformedLine if a required field is empty / no media negotiated.
SdpError build_media_answer(const MediaAnswerParams& p, std::string& out);

// ===========================================================================
// WM6 — combined media + data-channel answer (the aiortc `server` shape).
// ===========================================================================

// EchoAnswerParams — inputs to build a COMBINED answer for an offer that may
// carry audio + video media AND a data channel, all BUNDLEd on one ICE/DTLS
// transport. Bolt answers as the relay/echo server (setup:passive, ice-lite):
// negotiated media m-lines (direction from negotiate_media — sendrecv when the
// offer is sendrecv, so the peer's media is echoed back) plus, when the offer
// had an m=application section, the data-channel m-line. The m-line ORDER and
// COUNT mirror what negotiate_media produced followed by the data line; the peer
// matches by a=mid (BUNDLE), so this is correct for aiortc/browsers. All views
// are copied at build time and need only outlive the call.
struct EchoAnswerParams {
    std::string_view origin_session_id = "4611731400430051336";
    std::string_view ice_ufrag;            // required
    std::string_view ice_pwd;              // required
    std::string_view fingerprint_sha256;   // hex "AB:CD:.." (no algo prefix)
    std::string_view setup     = "passive";
    bool             ice_lite  = true;
    const MediaNegotiation* negotiation = nullptr;  // required, non-empty

    // Data channel: when the offer contained an m=application section, emit a
    // matching data m-line under the same BUNDLE. `data_mid` is the offer's
    // application mid (echoed); empty => no data m-line in the answer.
    std::string_view data_mid;
    std::uint16_t    sctp_port        = 5000;
    std::uint32_t    max_message_size = 262144;

    // ICE candidate lines (IceCandidate::to_string form, no leading "a="),
    // emitted on the FIRST m-line. Views must outlive the build call.
    const std::string_view* candidates = nullptr;
    std::size_t             candidate_count = 0;
};

// build_echo_answer — emit a complete COMBINED audio+video+data answer SDP into
// `out` (cleared first): BUNDLE + rtcp-mux media m-lines (agreed PTs only,
// a=rtpmap/a=fmtp echoed, direction from negotiate_media) + an m=application
// data m-line when `data_mid` is set, all with shared ice-ufrag/pwd/fingerprint/
// setup. ICE candidates go on the first m-line. Requires ufrag/pwd/fingerprint +
// a non-empty negotiation. Returns SdpError::Ok, or SdpError::MalformedLine on a
// missing required field. No throw; allocation is std::string growth (build is
// not a per-packet hot path).
SdpError build_echo_answer(const EchoAnswerParams& p, std::string& out);

// ===========================================================================
// WI — Trickle ICE (RFC 8838) candidate exchange over signaling.
// ===========================================================================

// A trickled candidate as carried in the signaling JSON envelope browsers use
// (RTCIceCandidateInit): the SDP "candidate:..." line + the m-line identity. An
// END-OF-CANDIDATES signal is an empty `candidate` (RFC 8838 §10).
struct TrickleCandidate {
    std::string_view candidate;        // "candidate:..." (empty => end-of-cands)
    std::string_view sdp_mid;          // a=mid this candidate belongs to
    std::uint16_t    sdp_mline_index = 0;
    bool             end_of_candidates = false;
};

// parse_trickle — parse a single trickle candidate from a JSON envelope
//   {"candidate":"candidate:...","sdpMid":"0","sdpMLineIndex":0}
// OR a bare "candidate:..." line OR the literal "end-of-candidates". Views point
// into `body`, which must outlive `out`. Returns SdpError::Ok, or
// SdpError::MalformedLine on a body that is neither JSON nor a candidate line.
// noexcept, no allocation, bounded.
SdpError parse_trickle(std::string_view body, TrickleCandidate& out) noexcept;

// generate_trickle — emit the JSON envelope for `c` (the form a browser's
// onicecandidate handler POSTs) into `out` (append). An empty/end candidate
// emits {"candidate":""}. Returns SdpError::Ok.
SdpError generate_trickle(const TrickleCandidate& c, std::string& out);

}  // namespace webrtc
}  // namespace bolt::api
