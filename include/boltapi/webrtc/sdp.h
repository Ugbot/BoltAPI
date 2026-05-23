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
inline constexpr std::size_t kSdpMaxAttrsPerSection = 32;   // a= lines per scope
inline constexpr std::size_t kSdpMaxFormatsPerMedia = 16;   // m= format tokens
inline constexpr std::size_t kSdpMaxCandidates      = 16;   // a=candidate lines / media

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
};

// build_answer — emit a complete data-channel answer SDP into `out` (cleared
// first). Requires ufrag/pwd/fingerprint to be non-empty (asserted). Returns
// SdpError::Ok, or SdpError::MalformedLine if a required field is empty.
SdpError build_answer(const AnswerParams& p, std::string& out);

}  // namespace webrtc
}  // namespace bolt::api
