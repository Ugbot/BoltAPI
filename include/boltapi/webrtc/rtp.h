// boltapi/webrtc/rtp.h — RTP (RFC 3550 / RFC 3551 / RFC 8285) header codec.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A real RTP packet parse + serialize for WebRTC media. PORTED from FasterAPI
// (src/cpp/webrtc/rtp.{h,cpp}) whose fixed-header parse/serialize is correct;
// extended here to cover what the FasterAPI version was missing:
//
//   * Fixed 12-byte header: V / P / X / CC / M / PT, seq, timestamp, SSRC
//   * CSRC list (0..15 contributing sources), bounded
//   * Header extensions (RFC 8285): one-byte and two-byte profiles, plus the
//     generic "profile-specific" extension of RFC 3550 §5.3.1
//   * Padding (RFC 3550 §5.1): the trailing P-flag pad bytes are stripped from
//     the zero-copy payload view
//   * Zero-copy payload view (pointer + length into the source buffer)
//
// The FasterAPI SRTP code is intentionally NOT ported — it was a stub and SRTP
// is a separate module. This file is a pure codec: no crypto, no engine deps.
//
// TigerStyle: header-only, noexcept, error-return (no exceptions), bounded
// counts (CSRC <= 15, extensions <= kMaxExtensions), fixed caller buffers on
// the encode path, no heap allocation anywhere. >=2 asserts per function.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {
namespace rtp {

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------
inline constexpr std::size_t   kFixedHeaderSize = 12;
inline constexpr std::uint8_t  kVersion         = 2;
inline constexpr std::size_t   kMaxCsrc         = 15;   // CC field is 4 bits
inline constexpr std::size_t   kMaxExtensions   = 16;   // bounded (RFC 8285)
inline constexpr std::uint16_t kExtProfileOneByte = 0xBEDE;        // RFC 8285 §4.2
inline constexpr std::uint16_t kExtProfileTwoByteMask = 0x1000;    // RFC 8285 §4.3 (top 12 bits = 0x100)

// ----------------------------------------------------------------------------
// Error codes
// ----------------------------------------------------------------------------
enum class RtpError : std::uint8_t {
    Ok = 0,
    TooShort,        // buffer smaller than the header / a declared section
    BadVersion,      // version field != 2
    TooManyCsrc,     // CC implies more than kMaxCsrc (cannot happen, 4-bit) — defensive
    TooManyExt,      // header-extension element count exceeded kMaxExtensions
    BadExtension,    // malformed RFC 8285 extension element
    BadPadding,      // padding byte count is zero or larger than the payload
    BufferTooSmall,  // encode target buffer too small
};

// ----------------------------------------------------------------------------
// Extension — one RFC 8285 header-extension element (zero-copy value view).
// For one-byte form: id in [1..14], len in [1..16] (encoded as len-1).
// For two-byte form: id in [0..255], len in [0..255].
// ----------------------------------------------------------------------------
struct Extension {
    std::uint8_t        id     = 0;
    const std::uint8_t* value  = nullptr;  // points into the source buffer
    std::uint16_t       length = 0;        // value length (bytes)
};

// ----------------------------------------------------------------------------
// Header — a parsed RTP header. CSRC and extension element views are zero-copy
// into the source buffer (which must outlive the Header on the parse path).
// ----------------------------------------------------------------------------
struct Header {
    std::uint8_t  version        = kVersion;
    bool          padding        = false;
    bool          extension      = false;
    std::uint8_t  csrc_count     = 0;       // 0..15
    bool          marker         = false;
    std::uint8_t  payload_type   = 0;       // 0..127
    std::uint16_t sequence       = 0;
    std::uint32_t timestamp      = 0;
    std::uint32_t ssrc           = 0;

    std::uint32_t csrc[kMaxCsrc]{};

    // RFC 8285 header-extension block. extension_profile is the 16-bit profile
    // field (0xBEDE one-byte, 0x100x two-byte, or any other profile-specific
    // value). When the profile is a known RFC 8285 one, `extensions`/`ext_count`
    // are populated; otherwise the raw extension bytes are exposed via
    // ext_raw/ext_raw_len for the caller to interpret.
    std::uint16_t       extension_profile = 0;
    Extension           extensions[kMaxExtensions]{};
    std::size_t         ext_count = 0;
    const std::uint8_t* ext_raw = nullptr;      // raw extension payload (after the 4-byte ext header)
    std::uint16_t       ext_raw_len = 0;        // length in bytes (multiple of 4)

    // Total size of the header on the wire (fixed + CSRC + extension block).
    std::size_t header_len = 0;

    const Extension* find_extension(std::uint8_t id) const noexcept {
        assert(id != 0);
        assert(ext_count <= kMaxExtensions);
        for (std::size_t i = 0; i < ext_count; ++i) {
            if (extensions[i].id == id) return &extensions[i];
        }
        return nullptr;
    }
};

// ----------------------------------------------------------------------------
// Packet — a parsed RTP packet: header + a zero-copy payload view (with any
// RFC 3550 padding already removed).
// ----------------------------------------------------------------------------
struct Packet {
    Header              header{};
    const std::uint8_t* payload     = nullptr;  // points into the source buffer
    std::size_t         payload_len = 0;
    std::uint8_t        padding_len = 0;        // trailing pad bytes (stripped from payload)
};

// ============================================================================
// Internal big-endian helpers (portable; no winsock / no UB on alignment).
// ============================================================================
namespace detail {

inline std::uint16_t rd16(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
inline std::uint32_t rd32(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8)  |
            static_cast<std::uint32_t>(p[3]);
}
inline void wr16(std::uint8_t* p, std::uint16_t v) noexcept {
    assert(p != nullptr);
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void wr32(std::uint8_t* p, std::uint32_t v) noexcept {
    assert(p != nullptr);
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v & 0xFF);
}

// Parse an RFC 8285 extension block (already located). `ext` points at the
// first byte after the 4-byte extension header (profile+length); `bytes` is the
// declared extension length in bytes (a multiple of 4). Fills hdr.extensions.
inline RtpError parse_rfc8285(Header& hdr, const std::uint8_t* ext,
                              std::uint16_t bytes) noexcept {
    assert(ext != nullptr);
    assert((bytes % 4) == 0);
    const bool one_byte = (hdr.extension_profile == kExtProfileOneByte);
    const bool two_byte = ((hdr.extension_profile & 0xFFF0) == kExtProfileTwoByteMask);
    if (!one_byte && !two_byte) {
        // Profile-specific extension: expose raw bytes, no element parse.
        return RtpError::Ok;
    }
    std::size_t off = 0;
    while (off < bytes) {
        const std::uint8_t b0 = ext[off];
        if (one_byte) {
            if (b0 == 0x00) { ++off; continue; }   // padding
            const std::uint8_t id  = static_cast<std::uint8_t>(b0 >> 4);
            const std::uint8_t len = static_cast<std::uint8_t>((b0 & 0x0F) + 1);
            if (id == 15) break;                    // reserved terminator
            ++off;
            if (off + len > bytes) return RtpError::BadExtension;
            if (hdr.ext_count >= kMaxExtensions) return RtpError::TooManyExt;
            hdr.extensions[hdr.ext_count++] = Extension{id, ext + off, len};
            off += len;
        } else {  // two-byte
            if (b0 == 0x00) { ++off; continue; }    // padding
            if (off + 2 > bytes) return RtpError::BadExtension;
            const std::uint8_t id  = b0;
            const std::uint8_t len = ext[off + 1];
            off += 2;
            if (off + len > bytes) return RtpError::BadExtension;
            if (hdr.ext_count >= kMaxExtensions) return RtpError::TooManyExt;
            hdr.extensions[hdr.ext_count++] = Extension{id, ext + off, len};
            off += len;
        }
    }
    return RtpError::Ok;
}

}  // namespace detail

// ----------------------------------------------------------------------------
// parse_header — decode an RTP header (fixed + CSRC + extension block) from
// data[0..len). Zero-copy, noexcept, no allocation. On success out.header_len
// is the on-wire header size.
// ----------------------------------------------------------------------------
inline RtpError parse_header(const std::uint8_t* data, std::size_t len,
                             Header& out) noexcept {
    assert(data != nullptr || len == 0);
    assert(kFixedHeaderSize == 12);
    if (data == nullptr || len < kFixedHeaderSize) return RtpError::TooShort;

    out = Header{};
    out.version      = static_cast<std::uint8_t>((data[0] >> 6) & 0x03);
    out.padding      = ((data[0] >> 5) & 0x01) != 0;
    out.extension    = ((data[0] >> 4) & 0x01) != 0;
    out.csrc_count   = static_cast<std::uint8_t>(data[0] & 0x0F);
    out.marker       = ((data[1] >> 7) & 0x01) != 0;
    out.payload_type = static_cast<std::uint8_t>(data[1] & 0x7F);
    out.sequence     = detail::rd16(data + 2);
    out.timestamp    = detail::rd32(data + 4);
    out.ssrc         = detail::rd32(data + 8);

    if (out.version != kVersion) return RtpError::BadVersion;

    std::size_t off = kFixedHeaderSize;
    const std::size_t csrc_bytes = static_cast<std::size_t>(out.csrc_count) * 4;
    if (len < off + csrc_bytes) return RtpError::TooShort;
    for (std::uint8_t i = 0; i < out.csrc_count; ++i) {
        out.csrc[i] = detail::rd32(data + off);
        off += 4;
    }

    if (out.extension) {
        if (len < off + 4) return RtpError::TooShort;
        out.extension_profile = detail::rd16(data + off);
        const std::uint16_t words = detail::rd16(data + off + 2);
        const std::uint16_t ext_bytes = static_cast<std::uint16_t>(words * 4);
        off += 4;
        if (len < off + ext_bytes) return RtpError::TooShort;
        out.ext_raw     = data + off;
        out.ext_raw_len = ext_bytes;
        const RtpError e = detail::parse_rfc8285(out, data + off, ext_bytes);
        if (e != RtpError::Ok) return e;
        off += ext_bytes;
    }

    out.header_len = off;
    return RtpError::Ok;
}

// ----------------------------------------------------------------------------
// parse — decode a full RTP packet. Strips RFC 3550 padding from the payload
// view (the last padding byte gives the pad count). Zero-copy, noexcept.
// ----------------------------------------------------------------------------
inline RtpError parse(const std::uint8_t* data, std::size_t len,
                      Packet& out) noexcept {
    assert(data != nullptr || len == 0);
    assert(kVersion == 2);
    out = Packet{};
    const RtpError e = parse_header(data, len, out.header);
    if (e != RtpError::Ok) return e;

    std::size_t body_len = len - out.header.header_len;
    const std::uint8_t* body = data + out.header.header_len;

    if (out.header.padding) {
        if (body_len == 0) return RtpError::BadPadding;
        const std::uint8_t pad = body[body_len - 1];
        if (pad == 0 || pad > body_len) return RtpError::BadPadding;
        out.padding_len = pad;
        body_len -= pad;
    }
    out.payload     = body;
    out.payload_len = body_len;
    return RtpError::Ok;
}

// ----------------------------------------------------------------------------
// serialize_header — write the header (fixed + CSRC + extension block) into a
// caller buffer. Uses hdr.ext_raw/ext_raw_len for the extension payload when
// hdr.extension is set (the caller owns extension element layout, mirroring the
// zero-copy parse). Returns the byte count via out_written. noexcept, no heap.
// ----------------------------------------------------------------------------
inline RtpError serialize_header(const Header& hdr, std::uint8_t* buf,
                                 std::size_t cap, std::size_t& out_written) noexcept {
    assert(buf != nullptr || cap == 0);
    assert(hdr.csrc_count <= kMaxCsrc);
    if (hdr.csrc_count > kMaxCsrc) return RtpError::TooManyCsrc;

    const std::size_t csrc_bytes = static_cast<std::size_t>(hdr.csrc_count) * 4;
    std::size_t ext_total = 0;
    if (hdr.extension) {
        assert((hdr.ext_raw_len % 4) == 0);
        ext_total = 4 + hdr.ext_raw_len;
    }
    const std::size_t need = kFixedHeaderSize + csrc_bytes + ext_total;
    if (buf == nullptr || cap < need) return RtpError::BufferTooSmall;

    buf[0] = static_cast<std::uint8_t>(
        (kVersion << 6) | ((hdr.padding ? 1 : 0) << 5) |
        ((hdr.extension ? 1 : 0) << 4) | (hdr.csrc_count & 0x0F));
    buf[1] = static_cast<std::uint8_t>(((hdr.marker ? 1 : 0) << 7) |
                                       (hdr.payload_type & 0x7F));
    detail::wr16(buf + 2, hdr.sequence);
    detail::wr32(buf + 4, hdr.timestamp);
    detail::wr32(buf + 8, hdr.ssrc);

    std::size_t off = kFixedHeaderSize;
    for (std::uint8_t i = 0; i < hdr.csrc_count; ++i) {
        detail::wr32(buf + off, hdr.csrc[i]);
        off += 4;
    }
    if (hdr.extension) {
        detail::wr16(buf + off, hdr.extension_profile);
        detail::wr16(buf + off + 2, static_cast<std::uint16_t>(hdr.ext_raw_len / 4));
        off += 4;
        if (hdr.ext_raw_len > 0) {
            assert(hdr.ext_raw != nullptr);
            std::memcpy(buf + off, hdr.ext_raw, hdr.ext_raw_len);
            off += hdr.ext_raw_len;
        }
    }
    out_written = off;
    return RtpError::Ok;
}

// ----------------------------------------------------------------------------
// serialize — write a full packet (header + payload + RFC 3550 padding). If
// hdr.padding is set, `pad_len` trailing bytes are appended (zeroed) with the
// final byte set to pad_len. Returns byte count via out_written. noexcept.
// ----------------------------------------------------------------------------
inline RtpError serialize(const Header& hdr, const std::uint8_t* payload,
                          std::size_t payload_len, std::uint8_t pad_len,
                          std::uint8_t* buf, std::size_t cap,
                          std::size_t& out_written) noexcept {
    assert(buf != nullptr || cap == 0);
    assert(payload != nullptr || payload_len == 0);
    std::size_t hdr_written = 0;
    const RtpError e = serialize_header(hdr, buf, cap, hdr_written);
    if (e != RtpError::Ok) return e;

    const std::size_t pad = hdr.padding ? pad_len : 0u;
    if (hdr.padding && pad == 0) return RtpError::BadPadding;
    const std::size_t need = hdr_written + payload_len + pad;
    if (cap < need) return RtpError::BufferTooSmall;

    if (payload_len > 0) std::memcpy(buf + hdr_written, payload, payload_len);
    if (pad > 0) {
        std::memset(buf + hdr_written + payload_len, 0, pad);
        buf[hdr_written + payload_len + pad - 1] = static_cast<std::uint8_t>(pad);
    }
    out_written = need;
    return RtpError::Ok;
}

// ----------------------------------------------------------------------------
// build_one_byte_extensions — pack `count` RFC 8285 one-byte extension elements
// into `buf` (a 4-byte-aligned block, zero-padded) and set hdr.extension /
// extension_profile / ext_raw / ext_raw_len so a following serialize() emits
// them. `buf` is caller-owned and must outlive the serialize call. Returns the
// byte length written (multiple of 4), or 0 on overflow / bad input. No heap.
// ----------------------------------------------------------------------------
inline std::size_t build_one_byte_extensions(Header& hdr, const Extension* exts,
                                             std::size_t count, std::uint8_t* buf,
                                             std::size_t cap) noexcept {
    assert(exts != nullptr || count == 0);
    assert(buf != nullptr && cap > 0);
    std::size_t off = 0;
    for (std::size_t i = 0; i < count; ++i) {
        assert(exts[i].id >= 1 && exts[i].id <= 14 && "ext: one-byte id");
        assert(exts[i].length >= 1 && exts[i].length <= 16 && "ext: one-byte len");
        if (off + 1 + exts[i].length > cap) return 0;
        buf[off++] = static_cast<std::uint8_t>(
            (exts[i].id << 4) | ((exts[i].length - 1) & 0x0F));
        std::memcpy(buf + off, exts[i].value, exts[i].length);
        off += exts[i].length;
    }
    while (off % 4 != 0) {                 // zero-pad to a 4-byte boundary
        if (off >= cap) return 0;
        buf[off++] = 0;
    }
    hdr.extension = true;
    hdr.extension_profile = kExtProfileOneByte;
    hdr.ext_raw = buf;
    hdr.ext_raw_len = static_cast<std::uint16_t>(off);
    return off;
}

// ============================================================================
// WA — header-extension value accessors for media demux / BWE.
// ============================================================================

// rid_value — copy the RFC 8852 RID (rtp-stream-id) extension value carried with
// header-extension id `ext_id` into `out` (NUL-terminated, capacity `cap`).
// Returns the length, or 0 if the extension is absent / too long. No allocation.
inline std::size_t rid_value(const Header& hdr, std::uint8_t ext_id,
                             char* out, std::size_t cap) noexcept {
    assert(out != nullptr && cap > 0);
    assert(ext_id >= 1 && "rid_value: ext id");
    const Extension* e = hdr.find_extension(ext_id);
    if (e == nullptr || e->length == 0) return 0;
    if (static_cast<std::size_t>(e->length) + 1 > cap) return 0;
    std::memcpy(out, e->value, e->length);
    out[e->length] = '\0';
    return e->length;
}

// abs_send_time — decode the 24-bit absolute send time (6.18 fixed-point seconds,
// RTP abs-send-time extension) carried with id `ext_id`. Returns true + the raw
// 24-bit value via `out`; false if the extension is absent / malformed.
inline bool abs_send_time(const Header& hdr, std::uint8_t ext_id,
                          std::uint32_t* out) noexcept {
    assert(out != nullptr && "abs_send_time: null out");
    assert(ext_id >= 1 && "abs_send_time: ext id");
    const Extension* e = hdr.find_extension(ext_id);
    if (e == nullptr || e->length != 3) return false;
    *out = (static_cast<std::uint32_t>(e->value[0]) << 16) |
           (static_cast<std::uint32_t>(e->value[1]) << 8) |
            static_cast<std::uint32_t>(e->value[2]);
    return true;
}

// transport_cc_seq — decode the 16-bit transport-wide sequence number (RFC 8888
// transport-cc extension) carried with id `ext_id`. Returns true + the value via
// `out`; false if absent / malformed (the ext is exactly 2 bytes).
inline bool transport_cc_seq(const Header& hdr, std::uint8_t ext_id,
                             std::uint16_t* out) noexcept {
    assert(out != nullptr && "transport_cc_seq: null out");
    assert(ext_id >= 1 && "transport_cc_seq: ext id");
    const Extension* e = hdr.find_extension(ext_id);
    if (e == nullptr || e->length != 2) return false;
    *out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(e->value[0]) << 8) |
                                      e->value[1]);
    return true;
}

}  // namespace rtp
}  // namespace webrtc
}  // namespace bolt::api
