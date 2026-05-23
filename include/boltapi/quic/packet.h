// boltapi/quic/packet.h — QUIC packet header PARSE (no crypto).
//
// PORTED/RESHAPED from FasterAPI src/cpp/http/quic/quic_packet.{h,cpp}, reshaped
// to Bolt Tiger Style: namespace bolt::api::quic, named bounds, >=2 asserts per
// function, noexcept, no allocation, no exceptions. Parsing borrows spans into
// the caller-owned datagram (no copies of payload/token bytes).
//
// SCOPE: header parsing ONLY. There is NO decryption / header-protection removal
// here — that is the crypto phase (gated on the TLS decision). Long-header
// packet numbers are protected, so we expose the header up to (and including)
// the Length field; the packet-number bytes live in the protected payload.
//
// Dependency-free; compiles UNCONDITIONALLY (covered by the default suite).

#pragma once

#include "boltapi/quic/varint.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (RFC 9000).
// ----------------------------------------------------------------------------
inline constexpr std::uint8_t kMaxConnectionIdLen = 20;   // RFC 9000 §17.2
inline constexpr std::uint32_t kQuicVersion1 = 0x00000001; // RFC 9000
inline constexpr std::uint32_t kQuicVersionNegotiation = 0x00000000;

// Long-header first-byte bit layout (RFC 9000 §17.2):
//   1 (header form) | 1 (fixed bit) | T T (type) | type-specific (4 bits)
inline constexpr std::uint8_t kHeaderFormLong = 0x80;
inline constexpr std::uint8_t kFixedBit = 0x40;

// Parse result codes (mirrors the FasterAPI convention).
inline constexpr int kParseOk = 0;
inline constexpr int kParseNeedMore = -1;
inline constexpr int kParseError = 1;

// ----------------------------------------------------------------------------
// Long-header packet types (RFC 9000 §17.2 Table 5), from the T T bits.
// ----------------------------------------------------------------------------
enum class LongPacketType : std::uint8_t {
    kInitial   = 0x00,
    kZeroRtt   = 0x01,
    kHandshake = 0x02,
    kRetry     = 0x03,
};

// Overall packet discrimination (form + version) reported by parse_form().
enum class PacketForm : std::uint8_t {
    kShort,               // 1-RTT (short header)
    kLongInitial,
    kLongZeroRtt,
    kLongHandshake,
    kLongRetry,
    kVersionNegotiation,  // long header, version == 0
};

// ----------------------------------------------------------------------------
// ConnectionId — value type, max 20 bytes. Borrow-on-parse from the datagram.
// ----------------------------------------------------------------------------
struct ConnectionId {
    std::uint8_t data[kMaxConnectionIdLen]{};
    std::uint8_t length = 0;

    ConnectionId() noexcept = default;

    ConnectionId(const std::uint8_t* bytes, std::uint8_t len) noexcept {
        assert(len <= kMaxConnectionIdLen && "CID length exceeds 20");
        assert((bytes != nullptr || len == 0) && "CID null with len>0");
        length = len;
        if (len > 0) {
            std::memcpy(data, bytes, len);
        }
    }

    bool operator==(const ConnectionId& o) const noexcept {
        assert(length <= kMaxConnectionIdLen);
        assert(o.length <= kMaxConnectionIdLen);
        return length == o.length && std::memcmp(data, o.data, length) == 0;
    }
    bool operator!=(const ConnectionId& o) const noexcept { return !(*this == o); }
};

// ----------------------------------------------------------------------------
// Parsed long header (public fields; packet number stays protected in payload).
// ----------------------------------------------------------------------------
struct LongHeader {
    LongPacketType type = LongPacketType::kInitial;
    std::uint32_t version = 0;
    ConnectionId dest_cid;
    ConnectionId source_cid;
    // Initial only: token borrows into the datagram.
    const std::uint8_t* token = nullptr;
    std::uint64_t token_length = 0;
    // Length field (covers packet number + protected payload). Not present for
    // Retry / Version Negotiation.
    std::uint64_t length = 0;
    bool has_length = false;
};

// ----------------------------------------------------------------------------
// Parsed short header (1-RTT). DCID length must be supplied by the caller (it
// is connection state, not on the wire). Packet number stays protected.
// ----------------------------------------------------------------------------
struct ShortHeader {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId dest_cid;
};

// ----------------------------------------------------------------------------
// Free helpers.
// ----------------------------------------------------------------------------
inline bool is_long_header(std::uint8_t first_byte) noexcept {
    return (first_byte & kHeaderFormLong) != 0;
}

inline bool has_fixed_bit(std::uint8_t first_byte) noexcept {
    // Note: Version Negotiation packets ignore the fixed bit (it is random).
    return (first_byte & kFixedBit) != 0;
}

inline bool is_version_negotiation(std::uint8_t first_byte,
                                   std::uint32_t version) noexcept {
    return is_long_header(first_byte) && version == kQuicVersionNegotiation;
}

// Read the 32-bit version that follows the first byte of a long header.
// Returns kParseOk / kParseNeedMore. Pure big-endian load.
inline int read_version(const std::uint8_t* data, std::size_t len,
                        std::uint32_t& out_version) noexcept {
    assert((data != nullptr || len == 0) && "read_version: null with len>0");
    if (len < 5) {
        return kParseNeedMore;  // 1 first byte + 4 version bytes
    }
    out_version = (static_cast<std::uint32_t>(data[1]) << 24) |
                  (static_cast<std::uint32_t>(data[2]) << 16) |
                  (static_cast<std::uint32_t>(data[3]) << 8) |
                  static_cast<std::uint32_t>(data[4]);
    assert(len >= 5 && "read_version consumed past buffer");
    return kParseOk;
}

// Cheap discrimination of a datagram's first packet without full parse.
// Requires at least the first byte; reads the version for long headers.
inline int parse_form(const std::uint8_t* data, std::size_t len,
                     PacketForm& out_form) noexcept {
    assert((data != nullptr || len == 0) && "parse_form: null with len>0");
    if (len < 1) {
        return kParseNeedMore;
    }
    const std::uint8_t first = data[0];
    if (!is_long_header(first)) {
        out_form = PacketForm::kShort;
        return kParseOk;
    }
    std::uint32_t version = 0;
    const int vr = read_version(data, len, version);
    if (vr != kParseOk) {
        return vr;
    }
    if (version == kQuicVersionNegotiation) {
        out_form = PacketForm::kVersionNegotiation;
        return kParseOk;
    }
    const std::uint8_t type_bits = static_cast<std::uint8_t>((first >> 4) & 0x03);
    switch (static_cast<LongPacketType>(type_bits)) {
        case LongPacketType::kInitial:   out_form = PacketForm::kLongInitial;   break;
        case LongPacketType::kZeroRtt:   out_form = PacketForm::kLongZeroRtt;   break;
        case LongPacketType::kHandshake: out_form = PacketForm::kLongHandshake; break;
        case LongPacketType::kRetry:     out_form = PacketForm::kLongRetry;     break;
    }
    return kParseOk;
}

// ----------------------------------------------------------------------------
// parse_long_header — parse a long header up to (and incl.) the Length field.
// `out_consumed` is the offset of the first protected byte (the packet number
// for Initial/0-RTT/Handshake; the Retry token / VN supported-versions list
// otherwise). Borrows token bytes; copies CIDs (<=20B each).
// ----------------------------------------------------------------------------
inline int parse_long_header(const std::uint8_t* data, std::size_t len,
                            LongHeader& out, std::size_t& out_consumed) noexcept {
    assert((data != nullptr || len == 0) && "parse_long_header: null with len>0");
    if (len < 1) return kParseNeedMore;

    const std::uint8_t first = data[0];
    if (!is_long_header(first)) return kParseError;

    std::size_t pos = 1;
    if (len < pos + 4) return kParseNeedMore;
    out.version = (static_cast<std::uint32_t>(data[pos]) << 24) |
                  (static_cast<std::uint32_t>(data[pos + 1]) << 16) |
                  (static_cast<std::uint32_t>(data[pos + 2]) << 8) |
                  static_cast<std::uint32_t>(data[pos + 3]);
    pos += 4;

    out.type = static_cast<LongPacketType>((first >> 4) & 0x03);

    // DCID (length-prefixed).
    if (len < pos + 1) return kParseNeedMore;
    const std::uint8_t dcid_len = data[pos++];
    if (dcid_len > kMaxConnectionIdLen) return kParseError;
    if (len < pos + dcid_len) return kParseNeedMore;
    out.dest_cid = ConnectionId(data + pos, dcid_len);
    pos += dcid_len;

    // SCID (length-prefixed).
    if (len < pos + 1) return kParseNeedMore;
    const std::uint8_t scid_len = data[pos++];
    if (scid_len > kMaxConnectionIdLen) return kParseError;
    if (len < pos + scid_len) return kParseNeedMore;
    out.source_cid = ConnectionId(data + pos, scid_len);
    pos += scid_len;

    const bool is_vn = (out.version == kQuicVersionNegotiation);
    if (is_vn || out.type == LongPacketType::kRetry) {
        // VN: supported-version list follows. Retry: token + integrity tag.
        // Neither has a Length / packet-number field; stop after the CIDs.
        out.has_length = false;
        out.token = nullptr;
        out.token_length = 0;
        out_consumed = pos;
        assert(out_consumed <= len && "parse overran buffer");
        return kParseOk;
    }

    // Initial packets carry a token.
    if (out.type == LongPacketType::kInitial) {
        std::uint64_t token_len = 0;
        const int c = varint_decode(data + pos, len - pos, token_len);
        if (c < 0) return kParseNeedMore;
        pos += static_cast<std::size_t>(c);
        if (len < pos + token_len) return kParseNeedMore;
        out.token_length = token_len;
        out.token = (token_len > 0) ? data + pos : nullptr;
        pos += static_cast<std::size_t>(token_len);
    } else {
        out.token = nullptr;
        out.token_length = 0;
    }

    // Length field (varint).
    std::uint64_t length = 0;
    const int c = varint_decode(data + pos, len - pos, length);
    if (c < 0) return kParseNeedMore;
    pos += static_cast<std::size_t>(c);
    out.length = length;
    out.has_length = true;

    out_consumed = pos;
    assert(out_consumed <= len && "parse overran buffer");
    assert(out.dest_cid.length <= kMaxConnectionIdLen);
    return kParseOk;
}

// ----------------------------------------------------------------------------
// parse_short_header — parse a 1-RTT header given the expected DCID length.
// `out_consumed` is the offset of the first protected byte (packet number).
// ----------------------------------------------------------------------------
inline int parse_short_header(const std::uint8_t* data, std::size_t len,
                             std::uint8_t dcid_len, ShortHeader& out,
                             std::size_t& out_consumed) noexcept {
    assert((data != nullptr || len == 0) && "parse_short_header: null with len>0");
    assert(dcid_len <= kMaxConnectionIdLen && "dcid_len exceeds 20");
    if (len < 1) return kParseNeedMore;

    const std::uint8_t first = data[0];
    if (is_long_header(first)) return kParseError;

    out.spin_bit = (first & 0x20) != 0;
    out.key_phase = (first & 0x04) != 0;

    std::size_t pos = 1;
    if (len < pos + dcid_len) return kParseNeedMore;
    out.dest_cid = ConnectionId(data + pos, dcid_len);
    pos += dcid_len;

    out_consumed = pos;
    assert(out_consumed <= len && "parse overran buffer");
    return kParseOk;
}

}  // namespace bolt::api::quic
