// boltapi/quic/frames.h — QUIC frame type constants + parse/serialize for the
// no-crypto frames (RFC 9000 §19).
//
// PORTED/RESHAPED from FasterAPI src/cpp/http/quic/quic_frames.h, reshaped to
// Bolt Tiger Style: namespace bolt::api::quic, named bounds, >=2 asserts per
// function, noexcept, no allocation, no exceptions.
//
// SCOPE for this bounded wave:
//   * full type constants (RFC 9000 §19);
//   * parse/serialize for PADDING, PING, ACK (with ranges), CONNECTION_CLOSE;
//   * FRAMING (type + length/offset header) for CRYPTO and STREAM — the payload
//     stays a borrowed view into the datagram (no copy, no decode of contents).
// The remaining flow-control / connection-management frames keep their type
// constants here for later phases.
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
// Frame type constants (RFC 9000 §19). STREAM is a base value; its low 3 bits
// are the OFF/LEN/FIN flags (0x08..0x0F).
// ----------------------------------------------------------------------------
enum class FrameType : std::uint64_t {
    kPadding             = 0x00,
    kPing                = 0x01,
    kAck                 = 0x02,
    kAckEcn              = 0x03,
    kResetStream         = 0x04,
    kStopSending         = 0x05,
    kCrypto              = 0x06,
    kNewToken            = 0x07,
    kStream              = 0x08,  // base; 0x08..0x0F per flags
    kMaxData             = 0x10,
    kMaxStreamData       = 0x11,
    kMaxStreamsBidi      = 0x12,
    kMaxStreamsUni       = 0x13,
    kDataBlocked         = 0x14,
    kStreamDataBlocked   = 0x15,
    kStreamsBlockedBidi  = 0x16,
    kStreamsBlockedUni   = 0x17,
    kNewConnectionId     = 0x18,
    kRetireConnectionId  = 0x19,
    kPathChallenge       = 0x1A,
    kPathResponse        = 0x1B,
    kConnectionClose     = 0x1C,  // transport error
    kConnectionCloseApp  = 0x1D,  // application error
    kHandshakeDone       = 0x1E,
    kDatagram            = 0x30,  // RFC 9221 base
    kDatagramWithLen     = 0x31,  // RFC 9221 with length
};

// STREAM frame flag bits (low 3 bits of the type byte).
inline constexpr std::uint8_t kStreamFlagFin = 0x01;
inline constexpr std::uint8_t kStreamFlagLen = 0x02;
inline constexpr std::uint8_t kStreamFlagOff = 0x04;
inline constexpr std::uint8_t kStreamTypeBase = 0x08;

// Parse result codes (mirror packet.h).
inline constexpr int kFrameOk = 0;
inline constexpr int kFrameNeedMore = -1;
inline constexpr int kFrameError = 1;

// Bound on ACK ranges we will parse/serialize (TigerStyle: explicit + asserted).
inline constexpr std::size_t kMaxAckRanges = 256;

inline bool is_stream_frame_type(std::uint64_t t) noexcept {
    return t >= 0x08 && t <= 0x0F;
}

// ----------------------------------------------------------------------------
// STREAM frame — parse the framing only; `data` borrows into the datagram.
// `frame_type` is the already-consumed type byte (0x08..0x0F).
// ----------------------------------------------------------------------------
struct StreamFrame {
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    bool fin = false;
    const std::uint8_t* data = nullptr;

    int parse(std::uint8_t frame_type, const std::uint8_t* buf, std::size_t len,
              std::size_t& out_consumed) noexcept {
        assert(is_stream_frame_type(frame_type) && "not a STREAM type byte");
        assert((buf != nullptr || len == 0) && "STREAM parse: null with len>0");

        const std::uint8_t flags = static_cast<std::uint8_t>(frame_type & 0x07);
        fin = (flags & kStreamFlagFin) != 0;
        const bool has_off = (flags & kStreamFlagOff) != 0;
        const bool has_len = (flags & kStreamFlagLen) != 0;

        std::size_t pos = 0;
        int c = varint_decode(buf + pos, len - pos, stream_id);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);

        if (has_off) {
            c = varint_decode(buf + pos, len - pos, offset);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
        } else {
            offset = 0;
        }

        if (has_len) {
            c = varint_decode(buf + pos, len - pos, length);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
        } else {
            length = len - pos;  // extends to end of packet
        }

        if (len < pos + length) return kFrameNeedMore;
        data = (length > 0) ? buf + pos : nullptr;
        pos += static_cast<std::size_t>(length);

        out_consumed = pos;
        assert(out_consumed <= len && "STREAM parse overran");
        return kFrameOk;
    }

    // Serialize incl. type byte. Always emits OFF+LEN for an explicit, framable
    // result (callers who want minimal framing can post-process). Returns bytes.
    std::size_t serialize(std::uint8_t* out) const noexcept {
        assert(out != nullptr && "STREAM serialize: null output");
        assert((data != nullptr || length == 0) && "STREAM serialize: null data");

        std::size_t pos = 0;
        std::uint8_t type_byte = kStreamTypeBase | kStreamFlagOff | kStreamFlagLen;
        if (fin) type_byte |= kStreamFlagFin;
        out[pos++] = type_byte;
        pos += varint_encode(stream_id, out + pos);
        pos += varint_encode(offset, out + pos);
        pos += varint_encode(length, out + pos);
        if (length > 0) {
            std::memcpy(out + pos, data, length);
            pos += static_cast<std::size_t>(length);
        }
        return pos;
    }
};

// ----------------------------------------------------------------------------
// CRYPTO frame — framing only; payload borrows into the datagram.
// ----------------------------------------------------------------------------
struct CryptoFrame {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    const std::uint8_t* data = nullptr;

    int parse(const std::uint8_t* buf, std::size_t len,
              std::size_t& out_consumed) noexcept {
        assert((buf != nullptr || len == 0) && "CRYPTO parse: null with len>0");

        std::size_t pos = 0;
        int c = varint_decode(buf + pos, len - pos, offset);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);
        c = varint_decode(buf + pos, len - pos, length);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);

        if (len < pos + length) return kFrameNeedMore;
        data = (length > 0) ? buf + pos : nullptr;
        pos += static_cast<std::size_t>(length);

        out_consumed = pos;
        assert(out_consumed <= len && "CRYPTO parse overran");
        return kFrameOk;
    }

    std::size_t serialize(std::uint8_t* out) const noexcept {
        assert(out != nullptr && "CRYPTO serialize: null output");
        assert((data != nullptr || length == 0) && "CRYPTO serialize: null data");
        std::size_t pos = 0;
        out[pos++] = static_cast<std::uint8_t>(FrameType::kCrypto);
        pos += varint_encode(offset, out + pos);
        pos += varint_encode(length, out + pos);
        if (length > 0) {
            std::memcpy(out + pos, data, length);
            pos += static_cast<std::size_t>(length);
        }
        return pos;
    }
};

// ----------------------------------------------------------------------------
// ACK frame — bounded ranges. The type byte is consumed by the caller; pass
// `with_ecn` for the 0x03 (ACK_ECN) variant.
// ----------------------------------------------------------------------------
struct AckRange {
    std::uint64_t gap = 0;      // missing packets - 1 between ranges
    std::uint64_t length = 0;   // additional acked packets in this range
};

struct AckFrame {
    std::uint64_t largest_acked = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t first_ack_range = 0;
    AckRange ranges[kMaxAckRanges]{};
    std::size_t range_count = 0;
    // ECN counts (only valid when parsed/serialized as ACK_ECN).
    bool has_ecn = false;
    std::uint64_t ect0 = 0;
    std::uint64_t ect1 = 0;
    std::uint64_t ecn_ce = 0;

    int parse(const std::uint8_t* buf, std::size_t len, bool with_ecn,
              std::size_t& out_consumed) noexcept {
        assert((buf != nullptr || len == 0) && "ACK parse: null with len>0");
        has_ecn = with_ecn;

        std::size_t pos = 0;
        int c = varint_decode(buf + pos, len - pos, largest_acked);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);
        c = varint_decode(buf + pos, len - pos, ack_delay);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);

        std::uint64_t range_cnt = 0;
        c = varint_decode(buf + pos, len - pos, range_cnt);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);
        if (range_cnt > kMaxAckRanges) return kFrameError;
        range_count = static_cast<std::size_t>(range_cnt);

        c = varint_decode(buf + pos, len - pos, first_ack_range);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);

        for (std::size_t i = 0; i < range_count; ++i) {
            c = varint_decode(buf + pos, len - pos, ranges[i].gap);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
            c = varint_decode(buf + pos, len - pos, ranges[i].length);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
        }

        if (with_ecn) {
            c = varint_decode(buf + pos, len - pos, ect0);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
            c = varint_decode(buf + pos, len - pos, ect1);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
            c = varint_decode(buf + pos, len - pos, ecn_ce);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
        }

        out_consumed = pos;
        assert(out_consumed <= len && "ACK parse overran");
        assert(range_count <= kMaxAckRanges && "ACK range overflow");
        return kFrameOk;
    }

    std::size_t serialize(std::uint8_t* out) const noexcept {
        assert(out != nullptr && "ACK serialize: null output");
        assert(range_count <= kMaxAckRanges && "ACK range overflow");

        std::size_t pos = 0;
        out[pos++] = static_cast<std::uint8_t>(
            has_ecn ? FrameType::kAckEcn : FrameType::kAck);
        pos += varint_encode(largest_acked, out + pos);
        pos += varint_encode(ack_delay, out + pos);
        pos += varint_encode(range_count, out + pos);
        pos += varint_encode(first_ack_range, out + pos);
        for (std::size_t i = 0; i < range_count; ++i) {
            pos += varint_encode(ranges[i].gap, out + pos);
            pos += varint_encode(ranges[i].length, out + pos);
        }
        if (has_ecn) {
            pos += varint_encode(ect0, out + pos);
            pos += varint_encode(ect1, out + pos);
            pos += varint_encode(ecn_ce, out + pos);
        }
        return pos;
    }
};

// ----------------------------------------------------------------------------
// CONNECTION_CLOSE frame (0x1C transport / 0x1D application). Reason borrows.
// ----------------------------------------------------------------------------
struct ConnectionCloseFrame {
    std::uint64_t error_code = 0;
    std::uint64_t frame_type = 0;   // transport variant only
    std::uint64_t reason_length = 0;
    const char* reason_phrase = nullptr;
    bool is_application = false;

    int parse(const std::uint8_t* buf, std::size_t len, bool is_app,
              std::size_t& out_consumed) noexcept {
        assert((buf != nullptr || len == 0) && "CLOSE parse: null with len>0");
        is_application = is_app;

        std::size_t pos = 0;
        int c = varint_decode(buf + pos, len - pos, error_code);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);

        if (!is_app) {
            c = varint_decode(buf + pos, len - pos, frame_type);
            if (c < 0) return kFrameNeedMore;
            pos += static_cast<std::size_t>(c);
        } else {
            frame_type = 0;
        }

        c = varint_decode(buf + pos, len - pos, reason_length);
        if (c < 0) return kFrameNeedMore;
        pos += static_cast<std::size_t>(c);

        if (len < pos + reason_length) return kFrameNeedMore;
        reason_phrase = (reason_length > 0)
                            ? reinterpret_cast<const char*>(buf + pos)
                            : nullptr;
        pos += static_cast<std::size_t>(reason_length);

        out_consumed = pos;
        assert(out_consumed <= len && "CLOSE parse overran");
        return kFrameOk;
    }

    std::size_t serialize(std::uint8_t* out) const noexcept {
        assert(out != nullptr && "CLOSE serialize: null output");
        assert((reason_phrase != nullptr || reason_length == 0) &&
               "CLOSE serialize: null reason");
        std::size_t pos = 0;
        out[pos++] = static_cast<std::uint8_t>(
            is_application ? FrameType::kConnectionCloseApp
                           : FrameType::kConnectionClose);
        pos += varint_encode(error_code, out + pos);
        if (!is_application) {
            pos += varint_encode(frame_type, out + pos);
        }
        pos += varint_encode(reason_length, out + pos);
        if (reason_length > 0) {
            std::memcpy(out + pos, reason_phrase, reason_length);
            pos += static_cast<std::size_t>(reason_length);
        }
        return pos;
    }
};

// ----------------------------------------------------------------------------
// PADDING / PING — single-byte frames; helpers for completeness.
// ----------------------------------------------------------------------------

// Count a contiguous run of PADDING (0x00) bytes starting at `buf`. Returns the
// number of padding bytes consumed (>= 1; caller guarantees buf[0]==0x00).
inline std::size_t parse_padding_run(const std::uint8_t* buf,
                                    std::size_t len) noexcept {
    assert(buf != nullptr && "PADDING parse: null buffer");
    assert(len > 0 && buf[0] == 0x00 && "PADDING parse: not at a padding byte");
    std::size_t n = 0;
    while (n < len && buf[n] == 0x00) {
        ++n;
    }
    assert(n >= 1 && n <= len && "PADDING run out of range");
    return n;
}

}  // namespace bolt::api::quic
