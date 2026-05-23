// boltapi/quic/varint.h — QUIC variable-length integer codec (RFC 9000 §16).
//
// PORTED from FasterAPI src/cpp/http/quic/quic_varint.h and reshaped to Bolt
// Tiger Style: namespace bolt::api::quic, named bound constants, >=2 asserts per
// function, noexcept, no allocation, no exceptions. The wire logic is byte-
// identical to the RFC (and to the FasterAPI source it came from).
//
// Encoding (2-bit length prefix in the top bits of the first byte):
//   00 => 1 byte  (values 0 .. 63)
//   01 => 2 bytes (values 0 .. 16383)
//   10 => 4 bytes (values 0 .. 1073741823)
//   11 => 8 bytes (values 0 .. 4611686018427387903)
//
// This translation unit is dependency-free and compiles UNCONDITIONALLY so the
// default test suite covers it (no OpenSSL, no BOLTAPI_WITH_HTTP3 gate).

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style: every limit is an explicit, asserted constant).
// ----------------------------------------------------------------------------

// Largest value representable in a QUIC varint (2^62 - 1, RFC 9000 §16).
inline constexpr std::uint64_t kVarIntMax = (1ULL << 62) - 1;

// Per-prefix inclusive maxima.
inline constexpr std::uint64_t kVarInt1Max = 63ULL;
inline constexpr std::uint64_t kVarInt2Max = 16383ULL;
inline constexpr std::uint64_t kVarInt4Max = 1073741823ULL;

// The codec never reads or writes more than 8 bytes.
inline constexpr std::size_t kVarIntMaxBytes = 8;

// Sentinel returned by decode() when the buffer is too short.
inline constexpr int kVarIntNeedMore = -1;

// ----------------------------------------------------------------------------
// encoded_size — bytes required to encode `value`, without encoding it.
// ----------------------------------------------------------------------------
inline std::size_t varint_encoded_size(std::uint64_t value) noexcept {
    assert(value <= kVarIntMax && "varint value exceeds 2^62-1");
    if (value <= kVarInt1Max) return 1;
    if (value <= kVarInt2Max) return 2;
    if (value <= kVarInt4Max) return 4;
    const std::size_t n = 8;
    assert(n == kVarIntMaxBytes && "8-byte varint is the largest form");
    return n;
}

// ----------------------------------------------------------------------------
// encode — write `value` into `out` (>= 8 bytes). Returns bytes written.
// ----------------------------------------------------------------------------
inline std::size_t varint_encode(std::uint64_t value, std::uint8_t* out) noexcept {
    assert(out != nullptr && "varint_encode: null output buffer");
    assert(value <= kVarIntMax && "varint value exceeds 2^62-1");

    if (value <= kVarInt1Max) {
        out[0] = static_cast<std::uint8_t>(value);
        return 1;
    }
    if (value <= kVarInt2Max) {
        out[0] = static_cast<std::uint8_t>(0x40 | (value >> 8));
        out[1] = static_cast<std::uint8_t>(value & 0xFF);
        return 2;
    }
    if (value <= kVarInt4Max) {
        out[0] = static_cast<std::uint8_t>(0x80 | (value >> 24));
        out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
        out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        out[3] = static_cast<std::uint8_t>(value & 0xFF);
        return 4;
    }
    out[0] = static_cast<std::uint8_t>(0xC0 | (value >> 56));
    for (std::size_t i = 1; i < kVarIntMaxBytes; ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (8 * (7 - i))) & 0xFF);
    }
    return kVarIntMaxBytes;
}

// ----------------------------------------------------------------------------
// decode — read a varint from `data` (len bytes). Returns bytes consumed
// (1/2/4/8) or kVarIntNeedMore (-1) when the buffer is too short. `out` is set
// only on success.
// ----------------------------------------------------------------------------
inline int varint_decode(const std::uint8_t* data, std::size_t len,
                         std::uint64_t& out) noexcept {
    assert((data != nullptr || len == 0) && "varint_decode: null with len>0");
    if (len == 0) {
        return kVarIntNeedMore;
    }

    const std::uint8_t prefix = static_cast<std::uint8_t>(data[0] >> 6);
    const std::size_t bytes = static_cast<std::size_t>(1) << prefix;
    assert(bytes <= kVarIntMaxBytes && "varint length prefix out of range");

    if (len < bytes) {
        return kVarIntNeedMore;
    }

    std::uint64_t value = static_cast<std::uint64_t>(data[0] & 0x3F);
    for (std::size_t i = 1; i < bytes; ++i) {
        value = (value << 8) | data[i];
    }
    out = value;
    assert(out <= kVarIntMax && "decoded varint exceeds 2^62-1");
    return static_cast<int>(bytes);
}

}  // namespace bolt::api::quic
