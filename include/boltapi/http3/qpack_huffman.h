#pragma once

// QPACK Huffman coding — RFC 7541 Appendix B (the QPACK Huffman code in
// RFC 9204 Section 4.1.2 is *identical* to the HPACK one). Self-contained,
// header-only: this carries its own copy of the 256-symbol code table so the
// http3 module pulls in NO http2 / HPACK sources.
//
// Encoder: classic MSB-first bit packer using the {code,nbits} table. Padding
// is the EOS prefix (all-ones), per spec.
//
// Decoder: rather than ship the ~5000-line nghttp2 FSA table, we build a compact
// per-length canonical decode index ONCE (function-local static, thread-safe in
// C++11+). Codes are grouped by bit length (5..30); for each input we test the
// current bit-accumulator against each length's [first_code, first_code+count)
// span. This is bounded (<= 26 length buckets), allocation-free at steady state,
// and validates EOS padding exactly like the FSA.
//
// Reshaped to Bolt Tiger Style: noexcept, bounded, error returns (no
// exceptions), >= 2 asserts per function, functions < 70 lines.

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace bolt::api::http3 {

// One Huffman symbol: right-aligned code of `nbits` bits.
struct QpackHuffmanCode {
    uint32_t code;
    uint8_t nbits;
};

// RFC 7541 Appendix B — 256 symbols. Index = byte value.
inline const QpackHuffmanCode* qpack_huffman_table() noexcept {
    static const QpackHuffmanCode kTable[256] = {
        {0x1ff8, 13},     {0x7fffd8, 23},   {0xfffffe2, 28},  {0xfffffe3, 28},
        {0xfffffe4, 28},  {0xfffffe5, 28},  {0xfffffe6, 28},  {0xfffffe7, 28},
        {0xfffffe8, 28},  {0xffffea, 24},   {0x3ffffffc, 30}, {0xfffffe9, 28},
        {0xfffffea, 28},  {0x3ffffffd, 30}, {0xfffffeb, 28},  {0xfffffec, 28},
        {0xfffffed, 28},  {0xfffffee, 28},  {0xfffffef, 28},  {0xffffff0, 28},
        {0xffffff1, 28},  {0xffffff2, 28},  {0x3ffffffe, 30}, {0xffffff3, 28},
        {0xffffff4, 28},  {0xffffff5, 28},  {0xffffff6, 28},  {0xffffff7, 28},
        {0xffffff8, 28},  {0xffffff9, 28},  {0xffffffa, 28},  {0xffffffb, 28},
        {0x14, 6},        {0x3f8, 10},      {0x3f9, 10},      {0xffa, 12},
        {0x1ff9, 13},     {0x15, 6},        {0xf8, 8},        {0x7fa, 11},
        {0x3fa, 10},      {0x3fb, 10},      {0xf9, 8},        {0x7fb, 11},
        {0xfa, 8},        {0x16, 6},        {0x17, 6},        {0x18, 6},
        {0x0, 5},         {0x1, 5},         {0x2, 5},         {0x19, 6},
        {0x1a, 6},        {0x1b, 6},        {0x1c, 6},        {0x1d, 6},
        {0x1e, 6},        {0x1f, 6},        {0x5c, 7},        {0xfb, 8},
        {0x7ffc, 15},     {0x20, 6},        {0xffb, 12},      {0x3fc, 10},
        {0x1ffa, 13},     {0x21, 6},        {0x5d, 7},        {0x5e, 7},
        {0x5f, 7},        {0x60, 7},        {0x61, 7},        {0x62, 7},
        {0x63, 7},        {0x64, 7},        {0x65, 7},        {0x66, 7},
        {0x67, 7},        {0x68, 7},        {0x69, 7},        {0x6a, 7},
        {0x6b, 7},        {0x6c, 7},        {0x6d, 7},        {0x6e, 7},
        {0x6f, 7},        {0x70, 7},        {0x71, 7},        {0x72, 7},
        {0xfc, 8},        {0x73, 7},        {0xfd, 8},        {0x1ffb, 13},
        {0x7fff0, 19},    {0x1ffc, 13},     {0x3ffc, 14},     {0x22, 6},
        {0x7ffd, 15},     {0x3, 5},         {0x23, 6},        {0x4, 5},
        {0x24, 6},        {0x5, 5},         {0x25, 6},        {0x26, 6},
        {0x27, 6},        {0x6, 5},         {0x74, 7},        {0x75, 7},
        {0x28, 6},        {0x29, 6},        {0x2a, 6},        {0x7, 5},
        {0x2b, 6},        {0x76, 7},        {0x2c, 6},        {0x8, 5},
        {0x9, 5},         {0x2d, 6},        {0x77, 7},        {0x78, 7},
        {0x79, 7},        {0x7a, 7},        {0x7b, 7},        {0x7ffe, 15},
        {0x7fc, 11},      {0x3ffd, 14},     {0x1ffd, 13},     {0xffffffc, 28},
        {0xfffe6, 20},    {0x3fffd2, 22},   {0xfffe7, 20},    {0xfffe8, 20},
        {0x3fffd3, 22},   {0x3fffd4, 22},   {0x3fffd5, 22},   {0x7fffd9, 23},
        {0x3fffd6, 22},   {0x7fffda, 23},   {0x7fffdb, 23},   {0x7fffdc, 23},
        {0x7fffdd, 23},   {0x7fffde, 23},   {0xffffeb, 24},   {0x7fffdf, 23},
        {0xffffec, 24},   {0xffffed, 24},   {0x3fffd7, 22},   {0x7fffe0, 23},
        {0xffffee, 24},   {0x7fffe1, 23},   {0x7fffe2, 23},   {0x7fffe3, 23},
        {0x7fffe4, 23},   {0x1fffdc, 21},   {0x3fffd8, 22},   {0x7fffe5, 23},
        {0x3fffd9, 22},   {0x7fffe6, 23},   {0x7fffe7, 23},   {0xffffef, 24},
        {0x3fffda, 22},   {0x1fffdd, 21},   {0xfffe9, 20},    {0x3fffdb, 22},
        {0x3fffdc, 22},   {0x7fffe8, 23},   {0x7fffe9, 23},   {0x1fffde, 21},
        {0x7fffea, 23},   {0x3fffdd, 22},   {0x3fffde, 22},   {0xfffff0, 24},
        {0x1fffdf, 21},   {0x3fffdf, 22},   {0x7fffeb, 23},   {0x7fffec, 23},
        {0x1fffe0, 21},   {0x1fffe1, 21},   {0x3fffe0, 22},   {0x1fffe2, 21},
        {0x7fffed, 23},   {0x3fffe1, 22},   {0x7fffee, 23},   {0x7fffef, 23},
        {0xfffea, 20},    {0x3fffe2, 22},   {0x3fffe3, 22},   {0x3fffe4, 22},
        {0x7ffff0, 23},   {0x3fffe5, 22},   {0x3fffe6, 22},   {0x7ffff1, 23},
        {0x3ffffe0, 26},  {0x3ffffe1, 26},  {0xfffeb, 20},    {0x7fff1, 19},
        {0x3fffe7, 22},   {0x7ffff2, 23},   {0x3fffe8, 22},   {0x1ffffec, 25},
        {0x3ffffe2, 26},  {0x3ffffe3, 26},  {0x3ffffe4, 26},  {0x7ffffde, 27},
        {0x7ffffdf, 27},  {0x3ffffe5, 26},  {0xfffff1, 24},   {0x1ffffed, 25},
        {0x7fff2, 19},    {0x1fffe3, 21},   {0x3ffffe6, 26},  {0x7ffffe0, 27},
        {0x7ffffe1, 27},  {0x3ffffe7, 26},  {0x7ffffe2, 27},  {0xfffff2, 24},
        {0x1fffe4, 21},   {0x1fffe5, 21},   {0x3ffffe8, 26},  {0x3ffffe9, 26},
        {0xffffffd, 28},  {0x7ffffe3, 27},  {0x7ffffe4, 27},  {0x7ffffe5, 27},
        {0xfffec, 20},    {0xfffff3, 24},   {0xfffed, 20},    {0x1fffe6, 21},
        {0x3fffe9, 22},   {0x1fffe7, 21},   {0x1fffe8, 21},   {0x7ffff3, 23},
        {0x3fffea, 22},   {0x3fffeb, 22},   {0x1ffffee, 25},  {0x1ffffef, 25},
        {0xfffff4, 24},   {0xfffff5, 24},   {0x3ffffea, 26},  {0x7ffff4, 23},
        {0x3ffffeb, 26},  {0x7ffffe6, 27},  {0x3ffffec, 26},  {0x3ffffed, 26},
        {0x7ffffe7, 27},  {0x7ffffe8, 27},  {0x7ffffe9, 27},  {0x7ffffea, 27},
        {0x7ffffeb, 27},  {0xffffffe, 28},  {0x7ffffec, 27},  {0x7ffffed, 27},
        {0x7ffffee, 27},  {0x7ffffef, 27},  {0x7fffff0, 27},  {0x3ffffee, 26},
    };
    return kTable;
}

// Length of the EOS symbol's prefix used for padding (30 bits, all ones).
inline constexpr uint8_t kQpackHuffmanEosBits = 30;

// Bytes required to Huffman-encode [input, input+len). No allocation.
inline std::size_t qpack_huffman_encoded_size(const uint8_t* input,
                                              std::size_t len) noexcept {
    assert((input != nullptr || len == 0) && "null input with non-zero len");
    assert(len <= (1u << 24) && "encode size input implausibly large");
    const QpackHuffmanCode* table = qpack_huffman_table();
    std::size_t bits = 0;
    for (std::size_t i = 0; i < len; ++i) {
        bits += table[input[i]].nbits;
    }
    return (bits + 7) / 8;
}

// Encode [input,len) into output. Returns 0 on success, 1 if buffer too small.
inline int qpack_huffman_encode(const uint8_t* input, std::size_t len,
                                uint8_t* output, std::size_t output_capacity,
                                std::size_t& out_len) noexcept {
    assert((input != nullptr || len == 0) && "null input with non-zero len");
    assert((output != nullptr || output_capacity == 0) && "null output buffer");

    const std::size_t required = qpack_huffman_encoded_size(input, len);
    if (required > output_capacity) {
        return 1;
    }
    const QpackHuffmanCode* table = qpack_huffman_table();
    uint64_t acc = 0;
    uint32_t nbits = 0;
    std::size_t out_pos = 0;
    for (std::size_t i = 0; i < len; ++i) {
        const QpackHuffmanCode& c = table[input[i]];
        acc = (acc << c.nbits) | c.code;
        nbits += c.nbits;
        while (nbits >= 8) {
            nbits -= 8;
            output[out_pos++] = static_cast<uint8_t>((acc >> nbits) & 0xFF);
        }
    }
    if (nbits > 0) {
        const uint32_t pad = 8 - nbits;
        acc = (acc << pad) | ((1u << pad) - 1u);  // all-ones EOS padding
        output[out_pos++] = static_cast<uint8_t>(acc & 0xFF);
    }
    assert(out_pos == required && "encode wrote unexpected byte count");
    out_len = out_pos;
    return 0;
}

namespace detail {

// Per-length canonical decode bucket built once from the code table.
struct QpackHuffmanDecodeIndex {
    static constexpr int kMinBits = 5;
    static constexpr int kMaxBits = 30;
    // For each length L: first canonical code value and how many codes share L.
    uint32_t first_code[kMaxBits + 1] = {};
    uint32_t first_symbol[kMaxBits + 1] = {};
    uint32_t count[kMaxBits + 1] = {};
    // symbols[]: symbols sorted by (nbits, code) so canonical offset works.
    uint16_t symbols[256] = {};
};

// Build the canonical index. Called once via the function-local static below.
inline QpackHuffmanDecodeIndex qpack_build_decode_index() noexcept {
    QpackHuffmanDecodeIndex idx{};
    const QpackHuffmanCode* table = qpack_huffman_table();
    // Stable sort of symbols by (nbits, code) into idx.symbols.
    uint16_t order[256];
    for (int i = 0; i < 256; ++i) {
        order[i] = static_cast<uint16_t>(i);
    }
    for (int i = 1; i < 256; ++i) {
        uint16_t key = order[i];
        const QpackHuffmanCode& kc = table[key];
        int j = i - 1;
        while (j >= 0 &&
               (table[order[j]].nbits > kc.nbits ||
                (table[order[j]].nbits == kc.nbits &&
                 table[order[j]].code > kc.code))) {
            order[j + 1] = order[j];
            --j;
        }
        order[j + 1] = key;
    }
    for (int i = 0; i < 256; ++i) {
        idx.symbols[i] = order[i];
    }
    // Per length: first code, first symbol position, count.
    for (int len = idx.kMinBits; len <= idx.kMaxBits; ++len) {
        bool seen = false;
        for (int i = 0; i < 256; ++i) {
            if (table[order[i]].nbits != len) {
                continue;
            }
            if (!seen) {
                idx.first_code[len] = table[order[i]].code;
                idx.first_symbol[len] = static_cast<uint32_t>(i);
                seen = true;
            }
            ++idx.count[len];
        }
    }
    return idx;
}

inline const QpackHuffmanDecodeIndex& qpack_decode_index() noexcept {
    static const QpackHuffmanDecodeIndex idx = qpack_build_decode_index();
    return idx;
}

}  // namespace detail

// Decode Huffman bytes [input,len) into output. Returns 0 on success, 1 on
// malformed input / undersized output. Validates EOS padding (RFC 7541 5.2).
inline int qpack_huffman_decode(const uint8_t* input, std::size_t len,
                                uint8_t* output, std::size_t output_capacity,
                                std::size_t& out_len) noexcept {
    assert((input != nullptr || len == 0) && "null input with non-zero len");
    assert((output != nullptr || output_capacity == 0) && "null output buffer");

    const detail::QpackHuffmanDecodeIndex& idx = detail::qpack_decode_index();
    const QpackHuffmanCode* table = qpack_huffman_table();
    uint64_t acc = 0;
    int nbits = 0;
    std::size_t out_pos = 0;
    std::size_t in_pos = 0;
    for (;;) {
        // Refill accumulator from input while we have room and bytes.
        while (nbits <= 56 && in_pos < len) {
            acc = (acc << 8) | input[in_pos++];
            nbits += 8;
        }
        if (nbits < idx.kMinBits) {
            break;  // not enough bits left for any symbol -> padding region
        }
        bool matched = false;
        for (int L = idx.kMinBits; L <= idx.kMaxBits && L <= nbits; ++L) {
            if (idx.count[L] == 0) {
                continue;
            }
            const uint32_t cand =
                static_cast<uint32_t>((acc >> (nbits - L)) & ((1ull << L) - 1));
            if (cand >= idx.first_code[L] &&
                cand < idx.first_code[L] + idx.count[L]) {
                const uint32_t sym_pos =
                    idx.first_symbol[L] + (cand - idx.first_code[L]);
                if (out_pos >= output_capacity) {
                    return 1;
                }
                output[out_pos++] = static_cast<uint8_t>(idx.symbols[sym_pos]);
                nbits -= L;
                matched = true;
                break;
            }
        }
        if (!matched) {
            break;  // remaining bits must be valid all-ones padding
        }
    }
    // Validate trailing padding: <= 7 bits, all ones, no EOS symbol emitted.
    if (nbits > 7) {
        return 1;
    }
    if (nbits > 0) {
        const uint32_t pad = static_cast<uint32_t>(acc & ((1u << nbits) - 1));
        if (pad != (1u << nbits) - 1u) {
            return 1;
        }
    }
    (void)table;
    out_len = out_pos;
    return 0;
}

}  // namespace bolt::api::http3
