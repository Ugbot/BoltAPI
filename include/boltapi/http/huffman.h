#pragma once

#include <cstdint>
#include <cstddef>

namespace bolt::api {
namespace http {

/**
 * Huffman encoder/decoder for HPACK.
 * 
 * Based on nghttp2's Huffman implementation.
 * Adapted for zero-allocation, stack-only operation.
 * 
 * Spec: RFC 7541 Appendix B (HPACK Huffman Code)
 * 
 * Performance targets:
 * - Encode: <50ns per byte
 * - Decode: <80ns per byte
 * - Zero allocations
 * 
 * Compression ratio: ~30-40% for typical headers
 */

/**
 * Huffman encoder.
 */
class HuffmanEncoder {
public:
    /**
     * Encode data using Huffman coding.
     * 
     * @param input Input data
     * @param input_len Input length
     * @param output Output buffer
     * @param output_capacity Output buffer capacity
     * @param out_encoded_len Encoded length
     * @return 0 on success, 1 if output buffer too small
     */
    static int encode(
        const uint8_t* input,
        size_t input_len,
        uint8_t* output,
        size_t output_capacity,
        size_t& out_encoded_len
    ) noexcept;
    
    /**
     * Get encoded size (without actually encoding).
     * 
     * Useful for buffer allocation.
     * 
     * @param input Input data
     * @param input_len Input length
     * @return Encoded size in bytes
     */
    static size_t encoded_size(
        const uint8_t* input,
        size_t input_len
    ) noexcept;
};

/**
 * Huffman decoder.
 */
class HuffmanDecoder {
public:
    /**
     * Decode Huffman-encoded data.
     * 
     * @param input Encoded data
     * @param input_len Encoded length
     * @param output Output buffer
     * @param output_capacity Output buffer capacity
     * @param out_decoded_len Decoded length
     * @return 0 on success, 1 on error
     */
    static int decode(
        const uint8_t* input,
        size_t input_len,
        uint8_t* output,
        size_t output_capacity,
        size_t& out_decoded_len
    ) noexcept;
    
private:
    /**
     * Huffman decode state machine entry.
     *
     * Based on nghttp2_huff_decode structure.
     * Each entry represents a state transition in the Huffman FSA.
     */
    struct DecodeEntry {
        uint16_t state_and_flags;  // Packed: state (bits 0-8) + flags (bits 14-15)
        uint8_t symbol;             // Symbol to emit if HUFF_SYM flag is set

        // Modern C++ accessors with constexpr for compile-time evaluation
        constexpr uint16_t state() const noexcept {
            return state_and_flags & 0x1FF;  // Lower 9 bits = next state
        }

        constexpr bool emits_symbol() const noexcept {
            return (state_and_flags & 0x8000) != 0;  // Bit 15 = NGHTTP2_HUFF_SYM
        }

        constexpr bool is_accepted() const noexcept {
            return (state_and_flags & 0x4000) != 0;  // Bit 14 = NGHTTP2_HUFF_ACCEPTED
        }

        constexpr bool is_failure() const noexcept {
            return state() == 256;  // State 256 = terminal failure state
        }
    };

    // Decode table dimensions:
    // - 257 states (0-255 internal nodes + 1 terminal failure state 256)
    // - 16 entries per state (one for each 4-bit nibble value 0x0-0xF)
    static constexpr size_t DECODE_TABLE_STATES = 257;
    static constexpr size_t DECODE_TABLE_NIBBLES = 16;

    // Decode table from nghttp2 (see nghttp2_hd_huffman_data.c)
    static const DecodeEntry decode_table_[DECODE_TABLE_STATES][DECODE_TABLE_NIBBLES];
};

} // namespace http
} // namespace bolt::api

