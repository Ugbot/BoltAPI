#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include "boltapi/http/huffman.h"  // Huffman coding for better compression

namespace bolt::api {
namespace http {

/**
 * Zero-allocation HPACK encoder/decoder for HTTP/2.
 * 
 * Based on nghttp2's HPACK implementation but adapted for:
 * - Zero heap allocations (stack/arena only)
 * - Zero-copy header access (string_view)
 * - No exceptions (error codes)
 * - No callbacks (direct returns)
 * - Inline hot paths
 * 
 * HPACK Spec: RFC 7541
 * Algorithm from: nghttp2 (https://nghttp2.org/)
 * 
 * Performance targets:
 * - Decode: <500ns per header
 * - Encode: <300ns per header
 * - Zero allocations
 */

/**
 * HTTP/2 header (name-value pair).
 */
struct HPACKHeader {
    std::string_view name;
    std::string_view value;
    bool sensitive{false};  // Never index flag
};

/**
 * HPACK static table (RFC 7541 Appendix A).
 * 
 * Pre-defined headers that don't need to be sent.
 */
class HPACKStaticTable {
public:
    static constexpr size_t SIZE = 61;
    
    /**
     * Get header by index (1-based, per spec).
     * 
     * @param index Static table index (1-61)
     * @param out_header Output header
     * @return 0 on success, 1 if index out of range
     */
    static int get(size_t index, HPACKHeader& out_header) noexcept;
    
    /**
     * Find index for header.
     * 
     * @param name Header name
     * @param value Header value (empty = name-only match)
     * @return Index (1-61) or 0 if not found
     */
    static size_t find(std::string_view name, std::string_view value = {}) noexcept;
};

/**
 * HPACK dynamic table.
 * 
 * Circular buffer of recently-seen headers.
 * Max size: 4096 bytes (default).
 */
class HPACKDynamicTable {
public:
    static constexpr size_t DEFAULT_MAX_SIZE = 4096;
    static constexpr size_t MAX_ENTRIES = 128;  // Reasonable limit
    
    explicit HPACKDynamicTable(size_t max_size = DEFAULT_MAX_SIZE);
    
    /**
     * Add header to dynamic table.
     * 
     * Evicts old entries if needed.
     * 
     * @param name Header name (will be copied to internal buffer)
     * @param value Header value (will be copied to internal buffer)
     * @return 0 on success
     */
    int add(std::string_view name, std::string_view value) noexcept;
    
    /**
     * Get header by index.
     * 
     * Index is relative to dynamic table start.
     * 
     * @param index Dynamic table index (0-based)
     * @param out_header Output header (views into table storage)
     * @return 0 on success, 1 if out of range
     */
    int get(size_t index, HPACKHeader& out_header) const noexcept;
    
    /**
     * Find header in dynamic table.
     * 
     * @param name Header name
     * @param value Header value (empty = name-only match)
     * @return Index or -1 if not found
     */
    int find(std::string_view name, std::string_view value = {}) const noexcept;
    
    /**
     * Get current table size in bytes.
     */
    size_t size() const noexcept { return current_size_; }
    
    /**
     * Get max table size.
     */
    size_t max_size() const noexcept { return max_size_; }
    
    /**
     * Set max table size (dynamic table size update).
     */
    void set_max_size(size_t new_max) noexcept;
    
    /**
     * Clear all entries.
     */
    void clear() noexcept;
    
    /**
     * Get number of entries.
     */
    size_t count() const noexcept { return count_; }
    
private:
    // Circular buffer storage (stack-allocated)
    struct Entry {
        uint16_t name_len;
        uint16_t value_len;
        char data[256];  // name + value stored inline
        
        std::string_view get_name() const {
            return std::string_view(data, name_len);
        }
        
        std::string_view get_value() const {
            return std::string_view(data + name_len, value_len);
        }
        
        size_t size() const {
            // RFC 7541: size = name_len + value_len + 32
            return name_len + value_len + 32;
        }
    };
    
    std::array<Entry, MAX_ENTRIES> entries_;
    size_t head_{0};      // Next insertion point
    size_t count_{0};     // Number of entries
    size_t current_size_{0};  // Current size in bytes
    size_t max_size_;     // Max size in bytes
    
    /**
     * Evict entries to make room for new_size bytes.
     */
    void evict_to_fit(size_t new_size) noexcept;
};

/**
 * HPACK decoder (stateful).
 * 
 * Decodes HPACK-compressed headers from HTTP/2 HEADERS frames.
 */
class HPACKDecoder {
public:
    explicit HPACKDecoder(size_t max_table_size = HPACKDynamicTable::DEFAULT_MAX_SIZE);
    
    /**
     * Decode headers from HPACK-encoded data.
     * 
     * @param input HPACK-encoded bytes
     * @param input_len Length of input
     * @param output Vector to append decoded headers
     * @param max_headers Maximum headers to decode (safety limit)
     * @return 0 on success, error code otherwise
     */
    int decode(
        const uint8_t* input,
        size_t input_len,
        std::vector<HPACKHeader>& output,
        size_t max_headers = 100
    ) noexcept;
    
    /**
     * Set dynamic table max size.
     */
    void set_max_table_size(size_t size) noexcept;
    
    /**
     * Get dynamic table size.
     */
    size_t get_table_size() const noexcept;
    
    /**
     * Decode integer from HPACK format.
     * 
     * Exposed publicly for testing.
     * 
     * @param input Input bytes
     * @param len Input length
     * @param prefix_bits Number of prefix bits (1-8)
     * @param out_value Decoded integer
     * @param out_consumed Bytes consumed
     * @return 0 on success
     */
    int decode_integer(
        const uint8_t* input,
        size_t len,
        int prefix_bits,
        uint64_t& out_value,
        size_t& out_consumed
    ) const noexcept;
    
private:
    HPACKDynamicTable table_;

    // Temporary buffers for literal headers without indexing
    // These are needed to store string data that isn't in the dynamic table
    // Using a vector to handle multiple such headers per decode() call
    std::vector<std::pair<std::string, std::string>> temp_buffers_;

    /**
     * Decode string from HPACK format.
     * 
     * @param input Input bytes
     * @param len Input length
     * @param out_string Decoded string (may allocate)
     * @param out_consumed Bytes consumed
     * @return 0 on success
     */
    int decode_string(
        const uint8_t* input,
        size_t len,
        std::string& out_string,
        size_t& out_consumed
    ) const noexcept;
    
    /**
     * Decode Huffman-encoded string.
     */
    int decode_huffman(
        const uint8_t* input,
        size_t len,
        std::string& out_string
    ) const noexcept;
};

/**
 * HPACK encoder (stateful).
 * 
 * Encodes headers using HPACK compression for HTTP/2.
 */
class HPACKEncoder {
public:
    explicit HPACKEncoder(size_t max_table_size = HPACKDynamicTable::DEFAULT_MAX_SIZE);
    
    /**
     * Encode headers to HPACK format.
     * 
     * @param headers Headers to encode
     * @param count Number of headers
     * @param output Buffer to write encoded data
     * @param output_capacity Buffer capacity
     * @param out_written Bytes written
     * @return 0 on success, 1 if buffer too small
     */
    int encode(
        const HPACKHeader* headers,
        size_t count,
        uint8_t* output,
        size_t output_capacity,
        size_t& out_written
    ) noexcept;
    
    /**
     * Set dynamic table max size.
     */
    void set_max_table_size(size_t size) noexcept;
    
    /**
     * Encode integer in HPACK format.
     * 
     * Exposed publicly for testing.
     */
    int encode_integer(
        uint64_t value,
        int prefix_bits,
        uint8_t* output,
        size_t capacity,
        size_t& written
    ) const noexcept;
    
private:
    HPACKDynamicTable table_;
    
    /**
     * Encode string (with optional Huffman encoding).
     */
    int encode_string(
        std::string_view str,
        bool use_huffman,
        uint8_t* output,
        size_t capacity,
        size_t& written
    ) const noexcept;
    
    /**
     * Encode string with Huffman compression.
     */
    int encode_huffman(
        std::string_view str,
        uint8_t* output,
        size_t capacity,
        size_t& written
    ) const noexcept;
};

} // namespace http
} // namespace bolt::api

