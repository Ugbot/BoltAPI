#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "boltapi/http/huffman.h"

namespace bolt::api {
namespace http {

/**
 * HPACK (RFC 7541) for HTTP/2.
 *
 * Decoder: validates everything a peer controls (indices, integer and string
 * lengths, Huffman padding/EOS, table size updates and their position) and
 * reports COMPRESSION_ERROR instead of guessing. Encoder: static-table
 * indexing plus literals without indexing, so its dynamic table stays empty
 * and no peer table size can desynchronise it.
 */

struct HPACKHeader {
    std::string_view name;
    std::string_view value;
    bool sensitive{false};  // never-indexed representation
};

/** RFC 7541 Appendix A. */
class HPACKStaticTable {
public:
    static constexpr size_t SIZE = 61;

    /** 1-based lookup; 0 ok, 1 out of range. */
    static int get(size_t index, HPACKHeader& out_header) noexcept;

    /** Index of an entry whose name AND value both match, or 0. */
    static size_t find(std::string_view name, std::string_view value) noexcept;

    /** Index of the first entry with this name, or 0. */
    static size_t find_name(std::string_view name) noexcept;
};

/**
 * Dynamic table (RFC 7541 2.3.2 / 4). Entries live in one contiguous byte
 * region (oldest first); eviction advances its start and an insertion that
 * does not fit at the end compacts it. Bounded by kStorageBytes.
 */
class HPACKDynamicTable {
public:
    static constexpr size_t DEFAULT_MAX_SIZE = 4096;
    static constexpr size_t kStorageBytes = 4096;              // largest table held
    static constexpr size_t MAX_ENTRIES = kStorageBytes / 32;  // every entry costs >= 32

    explicit HPACKDynamicTable(size_t max_size = DEFAULT_MAX_SIZE) noexcept;

    /** Insert at the head, evicting as RFC 7541 4.4 requires. An entry larger
     *  than the table empties it and is not added (not an error). */
    void add(std::string_view name, std::string_view value) noexcept;

    /** 0-based from the newest entry; 0 ok, 1 out of range. Views are valid
     *  until the next add()/set_max_size(). */
    int get(size_t index, HPACKHeader& out_header) const noexcept;

    size_t size() const noexcept { return current_size_; }
    size_t max_size() const noexcept { return max_size_; }
    size_t count() const noexcept { return count_; }

    /** new_max <= kStorageBytes (callers validate peer input first). */
    void set_max_size(size_t new_max) noexcept;
    void clear() noexcept;

private:
    struct Entry {
        uint32_t off;
        uint16_t name_len;
        uint16_t value_len;
        size_t size() const noexcept { return static_cast<size_t>(name_len) + value_len + 32; }
    };

    std::array<Entry, MAX_ENTRIES> entries_{};  // ring, oldest at first_
    std::array<char, kStorageBytes> data_{};
    size_t first_{0};
    size_t count_{0};
    size_t current_size_{0};
    size_t max_size_;
    size_t data_begin_{0};
    size_t data_end_{0};

    void evict_oldest() noexcept;
    void compact() noexcept;
};

/**
 * HPACK decoder (one per connection direction).
 */
class HPACKDecoder {
public:
    static constexpr int kOk = 0;
    static constexpr int kCompressionError = 1;  // connection error
    static constexpr int kTooManyHeaders = 2;    // table still in sync; stream error
    static constexpr size_t kMaxStringLen = 64 * 1024;
    static constexpr size_t kMaxIntegerBytes = 6;  // up to 2^35: above any length we accept

    /** max_table_size = the SETTINGS_HEADER_TABLE_SIZE we advertised. */
    explicit HPACKDecoder(size_t max_table_size = HPACKDynamicTable::DEFAULT_MAX_SIZE);

    /**
     * Decode one complete header block. Every representation is processed
     * (the dynamic table must track the whole block) but at most max_headers
     * are appended to `output`. Views stay valid until the next decode().
     * @return kOk, kCompressionError or kTooManyHeaders.
     */
    int decode(const uint8_t* input, size_t input_len,
               std::vector<HPACKHeader>& output, size_t max_headers = 100) noexcept;

    /** Our advertised limit changed; also shrinks the table if needed. */
    void set_max_table_size(size_t size) noexcept;
    size_t get_table_size() const noexcept;

    /** RFC 7541 5.1. 0 ok, 1 incomplete/overflow. */
    int decode_integer(const uint8_t* input, size_t len, int prefix_bits,
                       uint64_t& out_value, size_t& out_consumed) const noexcept;

private:
    HPACKDynamicTable table_;
    size_t limit_;  // largest size a table size update may request

    // Decoded strings of the current block; reserved so views never move.
    std::vector<std::pair<std::string, std::string>> temp_buffers_;

    int decode_string(const uint8_t* input, size_t len, std::string& out,
                      size_t& out_consumed) const noexcept;
    int lookup(uint64_t index, HPACKHeader& out) const noexcept;
    int decode_literal(const uint8_t* input, size_t len, int prefix_bits,
                       std::string& name, std::string& value,
                       size_t& out_consumed) const noexcept;
};

/**
 * HPACK encoder. Never inserts into its dynamic table; announces a smaller
 * peer table size with a size update at the start of the next block.
 */
class HPACKEncoder {
public:
    explicit HPACKEncoder(size_t max_table_size = HPACKDynamicTable::DEFAULT_MAX_SIZE);

    /** 0 ok, 1 output too small. */
    int encode(const HPACKHeader* headers, size_t count, uint8_t* output,
               size_t output_capacity, size_t& out_written) noexcept;

    /** Peer's SETTINGS_HEADER_TABLE_SIZE. */
    void set_max_table_size(size_t size) noexcept;

    int encode_integer(uint64_t value, int prefix_bits, uint8_t* output,
                       size_t capacity, size_t& written) const noexcept;

private:
    size_t table_size_;   // size the peer's decoder currently assumes
    size_t pending_min_;  // smallest size announced since the last block
    bool pending_update_{false};

    int encode_string(std::string_view str, uint8_t* output, size_t capacity,
                      size_t& written) const noexcept;
};

} // namespace http
} // namespace bolt::api
