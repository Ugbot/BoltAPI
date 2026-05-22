#include "boltapi/http/hpack.h"
#include <cstring>
#include <algorithm>

namespace bolt::api {
namespace http {

// ============================================================================
// HPACK Static Table (RFC 7541 Appendix A)
// ============================================================================

// Pre-defined header table
static const struct {
    const char* name;
    const char* value;
} STATIC_TABLE[] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
};

static constexpr size_t STATIC_TABLE_SIZE = sizeof(STATIC_TABLE) / sizeof(STATIC_TABLE[0]);

int HPACKStaticTable::get(size_t index, HPACKHeader& out_header) noexcept {
    if (index == 0 || index > STATIC_TABLE_SIZE) {
        return 1;  // Invalid index
    }
    
    // Indices are 1-based
    const auto& entry = STATIC_TABLE[index - 1];
    out_header.name = entry.name;
    out_header.value = entry.value;
    out_header.sensitive = false;
    
    return 0;
}

size_t HPACKStaticTable::find(std::string_view name, std::string_view value) noexcept {
    for (size_t i = 0; i < STATIC_TABLE_SIZE; ++i) {
        const auto& entry = STATIC_TABLE[i];
        
        if (name == entry.name) {
            // Name matches
            if (value.empty() || value == entry.value) {
                return i + 1;  // Return 1-based index
            }
        }
    }
    
    return 0;  // Not found
}

// ============================================================================
// HPACK Dynamic Table
// ============================================================================

HPACKDynamicTable::HPACKDynamicTable(size_t max_size)
    : max_size_(max_size) {
}

int HPACKDynamicTable::add(std::string_view name, std::string_view value) noexcept {
    // Check if entry would fit
    size_t entry_size = name.length() + value.length() + 32;
    
    if (entry_size > max_size_) {
        // Entry too large, clear table
        clear();
        return 1;
    }
    
    // Evict old entries if needed
    evict_to_fit(entry_size);
    
    // Check if we have room for another entry
    if (count_ >= MAX_ENTRIES) {
        // Table full, evict oldest
        evict_to_fit(entry_size);
    }
    
    // Add new entry at head
    Entry& entry = entries_[head_];
    
    // Copy name and value into entry
    size_t total_len = name.length() + value.length();
    if (total_len >= sizeof(entry.data)) {
        // Too large for our inline storage
        return 1;
    }
    
    std::memcpy(entry.data, name.data(), name.length());
    std::memcpy(entry.data + name.length(), value.data(), value.length());
    
    entry.name_len = static_cast<uint16_t>(name.length());
    entry.value_len = static_cast<uint16_t>(value.length());
    
    // Update state
    current_size_ += entry.size();
    head_ = (head_ + 1) % MAX_ENTRIES;
    if (count_ < MAX_ENTRIES) {
        count_++;
    }
    
    return 0;
}

int HPACKDynamicTable::get(size_t index, HPACKHeader& out_header) const noexcept {
    if (index >= count_) {
        return 1;
    }
    
    // Calculate actual index in circular buffer
    size_t actual_idx = (head_ + MAX_ENTRIES - 1 - index) % MAX_ENTRIES;
    const Entry& entry = entries_[actual_idx];
    
    out_header.name = entry.get_name();
    out_header.value = entry.get_value();
    out_header.sensitive = false;
    
    return 0;
}

int HPACKDynamicTable::find(std::string_view name, std::string_view value) const noexcept {
    for (size_t i = 0; i < count_; ++i) {
        size_t actual_idx = (head_ + MAX_ENTRIES - 1 - i) % MAX_ENTRIES;
        const Entry& entry = entries_[actual_idx];
        
        if (name == entry.get_name()) {
            if (value.empty() || value == entry.get_value()) {
                return static_cast<int>(i);
            }
        }
    }
    
    return -1;
}

void HPACKDynamicTable::set_max_size(size_t new_max) noexcept {
    max_size_ = new_max;
    
    // Evict entries if new size is smaller
    while (current_size_ > max_size_ && count_ > 0) {
        // Remove oldest entry
        size_t tail = (head_ + MAX_ENTRIES - count_) % MAX_ENTRIES;
        current_size_ -= entries_[tail].size();
        count_--;
    }
}

void HPACKDynamicTable::clear() noexcept {
    head_ = 0;
    count_ = 0;
    current_size_ = 0;
}

void HPACKDynamicTable::evict_to_fit(size_t new_size) noexcept {
    while (current_size_ + new_size > max_size_ && count_ > 0) {
        // Remove oldest entry
        size_t tail = (head_ + MAX_ENTRIES - count_) % MAX_ENTRIES;
        current_size_ -= entries_[tail].size();
        count_--;
    }
}

// ============================================================================
// HPACK Decoder
// ============================================================================

HPACKDecoder::HPACKDecoder(size_t max_table_size)
    : table_(max_table_size) {
}

int HPACKDecoder::decode(
    const uint8_t* input,
    size_t input_len,
    std::vector<HPACKHeader>& output,
    size_t max_headers
) noexcept {
    size_t pos = 0;

    // Clear temporary buffers from previous decode() call
    // Reserve space to prevent reallocation (which would invalidate string_views)
    temp_buffers_.clear();
    temp_buffers_.reserve(max_headers);

    while (pos < input_len && output.size() < max_headers) {
        uint8_t first_byte = input[pos];
        
        // HPACK encoding types (RFC 7541 Section 6):
        // - Indexed (1xxxxxxx)
        // - Literal with incremental indexing (01xxxxxx)
        // - Literal without indexing (0000xxxx)
        // - Literal never indexed (0001xxxx)
        // - Dynamic table size update (001xxxxx)
        
        if (first_byte & 0x80) {
            // Indexed Header Field (Section 6.1)
            uint64_t index;
            size_t consumed;
            
            if (decode_integer(input + pos, input_len - pos, 7, index, consumed) != 0) {
                return 1;
            }
            
            pos += consumed;
            
            // Lookup in tables
            HPACKHeader header;
            if (index <= STATIC_TABLE_SIZE) {
                // Static table
                if (HPACKStaticTable::get(index, header) != 0) {
                    return 1;
                }
            } else {
                // Dynamic table
                size_t dyn_index = index - STATIC_TABLE_SIZE - 1;
                if (table_.get(dyn_index, header) != 0) {
                    return 1;
                }
            }
            
            output.push_back(header);
            
        } else if (first_byte & 0x40) {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            uint64_t index;
            size_t consumed;

            if (decode_integer(input + pos, input_len - pos, 6, index, consumed) != 0) {
                return 1;
            }

            pos += consumed;

            std::string name, value;

            if (index == 0) {
                // New name - decode name string
                size_t name_consumed;
                if (decode_string(input + pos, input_len - pos, name, name_consumed) != 0) {
                    return 1;
                }
                pos += name_consumed;
            } else {
                // Indexed name from table
                HPACKHeader name_header;
                if (index <= STATIC_TABLE_SIZE) {
                    if (HPACKStaticTable::get(index, name_header) != 0) {
                        return 1;
                    }
                } else {
                    size_t dyn_index = index - STATIC_TABLE_SIZE - 1;
                    if (table_.get(dyn_index, name_header) != 0) {
                        return 1;
                    }
                }
                name = std::string(name_header.name);
            }

            // Decode value string
            size_t value_consumed;
            if (decode_string(input + pos, input_len - pos, value, value_consumed) != 0) {
                return 1;
            }
            pos += value_consumed;

            // Add to dynamic table (for future lookups on same connection)
            table_.add(name, value);

            // Store in temp_buffers_ for safe output (avoids string_view lifetime issues)
            temp_buffers_.emplace_back(std::move(name), std::move(value));

            HPACKHeader header;
            header.name = temp_buffers_.back().first;
            header.value = temp_buffers_.back().second;
            header.sensitive = false;
            output.push_back(header);

        } else if ((first_byte & 0xE0) == 0x20) {
            // Dynamic Table Size Update (Section 6.3)
            uint64_t new_size;
            size_t consumed;
            
            if (decode_integer(input + pos, input_len - pos, 5, new_size, consumed) != 0) {
                return 1;
            }
            
            pos += consumed;
            table_.set_max_size(new_size);
            
        } else {
            // Literal Header Field without Indexing (0000xxxx) or Never Indexed (0001xxxx)
            bool never_indexed = (first_byte & 0x10) != 0;
            uint64_t index;
            size_t consumed;

            if (decode_integer(input + pos, input_len - pos, 4, index, consumed) != 0) {
                return 1;
            }

            pos += consumed;

            std::string name, value;

            if (index == 0) {
                // New name - decode name string
                size_t name_consumed;
                if (decode_string(input + pos, input_len - pos, name, name_consumed) != 0) {
                    return 1;
                }
                pos += name_consumed;
            } else {
                // Indexed name from table
                HPACKHeader name_header;
                if (index <= STATIC_TABLE_SIZE) {
                    if (HPACKStaticTable::get(index, name_header) != 0) {
                        return 1;
                    }
                } else {
                    size_t dyn_index = index - STATIC_TABLE_SIZE - 1;
                    if (table_.get(dyn_index, name_header) != 0) {
                        return 1;
                    }
                }
                name = std::string(name_header.name);
            }

            // Decode value string
            size_t value_consumed;
            if (decode_string(input + pos, input_len - pos, value, value_consumed) != 0) {
                return 1;
            }
            pos += value_consumed;

            // Store in temporary buffer (these headers are NOT added to dynamic table)
            // Use vector so each header gets its own storage (string_view lifetime fix)
            temp_buffers_.emplace_back(std::move(name), std::move(value));

            HPACKHeader header;
            header.name = temp_buffers_.back().first;
            header.value = temp_buffers_.back().second;
            header.sensitive = never_indexed;
            output.push_back(header);
        }
    }
    
    return 0;
}

void HPACKDecoder::set_max_table_size(size_t size) noexcept {
    table_.set_max_size(size);
}

size_t HPACKDecoder::get_table_size() const noexcept {
    return table_.size();
}

int HPACKDecoder::decode_integer(
    const uint8_t* input,
    size_t len,
    int prefix_bits,
    uint64_t& out_value,
    size_t& out_consumed
) const noexcept {
    if (len == 0 || prefix_bits < 1 || prefix_bits > 8) {
        return 1;
    }
    
    // Calculate prefix mask
    uint8_t prefix_mask = (1 << prefix_bits) - 1;
    uint8_t first_value = input[0] & prefix_mask;
    
    if (first_value < prefix_mask) {
        // Value fits in prefix bits
        out_value = first_value;
        out_consumed = 1;
        return 0;
    }
    
    // Multi-byte integer (RFC 7541 Section 5.1)
    uint64_t value = prefix_mask;
    size_t pos = 1;
    uint64_t multiplier = 1;
    
    while (pos < len) {
        uint8_t byte = input[pos++];
        
        value += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        
        if ((byte & 0x80) == 0) {
            // Last byte
            out_value = value;
            out_consumed = pos;
            return 0;
        }
        
        // Check for overflow
        if (multiplier > (UINT64_MAX / 128)) {
            return 1;  // Integer too large
        }
    }
    
    return 1;  // Incomplete integer
}

int HPACKDecoder::decode_string(
    const uint8_t* input,
    size_t len,
    std::string& out_string,
    size_t& out_consumed
) const noexcept {
    if (len == 0) {
        return 1;
    }
    
    bool huffman = (input[0] & 0x80) != 0;
    
    // Decode string length
    uint64_t str_len;
    size_t integer_consumed;
    
    if (decode_integer(input, len, 7, str_len, integer_consumed) != 0) {
        return 1;
    }
    
    if (integer_consumed + str_len > len) {
        return 1;  // Not enough data
    }
    
    const uint8_t* str_data = input + integer_consumed;
    
    if (huffman) {
        // Huffman-encoded
        if (decode_huffman(str_data, str_len, out_string) != 0) {
            return 1;
        }
    } else {
        // Plain string
        out_string.assign(reinterpret_cast<const char*>(str_data), str_len);
    }
    
    out_consumed = integer_consumed + str_len;
    return 0;
}

int HPACKDecoder::decode_huffman(
    const uint8_t* input,
    size_t len,
    std::string& out_string
) const noexcept {
    // Use our Huffman decoder
    uint8_t buffer[4096];  // Stack-allocated decode buffer
    size_t decoded_len;
    
    if (HuffmanDecoder::decode(input, len, buffer, sizeof(buffer), decoded_len) != 0) {
        // Fallback: just copy as plain string
        out_string.assign(reinterpret_cast<const char*>(input), len);
        return 0;
    }
    
    out_string.assign(reinterpret_cast<const char*>(buffer), decoded_len);
    return 0;
}

// ============================================================================
// HPACK Encoder
// ============================================================================

HPACKEncoder::HPACKEncoder(size_t max_table_size)
    : table_(max_table_size) {
}

int HPACKEncoder::encode(
    const HPACKHeader* headers,
    size_t count,
    uint8_t* output,
    size_t output_capacity,
    size_t& out_written
) noexcept {
    size_t written = 0;
    
    for (size_t i = 0; i < count; ++i) {
        const HPACKHeader& header = headers[i];
        
        // Try to find in static table
        size_t static_idx = HPACKStaticTable::find(header.name, header.value);
        
        if (static_idx > 0) {
            // Indexed header (1xxxxxxx)
            size_t idx_written;
            if (encode_integer(static_idx, 7, output + written, 
                             output_capacity - written, idx_written) != 0) {
                return 1;
            }
            
            output[written] |= 0x80;  // Set indexed bit
            written += idx_written;
            
        } else {
            // Literal with incremental indexing (01xxxxxx)
            // For simplicity, use index 0 (new name)
            
            if (written >= output_capacity) {
                return 1;
            }
            
            output[written++] = 0x40;  // Literal with indexing, index 0
            
            // Encode name
            size_t name_written;
            if (encode_string(header.name, false, output + written,
                            output_capacity - written, name_written) != 0) {
                return 1;
            }
            written += name_written;
            
            // Encode value
            size_t value_written;
            if (encode_string(header.value, false, output + written,
                            output_capacity - written, value_written) != 0) {
                return 1;
            }
            written += value_written;
            
            // Add to dynamic table
            table_.add(header.name, header.value);
        }
    }
    
    out_written = written;
    return 0;
}

void HPACKEncoder::set_max_table_size(size_t size) noexcept {
    table_.set_max_size(size);
}

int HPACKEncoder::encode_integer(
    uint64_t value,
    int prefix_bits,
    uint8_t* output,
    size_t capacity,
    size_t& written
) const noexcept {
    if (capacity == 0 || prefix_bits < 1 || prefix_bits > 8) {
        return 1;
    }
    
    uint8_t prefix_mask = (1 << prefix_bits) - 1;
    
    if (value < prefix_mask) {
        // Fits in prefix
        output[0] = static_cast<uint8_t>(value);
        written = 1;
        return 0;
    }
    
    // Multi-byte encoding
    output[0] = prefix_mask;
    value -= prefix_mask;
    
    size_t pos = 1;
    while (value >= 128 && pos < capacity) {
        output[pos++] = static_cast<uint8_t>((value % 128) | 0x80);
        value /= 128;
    }
    
    if (pos >= capacity) {
        return 1;  // Buffer too small
    }
    
    output[pos++] = static_cast<uint8_t>(value);
    written = pos;
    
    return 0;
}

int HPACKEncoder::encode_string(
    std::string_view str,
    bool use_huffman,
    uint8_t* output,
    size_t capacity,
    size_t& written
) const noexcept {
    // Encode length
    size_t len_written;
    if (encode_integer(str.length(), 7, output, capacity, len_written) != 0) {
        return 1;
    }
    
    if (use_huffman) {
        output[0] |= 0x80;  // Set Huffman bit
    }
    
    // Copy string data
    if (len_written + str.length() > capacity) {
        return 1;  // Buffer too small
    }
    
    std::memcpy(output + len_written, str.data(), str.length());
    written = len_written + str.length();
    
    return 0;
}

int HPACKEncoder::encode_huffman(
    std::string_view str,
    uint8_t* output,
    size_t capacity,
    size_t& written
) const noexcept {
    // Use our Huffman encoder
    size_t encoded_len;
    
    if (HuffmanEncoder::encode(
        reinterpret_cast<const uint8_t*>(str.data()),
        str.length(),
        output,
        capacity,
        encoded_len
    ) != 0) {
        // Fallback to plain encoding if Huffman fails
        return encode_string(str, false, output, capacity, written);
    }
    
    written = encoded_len;
    return 0;
}

} // namespace http
} // namespace bolt::api

