#include "boltapi/http/hpack.h"

#include <algorithm>
#include <cassert>
#include <cstring>

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
static_assert(STATIC_TABLE_SIZE == HPACKStaticTable::SIZE, "RFC 7541 Appendix A has 61 entries");

int HPACKStaticTable::get(size_t index, HPACKHeader& out_header) noexcept {
    if (index == 0 || index > STATIC_TABLE_SIZE) return 1;
    const auto& entry = STATIC_TABLE[index - 1];
    out_header.name = entry.name;
    out_header.value = entry.value;
    out_header.sensitive = false;
    return 0;
}

size_t HPACKStaticTable::find(std::string_view name, std::string_view value) noexcept {
    for (size_t i = 0; i < STATIC_TABLE_SIZE; ++i) {
        if (name == STATIC_TABLE[i].name && value == STATIC_TABLE[i].value) return i + 1;
    }
    return 0;
}

size_t HPACKStaticTable::find_name(std::string_view name) noexcept {
    for (size_t i = 0; i < STATIC_TABLE_SIZE; ++i) {
        if (name == STATIC_TABLE[i].name) return i + 1;
    }
    return 0;
}

// ============================================================================
// Dynamic table
// ============================================================================

HPACKDynamicTable::HPACKDynamicTable(size_t max_size) noexcept
    : max_size_(std::min(max_size, kStorageBytes)) {
    assert(max_size_ <= kStorageBytes);
    assert(count_ == 0 && current_size_ == 0);
}

void HPACKDynamicTable::evict_oldest() noexcept {
    assert(count_ > 0);
    const Entry& e = entries_[first_];
    assert(current_size_ >= e.size());
    current_size_ -= e.size();
    first_ = (first_ + 1) % MAX_ENTRIES;
    --count_;
    if (count_ == 0) {
        data_begin_ = data_end_ = 0;
        first_ = 0;
        assert(current_size_ == 0);
    } else {
        data_begin_ = entries_[first_].off;
    }
}

void HPACKDynamicTable::compact() noexcept {
    assert(data_begin_ <= data_end_ && data_end_ <= kStorageBytes);
    const size_t live = data_end_ - data_begin_;
    if (data_begin_ == 0) return;
    std::memmove(data_.data(), data_.data() + data_begin_, live);
    for (size_t i = 0; i < count_; ++i) {
        Entry& e = entries_[(first_ + i) % MAX_ENTRIES];
        assert(e.off >= data_begin_);
        e.off -= static_cast<uint32_t>(data_begin_);
    }
    data_begin_ = 0;
    data_end_ = live;
}

void HPACKDynamicTable::add(std::string_view name, std::string_view value) noexcept {
    const size_t entry_size = name.size() + value.size() + 32;
    if (entry_size > max_size_) {
        clear();  // RFC 7541 4.4: not an error, the table just empties
        return;
    }
    while (count_ > 0 && (current_size_ + entry_size > max_size_ || count_ == MAX_ENTRIES)) {
        evict_oldest();
    }
    const size_t bytes = name.size() + value.size();
    if (data_end_ + bytes > kStorageBytes) compact();
    // Live bytes <= max_size_ - 32 * entries, so after compaction it fits.
    assert(data_end_ + bytes <= kStorageBytes);
    std::memcpy(data_.data() + data_end_, name.data(), name.size());
    std::memcpy(data_.data() + data_end_ + name.size(), value.data(), value.size());
    Entry& e = entries_[(first_ + count_) % MAX_ENTRIES];
    e.off = static_cast<uint32_t>(data_end_);
    e.name_len = static_cast<uint16_t>(name.size());
    e.value_len = static_cast<uint16_t>(value.size());
    if (count_ == 0) data_begin_ = data_end_;
    data_end_ += bytes;
    ++count_;
    current_size_ += entry_size;
    assert(current_size_ <= max_size_);
}

int HPACKDynamicTable::get(size_t index, HPACKHeader& out_header) const noexcept {
    if (index >= count_) return 1;
    const Entry& e = entries_[(first_ + count_ - 1 - index) % MAX_ENTRIES];
    assert(static_cast<size_t>(e.off) + e.name_len + e.value_len <= kStorageBytes);
    out_header.name = std::string_view(data_.data() + e.off, e.name_len);
    out_header.value = std::string_view(data_.data() + e.off + e.name_len, e.value_len);
    out_header.sensitive = false;
    return 0;
}

void HPACKDynamicTable::set_max_size(size_t new_max) noexcept {
    assert(new_max <= kStorageBytes);
    max_size_ = std::min(new_max, kStorageBytes);
    while (count_ > 0 && current_size_ > max_size_) evict_oldest();
    assert(current_size_ <= max_size_);
}

void HPACKDynamicTable::clear() noexcept {
    first_ = count_ = current_size_ = 0;
    data_begin_ = data_end_ = 0;
}

// ============================================================================
// Decoder
// ============================================================================

HPACKDecoder::HPACKDecoder(size_t max_table_size)
    : table_(std::min(max_table_size, HPACKDynamicTable::kStorageBytes)),
      limit_(std::min(max_table_size, HPACKDynamicTable::kStorageBytes)) {
    assert(limit_ <= HPACKDynamicTable::kStorageBytes);
}

void HPACKDecoder::set_max_table_size(size_t size) noexcept {
    limit_ = std::min(size, HPACKDynamicTable::kStorageBytes);
    if (table_.max_size() > limit_) table_.set_max_size(limit_);
    assert(table_.max_size() <= limit_ || limit_ == 0);
}

size_t HPACKDecoder::get_table_size() const noexcept { return table_.size(); }

int HPACKDecoder::decode_integer(const uint8_t* input, size_t len, int prefix_bits,
                                 uint64_t& out_value, size_t& out_consumed) const noexcept {
    if (len == 0 || prefix_bits < 1 || prefix_bits > 8) return 1;
    const uint8_t mask = static_cast<uint8_t>((1u << prefix_bits) - 1);
    uint64_t value = input[0] & mask;
    if (value < mask) {
        out_value = value;
        out_consumed = 1;
        return 0;
    }
    for (size_t i = 1; i < len && i < kMaxIntegerBytes; ++i) {
        value += static_cast<uint64_t>(input[i] & 0x7F) << (7 * (i - 1));
        if ((input[i] & 0x80) == 0) {
            out_value = value;
            out_consumed = i + 1;
            assert(out_consumed <= kMaxIntegerBytes);
            return 0;
        }
    }
    return 1;  // truncated, or longer than any value we accept
}

int HPACKDecoder::decode_string(const uint8_t* input, size_t len, std::string& out,
                                size_t& out_consumed) const noexcept {
    if (len == 0) return 1;
    const bool huffman = (input[0] & 0x80) != 0;
    uint64_t str_len = 0;
    size_t int_len = 0;
    if (decode_integer(input, len, 7, str_len, int_len) != 0) return 1;
    if (str_len > kMaxStringLen || str_len > len - int_len) return 1;
    const uint8_t* p = input + int_len;
    const size_t n = static_cast<size_t>(str_len);
    if (!huffman) {
        out.assign(reinterpret_cast<const char*>(p), n);
    } else if (n == 0) {
        out.clear();
    } else {
        out.resize(n * 8 / 5 + 1);  // shortest code is 5 bits
        size_t decoded = 0;
        if (HuffmanDecoder::decode(p, n, reinterpret_cast<uint8_t*>(out.data()), out.size(),
                                   decoded) != 0) {
            return 1;  // EOS, over-long or non-EOS padding: COMPRESSION_ERROR
        }
        out.resize(decoded);
    }
    out_consumed = int_len + n;
    assert(out_consumed <= len);
    return 0;
}

int HPACKDecoder::lookup(uint64_t index, HPACKHeader& out) const noexcept {
    if (index == 0) return 1;
    if (index <= STATIC_TABLE_SIZE) return HPACKStaticTable::get(static_cast<size_t>(index), out);
    const uint64_t dyn = index - STATIC_TABLE_SIZE - 1;
    if (dyn >= table_.count()) return 1;
    return table_.get(static_cast<size_t>(dyn), out);
}

int HPACKDecoder::decode_literal(const uint8_t* input, size_t len, int prefix_bits,
                                 std::string& name, std::string& value,
                                 size_t& out_consumed) const noexcept {
    uint64_t index = 0;
    size_t pos = 0;
    if (decode_integer(input, len, prefix_bits, index, pos) != 0) return 1;
    if (index == 0) {
        size_t used = 0;
        if (decode_string(input + pos, len - pos, name, used) != 0) return 1;
        pos += used;
    } else {
        HPACKHeader h;
        if (lookup(index, h) != 0) return 1;
        name.assign(h.name.data(), h.name.size());
    }
    size_t used = 0;
    if (decode_string(input + pos, len - pos, value, used) != 0) return 1;
    out_consumed = pos + used;
    assert(out_consumed <= len);
    return 0;
}

int HPACKDecoder::decode(const uint8_t* input, size_t input_len,
                         std::vector<HPACKHeader>& output, size_t max_headers) noexcept {
    assert(input != nullptr || input_len == 0);
    temp_buffers_.clear();
    temp_buffers_.reserve(max_headers);
    size_t pos = 0;
    size_t produced = 0;
    bool field_seen = false;
    bool too_many = false;
    // Each representation consumes at least one byte.
    for (size_t guard = 0; guard < input_len && pos < input_len; ++guard) {
        const uint8_t b = input[pos];
        std::string name, value;
        bool sensitive = false;
        size_t used = 0;
        if (b & 0x80) {  // indexed field (6.1)
            uint64_t index = 0;
            HPACKHeader h;
            if (decode_integer(input + pos, input_len - pos, 7, index, used) != 0) return kCompressionError;
            if (lookup(index, h) != 0) return kCompressionError;
            pos += used;
            field_seen = true;
            if (index <= STATIC_TABLE_SIZE) {  // static strings outlive everything
                if (produced < max_headers) {
                    output.push_back(h);
                    ++produced;
                } else {
                    too_many = true;
                }
                continue;
            }
            name.assign(h.name.data(), h.name.size());
            value.assign(h.value.data(), h.value.size());
        } else if ((b & 0xC0) == 0x40) {  // literal, incremental indexing (6.2.1)
            if (decode_literal(input + pos, input_len - pos, 6, name, value, used) != 0) return kCompressionError;
            pos += used;
            field_seen = true;
            table_.add(name, value);
        } else if ((b & 0xE0) == 0x20) {  // dynamic table size update (6.3)
            uint64_t size = 0;
            if (field_seen) return kCompressionError;  // only at the start of a block (4.2)
            if (decode_integer(input + pos, input_len - pos, 5, size, used) != 0) return kCompressionError;
            if (size > limit_) return kCompressionError;
            pos += used;
            table_.set_max_size(static_cast<size_t>(size));
            continue;
        } else {  // literal without indexing / never indexed (6.2.2, 6.2.3)
            sensitive = (b & 0x10) != 0;
            if (decode_literal(input + pos, input_len - pos, 4, name, value, used) != 0) return kCompressionError;
            pos += used;
            field_seen = true;
        }
        if (produced >= max_headers) {
            too_many = true;
            continue;
        }
        temp_buffers_.emplace_back(std::move(name), std::move(value));
        HPACKHeader out;
        out.name = temp_buffers_.back().first;
        out.value = temp_buffers_.back().second;
        out.sensitive = sensitive;
        output.push_back(out);
        ++produced;
    }
    assert(pos == input_len);
    assert(temp_buffers_.size() <= max_headers);
    return too_many ? kTooManyHeaders : kOk;
}

// ============================================================================
// Encoder
// ============================================================================

HPACKEncoder::HPACKEncoder(size_t max_table_size)
    : table_size_(std::min(max_table_size, HPACKDynamicTable::kStorageBytes)),
      pending_min_(table_size_) {
    assert(table_size_ <= HPACKDynamicTable::kStorageBytes);
    assert(!pending_update_);
}

void HPACKEncoder::set_max_table_size(size_t size) noexcept {
    // Our table is always empty, so a larger peer table needs no announcement;
    // a smaller one must be acknowledged before the next field (RFC 7541 4.2).
    if (size >= table_size_) return;
    table_size_ = size;
    pending_min_ = pending_update_ ? std::min(pending_min_, size) : size;
    pending_update_ = true;
    assert(pending_min_ <= table_size_);
}

int HPACKEncoder::encode_integer(uint64_t value, int prefix_bits, uint8_t* output,
                                 size_t capacity, size_t& written) const noexcept {
    if (capacity == 0 || prefix_bits < 1 || prefix_bits > 8) return 1;
    const uint8_t mask = static_cast<uint8_t>((1u << prefix_bits) - 1);
    const uint8_t flags = static_cast<uint8_t>(output[0] & ~mask);  // caller-set high bits
    if (value < mask) {
        output[0] = static_cast<uint8_t>(flags | value);
        written = 1;
        return 0;
    }
    output[0] = static_cast<uint8_t>(flags | mask);
    value -= mask;
    size_t pos = 1;
    for (; value >= 128; ++pos) {  // at most 10 bytes for 64-bit values
        if (pos >= capacity) return 1;
        output[pos] = static_cast<uint8_t>((value & 0x7F) | 0x80);
        value >>= 7;
    }
    if (pos >= capacity) return 1;
    output[pos++] = static_cast<uint8_t>(value);
    written = pos;
    assert(written <= capacity);
    return 0;
}

int HPACKEncoder::encode_string(std::string_view str, uint8_t* output, size_t capacity,
                                size_t& written) const noexcept {
    if (capacity == 0) return 1;
    const auto* in = reinterpret_cast<const uint8_t*>(str.data());
    const size_t huff_len = str.empty() ? 0 : HuffmanEncoder::encoded_size(in, str.size());
    const bool huffman = !str.empty() && huff_len < str.size();
    const size_t payload = huffman ? huff_len : str.size();
    size_t len_bytes = 0;
    output[0] = huffman ? 0x80 : 0x00;
    if (encode_integer(payload, 7, output, capacity, len_bytes) != 0) return 1;
    if (payload > capacity - len_bytes) return 1;
    if (huffman) {
        size_t n = 0;
        if (HuffmanEncoder::encode(in, str.size(), output + len_bytes, payload, n) != 0) return 1;
        assert(n == payload);
    } else if (payload > 0) {
        std::memcpy(output + len_bytes, str.data(), payload);
    }
    written = len_bytes + payload;
    assert(written <= capacity);
    return 0;
}

int HPACKEncoder::encode(const HPACKHeader* headers, size_t count, uint8_t* output,
                         size_t output_capacity, size_t& out_written) noexcept {
    assert(headers != nullptr || count == 0);
    size_t w = 0;
    size_t n = 0;
    if (pending_update_) {
        const size_t sizes[2] = {pending_min_, table_size_};
        for (size_t i = 0; i < 2; ++i) {
            if (i == 1 && table_size_ == pending_min_) break;
            if (w >= output_capacity) return 1;
            output[w] = 0x20;
            if (encode_integer(sizes[i], 5, output + w, output_capacity - w, n) != 0) return 1;
            w += n;
        }
    }
    for (size_t i = 0; i < count; ++i) {
        const HPACKHeader& h = headers[i];
        if (w >= output_capacity) return 1;
        const size_t full = h.sensitive ? 0 : HPACKStaticTable::find(h.name, h.value);
        if (full != 0) {
            output[w] = 0x80;
            if (encode_integer(full, 7, output + w, output_capacity - w, n) != 0) return 1;
            w += n;
            continue;
        }
        const size_t name_idx = HPACKStaticTable::find_name(h.name);
        output[w] = h.sensitive ? 0x10 : 0x00;  // never indexed / without indexing
        if (encode_integer(name_idx, 4, output + w, output_capacity - w, n) != 0) return 1;
        w += n;
        if (name_idx == 0) {
            if (encode_string(h.name, output + w, output_capacity - w, n) != 0) return 1;
            w += n;
        }
        if (encode_string(h.value, output + w, output_capacity - w, n) != 0) return 1;
        w += n;
    }
    pending_update_ = false;  // only once the whole block is known to fit
    out_written = w;
    assert(out_written <= output_capacity);
    return 0;
}

} // namespace http
} // namespace bolt::api
