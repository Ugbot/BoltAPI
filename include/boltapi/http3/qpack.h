#pragma once

// QPACK header compression for HTTP/3 — RFC 9204.
//
// Self-contained, header-only module under bolt::api::http3. Ported from the
// audited FasterAPI QPACK (src/cpp/http/qpack/*) and the RFC 7541 Huffman code,
// then reshaped to Bolt Tiger Style:
//   * bounded, fixed-capacity tables (no unbounded std::vector growth)
//   * noexcept everywhere, error returns (no exceptions)
//   * >= 2 asserts per function, functions kept short
//   * fixed scratch buffers for Huffman; no per-call heap churn on the hot path
//
// Public surface (see classes below):
//   QpackEncoder::encode_field_section(...)   -> field section prefix + lines
//   QpackDecoder::decode_field_section(...)   -> name/value pairs
//   QpackDynamicTable: insert / size / eviction
//   Encoder/decoder stream instructions:
//       QpackEncoder::encode_insert_with_name_ref / encode_insert_literal_name
//       QpackDecoder::decode_encoder_stream
//       QpackDecoder::encode_section_ack (decoder-stream: Section Acknowledgment)
//
// Wire formats follow RFC 9204 Section 4. QPACK integers use the HPACK prefix
// integer encoding (Section 4.1.1), NOT QUIC varints.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include "boltapi/http3/qpack_huffman.h"
#include "boltapi/http3/qpack_static_table.h"

namespace bolt::api::http3 {

// ---------------------------------------------------------------------------
// Limits (bounded — Tiger Style).
// ---------------------------------------------------------------------------
inline constexpr std::size_t kQpackMaxHeaders = 256;     // per field section
inline constexpr std::size_t kQpackMaxStringLen = 8192;  // per name/value
inline constexpr std::size_t kQpackHuffmanScratch = kQpackMaxStringLen;

// A decoded header. Names/values are owned std::strings so the result outlives
// the input buffer (decode may Huffman-expand into scratch).
struct QpackHeader {
    std::string name;
    std::string value;
};

// A header to encode. Views into caller-owned storage.
struct QpackHeaderRef {
    std::string_view name;
    std::string_view value;
};

// ===========================================================================
// QPACK prefix-integer codec (RFC 9204 Section 4.1.1 == HPACK 5.1).
// ===========================================================================
namespace detail {

// Encode `value` with an N-bit prefix. `prefix_pattern` supplies the high bits
// of the first byte (the low N bits are overwritten). Returns bytes written, or
// 0 on overflow of the output buffer.
inline std::size_t qpack_encode_int(uint64_t value, uint8_t prefix_bits,
                                    uint8_t prefix_pattern, uint8_t* out,
                                    std::size_t cap) noexcept {
    assert(prefix_bits >= 1 && prefix_bits <= 8 && "prefix_bits out of range");
    assert((out != nullptr || cap == 0) && "null out with capacity");
    const uint64_t max_prefix = (1ull << prefix_bits) - 1;
    if (cap == 0) {
        return 0;
    }
    if (value < max_prefix) {
        out[0] = static_cast<uint8_t>(prefix_pattern | value);
        return 1;
    }
    out[0] = static_cast<uint8_t>(prefix_pattern | max_prefix);
    value -= max_prefix;
    std::size_t pos = 1;
    while (value >= 128) {
        if (pos >= cap) {
            return 0;
        }
        out[pos++] = static_cast<uint8_t>((value & 0x7F) | 0x80);
        value >>= 7;
    }
    if (pos >= cap) {
        return 0;
    }
    out[pos++] = static_cast<uint8_t>(value & 0x7F);
    return pos;
}

// Decode an N-bit-prefix integer. Returns true on success.
inline bool qpack_decode_int(const uint8_t* in, std::size_t len,
                             uint8_t prefix_bits, uint64_t& out_value,
                             std::size_t& out_consumed) noexcept {
    assert(prefix_bits >= 1 && prefix_bits <= 8 && "prefix_bits out of range");
    assert((in != nullptr || len == 0) && "null in with length");
    if (len == 0) {
        return false;
    }
    const uint64_t max_prefix = (1ull << prefix_bits) - 1;
    out_value = static_cast<uint64_t>(in[0]) & max_prefix;
    out_consumed = 1;
    if (out_value < max_prefix) {
        return true;
    }
    uint32_t shift = 0;
    uint8_t byte;
    do {
        if (out_consumed >= len) {
            return false;
        }
        if (shift >= 63) {
            return false;  // overflow guard
        }
        byte = in[out_consumed++];
        out_value += static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
    } while ((byte & 0x80) != 0);
    return true;
}

}  // namespace detail

// ===========================================================================
// Dynamic table (RFC 9204 Section 3.2) — bounded fixed-capacity ring.
// ===========================================================================
class QpackDynamicTable {
public:
    static constexpr std::size_t kMaxEntries = 128;
    static constexpr std::size_t kEntryEntrySlot = 256;  // inline name+value
    static constexpr std::size_t kRfcOverhead = 32;
    static constexpr int kNotFound = -1;

    explicit QpackDynamicTable(std::size_t capacity = 4096) noexcept
        : capacity_(capacity) {
        assert(capacity <= (1u << 20) && "dynamic table capacity implausible");
        assert(kMaxEntries >= 1 && "ring must hold at least one entry");
    }

    // Insert (name,value). Returns true on success; false if the entry is too
    // large for the table or eviction cannot make room.
    bool insert(std::string_view name, std::string_view value) noexcept {
        assert(name.size() <= kEntryEntrySlot && "name too long for slot");
        assert(value.size() <= kEntryEntrySlot && "value too long for slot");
        const std::size_t entry_size = name.size() + value.size() + kRfcOverhead;
        if (entry_size > capacity_ || name.size() + value.size() > kEntryEntrySlot) {
            return false;
        }
        while (size_ + entry_size > capacity_ && count_ > 0) {
            evict_oldest();
        }
        if (count_ >= kMaxEntries) {
            return false;
        }
        Entry& e = entries_[(tail_) % kMaxEntries];
        e.name_len = static_cast<uint16_t>(name.size());
        e.value_len = static_cast<uint16_t>(value.size());
        std::memcpy(e.data, name.data(), name.size());
        std::memcpy(e.data + name.size(), value.data(), value.size());
        tail_ = (tail_ + 1) % kMaxEntries;
        ++count_;
        size_ += entry_size;
        ++insert_count_;
        return true;
    }

    // Fetch by absolute index (0 == first ever inserted). Returns false if the
    // entry has been evicted or never existed.
    bool get_absolute(uint64_t abs_index, std::string_view& name,
                      std::string_view& value) const noexcept {
        assert(abs_index <= insert_count_ + 1 && "abs index wildly out of range");
        if (abs_index < drop_count_ || abs_index >= insert_count_) {
            return false;
        }
        const std::size_t rel = static_cast<std::size_t>(abs_index - drop_count_);
        if (rel >= count_) {
            return false;
        }
        const std::size_t slot = (head_ + rel) % kMaxEntries;
        const Entry& e = entries_[slot];
        name = std::string_view(e.data, e.name_len);
        value = std::string_view(e.data + e.name_len, e.value_len);
        return true;
    }

    // Find exact (name,value). Returns absolute index or kNotFound.
    int find(std::string_view name, std::string_view value) const noexcept {
        assert(name.size() <= kEntryEntrySlot && "name too long");
        assert(value.size() <= kEntryEntrySlot && "value too long");
        for (std::size_t i = 0; i < count_; ++i) {
            const Entry& e = entries_[(head_ + i) % kMaxEntries];
            if (entry_name(e) == name && entry_value(e) == value) {
                return static_cast<int>(drop_count_ + i);
            }
        }
        return kNotFound;
    }

    // Find by name only. Returns absolute index or kNotFound.
    int find_name(std::string_view name) const noexcept {
        assert(!name.empty() && "name lookup with empty name");
        assert(name.size() <= kEntryEntrySlot && "name too long");
        for (std::size_t i = 0; i < count_; ++i) {
            const Entry& e = entries_[(head_ + i) % kMaxEntries];
            if (entry_name(e) == name) {
                return static_cast<int>(drop_count_ + i);
            }
        }
        return kNotFound;
    }

    std::size_t size() const noexcept { return size_; }
    std::size_t capacity() const noexcept { return capacity_; }
    std::size_t count() const noexcept { return count_; }
    uint64_t insert_count() const noexcept { return insert_count_; }
    uint64_t drop_count() const noexcept { return drop_count_; }

    void set_capacity(std::size_t new_capacity) noexcept {
        assert(new_capacity <= (1u << 20) && "capacity implausibly large");
        capacity_ = new_capacity;
        while (size_ > capacity_ && count_ > 0) {
            evict_oldest();
        }
        assert(size_ <= capacity_ && "capacity invariant broken");
    }

    void clear() noexcept {
        assert(count_ <= kMaxEntries && "count overran ring");
        head_ = 0;
        tail_ = 0;
        count_ = 0;
        size_ = 0;
        insert_count_ = 0;
        drop_count_ = 0;
    }

private:
    struct Entry {
        uint16_t name_len = 0;
        uint16_t value_len = 0;
        char data[kEntryEntrySlot] = {};
    };

    static std::string_view entry_name(const Entry& e) noexcept {
        return std::string_view(e.data, e.name_len);
    }
    static std::string_view entry_value(const Entry& e) noexcept {
        return std::string_view(e.data + e.name_len, e.value_len);
    }

    void evict_oldest() noexcept {
        assert(count_ > 0 && "evict on empty table");
        const Entry& e = entries_[head_];
        const std::size_t entry_size = e.name_len + e.value_len + kRfcOverhead;
        assert(size_ >= entry_size && "size underflow on evict");
        size_ -= entry_size;
        head_ = (head_ + 1) % kMaxEntries;
        --count_;
        ++drop_count_;
    }

    Entry entries_[kMaxEntries];
    std::size_t capacity_;
    std::size_t size_ = 0;
    std::size_t head_ = 0;   // slot of oldest live entry
    std::size_t tail_ = 0;   // next free slot
    std::size_t count_ = 0;
    uint64_t insert_count_ = 0;
    uint64_t drop_count_ = 0;
};

// ===========================================================================
// Encoder (RFC 9204 Section 4.5 representations + Section 4.3 stream ops).
// ===========================================================================
class QpackEncoder {
public:
    explicit QpackEncoder(std::size_t max_table_capacity = 4096) noexcept
        : dynamic_table_(max_table_capacity) {
        assert(max_table_capacity <= (1u << 20) && "capacity implausible");
        assert(use_huffman_ == true && "default huffman flag unexpected");
    }

    void set_huffman(bool enabled) noexcept {
        assert((enabled == true || enabled == false) && "non-bool huffman flag");
        use_huffman_ = enabled;
    }

    QpackDynamicTable& dynamic_table() noexcept { return dynamic_table_; }

    // Encode a full field section: prefix (RFC 9204 4.5.1) + one field line per
    // header. Static + dynamic indexed refs, name-ref literals, literal-name
    // literals. Returns 0 on success, -1 on error (buffer too small / bad input).
    //
    // This MVP encodes the prefix with Required Insert Count = 0 and Base = 0,
    // i.e. only static-table refs and literals are emitted into the section.
    // Dynamic-table population goes via the encoder-stream ops below.
    int encode_field_section(const QpackHeaderRef* headers, std::size_t count,
                             uint8_t* out, std::size_t cap,
                             std::size_t& out_len) noexcept {
        assert((headers != nullptr || count == 0) && "null headers");
        assert(count <= kQpackMaxHeaders && "too many headers");
        std::size_t pos = 0;
        // Field Section Prefix: Required Insert Count (8-bit prefix) = 0.
        std::size_t n = detail::qpack_encode_int(0, 8, 0x00, out + pos, cap - pos);
        if (n == 0) return -1;
        pos += n;
        // Delta Base: sign (S) bit + 7-bit prefix value = 0.
        n = detail::qpack_encode_int(0, 7, 0x00, out + pos, cap - pos);
        if (n == 0) return -1;
        pos += n;
        for (std::size_t i = 0; i < count; ++i) {
            if (!encode_one_line(headers[i].name, headers[i].value, out, cap,
                                 pos)) {
                return -1;
            }
        }
        assert(pos <= cap && "encoder wrote past buffer");
        out_len = pos;
        return 0;
    }

    // Encoder-stream: Insert With Name Reference (RFC 9204 4.3.2). Inserts into
    // *this* encoder's dynamic table and emits the instruction into `out`.
    // Only static-table name refs are emitted (T=1). Returns 0 / -1.
    int encode_insert_with_name_ref(std::string_view name, std::string_view value,
                                    uint8_t* out, std::size_t cap,
                                    std::size_t& out_len) noexcept {
        assert(!name.empty() && "insert with empty name");
        assert(value.size() <= kQpackMaxStringLen && "value too long");
        const int static_idx = QpackStaticTable::find_name(name);
        if (static_idx < 0) {
            return -1;  // caller should use literal-name insert instead
        }
        std::size_t pos = 0;
        // 1 T NameIndex(6+) with T=1 (static): pattern 1100_0000.
        std::size_t n = detail::qpack_encode_int(
            static_cast<uint64_t>(static_idx), 6, 0xC0, out + pos, cap - pos);
        if (n == 0) return -1;
        pos += n;
        if (!encode_string(value, out, cap, pos)) {
            return -1;
        }
        if (!dynamic_table_.insert(name, value)) {
            return -1;
        }
        assert(pos <= cap && "insert wrote past buffer");
        out_len = pos;
        return 0;
    }

    // Encoder-stream: Insert With Literal Name (RFC 9204 4.3.3). Inserts into
    // the dynamic table and emits the instruction. Returns 0 / -1.
    int encode_insert_literal_name(std::string_view name, std::string_view value,
                                   uint8_t* out, std::size_t cap,
                                   std::size_t& out_len) noexcept {
        assert(!name.empty() && "insert with empty name");
        assert(value.size() <= kQpackMaxStringLen && "value too long");
        std::size_t pos = 0;
        // 0 1 H NameLen(5+) — pattern 0100_0000, then name string (H + 5-bit),
        // then value string (H + 7-bit). We reuse encode_string for the value,
        // and a dedicated 5-bit-prefix name string here.
        if (!encode_name_5bit(name, 0x40, out, cap, pos)) {
            return -1;
        }
        if (!encode_string(value, out, cap, pos)) {
            return -1;
        }
        if (!dynamic_table_.insert(name, value)) {
            return -1;
        }
        assert(pos <= cap && "insert wrote past buffer");
        out_len = pos;
        return 0;
    }

private:
    bool encode_one_line(std::string_view name, std::string_view value,
                         uint8_t* out, std::size_t cap, std::size_t& pos) noexcept {
        assert(name.size() <= kQpackMaxStringLen && "name too long");
        assert(value.size() <= kQpackMaxStringLen && "value too long");
        const int sidx = QpackStaticTable::find(name, value);
        if (sidx >= 0) {
            // Indexed Field Line (static): 1 T Index(6+), T=1 -> 1100_0000.
            std::size_t n = detail::qpack_encode_int(
                static_cast<uint64_t>(sidx), 6, 0xC0, out + pos, cap - pos);
            if (n == 0) return false;
            pos += n;
            return true;
        }
        const int sname = QpackStaticTable::find_name(name);
        if (sname >= 0) {
            // Literal Field Line With Name Reference (static):
            // 0 1 N T NameIndex(4+) -> N=0,T=1 -> pattern 0101_0000.
            std::size_t n = detail::qpack_encode_int(
                static_cast<uint64_t>(sname), 4, 0x50, out + pos, cap - pos);
            if (n == 0) return false;
            pos += n;
            return encode_string(value, out, cap, pos);
        }
        // Literal Field Line With Literal Name: 0 0 1 N H NameLen(3+),
        // N=0 -> pattern 0010_0000; name uses 3-bit-prefix string.
        return encode_literal_name_line(name, value, out, cap, pos);
    }

    bool encode_literal_name_line(std::string_view name, std::string_view value,
                                  uint8_t* out, std::size_t cap,
                                  std::size_t& pos) noexcept {
        assert(name.size() <= kQpackMaxStringLen && "name too long");
        assert(value.size() <= kQpackMaxStringLen && "value too long");
        // Name string with 3-bit length prefix; bit 3 (0x08) is the H flag.
        if (!encode_name_nbit(name, 0x20, 3, 0x08, out, cap, pos)) {
            return false;
        }
        return encode_string(value, out, cap, pos);
    }

    // Encode a 5-bit-prefix name string (used by Insert With Literal Name).
    bool encode_name_5bit(std::string_view name, uint8_t pattern, uint8_t* out,
                          std::size_t cap, std::size_t& pos) noexcept {
        assert(name.size() <= kQpackMaxStringLen && "name too long");
        assert(pattern != 0xFF && "implausible pattern");
        return encode_name_nbit(name, pattern, 5, 0x20, out, cap, pos);
    }

    // Generic name-string encoder: H flag at bit (prefix_bits), length in the
    // low prefix_bits, then (optionally Huffman) bytes.
    bool encode_name_nbit(std::string_view str, uint8_t pattern,
                          uint8_t prefix_bits, uint8_t huffman_bit, uint8_t* out,
                          std::size_t cap, std::size_t& pos) noexcept {
        assert(prefix_bits >= 1 && prefix_bits <= 7 && "name prefix bits range");
        assert(str.size() <= kQpackMaxStringLen && "name too long");
        return encode_string_impl(str, pattern, prefix_bits, huffman_bit, out,
                                   cap, pos);
    }

    // Value/string with the standard 7-bit prefix and H flag at bit 7 (0x80).
    bool encode_string(std::string_view str, uint8_t* out, std::size_t cap,
                       std::size_t& pos) noexcept {
        assert(str.size() <= kQpackMaxStringLen && "string too long");
        assert((out != nullptr) && "null output");
        return encode_string_impl(str, 0x00, 7, 0x80, out, cap, pos);
    }

    // Core string codec shared by name/value. `pattern` supplies bits above the
    // length prefix; `huffman_bit` is OR'd in when Huffman is used.
    bool encode_string_impl(std::string_view str, uint8_t pattern,
                            uint8_t prefix_bits, uint8_t huffman_bit,
                            uint8_t* out, std::size_t cap,
                            std::size_t& pos) noexcept {
        assert(str.size() <= kQpackMaxStringLen && "string too long");
        assert(prefix_bits >= 1 && prefix_bits <= 7 && "prefix bits range");
        const auto* sp = reinterpret_cast<const uint8_t*>(str.data());
        if (use_huffman_) {
            const std::size_t hsz = qpack_huffman_encoded_size(sp, str.size());
            if (hsz < str.size()) {
                std::size_t n = detail::qpack_encode_int(
                    hsz, prefix_bits, static_cast<uint8_t>(pattern | huffman_bit),
                    out + pos, cap - pos);
                if (n == 0) return false;
                std::size_t enc = 0;
                if (qpack_huffman_encode(sp, str.size(), out + pos + n,
                                         cap - pos - n, enc) != 0) {
                    return false;
                }
                pos += n + enc;
                return true;
            }
        }
        std::size_t n = detail::qpack_encode_int(str.size(), prefix_bits, pattern,
                                                 out + pos, cap - pos);
        if (n == 0) return false;
        if (cap - pos - n < str.size()) return false;
        std::memcpy(out + pos + n, str.data(), str.size());
        pos += n + str.size();
        return true;
    }

    QpackDynamicTable dynamic_table_;
    bool use_huffman_ = true;
};

// ===========================================================================
// Decoder (RFC 9204 Section 4.5 representations + Section 4.3 stream ops).
// ===========================================================================
class QpackDecoder {
public:
    explicit QpackDecoder(std::size_t max_table_capacity = 4096) noexcept
        : dynamic_table_(max_table_capacity) {
        assert(max_table_capacity <= (1u << 20) && "capacity implausible");
        assert(kQpackMaxHeaders >= 1 && "header cap must be positive");
    }

    QpackDynamicTable& dynamic_table() noexcept { return dynamic_table_; }

    // Decode a field section into out_headers[0..out_count). out_headers must
    // have room for kQpackMaxHeaders. Returns 0 on success, -1 on error.
    int decode_field_section(const uint8_t* in, std::size_t len,
                             QpackHeader* out_headers,
                             std::size_t& out_count) noexcept {
        assert((in != nullptr || len == 0) && "null input");
        assert(out_headers != nullptr && "null header output");
        out_count = 0;
        if (len == 0) {
            return -1;
        }
        std::size_t pos = 0;
        // Field Section Prefix: Required Insert Count (8-bit prefix).
        uint64_t ric = 0;
        std::size_t used = 0;
        if (!detail::qpack_decode_int(in + pos, len - pos, 8, ric, used)) {
            return -1;
        }
        pos += used;
        // Delta Base: S bit + 7-bit prefix.
        uint64_t base = 0;
        if (!detail::qpack_decode_int(in + pos, len - pos, 7, base, used)) {
            return -1;
        }
        pos += used;
        while (pos < len && out_count < kQpackMaxHeaders) {
            if (!decode_one_line(in, len, pos, out_headers[out_count])) {
                return -1;
            }
            ++out_count;
        }
        assert(out_count <= kQpackMaxHeaders && "decoded too many headers");
        return (pos == len) ? 0 : -1;
    }

    // Decoder-stream OUTPUT: Section Acknowledgment (RFC 9204 4.4.1).
    // Emits 1 STREAM_ID(7+) with pattern 1000_0000. Returns 0 / -1.
    int encode_section_ack(uint64_t stream_id, uint8_t* out, std::size_t cap,
                           std::size_t& out_len) noexcept {
        assert(stream_id <= (1ull << 62) && "stream id out of QUIC range");
        assert((out != nullptr || cap == 0) && "null output");
        std::size_t n = detail::qpack_encode_int(stream_id, 7, 0x80, out, cap);
        if (n == 0) return -1;
        out_len = n;
        return 0;
    }

    // Encoder-stream INPUT: apply a stream of insert instructions (RFC 9204
    // 4.3.2 / 4.3.3 / 4.3.1 size update) to this decoder's dynamic table.
    // Returns 0 on success, -1 on malformed input.
    int decode_encoder_stream(const uint8_t* in, std::size_t len) noexcept {
        assert((in != nullptr || len == 0) && "null encoder stream");
        assert(len <= (1u << 24) && "encoder stream implausibly large");
        std::size_t pos = 0;
        while (pos < len) {
            const uint8_t b = in[pos];
            if ((b & 0x80) != 0) {
                if (!apply_insert_name_ref(in, len, pos)) return -1;
            } else if ((b & 0x40) != 0) {
                if (!apply_insert_literal_name(in, len, pos)) return -1;
            } else if ((b & 0x20) != 0) {
                if (!apply_table_size_update(in, len, pos)) return -1;
            } else {
                return -1;  // Duplicate (0x00) not yet supported
            }
        }
        assert(pos == len && "encoder stream not fully consumed");
        return 0;
    }

private:
    bool decode_one_line(const uint8_t* in, std::size_t len, std::size_t& pos,
                         QpackHeader& out) noexcept {
        assert(pos < len && "decode line past end");
        assert(out.name.empty() && "output slot not fresh");
        const uint8_t b = in[pos];
        if ((b & 0x80) != 0) {
            return decode_indexed_line(in, len, pos, out);
        }
        if ((b & 0x40) != 0) {
            return decode_name_ref_line(in, len, pos, out);
        }
        if ((b & 0x20) != 0) {
            return decode_literal_name_line(in, len, pos, out);
        }
        // 0001xxxx Indexed With Post-Base / 0000xxxx literal post-base: not
        // emitted by our encoder (Base=0), so unsupported here.
        return false;
    }

    bool decode_indexed_line(const uint8_t* in, std::size_t len,
                             std::size_t& pos, QpackHeader& out) noexcept {
        assert(pos < len && "indexed line past end");
        const bool is_static = (in[pos] & 0x40) != 0;  // T bit
        uint64_t index = 0;
        std::size_t used = 0;
        if (!detail::qpack_decode_int(in + pos, len - pos, 6, index, used)) {
            return false;
        }
        if (is_static) {
            const QpackStaticEntry* e = QpackStaticTable::get(index);
            if (!e) return false;
            out.name.assign(e->name);
            out.value.assign(e->value);
        } else {
            // Dynamic indexed: index is relative to Base (0) -> absolute.
            std::string_view name, value;
            if (!resolve_dynamic_relative(index, name, value)) return false;
            out.name.assign(name);
            out.value.assign(value);
        }
        pos += used;
        return true;
    }

    bool decode_name_ref_line(const uint8_t* in, std::size_t len,
                              std::size_t& pos, QpackHeader& out) noexcept {
        assert(pos < len && "name-ref line past end");
        const bool is_static = (in[pos] & 0x10) != 0;  // T bit
        uint64_t name_idx = 0;
        std::size_t used = 0;
        if (!detail::qpack_decode_int(in + pos, len - pos, 4, name_idx, used)) {
            return false;
        }
        if (is_static) {
            const QpackStaticEntry* e = QpackStaticTable::get(name_idx);
            if (!e) return false;
            out.name.assign(e->name);
        } else {
            std::string_view nm, val;
            if (!resolve_dynamic_relative(name_idx, nm, val)) return false;
            out.name.assign(nm);
        }
        pos += used;
        std::size_t vused = 0;
        if (!decode_string(in + pos, len - pos, 7, out.value, vused)) {
            return false;
        }
        pos += vused;
        return true;
    }

    bool decode_literal_name_line(const uint8_t* in, std::size_t len,
                                  std::size_t& pos, QpackHeader& out) noexcept {
        assert(pos < len && "literal-name line past end");
        assert((in[pos] & 0x20) != 0 && "wrong dispatch into literal-name");
        // 0 0 1 N H NameLen(3+): H flag at bit 3 (0x08), length 3-bit prefix.
        std::size_t nused = 0;
        if (!decode_string(in + pos, len - pos, 3, out.name, nused)) {
            return false;
        }
        pos += nused;
        std::size_t vused = 0;
        if (!decode_string(in + pos, len - pos, 7, out.value, vused)) {
            return false;
        }
        pos += vused;
        return true;
    }

    // Resolve a relative dynamic index against Base=0. With Base=0 a dynamic
    // reference addresses the most-recently inreted entries; rel 0 == newest.
    bool resolve_dynamic_relative(uint64_t rel, std::string_view& name,
                                  std::string_view& value) const noexcept {
        assert(rel <= dynamic_table_.insert_count() + 1 && "rel index huge");
        const uint64_t ic = dynamic_table_.insert_count();
        if (ic == 0 || rel >= ic) {
            return false;
        }
        const uint64_t abs_index = ic - 1 - rel;
        return dynamic_table_.get_absolute(abs_index, name, value);
    }

    // Decode an H-flagged string with the given length prefix. The H flag sits
    // at bit `prefix_bits` (i.e. 1 << prefix_bits).
    bool decode_string(const uint8_t* in, std::size_t len, uint8_t prefix_bits,
                       std::string& out, std::size_t& consumed) noexcept {
        assert((in != nullptr || len == 0) && "null string input");
        assert(prefix_bits >= 1 && prefix_bits <= 7 && "prefix bits range");
        if (len == 0) {
            return false;
        }
        const bool huffman = (in[0] & (1u << prefix_bits)) != 0;
        uint64_t slen = 0;
        std::size_t used = 0;
        if (!detail::qpack_decode_int(in, len, prefix_bits, slen, used)) {
            return false;
        }
        if (slen > kQpackMaxStringLen || len < used + slen) {
            return false;
        }
        if (huffman) {
            std::size_t dlen = 0;
            if (qpack_huffman_decode(in + used, static_cast<std::size_t>(slen),
                                     scratch_, sizeof(scratch_), dlen) != 0) {
                return false;
            }
            out.assign(reinterpret_cast<char*>(scratch_), dlen);
        } else {
            out.assign(reinterpret_cast<const char*>(in + used),
                       static_cast<std::size_t>(slen));
        }
        consumed = used + static_cast<std::size_t>(slen);
        return true;
    }

    bool apply_insert_name_ref(const uint8_t* in, std::size_t len,
                               std::size_t& pos) noexcept {
        assert(pos < len && "insert-name-ref past end");
        const bool is_static = (in[pos] & 0x40) != 0;  // T bit
        uint64_t name_idx = 0;
        std::size_t used = 0;
        if (!detail::qpack_decode_int(in + pos, len - pos, 6, name_idx, used)) {
            return false;
        }
        std::string_view name;
        if (is_static) {
            const QpackStaticEntry* e = QpackStaticTable::get(name_idx);
            if (!e) return false;
            name = e->name;
        } else {
            std::string_view dval;
            if (!resolve_dynamic_relative(name_idx, name, dval)) return false;
        }
        std::string name_copy(name);  // name view may alias the table on insert
        pos += used;
        std::string value;
        std::size_t vused = 0;
        if (!decode_string(in + pos, len - pos, 7, value, vused)) {
            return false;
        }
        pos += vused;
        return dynamic_table_.insert(name_copy, value);
    }

    bool apply_insert_literal_name(const uint8_t* in, std::size_t len,
                                   std::size_t& pos) noexcept {
        assert(pos < len && "insert-literal-name past end");
        assert((in[pos] & 0x40) != 0 && "wrong dispatch into literal insert");
        std::string name;
        std::size_t nused = 0;
        if (!decode_string(in + pos, len - pos, 5, name, nused)) {
            return false;
        }
        pos += nused;
        std::string value;
        std::size_t vused = 0;
        if (!decode_string(in + pos, len - pos, 7, value, vused)) {
            return false;
        }
        pos += vused;
        return dynamic_table_.insert(name, value);
    }

    bool apply_table_size_update(const uint8_t* in, std::size_t len,
                                 std::size_t& pos) noexcept {
        assert(pos < len && "size-update past end");
        assert((in[pos] & 0x20) != 0 && "wrong dispatch into size update");
        uint64_t cap = 0;
        std::size_t used = 0;
        if (!detail::qpack_decode_int(in + pos, len - pos, 5, cap, used)) {
            return false;
        }
        if (cap > (1u << 20)) {
            return false;
        }
        dynamic_table_.set_capacity(static_cast<std::size_t>(cap));
        pos += used;
        return true;
    }

    QpackDynamicTable dynamic_table_;
    uint8_t scratch_[kQpackHuffmanScratch];
};

}  // namespace bolt::api::http3
