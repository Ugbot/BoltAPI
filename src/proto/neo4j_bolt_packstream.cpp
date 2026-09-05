// src/proto/neo4j_bolt_packstream.cpp — PackStream v2 encode/decode.
//
// Compiled ONLY under BOLTAPI_WITH_NEO4J_BOLT (see root CMakeLists). "Bolt"
// here is Neo4j's CLIENT WIRE PROTOCOL, not extern/bolt (our columnar core).
//
// Byte layout follows the published PackStream v2 specification; the golden
// tests in tests/neo4j_bolt_packstream_test.cpp pin every marker against
// vectors taken from that spec, so a drift here fails loudly.

#include "boltapi/proto/packstream.h"

#if defined(BOLTAPI_WITH_NEO4J_BOLT)

namespace bolt::api {
namespace proto {
namespace packstream {
namespace {

// --- big-endian helpers ----------------------------------------------------
inline void store_be(std::uint8_t* d, std::uint64_t v, std::size_t width) noexcept {
    assert(width >= 1 && width <= 8);
    assert(d != nullptr);
    for (std::size_t k = 0; k < width; ++k) {
        d[k] = static_cast<std::uint8_t>(v >> (8 * (width - 1 - k)));
    }
}

inline std::uint64_t load_be(const std::uint8_t* s, std::size_t width) noexcept {
    assert(width >= 1 && width <= 8);
    assert(s != nullptr);
    std::uint64_t v = 0;
    for (std::size_t k = 0; k < width; ++k) v = (v << 8) | s[k];
    return v;
}

inline double bits_to_double(std::uint64_t bits) noexcept {
    double d = 0.0;
    static_assert(sizeof(double) == 8, "PackStream float64 requires an 8-byte double");
    std::memcpy(&d, &bits, 8);
    return d;
}

inline std::uint64_t double_to_bits(double d) noexcept {
    std::uint64_t bits = 0;
    static_assert(sizeof(double) == 8, "PackStream float64 requires an 8-byte double");
    std::memcpy(&bits, &d, 8);
    return bits;
}

// Marker constants, named so the encoder and decoder cannot drift apart.
constexpr std::uint8_t kNull    = 0xC0;
constexpr std::uint8_t kFloat64 = 0xC1;
constexpr std::uint8_t kFalse   = 0xC2;
constexpr std::uint8_t kTrue    = 0xC3;
constexpr std::uint8_t kInt8    = 0xC8;
constexpr std::uint8_t kInt16   = 0xC9;
constexpr std::uint8_t kInt32   = 0xCA;
constexpr std::uint8_t kInt64   = 0xCB;
constexpr std::uint8_t kBytes8  = 0xCC;
constexpr std::uint8_t kBytes16 = 0xCD;
constexpr std::uint8_t kBytes32 = 0xCE;
constexpr std::uint8_t kStr8    = 0xD0;
constexpr std::uint8_t kStr16   = 0xD1;
constexpr std::uint8_t kStr32   = 0xD2;
constexpr std::uint8_t kList8   = 0xD4;
constexpr std::uint8_t kList16  = 0xD5;
constexpr std::uint8_t kList32  = 0xD6;
constexpr std::uint8_t kDict8   = 0xD8;
constexpr std::uint8_t kDict16  = 0xD9;
constexpr std::uint8_t kDict32  = 0xDA;
// 0xDC / 0xDD were PackStream v1's STRUCT_8 / STRUCT_16. v2 caps a structure at
// 15 fields (B0..BF only); we refuse them by name rather than guess.
constexpr std::uint8_t kStructRemoved8  = 0xDC;
constexpr std::uint8_t kStructRemoved16 = 0xDD;

}  // namespace

const char* pack_error_name(PackError e) noexcept {
    switch (e) {
        case PackError::Ok:            return "ok";
        case PackError::Truncated:     return "truncated";
        case PackError::BadMarker:     return "bad_marker";
        case PackError::Overflow:      return "buffer_overflow";
        case PackError::DepthExceeded: return "depth_exceeded";
        case PackError::TooLarge:      return "too_large";
        case PackError::OutOfMemory:   return "arena_exhausted";
        case PackError::Unsupported:   return "unsupported_marker";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// PackValue accessors
// ---------------------------------------------------------------------------
const PackValue* PackValue::find(std::string_view key) const noexcept {
    if (type != PackType::Dict || pairs == nullptr) return nullptr;
    assert(len <= kMaxElements);
    for (std::uint32_t k = 0; k < len; ++k) {
        if (pairs[k].key_view() == key) {
            assert(pairs[k].value != nullptr);
            return pairs[k].value;
        }
    }
    return nullptr;
}

std::string_view PackValue::find_str(std::string_view key) const noexcept {
    const PackValue* v = find(key);
    if (v == nullptr || v->type != PackType::String) return std::string_view();
    return v->str();
}

std::int64_t PackValue::find_int(std::string_view key, std::int64_t fallback) const noexcept {
    const PackValue* v = find(key);
    if (v == nullptr || v->type != PackType::Int) return fallback;
    return v->i;
}

// ---------------------------------------------------------------------------
// PackWriter
// ---------------------------------------------------------------------------
PackError PackWriter::raw(const void* p, std::size_t n) noexcept {
    assert(p != nullptr || n == 0);
    assert(n_ <= cap_);
    if (n > cap_ - n_) { overflow_ = true; return PackError::Overflow; }
    if (n != 0) std::memcpy(buf_ + n_, p, n);
    n_ += n;
    return PackError::Ok;
}

PackError PackWriter::byte(std::uint8_t b) noexcept {
    assert(n_ <= cap_);
    if (n_ == cap_) { overflow_ = true; return PackError::Overflow; }
    buf_[n_++] = b;
    assert(n_ <= cap_);
    return PackError::Ok;
}

PackError PackWriter::put_null() noexcept { return byte(kNull); }

PackError PackWriter::put_bool(bool v) noexcept { return byte(v ? kTrue : kFalse); }

PackError PackWriter::put_int(std::int64_t v) noexcept {
    assert(n_ <= cap_);
    std::uint8_t tmp[9];
    std::size_t w = 0;
    if (v >= -16 && v <= 127) {
        tmp[0] = static_cast<std::uint8_t>(static_cast<std::int8_t>(v));
        w = 1;
    } else if (v >= -128 && v <= 127) {
        tmp[0] = kInt8;
        tmp[1] = static_cast<std::uint8_t>(static_cast<std::int8_t>(v));
        w = 2;
    } else if (v >= -32768 && v <= 32767) {
        tmp[0] = kInt16;
        store_be(tmp + 1, static_cast<std::uint64_t>(static_cast<std::uint16_t>(v)), 2);
        w = 3;
    } else if (v >= -2147483648LL && v <= 2147483647LL) {
        tmp[0] = kInt32;
        store_be(tmp + 1, static_cast<std::uint64_t>(static_cast<std::uint32_t>(v)), 4);
        w = 5;
    } else {
        tmp[0] = kInt64;
        store_be(tmp + 1, static_cast<std::uint64_t>(v), 8);
        w = 9;
    }
    assert(w >= 1 && w <= 9);
    return raw(tmp, w);
}

PackError PackWriter::put_float(double v) noexcept {
    std::uint8_t tmp[9];
    tmp[0] = kFloat64;
    store_be(tmp + 1, double_to_bits(v), 8);
    assert(tmp[0] == kFloat64);
    return raw(tmp, 9);
}

// Shared header emitter for the string / bytes / list / dict families. `tiny`
// is the tiny-marker base (0 when the family has none, i.e. Bytes).
static PackError put_sized_header(std::uint8_t* tmp, std::size_t& out_w,
                                  std::uint32_t n, std::uint8_t tiny,
                                  std::uint8_t m8, std::uint8_t m16, std::uint8_t m32,
                                  std::uint32_t limit) noexcept {
    assert(tmp != nullptr);
    assert(limit != 0);
    if (n > limit) return PackError::TooLarge;
    if (tiny != 0 && n <= 0x0F) {
        tmp[0] = static_cast<std::uint8_t>(tiny | n);
        out_w = 1;
    } else if (n <= 0xFF) {
        tmp[0] = m8;  tmp[1] = static_cast<std::uint8_t>(n);      out_w = 2;
    } else if (n <= 0xFFFF) {
        tmp[0] = m16; store_be(tmp + 1, n, 2);                    out_w = 3;
    } else {
        tmp[0] = m32; store_be(tmp + 1, n, 4);                    out_w = 5;
    }
    assert(out_w >= 1 && out_w <= 5);
    return PackError::Ok;
}

PackError PackWriter::put_string(std::string_view s) noexcept {
    if (s.size() > kMaxStringBytes) return PackError::TooLarge;
    std::uint8_t tmp[5];
    std::size_t hw = 0;
    const PackError e = put_sized_header(tmp, hw,
                                         static_cast<std::uint32_t>(s.size()),
                                         0x80, kStr8, kStr16, kStr32, kMaxStringBytes);
    if (e != PackError::Ok) return e;
    const PackError e2 = raw(tmp, hw);
    if (e2 != PackError::Ok) return e2;
    return raw(s.data(), s.size());
}

PackError PackWriter::put_bytes(const void* p, std::size_t n) noexcept {
    assert(p != nullptr || n == 0);
    if (n > kMaxStringBytes) return PackError::TooLarge;
    std::uint8_t tmp[5];
    std::size_t hw = 0;
    const PackError e = put_sized_header(tmp, hw, static_cast<std::uint32_t>(n),
                                         0, kBytes8, kBytes16, kBytes32, kMaxStringBytes);
    if (e != PackError::Ok) return e;
    const PackError e2 = raw(tmp, hw);
    if (e2 != PackError::Ok) return e2;
    return raw(p, n);
}

PackError PackWriter::begin_list(std::uint32_t n) noexcept {
    std::uint8_t tmp[5];
    std::size_t hw = 0;
    const PackError e = put_sized_header(tmp, hw, n, 0x90,
                                         kList8, kList16, kList32, kMaxElements);
    if (e != PackError::Ok) return e;
    assert(hw >= 1 && hw <= 5);
    return raw(tmp, hw);
}

PackError PackWriter::begin_dict(std::uint32_t n) noexcept {
    std::uint8_t tmp[5];
    std::size_t hw = 0;
    const PackError e = put_sized_header(tmp, hw, n, 0xA0,
                                         kDict8, kDict16, kDict32, kMaxElements);
    if (e != PackError::Ok) return e;
    assert(hw >= 1 && hw <= 5);
    return raw(tmp, hw);
}

PackError PackWriter::begin_struct(std::uint8_t signature, std::uint8_t n_fields) noexcept {
    // PackStream v2 caps a structure at 15 fields. This is a CAPACITY bound, so
    // it is a runtime refusal and not an assert: this tree ships Release with
    // asserts live but RelWithDebInfo/MinSizeRel with -DNDEBUG, and a bound that
    // only holds in one of them is not a bound (the G2GRAPH-27 lesson).
    if (n_fields > 15) return PackError::TooLarge;
    std::uint8_t tmp[2];
    tmp[0] = static_cast<std::uint8_t>(0xB0 | n_fields);
    tmp[1] = signature;
    assert(tmp[0] >= 0xB0 && tmp[0] <= 0xBF);  // the only v2 structure markers
    return raw(tmp, 2);
}

PackError PackWriter::put_value(const PackValue& v) noexcept { return put_value_at(v, 0); }

PackError PackWriter::put_value_at(const PackValue& v, std::uint32_t depth) noexcept {
    assert(depth <= kMaxDepth);
    if (depth >= kMaxDepth) return PackError::DepthExceeded;
    switch (v.type) {
        case PackType::Null:   return put_null();
        case PackType::Bool:   return put_bool(v.b);
        case PackType::Int:    return put_int(v.i);
        case PackType::Float:  return put_float(v.f);
        case PackType::String: return put_string(v.str());
        case PackType::Bytes:  return put_bytes(v.bytes, v.len);
        case PackType::List:
        case PackType::Struct: {
            PackError e = (v.type == PackType::List)
                              ? begin_list(v.len)
                              : begin_struct(v.signature, static_cast<std::uint8_t>(v.len));
            if (e != PackError::Ok) return e;
            for (std::uint32_t k = 0; k < v.len; ++k) {
                assert(v.items != nullptr);
                e = put_value_at(v.items[k], depth + 1);
                if (e != PackError::Ok) return e;
            }
            return PackError::Ok;
        }
        case PackType::Dict: {
            PackError e = begin_dict(v.len);
            if (e != PackError::Ok) return e;
            for (std::uint32_t k = 0; k < v.len; ++k) {
                assert(v.pairs != nullptr && v.pairs[k].value != nullptr);
                e = put_string(v.pairs[k].key_view());
                if (e != PackError::Ok) return e;
                e = put_value_at(*v.pairs[k].value, depth + 1);
                if (e != PackError::Ok) return e;
            }
            return PackError::Ok;
        }
    }
    return PackError::BadMarker;
}

// ---------------------------------------------------------------------------
// PackReader
// ---------------------------------------------------------------------------
PackError PackReader::take(std::size_t n, const std::uint8_t*& out) noexcept {
    assert(off_ <= n_);
    if (n > n_ - off_) return PackError::Truncated;
    out = p_ + off_;
    off_ += n;
    assert(off_ <= n_);
    return PackError::Ok;
}

PackError PackReader::take_uint(std::size_t width, std::uint64_t& out) noexcept {
    assert(width >= 1 && width <= 8);
    const std::uint8_t* s = nullptr;
    const PackError e = take(width, s);
    if (e != PackError::Ok) return e;
    out = load_be(s, width);
    return PackError::Ok;
}

PackError PackReader::read_container(PackValue& out, std::uint32_t depth,
                                     PackType kind, std::uint32_t count) noexcept {
    assert(kind == PackType::List || kind == PackType::Dict || kind == PackType::Struct);
    if (count > kMaxElements) return PackError::TooLarge;
    out.type = kind;
    out.len  = count;
    if (kind == PackType::Dict) {
        out.pairs = (count == 0) ? nullptr : arena_.alloc_n<PackPair>(count);
        if (count != 0 && out.pairs == nullptr) return PackError::OutOfMemory;
        for (std::uint32_t k = 0; k < count; ++k) {
            PackValue key{};
            PackError e = read_at(key, depth + 1);
            if (e != PackError::Ok) return e;
            if (key.type != PackType::String) return PackError::BadMarker;
            out.pairs[k].key     = key.bytes;
            out.pairs[k].key_len = key.len;
            PackValue* v = arena_.alloc_n<PackValue>(1);
            if (v == nullptr) return PackError::OutOfMemory;
            *v = PackValue{};
            e = read_at(*v, depth + 1);
            if (e != PackError::Ok) return e;
            out.pairs[k].value = v;
        }
        return PackError::Ok;
    }
    out.items = (count == 0) ? nullptr : arena_.alloc_n<PackValue>(count);
    if (count != 0 && out.items == nullptr) return PackError::OutOfMemory;
    for (std::uint32_t k = 0; k < count; ++k) {
        out.items[k] = PackValue{};
        const PackError e = read_at(out.items[k], depth + 1);
        if (e != PackError::Ok) return e;
    }
    return PackError::Ok;
}

// Copy `n` payload bytes into the arena so the decoded value outlives the
// caller's wire buffer. A borrowed view would be faster but would tie every
// PackValue's lifetime to the socket read buffer; the message layer reuses that
// buffer per message, so borrowing is the shape that would silently corrupt.
PackError PackReader::read_at(PackValue& out, std::uint32_t depth) noexcept {
    assert(depth <= kMaxDepth);
    if (depth >= kMaxDepth) return PackError::DepthExceeded;
    out = PackValue{};

    const std::uint8_t* m = nullptr;
    PackError e = take(1, m);
    if (e != PackError::Ok) return e;
    const std::uint8_t marker = *m;

    // Tiny ints: F0..FF are -16..-1, 00..7F are 0..127.
    if (marker <= 0x7F || marker >= 0xF0) {
        out.type = PackType::Int;
        out.i = static_cast<std::int8_t>(marker);
        return PackError::Ok;
    }
    if (marker >= 0x80 && marker <= 0x8F) {
        return read_string_payload(out, marker & 0x0Fu);
    }
    if (marker >= 0x90 && marker <= 0x9F) {
        return read_container(out, depth, PackType::List, marker & 0x0Fu);
    }
    if (marker >= 0xA0 && marker <= 0xAF) {
        return read_container(out, depth, PackType::Dict, marker & 0x0Fu);
    }
    if (marker >= 0xB0 && marker <= 0xBF) {
        const std::uint8_t* sig = nullptr;
        e = take(1, sig);
        if (e != PackError::Ok) return e;
        e = read_container(out, depth, PackType::Struct, marker & 0x0Fu);
        out.signature = *sig;
        return e;
    }

    std::uint64_t n = 0;
    switch (marker) {
        case kNull:   out.type = PackType::Null;  return PackError::Ok;
        case kFalse:  out.type = PackType::Bool;  out.b = false; return PackError::Ok;
        case kTrue:   out.type = PackType::Bool;  out.b = true;  return PackError::Ok;
        case kFloat64: {
            e = take_uint(8, n);
            if (e != PackError::Ok) return e;
            out.type = PackType::Float;
            out.f = bits_to_double(n);
            return PackError::Ok;
        }
        case kInt8:  e = take_uint(1, n); if (e != PackError::Ok) return e;
                     out.type = PackType::Int; out.i = static_cast<std::int8_t>(n);  return PackError::Ok;
        case kInt16: e = take_uint(2, n); if (e != PackError::Ok) return e;
                     out.type = PackType::Int; out.i = static_cast<std::int16_t>(n); return PackError::Ok;
        case kInt32: e = take_uint(4, n); if (e != PackError::Ok) return e;
                     out.type = PackType::Int; out.i = static_cast<std::int32_t>(n); return PackError::Ok;
        case kInt64: e = take_uint(8, n); if (e != PackError::Ok) return e;
                     out.type = PackType::Int; out.i = static_cast<std::int64_t>(n); return PackError::Ok;

        case kStr8:  case kStr16: case kStr32: {
            const std::size_t w = (marker == kStr8) ? 1 : (marker == kStr16 ? 2 : 4);
            e = take_uint(w, n);
            if (e != PackError::Ok) return e;
            return read_string_payload(out, n);
        }
        case kBytes8: case kBytes16: case kBytes32: {
            const std::size_t w = (marker == kBytes8) ? 1 : (marker == kBytes16 ? 2 : 4);
            e = take_uint(w, n);
            if (e != PackError::Ok) return e;
            e = read_string_payload(out, n);
            if (e == PackError::Ok) out.type = PackType::Bytes;
            return e;
        }
        case kList8: case kList16: case kList32: {
            const std::size_t w = (marker == kList8) ? 1 : (marker == kList16 ? 2 : 4);
            e = take_uint(w, n);
            if (e != PackError::Ok) return e;
            if (n > kMaxElements) return PackError::TooLarge;
            return read_container(out, depth, PackType::List, static_cast<std::uint32_t>(n));
        }
        case kDict8: case kDict16: case kDict32: {
            const std::size_t w = (marker == kDict8) ? 1 : (marker == kDict16 ? 2 : 4);
            e = take_uint(w, n);
            if (e != PackError::Ok) return e;
            if (n > kMaxElements) return PackError::TooLarge;
            return read_container(out, depth, PackType::Dict, static_cast<std::uint32_t>(n));
        }
        case kStructRemoved8:
        case kStructRemoved16:
            // PackStream v1 STRUCT_8/STRUCT_16. v2 removed them; guessing a
            // field count here would be inventing a message, so refuse by name.
            return PackError::Unsupported;
        default:
            return PackError::BadMarker;
    }
}

PackError PackReader::read_string_payload(PackValue& out, std::uint64_t n) noexcept {
    assert(off_ <= n_);
    if (n > kMaxStringBytes) return PackError::TooLarge;
    const std::uint8_t* s = nullptr;
    const PackError e = take(static_cast<std::size_t>(n), s);
    if (e != PackError::Ok) return e;
    char* copy = nullptr;
    if (n != 0) {
        copy = static_cast<char*>(arena_.alloc(static_cast<std::size_t>(n), 1));
        if (copy == nullptr) return PackError::OutOfMemory;
        std::memcpy(copy, s, static_cast<std::size_t>(n));
    }
    out.type  = PackType::String;
    out.bytes = copy;
    out.len   = static_cast<std::uint32_t>(n);
    return PackError::Ok;
}

}  // namespace packstream
}  // namespace proto
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_NEO4J_BOLT
