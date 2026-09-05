// boltapi/proto/packstream.h — PackStream v2 codec (Neo4j Bolt's value encoding).
//
// ============================================================================
// NAME COLLISION — READ THIS FIRST
// ============================================================================
// `bolt` (extern/bolt) is OUR columnar core. "Bolt" here, and everywhere in
// this file and neo4j_bolt.h, means **Neo4j's CLIENT WIRE PROTOCOL**. They are
// unrelated projects that happen to share a word. PackStream is the value
// serialization Neo4j's Bolt protocol carries; it is not a bolt:: format.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A bounded, allocation-free-on-the-hot-path encoder/decoder for PackStream v2
// as published by Neo4j (https://neo4j.com/docs/bolt/current/packstream/).
// Big-endian throughout. Every fallible operation returns a PackError; nothing
// throws, nothing allocates from the general heap.
//
// Deliberate design choices (TigerStyle):
//   * The decoder builds values into a CALLER-OWNED fixed byte region via
//     `PackArena` (a bump allocator). Exhaustion is `PackError::OutOfMemory` —
//     an explicit, loud refusal, NEVER a truncated value. We do not use
//     bolt::Arena here precisely because bolt::Arena grows on demand; a wire
//     decoder facing untrusted input must have a hard ceiling it cannot pass.
//   * The encoder writes into a caller-owned buffer and refuses to overrun it.
//     A partially-written value leaves `overflowed()` set; callers must check.
//   * Depth, element count and string length all have explicit constants below.
//     A message that exceeds any of them is REFUSED by name, not clamped.
//
// PackStream v2 marker map (the published spec; the golden tests pin the bytes):
//   C0 null · C2 false · C3 true · C1 float64
//   F0..7F  tiny int (-16..127)   C8 int8  C9 int16  CA int32  CB int64
//   80..8F  tiny string           D0 str8  D1 str16  D2 str32
//   90..9F  tiny list             D4 list8 D5 list16 D6 list32
//   A0..AF  tiny dict             D8 dict8 D9 dict16 DA dict32
//   B0..BF  structure (0..15 fields) followed by a 1-byte signature
//   CC bytes8 · CD bytes16 · CE bytes32
// Structures larger than 15 fields (the removed DC/DD markers) are REFUSED.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace bolt::api {
namespace proto {
namespace packstream {

// ---------------------------------------------------------------------------
// Bounds. Every one of these is a refusal boundary, never a truncation point.
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kMaxDepth        = 16;         // nesting levels
inline constexpr std::uint32_t kMaxElements     = 1u << 20;   // list/dict/struct
inline constexpr std::uint32_t kMaxStringBytes  = 1u << 24;   // 16 MiB

enum class PackError : std::uint8_t {
    Ok = 0,
    Truncated,      // input ended mid-value
    BadMarker,      // marker byte is not part of PackStream v2
    Overflow,       // encoder ran out of caller buffer
    DepthExceeded,  // nesting past kMaxDepth
    TooLarge,       // container/string past its bound
    OutOfMemory,    // decoder arena exhausted
    Unsupported,    // valid PackStream v1 shape this codec refuses (e.g. DC/DD)
};

const char* pack_error_name(PackError e) noexcept;

enum class PackType : std::uint8_t {
    Null = 0, Bool, Int, Float, String, Bytes, List, Dict, Struct,
};

struct PackValue;

// A dictionary entry. Keys are always PackStream strings, so they are kept as a
// borrowed (arena-owned) byte range rather than a nested PackValue.
struct PackPair {
    const char*   key     = nullptr;
    std::uint32_t key_len = 0;
    PackValue*    value   = nullptr;

    std::string_view key_view() const noexcept {
        return std::string_view(key ? key : "", key_len);
    }
};

// A decoded value. Trivially copyable POD; every pointer is owned by the
// PackArena the value was decoded into and dies when that arena is reset.
struct PackValue {
    PackType      type      = PackType::Null;
    std::uint8_t  signature = 0;        // Struct only
    bool          b         = false;    // Bool
    std::int64_t  i         = 0;        // Int
    double        f         = 0.0;      // Float
    const char*   bytes     = nullptr;  // String / Bytes payload
    std::uint32_t len       = 0;        // String/Bytes: byte count.
                                        // List/Struct: element count.
                                        // Dict: pair count.
    PackValue*    items     = nullptr;  // List / Struct fields
    PackPair*     pairs     = nullptr;  // Dict entries

    bool is_null()   const noexcept { return type == PackType::Null; }
    bool is_string() const noexcept { return type == PackType::String; }
    bool is_int()    const noexcept { return type == PackType::Int; }
    bool is_dict()   const noexcept { return type == PackType::Dict; }
    bool is_list()   const noexcept { return type == PackType::List; }

    std::string_view str() const noexcept {
        return (type == PackType::String || type == PackType::Bytes)
                   ? std::string_view(bytes ? bytes : "", len)
                   : std::string_view();
    }

    // Dictionary lookup by key. Returns nullptr when absent or not a dict.
    const PackValue* find(std::string_view key) const noexcept;

    // Dictionary lookup coerced to a string view; empty when absent/not a string.
    std::string_view find_str(std::string_view key) const noexcept;

    // Dictionary lookup coerced to an integer; `fallback` when absent/not an int.
    std::int64_t find_int(std::string_view key, std::int64_t fallback) const noexcept;
};

// ---------------------------------------------------------------------------
// PackArena — bump allocator over a caller-owned fixed region.
//
// Not bolt::Arena on purpose: this backs a decoder for UNTRUSTED bytes, so the
// ceiling must be hard. `alloc` returns nullptr on exhaustion and the decoder
// turns that into PackError::OutOfMemory.
// ---------------------------------------------------------------------------
class PackArena {
public:
    PackArena(void* buffer, std::size_t capacity) noexcept
        : base_(static_cast<std::uint8_t*>(buffer)), cap_(capacity), used_(0) {
        assert(buffer != nullptr || capacity == 0);
        assert(capacity < (std::size_t{1} << 40));  // sanity: not a wild value
    }

    PackArena(const PackArena&) = delete;
    PackArena& operator=(const PackArena&) = delete;

    void reset() noexcept { used_ = 0; }

    void* alloc(std::size_t n, std::size_t align) noexcept {
        assert(align != 0 && (align & (align - 1)) == 0);
        assert(used_ <= cap_);
        const std::size_t pad = (align - (used_ & (align - 1))) & (align - 1);
        if (n > cap_ || pad > cap_ - n || used_ > cap_ - n - pad) {
            return nullptr;  // refuse; never wrap, never truncate
        }
        std::uint8_t* p = base_ + used_ + pad;
        used_ += pad + n;
        return p;
    }

    template <typename T>
    T* alloc_n(std::size_t n) noexcept {
        if (n != 0 && sizeof(T) > (std::size_t{1} << 40) / n) return nullptr;
        void* p = alloc(sizeof(T) * n, alignof(T));
        return static_cast<T*>(p);
    }

    std::size_t used() const noexcept { return used_; }
    std::size_t capacity() const noexcept { return cap_; }

private:
    std::uint8_t* base_;
    std::size_t   cap_;
    std::size_t   used_;
};

// ---------------------------------------------------------------------------
// PackWriter — encode into a caller-owned buffer.
//
// Every put_* refuses rather than overruns. After the first refusal the writer
// latches `overflowed()`; the caller must check before sending bytes.
// ---------------------------------------------------------------------------
class PackWriter {
public:
    PackWriter(std::uint8_t* buffer, std::size_t capacity) noexcept
        : buf_(buffer), cap_(capacity), n_(0), overflow_(false) {
        assert(buffer != nullptr || capacity == 0);
        assert(capacity < (std::size_t{1} << 32));
    }

    void reset() noexcept { n_ = 0; overflow_ = false; }

    PackError put_null() noexcept;
    PackError put_bool(bool v) noexcept;
    PackError put_int(std::int64_t v) noexcept;
    PackError put_float(double v) noexcept;
    PackError put_string(std::string_view s) noexcept;
    PackError put_bytes(const void* p, std::size_t n) noexcept;

    // Container headers: the caller then writes exactly `n` values (dict: `n`
    // key/value PAIRS, key first). The writer does not track that for you —
    // it is the caller's invariant, asserted at the message layer.
    PackError begin_list(std::uint32_t n) noexcept;
    PackError begin_dict(std::uint32_t n) noexcept;
    PackError begin_struct(std::uint8_t signature, std::uint8_t n_fields) noexcept;

    // Write a whole decoded value back out (depth-bounded, recursive).
    PackError put_value(const PackValue& v) noexcept;

    const std::uint8_t* data() const noexcept { return buf_; }
    std::size_t size() const noexcept { return n_; }
    bool overflowed() const noexcept { return overflow_; }

private:
    PackError raw(const void* p, std::size_t n) noexcept;
    PackError byte(std::uint8_t b) noexcept;
    PackError put_value_at(const PackValue& v, std::uint32_t depth) noexcept;

    std::uint8_t* buf_;
    std::size_t   cap_;
    std::size_t   n_;
    bool          overflow_;
};

// ---------------------------------------------------------------------------
// PackReader — decode one or more values out of a byte range into an arena.
// ---------------------------------------------------------------------------
class PackReader {
public:
    PackReader(const std::uint8_t* data, std::size_t len, PackArena& arena) noexcept
        : p_(data), n_(len), off_(0), arena_(arena) {
        assert(data != nullptr || len == 0);
        assert(len < (std::size_t{1} << 32));
    }

    PackError read(PackValue& out) noexcept { return read_at(out, 0); }

    std::size_t offset() const noexcept { return off_; }
    bool at_end() const noexcept { return off_ >= n_; }
    std::size_t remaining() const noexcept { return n_ - off_; }

private:
    PackError read_at(PackValue& out, std::uint32_t depth) noexcept;
    PackError read_container(PackValue& out, std::uint32_t depth,
                             PackType kind, std::uint32_t count) noexcept;
    // Copies `n` payload bytes into the arena (String/Bytes). The copy is what
    // lets a decoded value outlive the socket read buffer, which the message
    // layer reuses per message.
    PackError read_string_payload(PackValue& out, std::uint64_t n) noexcept;
    PackError take(std::size_t n, const std::uint8_t*& out) noexcept;
    PackError take_uint(std::size_t width, std::uint64_t& out) noexcept;

    const std::uint8_t* p_;
    std::size_t         n_;
    std::size_t         off_;
    PackArena&          arena_;
};

}  // namespace packstream
}  // namespace proto
}  // namespace bolt::api
