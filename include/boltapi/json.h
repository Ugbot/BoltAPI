// boltapi/json.h — Bolt API's canonical JSON facility.
//
// This is a THIN, allocation-conscious wrapper over Bolt's own JSON parser —
// "fionn" — which lives in the bolt::parse static library
// (extern/bolt/include/bolt/parse/bolt_json.h). It is the ONLY JSON path in
// Bolt API: no simdjson, no nlohmann, nothing hand-rolled. See docs/JSON.md.
//
// WHAT FIONN IS
//   fionn is a skip-aware, tape-based SAX parser. A single linear pass over the
//   source emits a flat array of `Token`s (the "structural index"); each token
//   records a TokenType plus a byte (start,length) span back into the SOURCE
//   buffer. Strings and numbers are NEVER copied — they are zero-copy slices of
//   the input. Numbers are materialised lazily (strtoll / strtod on demand).
//
// WHAT THIS HEADER ADDS
//   A small, ergonomic cursor on top of that tape:
//     * Document   — owns a bolt::Arena (the tape lives in it) + the index.
//     * Value      — a cheap cursor (index + token offset) into the tape with
//                    DOM-style navigation: object member by key, array element
//                    by index, array/object iteration, and scalar extraction.
//   We delegate ALL parsing to fionn; navigation is just tape walking driven by
//   fionn's iter_skip_to_close cost model (O(tokens-skipped)).
//
// LIFETIME CONTRACT  (read this before storing any view)
//   parse(sv) records `sv.data()` inside the Document. Every string/key view
//   returned by a Value aliases that ORIGINAL input buffer — they are NOT
//   copied. The input MUST outlive the Document and any view taken from it.
//   For request handling this is automatic: Request::json() parses req.body(),
//   which is a view into the connection buffer that is alive for the entire
//   handler invocation, so all views are valid for the duration of the handler.
//   Do not stash a Value (or a string_view from one) past the handler return.
//
// DESIGN RULES (TigerStyle): no exceptions (errors via bool / result), every
// non-trivial accessor asserts its invariants, and the parse-time arena is the
// only allocation (bump allocator, ~3ns/alloc, freed wholesale on destruction).
#pragma once

#include "boltapi/core/result.h"

#include "bolt/bolt_arena.h"
#include "bolt/parse/bolt_json.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>

namespace bolt::api::json {

namespace fj = ::bolt::parse::json;

// ---------------------------------------------------------------------------
// ValueType — the JSON kind at a cursor. Mirrors fionn's TokenType but folds
// the structural begin/end pair into one logical "object"/"array".
// ---------------------------------------------------------------------------
enum class ValueType : uint8_t {
    Null,
    Bool,
    Int,      // integer number (no '.'/'e')
    Double,   // fractional / exponent number
    String,
    Object,
    Array,
    Invalid,  // cursor is out of range or on a non-value token
};

// ---------------------------------------------------------------------------
// Value — a cheap, copyable cursor into a parsed tape. ~16 bytes; pass by value.
//
// A Value points at the FIRST token of a JSON value (BeginObject/BeginArray for
// containers, or the scalar token otherwise). All navigation is performed by
// walking the flat tape with fionn's skip primitive — no re-parsing.
// ---------------------------------------------------------------------------
class Value {
public:
    Value() noexcept : idx_(nullptr), cursor_(-1) {}
    Value(const fj::StructuralIndex* idx, int32_t cursor) noexcept
        : idx_(idx), cursor_(cursor) {}

    bool valid() const noexcept {
        return idx_ != nullptr && cursor_ >= 0 && cursor_ < idx_->token_count;
    }

    ValueType type() const noexcept {
        if (!valid()) return ValueType::Invalid;
        switch (idx_->tokens[cursor_].type) {
            case fj::TokenType::Null:        return ValueType::Null;
            case fj::TokenType::BoolTrue:
            case fj::TokenType::BoolFalse:   return ValueType::Bool;
            case fj::TokenType::Int64:       return ValueType::Int;
            case fj::TokenType::Float64:     return ValueType::Double;
            case fj::TokenType::String:      return ValueType::String;
            case fj::TokenType::BeginObject: return ValueType::Object;
            case fj::TokenType::BeginArray:  return ValueType::Array;
            default:                         return ValueType::Invalid;
        }
    }

    bool is_null()   const noexcept { return type() == ValueType::Null; }
    bool is_bool()   const noexcept { return type() == ValueType::Bool; }
    bool is_int()    const noexcept { return type() == ValueType::Int; }
    bool is_double() const noexcept { return type() == ValueType::Int ||
                                             type() == ValueType::Double; }
    bool is_number() const noexcept { return is_double(); }
    bool is_string() const noexcept { return type() == ValueType::String; }
    bool is_object() const noexcept { return type() == ValueType::Object; }
    bool is_array()  const noexcept { return type() == ValueType::Array; }

    // --- Scalar extraction (each returns false / leaves *out untouched on a
    //     type mismatch; no exceptions). String/number views ALIAS the input. ---

    // Zero-copy string view INTO THE INPUT BUFFER. Note: the slice is the raw
    // JSON string contents (escape sequences are NOT decoded — callers that
    // need decoding handle \" \\ \uXXXX themselves; typical fields are clean).
    bool get_string(std::string_view* out) const noexcept {
        assert(out != nullptr);
        if (!valid()) return false;
        const fj::Token& t = idx_->tokens[cursor_];
        if (t.type != fj::TokenType::String) return false;
        *out = raw_slice(t);
        return true;
    }

    std::string_view as_string(std::string_view fallback = {}) const noexcept {
        std::string_view sv;
        return get_string(&sv) ? sv : fallback;
    }

    bool get_bool(bool* out) const noexcept {
        assert(out != nullptr);
        if (!valid()) return false;
        const fj::TokenType tt = idx_->tokens[cursor_].type;
        if (tt == fj::TokenType::BoolTrue)  { *out = true;  return true; }
        if (tt == fj::TokenType::BoolFalse) { *out = false; return true; }
        return false;
    }

    bool as_bool(bool fallback = false) const noexcept {
        bool b;
        return get_bool(&b) ? b : fallback;
    }

    bool get_int(int64_t* out) const noexcept {
        assert(out != nullptr);
        if (!valid()) return false;
        fj::Iterator it{idx_, cursor_, 0};
        return fj::iter_int64(&it, out);  // accepts Int64 (and Float64) tokens
    }

    int64_t as_int(int64_t fallback = 0) const noexcept {
        int64_t v;
        return get_int(&v) ? v : fallback;
    }

    bool get_double(double* out) const noexcept {
        assert(out != nullptr);
        if (!valid()) return false;
        fj::Iterator it{idx_, cursor_, 0};
        return fj::iter_float64(&it, out);  // accepts Int64 + Float64 tokens
    }

    double as_double(double fallback = 0.0) const noexcept {
        double v;
        return get_double(&v) ? v : fallback;
    }

    // --- Object access ---

    // Number of members (objects) or elements (arrays). 0 for scalars.
    int32_t size() const noexcept {
        const ValueType ty = type();
        if (ty != ValueType::Object && ty != ValueType::Array) return 0;
        int32_t n = 0;
        if (ty == ValueType::Object) {
            for (int32_t c = cursor_ + 1; ; ) {
                if (c >= idx_->token_count) break;
                if (idx_->tokens[c].type == fj::TokenType::EndObject) break;
                // c is at a Key; value follows.
                c = skip_value(c + 1);
                ++n;
            }
        } else {
            for (int32_t c = cursor_ + 1; ; ) {
                if (c >= idx_->token_count) break;
                if (idx_->tokens[c].type == fj::TokenType::EndArray) break;
                c = skip_value(c);
                ++n;
            }
        }
        return n;
    }

    // Object member by key. Returns an invalid Value when absent / not object.
    // Key comparison is on the raw (un-unescaped) key bytes — matches plain
    // keys, which is the overwhelming common case.
    Value operator[](std::string_view key) const noexcept {
        return member(key);
    }

    Value member(std::string_view key) const noexcept {
        if (type() != ValueType::Object) return Value{};
        for (int32_t c = cursor_ + 1; ; ) {
            if (c >= idx_->token_count) break;
            const fj::Token& kt = idx_->tokens[c];
            if (kt.type == fj::TokenType::EndObject) break;
            if (kt.type != fj::TokenType::Key) break;  // malformed; bail
            const std::string_view k = raw_slice(kt);
            const int32_t val = c + 1;
            if (k == key) return Value{idx_, val};
            c = skip_value(val);
        }
        return Value{};
    }

    bool has(std::string_view key) const noexcept { return member(key).valid(); }

    // Array element by index. Returns invalid Value when out of range / not array.
    Value at(int32_t index) const noexcept {
        if (type() != ValueType::Array || index < 0) return Value{};
        int32_t c = cursor_ + 1;
        for (int32_t i = 0; ; ++i) {
            if (c >= idx_->token_count) break;
            if (idx_->tokens[c].type == fj::TokenType::EndArray) break;
            if (i == index) return Value{idx_, c};
            c = skip_value(c);
        }
        return Value{};
    }

    // --- Iteration (allocation-free; cursors only) ---
    //
    // for (auto m = obj.first_member(); m.valid(); m = m.next()) {
    //     std::string_view k = m.key();
    //     Value v = m.value();
    // }
    class Member {
    public:
        Member() noexcept : idx_(nullptr), key_cursor_(-1) {}
        Member(const fj::StructuralIndex* idx, int32_t key_cursor) noexcept
            : idx_(idx), key_cursor_(key_cursor) {}

        bool valid() const noexcept {
            return idx_ != nullptr && key_cursor_ >= 0 &&
                   key_cursor_ < idx_->token_count &&
                   idx_->tokens[key_cursor_].type == fj::TokenType::Key;
        }
        std::string_view key() const noexcept {
            assert(valid());
            const fj::Token& t = idx_->tokens[key_cursor_];
            return std::string_view(
                reinterpret_cast<const char*>(idx_->src) + t.start,
                static_cast<size_t>(t.length));
        }
        Value value() const noexcept {
            assert(valid());
            return Value{idx_, key_cursor_ + 1};
        }
        Member next() const noexcept {
            assert(valid());
            const int32_t after = Value::skip_value_in(idx_, key_cursor_ + 1);
            if (after >= idx_->token_count ||
                idx_->tokens[after].type != fj::TokenType::Key) {
                return Member{};
            }
            return Member{idx_, after};
        }

    private:
        const fj::StructuralIndex* idx_;
        int32_t                    key_cursor_;
    };

    Member first_member() const noexcept {
        if (type() != ValueType::Object) return Member{};
        const int32_t c = cursor_ + 1;
        if (c >= idx_->token_count ||
            idx_->tokens[c].type != fj::TokenType::Key) {
            return Member{};
        }
        return Member{idx_, c};
    }

    // Array element iterator.
    class Element {
    public:
        Element() noexcept : idx_(nullptr), cursor_(-1) {}
        Element(const fj::StructuralIndex* idx, int32_t cursor) noexcept
            : idx_(idx), cursor_(cursor) {}

        bool valid() const noexcept {
            return idx_ != nullptr && cursor_ >= 0 &&
                   cursor_ < idx_->token_count &&
                   idx_->tokens[cursor_].type != fj::TokenType::EndArray;
        }
        Value value() const noexcept {
            assert(valid());
            return Value{idx_, cursor_};
        }
        Element next() const noexcept {
            assert(valid());
            const int32_t after = Value::skip_value_in(idx_, cursor_);
            return Element{idx_, after};
        }

    private:
        const fj::StructuralIndex* idx_;
        int32_t                    cursor_;
    };

    Element first_element() const noexcept {
        if (type() != ValueType::Array) return Element{};
        return Element{idx_, cursor_ + 1};
    }

    // Raw underlying cursor (escape hatch for advanced fionn iterator use).
    const fj::StructuralIndex* index() const noexcept { return idx_; }
    int32_t cursor() const noexcept { return cursor_; }

private:
    std::string_view raw_slice(const fj::Token& t) const noexcept {
        return std::string_view(
            reinterpret_cast<const char*>(idx_->src) + t.start,
            static_cast<size_t>(t.length));
    }

    // Advance past the value starting at token `c`, returning the index of the
    // token immediately after it. Delegates to fionn's iter_skip_to_close (the
    // single source of truth for the O(tokens-skipped) skip cost model): for a
    // container it walks to the matching close; for a scalar it advances one.
    static int32_t skip_value_in(const fj::StructuralIndex* idx,
                                 int32_t c) noexcept {
        assert(idx != nullptr);
        if (c < 0 || c >= idx->token_count) return idx->token_count;
        fj::Iterator it{idx, c, 0};
        if (!fj::iter_skip_to_close(&it)) return idx->token_count;
        return it.cursor;
    }

    int32_t skip_value(int32_t c) const noexcept {
        return skip_value_in(idx_, c);
    }

    const fj::StructuralIndex* idx_;
    int32_t                    cursor_;
};

// ---------------------------------------------------------------------------
// Document — owns the parse arena + structural index. Move-only.
//
// The arena holds the tape (fionn's Token array). Scalar/string views returned
// from root()/Value navigation alias the ORIGINAL input buffer passed to
// parse(), NOT the arena — see the lifetime contract at the top of this file.
// ---------------------------------------------------------------------------
class Document {
public:
    Document() noexcept : ok_(false) {
        memset(&index_, 0, sizeof(index_));
    }

    // Move-only. The arena is held behind a unique_ptr because bolt::Arena is
    // deliberately non-movable (it owns raw blocks); the pointer indirection is
    // the ONLY heap allocation in the JSON path (one control object per parse —
    // the tape itself lives inside the arena's pre-allocated blocks, no per-token
    // new). Moving a Document transfers arena ownership + the (offset-based)
    // index unchanged; index_.src still aliases the caller's input buffer.
    Document(Document&& o) noexcept = default;
    Document& operator=(Document&& o) noexcept = default;
    Document(const Document&) = delete;
    Document& operator=(const Document&) = delete;

    bool ok() const noexcept { return ok_; }
    explicit operator bool() const noexcept { return ok_; }

    // Root value (object/array/scalar). Invalid Value when parse failed.
    Value root() const noexcept {
        if (!ok_) return Value{};
        return Value{&index_, 0};
    }

    // Convenience root accessors.
    Value operator[](std::string_view key) const noexcept {
        return root().member(key);
    }
    Value at(int32_t i) const noexcept { return root().at(i); }

    // Internal: invoked by parse(). Takes ownership of the arena/index.
    void adopt_(bool ok, const fj::StructuralIndex& idx) noexcept {
        ok_ = ok;
        index_ = idx;
    }

    // Lazily create + return the parse arena. parse() calls this exactly once.
    // 256 KiB initial block: a request body's tape is bounded by src_len+2
    // tokens (12 bytes each); this covers bodies up to ~21 KiB without growth,
    // and the arena grows transparently for larger ones.
    bolt::Arena& arena() noexcept {
        if (!arena_) {
            arena_ = std::make_unique<bolt::Arena>(
                bolt::ArenaConfig{/*initial*/ 256 * 1024,
                                  /*max*/ 64 * 1024 * 1024,
                                  /*align*/ 64,
                                  /*poison*/ false});
        }
        return *arena_;
    }

private:
    std::unique_ptr<bolt::Arena> arena_;
    fj::StructuralIndex          index_;
    bool                         ok_;
};

// ---------------------------------------------------------------------------
// parse — the public entry point. Delegates to fionn's build_index.
//
// On success returns a Document whose views alias `input`. On malformed JSON
// (or arena exhaustion) returns a Document with ok()==false (NO exception, NO
// crash). `input` MUST outlive the returned Document and any view from it.
// ---------------------------------------------------------------------------
inline Document parse(std::string_view input) noexcept {
    Document doc;
    fj::StructuralIndex idx;
    memset(&idx, 0, sizeof(idx));
    // src_len is int32 in fionn; clamp defensively (request bodies are bounded
    // far below 2 GiB by the engine, but never feed fionn a negative length).
    if (input.size() > static_cast<size_t>(INT32_MAX)) {
        doc.adopt_(false, idx);
        return doc;
    }
    const bool ok = fj::build_index(
        reinterpret_cast<const uint8_t*>(input.data()),
        static_cast<int32_t>(input.size()),
        &doc.arena(), &idx);
    doc.adopt_(ok, idx);
    return doc;
}

// result<Document> flavour for call sites that prefer core::result plumbing.
inline core::result<Document> parse_checked(std::string_view input) noexcept {
    Document doc = parse(input);
    if (!doc.ok()) return core::error_code::parse_error;
    return doc;  // moved into the result
}

// Cheap "is this body valid JSON?" probe (defined in src/json.cpp). Parses and
// discards — useful for 400 short-circuits without materialising fields.
bool is_valid(std::string_view input) noexcept;

}  // namespace bolt::api::json
