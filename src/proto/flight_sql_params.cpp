// src/proto/flight_sql_params.cpp — see boltapi/proto/flight_sql_params.h.

#include "boltapi/proto/flight_sql_params.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include "boltapi/proto/flight_sql_codec.h"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace bolt::api::proto::flightsql::params {

namespace {

// Schema.fbs Type union ids.
constexpr std::uint8_t kTypeNull = 1, kTypeInt = 2, kTypeFloat = 3, kTypeBinary = 4,
                       kTypeUtf8 = 5, kTypeBool = 6, kTypeUnion = 14, kTypeLargeUtf8 = 20;
constexpr std::uint32_t kMaxFields = 256;
constexpr std::uint32_t kMaxMembers = 16;
constexpr std::uint32_t kMaxBuffers = 4 * (kMaxFields + kMaxFields * kMaxMembers);

}  // namespace

namespace detail {

// ---------------------------------------------------------------------------
// Flatbuffer reader: every access is bounds-checked against the buffer, and
// a failed check poisons the reader (ok() false) instead of reading.
// ---------------------------------------------------------------------------
class Fb {
public:
    explicit Fb(std::string_view b) noexcept : b_(b) {}
    bool ok() const noexcept { return ok_; }

    template <class T>
    T get(std::size_t at) noexcept {
        T v{};
        if (at > b_.size() || b_.size() - at < sizeof(T)) { ok_ = false; return v; }
        std::memcpy(&v, b_.data() + at, sizeof(T));
        return v;
    }
    std::size_t root() noexcept { return deref(0); }
    std::size_t deref(std::size_t at) noexcept {
        const std::uint32_t off = get<std::uint32_t>(at);
        if (!ok_ || off == 0 || at + off >= b_.size()) { ok_ = false; return 0; }
        return at + off;
    }
    // Position of field `slot` in the table at `t`, 0 when absent.
    std::size_t field(std::size_t t, std::uint16_t slot) noexcept {
        const std::int32_t so = get<std::int32_t>(t);
        const std::int64_t vt = static_cast<std::int64_t>(t) - so;
        if (!ok_ || vt < 0 || static_cast<std::size_t>(vt) >= b_.size()) { ok_ = false; return 0; }
        const std::uint16_t vt_size = get<std::uint16_t>(static_cast<std::size_t>(vt));
        const std::size_t e = 4u + 2u * slot;
        if (!ok_ || e + 2 > vt_size) return 0;
        const std::uint16_t off = get<std::uint16_t>(static_cast<std::size_t>(vt) + e);
        return off == 0 ? 0 : t + off;
    }
    template <class T>
    T scalar(std::size_t t, std::uint16_t slot, T dflt) noexcept {
        const std::size_t p = field(t, slot);
        return p == 0 ? dflt : get<T>(p);
    }
    std::size_t table(std::size_t t, std::uint16_t slot) noexcept {
        const std::size_t p = field(t, slot);
        return p == 0 ? 0 : deref(p);
    }
    // Vector length and first-element position.
    std::uint32_t vec(std::size_t t, std::uint16_t slot, std::size_t* first) noexcept {
        const std::size_t v = table(t, slot);
        if (v == 0) { *first = 0; return 0; }
        *first = v + 4;
        return get<std::uint32_t>(v);
    }

private:
    std::string_view b_;
    bool             ok_ = true;
};

const char* type_name(std::uint8_t t) noexcept {
    switch (t) {
        case 4:  return "Binary";
        case 7:  return "Decimal";
        case 8:  return "Date";
        case 9:  return "Time";
        case 10: return "Timestamp";
        case 11: return "Interval";
        case 12: return "List";
        case 13: return "Struct";
        case 15: return "FixedSizeBinary";
        case 16: return "FixedSizeList";
        case 17: return "Map";
        case 18: return "Duration";
        case 19: return "LargeBinary";
        case 21: return "LargeList";
        default: return "this Arrow type";
    }
}

// One column's field node and buffers inside a record-batch body.
struct View {
    std::int64_t         len = 0;
    std::int64_t         nulls = 0;
    const std::uint8_t*  buf[3] = {nullptr, nullptr, nullptr};
    std::uint64_t        blen[3] = {0, 0, 0};
};

}  // namespace detail

namespace {

using detail::Fb;
using detail::View;
using detail::type_name;

// Walks a record batch's field nodes and buffers in pre-order.
struct Cursor {
    Fb*              fb;
    std::string_view body;
    bool             v4;
    std::size_t      nodes;
    std::size_t      bufs;
    std::uint32_t    n_nodes;
    std::uint32_t    n_bufs;
    std::uint32_t    node_i;
    std::uint32_t    buf_i;
};

bool valid_at(const View& v, std::int64_t j) noexcept {
    if (v.nulls == 0 || v.blen[0] == 0) return true;
    return (v.buf[0][j >> 3] >> (j & 7)) & 1u;
}

template <class T>
T load(const std::uint8_t* p) noexcept {
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

bool scalar_at(const Decoder::Col& c, const View& v, std::int64_t j, Value* out,
               const char** err) noexcept {
    assert(out != nullptr && j >= 0);
    *out = Value{};
    if (j >= v.len) { *err = "parameter index past its column"; return false; }
    if (c.type == kTypeNull || !valid_at(v, j)) return true;
    if (c.type == kTypeBinary) {
        *err = "Binary parameters are not supported (no SQL literal)";
        return false;
    }
    const auto uj = static_cast<std::uint64_t>(j);
    if (c.type == kTypeBool) {
        out->kind = Kind::kBool;
        out->b = ((v.buf[1][uj >> 3] >> (uj & 7)) & 1u) != 0;
        return true;
    }
    if (c.type == kTypeInt || c.type == kTypeFloat) {
        const std::uint64_t w = c.type == kTypeInt ? static_cast<std::uint64_t>(c.bits) / 8u
                                                   : (c.bits == 1 ? 4u : 8u);
        const std::uint8_t* p = v.buf[1] + uj * w;
        if (c.type == kTypeFloat) {
            out->kind = Kind::kFloat;
            out->f = w == 4 ? static_cast<double>(load<float>(p)) : load<double>(p);
            return true;
        }
        std::int64_t s = 0;
        std::uint64_t u = 0;
        switch (w) {
            case 1: s = load<std::int8_t>(p);  u = load<std::uint8_t>(p);  break;
            case 2: s = load<std::int16_t>(p); u = load<std::uint16_t>(p); break;
            case 4: s = load<std::int32_t>(p); u = load<std::uint32_t>(p); break;
            default: s = load<std::int64_t>(p); u = load<std::uint64_t>(p); break;
        }
        out->kind = c.is_signed ? Kind::kInt : Kind::kUInt;
        out->i = s;
        out->u = u;
        return true;
    }
    assert(c.type == kTypeUtf8 || c.type == kTypeLargeUtf8);
    std::uint64_t a = 0;
    std::uint64_t b = 0;
    if (c.type == kTypeUtf8) {
        const std::int32_t x = load<std::int32_t>(v.buf[1] + uj * 4);
        const std::int32_t y = load<std::int32_t>(v.buf[1] + uj * 4 + 4);
        if (x < 0 || y < x) { *err = "malformed Utf8 offsets"; return false; }
        a = static_cast<std::uint64_t>(x);
        b = static_cast<std::uint64_t>(y);
    } else {
        const std::int64_t x = load<std::int64_t>(v.buf[1] + uj * 8);
        const std::int64_t y = load<std::int64_t>(v.buf[1] + uj * 8 + 8);
        if (x < 0 || y < x) { *err = "malformed LargeUtf8 offsets"; return false; }
        a = static_cast<std::uint64_t>(x);
        b = static_cast<std::uint64_t>(y);
    }
    if (b > v.blen[2]) { *err = "string parameter past its data buffer"; return false; }
    out->kind = Kind::kString;
    out->s = std::string_view(reinterpret_cast<const char*>(v.buf[2]) + a,
                              static_cast<std::size_t>(b - a));
    return true;
}

std::uint32_t n_buffers(const Decoder::Col& c, bool v4) noexcept {
    switch (c.type) {
        case kTypeNull:      return 0;
        case kTypeBinary:
        case kTypeUtf8:
        case kTypeLargeUtf8: return 3;
        case kTypeUnion:     return v4 ? 3 : 2;
        default:             return 2;
    }
}

// Checks that `v`'s buffers are long enough for `v.len` values of `c`.
bool sized(const Decoder::Col& c, const View& v) noexcept {
    const auto n = static_cast<std::uint64_t>(v.len);
    if (v.nulls != 0 && v.blen[0] != 0 && v.blen[0] < (n + 7) / 8) return false;
    switch (c.type) {
        case kTypeNull:      return true;
        case kTypeBool:      return v.blen[1] >= (n + 7) / 8;
        case kTypeInt:       return v.blen[1] >= n * static_cast<std::uint64_t>(c.bits / 8);
        case kTypeFloat:     return v.blen[1] >= n * (c.bits == 1 ? 4u : 8u);
        case kTypeBinary:
        case kTypeUtf8:      return n == 0 || v.blen[1] >= (n + 1) * 4;
        case kTypeLargeUtf8: return n == 0 || v.blen[1] >= (n + 1) * 8;
        default:             return true;
    }
}

// Int/Float/Utf8/... type details of a non-union field.
bool describe(Fb& fb, std::size_t field, Decoder::Col* c, bool member) noexcept {
    assert(c != nullptr);
    c->type = fb.scalar<std::uint8_t>(field, 2, 0);
    const std::size_t t = fb.table(field, 3);
    if (c->type == kTypeInt) {
        c->bits = t == 0 ? 0 : fb.scalar<std::int32_t>(t, 0, 0);
        c->is_signed = t != 0 && fb.scalar<std::uint8_t>(t, 1, 0) != 0;
        return c->bits == 8 || c->bits == 16 || c->bits == 32 || c->bits == 64;
    }
    if (c->type == kTypeFloat) {
        c->bits = t == 0 ? 0 : fb.scalar<std::int16_t>(t, 0, 0);
        return c->bits == 1 || c->bits == 2;
    }
    // A Binary member is accepted so a batch cast to the advertised
    // parameter_schema decodes; a Binary value is still refused.
    return c->type == kTypeNull || c->type == kTypeUtf8 || c->type == kTypeBool ||
           c->type == kTypeLargeUtf8 || (member && c->type == kTypeBinary);
}

// The next field node and its buffers from the record batch.
bool take(Cursor& cur, const Decoder::Col& c, View* v) noexcept {
    assert(v != nullptr);
    Fb& fb = *cur.fb;
    if (cur.node_i >= cur.n_nodes) return false;
    v->len = fb.get<std::int64_t>(cur.nodes + 16u * cur.node_i);
    v->nulls = fb.get<std::int64_t>(cur.nodes + 16u * cur.node_i + 8);
    ++cur.node_i;
    const std::uint32_t nb = n_buffers(c, cur.v4);
    const bool skip_first = c.type == kTypeUnion && cur.v4;   // V4 union validity
    for (std::uint32_t k = 0; k < nb; ++k) {
        if (cur.buf_i >= cur.n_bufs) return false;
        const std::int64_t off = fb.get<std::int64_t>(cur.bufs + 16u * cur.buf_i);
        const std::int64_t len = fb.get<std::int64_t>(cur.bufs + 16u * cur.buf_i + 8);
        ++cur.buf_i;
        if (off < 0 || len < 0 || static_cast<std::uint64_t>(off) > cur.body.size() ||
            cur.body.size() - static_cast<std::uint64_t>(off) < static_cast<std::uint64_t>(len)) {
            return false;
        }
        if (skip_first && k == 0) continue;
        const std::uint32_t slot = skip_first ? k - 1 : k;
        assert(slot < 3);
        v->buf[slot] = reinterpret_cast<const std::uint8_t*>(cur.body.data()) + off;
        v->blen[slot] = static_cast<std::uint64_t>(len);
    }
    return fb.ok() && v->len >= 0 && v->nulls >= 0 && (c.type == kTypeUnion || sized(c, *v));
}

bool is_escape_string(std::string_view sql, std::size_t quote) noexcept {
    if (quote == 0 || (sql[quote - 1] != 'e' && sql[quote - 1] != 'E')) return false;
    if (quote == 1) return true;
    const char p = sql[quote - 2];
    return !((p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || (p >= '0' && p <= '9') ||
             p == '_');
}

// Calls `emit(pos)` for every placeholder position; false when emit does.
template <class Emit>
bool scan(std::string_view sql, Emit emit) {
    std::size_t i = 0;
    const std::size_t n = sql.size();
    for (std::size_t guard = 0; guard <= n && i < n; ++guard) {   // i strictly advances
        const char c = sql[i];
        if (c == '\'' || c == '"') {
            const bool esc = c == '\'' && is_escape_string(sql, i);
            std::size_t j = i + 1;
            for (; j < n; ++j) {
                if (esc && sql[j] == '\\') { ++j; continue; }
                if (sql[j] == c) {
                    if (j + 1 < n && sql[j + 1] == c) { ++j; continue; }
                    break;
                }
            }
            i = j + 1;
        } else if (c == '-' && i + 1 < n && sql[i + 1] == '-') {
            const std::size_t nl = sql.find('\n', i);
            i = nl == std::string_view::npos ? n : nl + 1;
        } else if (c == '/' && i + 1 < n && sql[i + 1] == '*') {
            const std::size_t end = sql.find("*/", i + 2);
            i = end == std::string_view::npos ? n : end + 2;
        } else {
            if (c == '?' && !emit(i)) return false;
            ++i;
        }
    }
    return true;
}

bool append_literal(const Value& v, std::string* out, const char** err) {
    char num[64];
    int len = 0;
    switch (v.kind) {
        case Kind::kNull:
            out->append("NULL");
            return true;
        case Kind::kBool:
            out->append(v.b ? "TRUE" : "FALSE");
            return true;
        case Kind::kInt:
            len = std::snprintf(num, sizeof(num), v.i < 0 ? "(%lld)" : "%lld",
                                static_cast<long long>(v.i));
            break;
        case Kind::kUInt:
            len = std::snprintf(num, sizeof(num), "%llu", static_cast<unsigned long long>(v.u));
            break;
        case Kind::kFloat: {
            if (!std::isfinite(v.f)) {
                *err = "a NaN or infinite parameter has no SQL literal";
                return false;
            }
            len = std::snprintf(num, sizeof(num), "%.17g", v.f);
            const std::string_view s(num, static_cast<std::size_t>(len));
            if (s.find_first_of(".e") == std::string_view::npos) {
                num[len++] = '.';
                num[len++] = '0';
                num[len] = '\0';
            }
            if (v.f < 0) {
                out->push_back('(');
                out->append(num, static_cast<std::size_t>(len));
                out->push_back(')');
                return true;
            }
            break;
        }
        case Kind::kString:
            out->push_back('\'');
            for (const char ch : v.s) {
                if (ch == '\'') out->push_back('\'');
                out->push_back(ch);
            }
            out->push_back('\'');
            return true;
    }
    assert(len > 0 && static_cast<std::size_t>(len) < sizeof(num));
    out->append(num, static_cast<std::size_t>(len));
    return true;
}

void put_value(std::string* out, const Value& v) {
    out->push_back(static_cast<char>(v.kind));
    switch (v.kind) {
        case Kind::kNull:   break;
        case Kind::kBool:   out->push_back(v.b ? 1 : 0); break;
        case Kind::kInt:    out->append(reinterpret_cast<const char*>(&v.i), 8); break;
        case Kind::kUInt:   out->append(reinterpret_cast<const char*>(&v.u), 8); break;
        case Kind::kFloat:  out->append(reinterpret_cast<const char*>(&v.f), 8); break;
        case Kind::kString:
            codec::pb_put_varint_raw(out, v.s.size());
            out->append(v.s.data(), v.s.size());
            break;
    }
}

bool get_value(std::string_view h, std::size_t* pos, Value* v) noexcept {
    if (*pos >= h.size()) return false;
    const auto k = static_cast<std::uint8_t>(h[(*pos)++]);
    if (k > static_cast<std::uint8_t>(Kind::kBool)) return false;
    *v = Value{};
    v->kind = static_cast<Kind>(k);
    std::uint64_t n = 0;
    switch (v->kind) {
        case Kind::kNull:
            return true;
        case Kind::kBool:
            if (*pos >= h.size()) return false;
            v->b = h[(*pos)++] != 0;
            return true;
        case Kind::kInt:
        case Kind::kUInt:
        case Kind::kFloat:
            if (h.size() - *pos < 8) return false;
            std::memcpy(v->kind == Kind::kInt ? static_cast<void*>(&v->i)
                        : v->kind == Kind::kUInt ? static_cast<void*>(&v->u)
                                                 : static_cast<void*>(&v->f),
                        h.data() + *pos, 8);
            *pos += 8;
            return true;
        case Kind::kString:
            if (!codec::pb_read_varint(h, pos, &n) || n > h.size() - *pos) return false;
            v->s = h.substr(*pos, static_cast<std::size_t>(n));
            *pos += static_cast<std::size_t>(n);
            return true;
    }
    return false;
}

}  // namespace

bool Decoder::schema(std::string_view metadata, const char** err) {
    assert(err != nullptr);
    unsupported_ = false;
    Fb fb(metadata);
    const std::size_t msg = fb.root();
    if (!fb.ok() || fb.scalar<std::uint8_t>(msg, 1, 0) != codec::kIpcHeaderSchema) {
        *err = "parameter stream does not start with an Arrow schema";
        return false;
    }
    const std::size_t sch = fb.table(msg, 2);
    std::size_t first = 0;
    const std::uint32_t n = sch == 0 ? 0 : fb.vec(sch, 1, &first);
    if (!fb.ok() || n > kMaxFields) {
        *err = "malformed or too wide parameter schema";
        return false;
    }
    cols_.clear();
    codes_.clear();
    cols_.reserve(static_cast<std::size_t>(n) * (1u + kMaxMembers));
    cols_.resize(n);
    for (std::uint32_t k = 0; k < n; ++k) {
        const std::size_t f = fb.deref(first + 4u * k);
        const Field r = f == 0 ? Field::kMalformed : describe_top(fb, f, k);
        if (r != Field::kOk) {
            unsupported_ = r == Field::kUnsupported;
            if (r == Field::kMalformed) *err = "malformed parameter schema";
            else *err = why_;
            return false;
        }
    }
    if (!fb.ok()) {
        *err = "malformed parameter schema";
        return false;
    }
    n_top_ = n;
    have_schema_ = true;
    assert(cols_.size() == n + codes_.size());
    return true;
}

// Top-level field k; a dense union appends its members to cols_/codes_.
Decoder::Field Decoder::describe_top(Fb& fb, std::size_t f, std::uint32_t k) {
    assert(k < cols_.size());
    if (fb.field(f, 4) != 0) {
        why_ = "dictionary-encoded parameters are not supported";
        return Field::kUnsupported;
    }
    Col& c = cols_[k];
    c.type = fb.scalar<std::uint8_t>(f, 2, 0);
    if (c.type != kTypeUnion) {
        if (describe(fb, f, &c, false)) return Field::kOk;
        std::snprintf(why_buf_, sizeof(why_buf_), "%s parameters are not supported",
                      type_name(c.type));
        why_ = why_buf_;
        return Field::kUnsupported;
    }
    const std::size_t t = fb.table(f, 3);
    if (t == 0 || fb.scalar<std::int16_t>(t, 0, 0) != 1) {
        why_ = "only dense-union parameters are supported (sparse union refused)";
        return Field::kUnsupported;
    }
    std::size_t ch = 0;
    const std::uint32_t m = fb.vec(f, 5, &ch);
    std::size_t idp = 0;
    const std::uint32_t nid = fb.vec(t, 1, &idp);
    if (!fb.ok() || m == 0 || m > kMaxMembers || (nid != 0 && nid != m)) return Field::kMalformed;
    c.n_children = static_cast<std::uint8_t>(m);
    c.child = static_cast<std::uint16_t>(cols_.size());
    for (std::uint32_t j = 0; j < m; ++j) {
        Col member;
        if (!describe(fb, fb.deref(ch + 4u * j), &member, true) || member.type == kTypeUnion) {
            why_ = "a dense-union parameter member has an unsupported type";
            return Field::kUnsupported;
        }
        codes_.push_back(nid == 0 ? static_cast<std::int32_t>(j)
                                  : fb.get<std::int32_t>(idp + 4u * j));
        cols_.push_back(member);
    }
    return Field::kOk;
}

bool Decoder::batch(std::string_view metadata, std::string_view body, Rows* out,
                    const char** err) {
    assert(out != nullptr && err != nullptr);
    if (!have_schema_) { *err = "record batch before the parameter schema"; return false; }
    Fb fb(metadata);
    const std::size_t msg = fb.root();
    const std::size_t rb = fb.table(msg, 2);
    if (!fb.ok() || rb == 0) { *err = "malformed record batch"; return false; }
    if (fb.field(rb, 3) != 0) {
        unsupported_ = true;
        *err = "compressed parameter batches are not supported";
        return false;
    }
    Cursor cur{&fb, body, fb.scalar<std::int16_t>(msg, 0, 0) < 4, 0, 0, 0, 0, 0, 0};
    const std::int64_t length = fb.scalar<std::int64_t>(rb, 0, 0);
    cur.n_nodes = fb.vec(rb, 1, &cur.nodes);
    cur.n_bufs = fb.vec(rb, 2, &cur.bufs);
    if (!fb.ok() || length < 0 || cur.n_bufs > kMaxBuffers ||
        static_cast<std::uint64_t>(out->n_rows) + static_cast<std::uint64_t>(length) > kMaxRows) {
        *err = "malformed record batch or more than 4096 parameter sets";
        return false;
    }
    if (out->n_rows != 0 && out->n_cols != n_top_) { *err = "parameter width changed"; return false; }
    std::vector<View> views(cols_.size());
    for (std::uint32_t k = 0; k < n_top_; ++k) {    // pre-order: a union's members follow it
        const Col& c = cols_[k];
        bool ok = take(cur, c, &views[k]);
        for (std::uint32_t j = 0; ok && j < c.n_children; ++j) {
            ok = take(cur, cols_[c.child + j], &views[c.child + j]);
        }
        ok = ok && views[k].len == length &&
             (c.type != kTypeUnion ||
              (views[k].blen[0] >= static_cast<std::uint64_t>(length) &&
               views[k].blen[1] >= static_cast<std::uint64_t>(length) * 4u));
        if (!ok) { *err = "malformed parameter batch buffers"; return false; }
    }
    out->n_cols = n_top_;
    return append_rows(views, length, out, err);
}

bool Decoder::append_rows(const std::vector<View>& views, std::int64_t length, Rows* out,
                          const char** err) {
    assert(views.size() == cols_.size() && length >= 0);
    const std::size_t base = out->values.size();
    out->values.resize(base + static_cast<std::size_t>(length) * n_top_);
    for (std::int64_t r = 0; r < length; ++r) {
        for (std::uint32_t k = 0; k < n_top_; ++k) {
            Value* dst = &out->values[base + static_cast<std::size_t>(r) * n_top_ + k];
            const Col& c = cols_[k];
            if (c.type != kTypeUnion) {
                if (!scalar_at(c, views[k], r, dst, err)) return false;
                continue;
            }
            const auto code = static_cast<std::int8_t>(views[k].buf[0][r]);
            const std::int32_t off =
                load<std::int32_t>(views[k].buf[1] + 4u * static_cast<std::size_t>(r));
            std::uint32_t member = kMaxMembers;
            for (std::uint32_t j = 0; j < c.n_children; ++j) {
                if (codes_[c.child + j - n_top_] == code) member = j;
            }
            if (member == kMaxMembers || off < 0) {
                *err = "dense-union parameter has an unknown type code";
                return false;
            }
            const std::uint32_t mi = c.child + member;
            if (!scalar_at(cols_[mi], views[mi], off, dst, err)) return false;
        }
    }
    out->n_rows += static_cast<std::uint32_t>(length);
    assert(out->values.size() == static_cast<std::size_t>(out->n_rows) * out->n_cols);
    return true;
}

std::uint8_t header_type(std::string_view metadata) noexcept {
    Fb fb(metadata);
    const std::size_t msg = fb.root();
    const auto t = fb.ok() ? fb.scalar<std::uint8_t>(msg, 1, 0) : std::uint8_t{0};
    return fb.ok() ? t : 0;
}

bool count_placeholders(std::string_view sql, std::uint32_t* n) noexcept {
    assert(n != nullptr);
    *n = 0;
    return scan(sql, [&](std::size_t) { return ++*n <= kMaxParams; });
}

bool render(std::string_view sql, const Value* row, std::uint32_t n, std::size_t cap,
            std::string* out, const char** err) {
    assert(out != nullptr && err != nullptr && (n == 0 || row != nullptr));
    out->clear();
    std::size_t from = 0;
    std::uint32_t k = 0;
    bool lit_ok = true;
    const bool ok = scan(sql, [&](std::size_t pos) {
        if (k >= n) return false;
        out->append(sql.data() + from, pos - from);
        from = pos + 1;
        lit_ok = append_literal(row[k++], out, err);
        return lit_ok && out->size() <= cap;
    });
    if (!lit_ok) return false;
    if (!ok || k != n) {
        *err = "parameter count does not match the statement's placeholders";
        return false;
    }
    out->append(sql.data() + from, sql.size() - from);
    if (out->size() > cap) {
        *err = "statement with its parameters bound exceeds 65536 bytes";
        return false;
    }
    return true;
}

void encode_unbound(std::string* out, std::string_view sql) {
    assert(out != nullptr);
    out->assign(kHandleMagic.data(), kHandleMagic.size());
    out->append(sql.data(), sql.size());
}

void encode_bound(std::string* out, std::string_view sql, const Value* row, std::uint32_t n) {
    assert(out != nullptr && (n == 0 || row != nullptr) && n <= kMaxParams);
    out->assign(kBoundMagic.data(), kBoundMagic.size());
    codec::pb_put_varint_raw(out, sql.size());
    out->append(sql.data(), sql.size());
    codec::pb_put_varint_raw(out, n);
    for (std::uint32_t i = 0; i < n; ++i) put_value(out, row[i]);
}

bool decode_handle(std::string_view handle, std::string_view* sql, bool* bound,
                   std::vector<Value>* row) {
    assert(sql != nullptr && bound != nullptr && row != nullptr);
    row->clear();
    if (handle.substr(0, kHandleMagic.size()) == kHandleMagic) {
        *sql = handle.substr(kHandleMagic.size());
        *bound = false;
        return true;
    }
    if (handle.substr(0, kBoundMagic.size()) != kBoundMagic) return false;
    std::size_t pos = kBoundMagic.size();
    std::uint64_t len = 0;
    std::uint64_t n = 0;
    if (!codec::pb_read_varint(handle, &pos, &len) || len > handle.size() - pos) return false;
    *sql = handle.substr(pos, static_cast<std::size_t>(len));
    pos += static_cast<std::size_t>(len);
    if (!codec::pb_read_varint(handle, &pos, &n) || n > kMaxParams) return false;
    row->resize(static_cast<std::size_t>(n));
    for (std::size_t i = 0; i < n; ++i) {
        if (!get_value(handle, &pos, &(*row)[i])) return false;
    }
    *bound = true;
    return pos == handle.size();
}

}  // namespace bolt::api::proto::flightsql::params

#endif  // BOLTAPI_WITH_FLIGHT_SQL
