// src/proto/postgres_wire_codec.cpp — see boltapi/proto/postgres_wire_codec.h.

#include "boltapi/proto/postgres_wire_codec.h"

#if defined(BOLTAPI_WITH_PG_WIRE)

#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace bolt::api::proto::pgwire {

namespace {

constexpr std::size_t kMaxScalarText = 128;   // numeric/date text scratch
constexpr std::uint32_t kMaxParamIndex = 65535;

bool fail(CodecError& err, const char* sqlstate, const char* message) noexcept {
    assert(sqlstate != nullptr && message != nullptr);
    err.sqlstate = sqlstate;
    err.message  = message;
    return false;
}

bool is_ident_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '$' ||
           static_cast<unsigned char>(c) >= 0x80;
}

bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

bool append(char* out, std::size_t cap, std::size_t& pos, const char* p,
            std::size_t n) noexcept {
    assert(out != nullptr || n == 0);
    if (pos + n > cap) return false;
    if (n > 0) std::memcpy(out + pos, p, n);
    pos += n;
    return true;
}

std::uint64_t be_u64(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

std::uint32_t be_u32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}

std::uint16_t be_u16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void put_be(std::uint8_t* out, std::uint64_t v, int n) noexcept {
    assert(n > 0 && n <= 8);
    for (int i = n - 1; i >= 0; --i) { out[i] = static_cast<std::uint8_t>(v); v >>= 8; }
}

// Postgres dates count days from 2000-01-01; civil<->days per H. Hinnant.
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) noexcept {
    y -= m <= 2 ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned mp = m > 2 ? m - 3 : m + 9;
    const unsigned doy = (153 * mp + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

void civil_from_days(std::int64_t z, std::int64_t& y, unsigned& m, unsigned& d) noexcept {
    z += 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y = static_cast<std::int64_t>(yoe) + era * 400 + (m <= 2 ? 1 : 0);
}

constexpr std::int64_t kPgEpochDays = 10957;   // 1970-01-01 -> 2000-01-01

// [+-]digits[.digits][(e|E)[+-]digits], or [+-]digits.digits forms; NaN and
// [+-]Infinity accepted as Postgres does.
bool is_numeric_text(std::string_view s) noexcept {
    if (s.empty() || s.size() > kMaxScalarText) return false;
    if (s == "NaN" || s == "Infinity" || s == "-Infinity" || s == "+Infinity") return true;
    std::size_t i = 0;
    if (s[i] == '+' || s[i] == '-') ++i;
    std::size_t digits = 0;
    while (i < s.size() && is_digit(s[i])) { ++i; ++digits; }
    if (i < s.size() && s[i] == '.') {
        ++i;
        while (i < s.size() && is_digit(s[i])) { ++i; ++digits; }
    }
    if (digits == 0) return false;
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
        std::size_t ed = 0;
        while (i < s.size() && is_digit(s[i])) { ++i; ++ed; }
        if (ed == 0) return false;
    }
    return i == s.size();
}

bool parse_bool_text(std::string_view s, bool& out) noexcept {
    char low[8] = {};
    if (s.empty() || s.size() >= sizeof(low)) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        low[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    }
    const std::string_view l(low, s.size());
    if (l == "t" || l == "true" || l == "y" || l == "yes" || l == "on" || l == "1") {
        out = true; return true;
    }
    if (l == "f" || l == "false" || l == "n" || l == "no" || l == "off" || l == "0") {
        out = false; return true;
    }
    return false;
}

bool parse_date_text(std::string_view s, std::int64_t& pg_days) noexcept {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return false;
    std::int64_t y = 0;
    unsigned m = 0, d = 0;
    for (std::size_t i = 0; i < 4; ++i) { if (!is_digit(s[i])) return false; y = y * 10 + (s[i] - '0'); }
    for (std::size_t i = 5; i < 7; ++i) { if (!is_digit(s[i])) return false; m = m * 10 + static_cast<unsigned>(s[i] - '0'); }
    for (std::size_t i = 8; i < 10; ++i) { if (!is_digit(s[i])) return false; d = d * 10 + static_cast<unsigned>(s[i] - '0'); }
    if (m < 1 || m > 12 || d < 1 || d > 31) return false;
    pg_days = days_from_civil(y, m, d) - kPgEpochDays;
    return true;
}

bool is_numeric_oid(std::int32_t t) noexcept {
    return t == oid::kInt2 || t == oid::kInt4 || t == oid::kInt8 ||
           t == oid::kOid || t == oid::kFloat4 || t == oid::kFloat8 ||
           t == oid::kNumeric;
}

bool is_text_oid(std::int32_t t) noexcept {
    return t == oid::kText || t == oid::kVarchar || t == oid::kBpchar ||
           t == oid::kName || t == oid::kUnknown || t == oid::kUnspecified;
}

// Postgres NUMERIC binary: ndigits, weight, sign, dscale (int16 each), then
// ndigits base-10000 int16 digits; value = sum(d[i] * 10000^(weight-i)).
bool numeric_binary_to_text(const std::uint8_t* p, std::size_t n, char* out,
                            std::size_t cap, std::size_t& len) noexcept {
    assert(out != nullptr);
    if (n < 8) return false;
    const std::int32_t ndigits = static_cast<std::int16_t>(be_u16(p));
    const std::int32_t weight  = static_cast<std::int16_t>(be_u16(p + 2));
    const std::uint16_t sign   = be_u16(p + 4);
    const std::int32_t dscale  = static_cast<std::int16_t>(be_u16(p + 6));
    if (ndigits < 0 || dscale < 0 || dscale > 1000 ||
        static_cast<std::size_t>(ndigits) * 2 + 8 != n) {
        return false;
    }
    len = 0;
    if (sign == 0xC000) return append(out, cap, len, "NaN", 3);
    if (sign != 0x0000 && sign != 0x4000) return false;
    if (sign == 0x4000 && !append(out, cap, len, "-", 1)) return false;
    auto digit = [&](std::int32_t i) -> std::int32_t {
        if (i < 0 || i >= ndigits) return 0;
        return static_cast<std::int32_t>(be_u16(p + 8 + 2 * i));
    };
    // Integer part: groups 0..weight.
    if (weight < 0) {
        if (!append(out, cap, len, "0", 1)) return false;
    } else {
        if (weight > 256) return false;
        for (std::int32_t g = 0; g <= weight; ++g) {           // bounded by weight
            char buf[8];
            const int w = std::snprintf(buf, sizeof(buf), g == 0 ? "%d" : "%04d",
                                        static_cast<int>(digit(g)));
            if (w <= 0 || !append(out, cap, len, buf, static_cast<std::size_t>(w))) return false;
        }
    }
    if (dscale > 0) {
        if (!append(out, cap, len, ".", 1)) return false;
        std::int32_t written = 0;
        for (std::int32_t g = weight + 1; written < dscale; ++g) {   // bounded by dscale
            char buf[8];
            std::snprintf(buf, sizeof(buf), "%04d", static_cast<int>(digit(g)));
            for (int k = 0; k < 4 && written < dscale; ++k, ++written) {
                if (!append(out, cap, len, &buf[k], 1)) return false;
            }
        }
    }
    return true;
}

bool numeric_text_to_binary(std::string_view s, std::uint8_t* out, std::size_t cap,
                            std::size_t& len) noexcept {
    assert(out != nullptr);
    if (s == "NaN") {
        if (cap < 8) return false;
        put_be(out, 0, 2); put_be(out + 2, 0, 2); put_be(out + 4, 0xC000, 2); put_be(out + 6, 0, 2);
        len = 8;
        return true;
    }
    std::size_t i = 0;
    bool neg = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) { neg = s[i] == '-'; ++i; }
    char ip[kMaxScalarText], fp[kMaxScalarText];
    std::size_t il = 0, fl = 0;
    while (i < s.size() && is_digit(s[i])) {
        if (il + 1 >= sizeof(ip)) return false;
        ip[il++] = s[i++];
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        while (i < s.size() && is_digit(s[i])) {
            if (fl + 1 >= sizeof(fp)) return false;
            fp[fl++] = s[i++];
        }
    }
    if (i != s.size() || il + fl == 0) return false;   // exponent forms refused
    std::size_t lead = 0;
    while (lead < il && ip[lead] == '0') ++lead;        // strip leading zeros
    const std::size_t int_digits = il - lead;
    const std::size_t int_groups = (int_digits + 3) / 4;
    const std::size_t frac_groups = (fl + 3) / 4;
    std::uint16_t groups[2 * kMaxScalarText / 4 + 2];
    std::size_t ng = 0;
    const std::size_t pad = int_groups * 4 - int_digits;   // left-pad first group
    for (std::size_t g = 0; g < int_groups; ++g) {
        std::uint16_t v = 0;
        for (std::size_t k = 0; k < 4; ++k) {
            const std::size_t pos = g * 4 + k;
            const char c = pos < pad ? '0' : ip[lead + pos - pad];
            v = static_cast<std::uint16_t>(v * 10 + (c - '0'));
        }
        groups[ng++] = v;
    }
    for (std::size_t g = 0; g < frac_groups; ++g) {
        std::uint16_t v = 0;
        for (std::size_t k = 0; k < 4; ++k) {
            const std::size_t pos = g * 4 + k;
            const char c = pos < fl ? fp[pos] : '0';
            v = static_cast<std::uint16_t>(v * 10 + (c - '0'));
        }
        groups[ng++] = v;
    }
    std::int32_t weight = static_cast<std::int32_t>(int_groups) - 1;
    std::size_t first = 0;
    while (first < ng && groups[first] == 0) { ++first; --weight; }
    std::size_t last = ng;
    while (last > first && groups[last - 1] == 0) --last;
    const std::size_t nd = last - first;
    if (nd == 0) weight = 0;
    if (cap < 8 + 2 * nd) return false;
    put_be(out, nd, 2);
    put_be(out + 2, static_cast<std::uint16_t>(static_cast<std::int16_t>(weight)), 2);
    put_be(out + 4, (neg && nd > 0) ? 0x4000 : 0x0000, 2);
    put_be(out + 6, fl, 2);
    for (std::size_t k = 0; k < nd; ++k) put_be(out + 8 + 2 * k, groups[first + k], 2);
    len = 8 + 2 * nd;
    assert(len <= cap);
    return true;
}

// Walk `sql`, calling on_text(begin, len) for literal passthrough spans and
// on_param(n) for each placeholder outside quotes/comments. Bounded by
// sql.size(); returns false on an unterminated quote only when strict.
template <typename OnText, typename OnParam>
bool scan_placeholders(std::string_view sql, OnText on_text, OnParam on_param) noexcept {
    const std::size_t n = sql.size();
    std::size_t i = 0;
    std::size_t span = 0;
    auto flush = [&](std::size_t upto) -> bool {
        const bool ok = upto <= span || on_text(sql.data() + span, upto - span);
        span = upto;
        return ok;
    };
    while (i < n) {
        const char c = sql[i];
        const bool prev_ident = i > 0 && is_ident_char(sql[i - 1]);
        if (c == '\'') {
            const bool esc = i > 0 && (sql[i - 1] == 'E' || sql[i - 1] == 'e') &&
                             !(i > 1 && is_ident_char(sql[i - 2]));
            ++i;
            while (i < n) {
                if (esc && sql[i] == '\\' && i + 1 < n) { i += 2; continue; }
                if (sql[i] == '\'') {
                    if (i + 1 < n && sql[i + 1] == '\'') { i += 2; continue; }
                    break;
                }
                ++i;
            }
            if (i < n) ++i;
        } else if (c == '"') {
            ++i;
            while (i < n) {
                if (sql[i] == '"') {
                    if (i + 1 < n && sql[i + 1] == '"') { i += 2; continue; }
                    break;
                }
                ++i;
            }
            if (i < n) ++i;
        } else if (c == '-' && i + 1 < n && sql[i + 1] == '-') {
            while (i < n && sql[i] != '\n') ++i;
        } else if (c == '/' && i + 1 < n && sql[i + 1] == '*') {
            std::size_t depth = 1;
            i += 2;
            while (i < n && depth > 0) {
                if (sql[i] == '/' && i + 1 < n && sql[i + 1] == '*') { ++depth; i += 2; }
                else if (sql[i] == '*' && i + 1 < n && sql[i + 1] == '/') { --depth; i += 2; }
                else ++i;
            }
        } else if (c == '$' && !prev_ident && i + 1 < n && is_digit(sql[i + 1])) {
            std::size_t j = i + 1;
            std::uint32_t num = 0;
            while (j < n && is_digit(sql[j])) {
                if (num > kMaxParamIndex) return false;
                num = num * 10 + static_cast<std::uint32_t>(sql[j] - '0');
                ++j;
            }
            if (!flush(i)) return false;
            if (!on_param(num)) return false;
            i = j;
            span = j;
        } else if (c == '$' && !prev_ident) {
            // Dollar-quoted body: $tag$ ... $tag$ (tag may be empty).
            std::size_t j = i + 1;
            while (j < n && is_ident_char(sql[j]) && sql[j] != '$') ++j;
            if (j < n && sql[j] == '$') {
                const std::string_view tag = sql.substr(i, j - i + 1);
                const std::size_t close = sql.find(tag, j + 1);
                i = close == std::string_view::npos ? n : close + tag.size();
            } else {
                ++i;
            }
        } else {
            ++i;
        }
    }
    return flush(n);
}

}  // namespace

bool binary_param_to_text(const BoundParam& p, char* out, std::size_t cap,
                          std::size_t& out_len, CodecError& err) noexcept {
    assert(out != nullptr);
    assert(p.binary);
    const auto* b = reinterpret_cast<const std::uint8_t*>(p.bytes.data());
    const std::size_t n = p.bytes.size();
    int w = -1;
    switch (p.type_oid) {
        case oid::kBool:
            if (n != 1) return fail(err, "22P03", "binary bool parameter must be 1 byte");
            w = std::snprintf(out, cap, "%s", b[0] != 0 ? "true" : "false");
            break;
        case oid::kInt2:
            if (n != 2) return fail(err, "22P03", "binary int2 parameter must be 2 bytes");
            w = std::snprintf(out, cap, "%d", static_cast<int>(static_cast<std::int16_t>(be_u16(b))));
            break;
        case oid::kInt4:
        case oid::kOid:
            if (n != 4) return fail(err, "22P03", "binary int4 parameter must be 4 bytes");
            w = p.type_oid == oid::kOid
                ? std::snprintf(out, cap, "%u", static_cast<unsigned>(be_u32(b)))
                : std::snprintf(out, cap, "%d", static_cast<int>(static_cast<std::int32_t>(be_u32(b))));
            break;
        case oid::kInt8:
            if (n != 8) return fail(err, "22P03", "binary int8 parameter must be 8 bytes");
            w = std::snprintf(out, cap, "%lld", static_cast<long long>(static_cast<std::int64_t>(be_u64(b))));
            break;
        case oid::kFloat4: {
            if (n != 4) return fail(err, "22P03", "binary float4 parameter must be 4 bytes");
            const std::uint32_t u = be_u32(b);
            float f;
            std::memcpy(&f, &u, sizeof(f));
            w = std::snprintf(out, cap, "%.9g", static_cast<double>(f));
            break;
        }
        case oid::kFloat8: {
            if (n != 8) return fail(err, "22P03", "binary float8 parameter must be 8 bytes");
            const std::uint64_t u = be_u64(b);
            double d;
            std::memcpy(&d, &u, sizeof(d));
            w = std::snprintf(out, cap, "%.17g", d);
            break;
        }
        case oid::kDate: {
            if (n != 4) return fail(err, "22P03", "binary date parameter must be 4 bytes");
            std::int64_t y; unsigned m, d;
            civil_from_days(static_cast<std::int32_t>(be_u32(b)) + kPgEpochDays, y, m, d);
            w = std::snprintf(out, cap, "%04lld-%02u-%02u", static_cast<long long>(y), m, d);
            break;
        }
        case oid::kNumeric: {
            std::size_t len = 0;
            if (!numeric_binary_to_text(b, n, out, cap, len)) {
                return fail(err, "22P03", "malformed binary numeric parameter");
            }
            out_len = len;
            return true;
        }
        default:
            if (!is_text_oid(p.type_oid)) {
                return fail(err, "0A000", "binary-format parameter of this type is "
                            "not supported -- send it in text format");
            }
            if (n > cap) return fail(err, "54000", "parameter value too large");
            if (n > 0) std::memcpy(out, b, n);
            out_len = n;
            return true;
    }
    if (w < 0 || static_cast<std::size_t>(w) >= cap) {
        return fail(err, "54000", "parameter value too large");
    }
    out_len = static_cast<std::size_t>(w);
    return true;
}

bool render_literal(std::string_view text, bool is_null, std::int32_t type_oid,
                    char* out, std::size_t cap, std::size_t& pos,
                    CodecError& err) noexcept {
    assert(out != nullptr);
    assert(pos <= cap);
    const auto too_big = [&]() { return fail(err, "54000", "statement with bound parameters is too large"); };
    if (is_null) return append(out, cap, pos, "NULL", 4) || too_big();
    if (std::memchr(text.data(), '\0', text.size()) != nullptr) {
        return fail(err, "22021", "parameter value contains a NUL byte");
    }
    if (is_numeric_oid(type_oid)) {
        if (!is_numeric_text(text)) {
            return fail(err, "22P02", "invalid input syntax for a numeric parameter");
        }
        const bool wrap = text[0] == '-' || text[0] == '+' || !is_digit(text[0]);
        if (wrap && !append(out, cap, pos, "(", 1)) return too_big();
        if (!is_digit(text[0]) && text[0] != '-' && text[0] != '+' && text[0] != '.') {
            // NaN / Infinity have no bare SQL spelling: quote them.
            if (!append(out, cap, pos, "'", 1) || !append(out, cap, pos, text.data(), text.size()) ||
                !append(out, cap, pos, "'", 1)) return too_big();
        } else if (!append(out, cap, pos, text.data(), text.size())) {
            return too_big();
        }
        if (wrap && !append(out, cap, pos, ")", 1)) return too_big();
        return true;
    }
    if (type_oid == oid::kBool) {
        bool v = false;
        if (!parse_bool_text(text, v)) {
            return fail(err, "22P02", "invalid input syntax for a boolean parameter");
        }
        return append(out, cap, pos, v ? "TRUE" : "FALSE", v ? 4 : 5) || too_big();
    }
    if (type_oid == oid::kDate) {
        std::int64_t days = 0;
        if (!parse_date_text(text, days)) {
            return fail(err, "22007", "invalid input syntax for a date parameter");
        }
        if (!append(out, cap, pos, "DATE ", 5)) return too_big();
    }
    if (!append(out, cap, pos, "'", 1)) return too_big();
    for (std::size_t i = 0; i < text.size(); ++i) {           // bounded by text.size()
        if (text[i] == '\'' && !append(out, cap, pos, "'", 1)) return too_big();
        if (!append(out, cap, pos, &text[i], 1)) return too_big();
    }
    return append(out, cap, pos, "'", 1) || too_big();
}

bool substitute_params(std::string_view sql, const BoundParam* params,
                       std::uint32_t n_params, char* out, std::size_t cap,
                       std::size_t& out_len, CodecError& err) noexcept {
    assert(out != nullptr);
    assert(params != nullptr || n_params == 0);
    std::size_t pos = 0;
    bool failed = false;
    char scratch[kMaxScalarText * 2 + 16];
    const bool ok = scan_placeholders(
        sql,
        [&](const char* p, std::size_t n) {
            if (append(out, cap, pos, p, n)) return true;
            failed = true;
            fail(err, "54000", "statement with bound parameters is too large");
            return false;
        },
        [&](std::uint32_t num) {
            if (num == 0 || num > n_params) {
                failed = true;
                fail(err, "42P02", "statement references a parameter that was not bound");
                return false;
            }
            const BoundParam& bp = params[num - 1];
            std::string_view text = bp.bytes;
            if (bp.binary && !bp.is_null) {
                std::size_t tl = 0;
                // Text-like binary values are their own text form: no scratch copy.
                if (is_text_oid(bp.type_oid)) {
                    text = bp.bytes;
                } else if (!binary_param_to_text(bp, scratch, sizeof(scratch), tl, err)) {
                    failed = true;
                    return false;
                } else {
                    text = std::string_view(scratch, tl);
                }
            }
            if (!render_literal(text, bp.is_null, bp.type_oid, out, cap, pos, err)) {
                failed = true;
                return false;
            }
            return true;
        });
    if (!ok || failed) {
        if (!failed) fail(err, "42P02", "parameter placeholder out of range");
        return false;
    }
    out_len = pos;
    assert(out_len <= cap);
    return true;
}

bool text_to_binary_result(std::string_view text, std::int32_t type_oid,
                           std::uint8_t* out, std::size_t cap,
                           std::size_t& out_len, CodecError& err) noexcept {
    assert(out != nullptr);
    char buf[kMaxScalarText + 1];
    auto z = [&]() -> const char* {
        const std::size_t n = text.size() < kMaxScalarText ? text.size() : kMaxScalarText;
        std::memcpy(buf, text.data(), n);
        buf[n] = '\0';
        return buf;
    };
    const auto bad = [&]() { return fail(err, "22P02", "result value does not match its declared type"); };
    const auto small = [&]() { return fail(err, "54000", "binary result cell exceeds the wire buffer"); };
    switch (type_oid) {
        case oid::kBool: {
            bool v = false;
            if (!parse_bool_text(text, v)) return bad();
            if (cap < 1) return small();
            out[0] = v ? 1 : 0;
            out_len = 1;
            return true;
        }
        case oid::kInt2: case oid::kInt4: case oid::kInt8: case oid::kOid: {
            if (text.empty() || text.size() > 24) return bad();
            char* end = nullptr;
            const long long v = std::strtoll(z(), &end, 10);
            if (end == nullptr || *end != '\0') return bad();
            const int w = type_oid == oid::kInt8 ? 8 : (type_oid == oid::kInt2 ? 2 : 4);
            if (cap < static_cast<std::size_t>(w)) return small();
            put_be(out, static_cast<std::uint64_t>(v), w);
            out_len = static_cast<std::size_t>(w);
            return true;
        }
        case oid::kFloat4: case oid::kFloat8: {
            if (text.empty() || text.size() > kMaxScalarText) return bad();
            char* end = nullptr;
            const double d = std::strtod(z(), &end);
            if (end == nullptr || *end != '\0') return bad();
            if (type_oid == oid::kFloat4) {
                if (cap < 4) return small();
                const float f = static_cast<float>(d);
                std::uint32_t u;
                std::memcpy(&u, &f, sizeof(u));
                put_be(out, u, 4);
                out_len = 4;
            } else {
                if (cap < 8) return small();
                std::uint64_t u;
                std::memcpy(&u, &d, sizeof(u));
                put_be(out, u, 8);
                out_len = 8;
            }
            return true;
        }
        case oid::kDate: {
            std::int64_t days = 0;
            if (!parse_date_text(text, days)) return bad();
            if (cap < 4) return small();
            put_be(out, static_cast<std::uint32_t>(static_cast<std::int32_t>(days)), 4);
            out_len = 4;
            return true;
        }
        case oid::kNumeric:
            if (!numeric_text_to_binary(text, out, cap, out_len)) return bad();
            return true;
        case oid::kBytea:
            break;
        default:
            if (is_text_oid(type_oid)) {
                if (text.size() > cap) return small();
                if (!text.empty()) std::memcpy(out, text.data(), text.size());
                out_len = text.size();
                return true;
            }
            break;
    }
    return fail(err, "0A000", "binary result format is not supported for this "
                "column type -- request text format");
}

namespace {

bool is_space(char c) noexcept { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (is_space(s.front()))) s.remove_prefix(1);
    while (!s.empty() && (is_space(s.back()) || s.back() == ';')) s.remove_suffix(1);
    return s;
}

bool ieq(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x + 32);
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y + 32);
        if (x != y) return false;
    }
    return true;
}

// Next whitespace/`=`-delimited word; advances `s`.
std::string_view next_word(std::string_view& s) noexcept {
    s = trim(s);
    std::size_t i = 0;
    while (i < s.size() && !is_space(s[i]) && s[i] != '=') ++i;
    const std::string_view w = s.substr(0, i);
    s.remove_prefix(i);
    return w;
}

std::string_view unquote(std::string_view v) noexcept {
    v = trim(v);
    if (v.size() >= 2 && (v.front() == '\'' || v.front() == '"') && v.back() == v.front()) {
        v = v.substr(1, v.size() - 2);
    }
    return v;
}

bool starts_ci(std::string_view s, std::string_view p) noexcept {
    return s.size() >= p.size() && ieq(s.substr(0, p.size()), p);
}

// Is SET <name> = <value> something this server already satisfies or that
// only affects client-side presentation?
bool session_value_ok(std::string_view name, std::string_view value) noexcept {
    if (ieq(name, "application_name") || ieq(name, "extra_float_digits") ||
        ieq(name, "client_min_messages")) {
        return true;
    }
    if (ieq(name, "client_encoding")) {
        return ieq(value, "UTF8") || ieq(value, "UTF-8") || ieq(value, "UNICODE");
    }
    if (ieq(name, "datestyle")) return starts_ci(value, "ISO");
    if (ieq(name, "intervalstyle")) return ieq(value, "postgres");
    if (ieq(name, "timezone")) {
        return ieq(value, "UTC") || ieq(value, "GMT") || ieq(value, "Etc/UTC") ||
               value == "0" || value == "+00:00";
    }
    return false;
}

}  // namespace

SessionCommand classify_session_command(std::string_view sql, const char*& tag,
                                        CodecError& err) noexcept {
    std::string_view s = trim(sql);
    const std::string_view verb = next_word(s);
    if (ieq(verb, "RESET")) {
        tag = "RESET";
        return SessionCommand::Accepted;   // back to this server's own values
    }
    if (!ieq(verb, "SET")) return SessionCommand::NotSession;
    std::string_view rest = s;
    std::string_view name = next_word(rest);
    if (ieq(name, "SESSION") || ieq(name, "LOCAL")) name = next_word(rest);
    if (ieq(name, "TIME")) {                    // SET TIME ZONE <value>
        (void)next_word(rest);
        name = "timezone";
    }
    rest = trim(rest);
    if (!rest.empty() && rest.front() == '=') rest.remove_prefix(1);
    else if (starts_ci(rest, "TO ")) rest.remove_prefix(3);
    const std::string_view value = unquote(rest);
    assert(name.size() <= sql.size());
    if (!name.empty() && session_value_ok(name, value)) {
        tag = "SET";
        return SessionCommand::Accepted;
    }
    err.sqlstate = "0A000";
    err.message  = "this SET is not supported: only client-presentation "
                   "settings (application_name, extra_float_digits, "
                   "client_encoding UTF8, DateStyle ISO, TimeZone UTC, ...) "
                   "are accepted";
    return SessionCommand::Refused;
}

std::uint32_t max_param_ref(std::string_view sql) noexcept {
    std::uint32_t mx = 0;
    (void)scan_placeholders(
        sql, [](const char*, std::size_t) { return true; },
        [&](std::uint32_t num) { if (num > mx) mx = num; return true; });
    assert(mx <= kMaxParamIndex + 9);
    return mx;
}

}  // namespace bolt::api::proto::pgwire

#endif  // BOLTAPI_WITH_PG_WIRE
