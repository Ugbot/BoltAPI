// src/proto/postgres_wire_cursor.cpp — SQL-level cursors (G2ETL-67):
// DECLARE / FETCH / MOVE / CLOSE over the extended session's portals.
// See postgres_wire_extended.h.

#include "postgres_wire_extended.h"

#if defined(BOLTAPI_WITH_PG_WIRE)

#include "boltapi/proto/postgres_wire_codec.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace bolt::api::proto::pgwire {

namespace {

constexpr std::uint32_t kMaxCursorTokens = 8;

enum class TokKind : std::uint8_t { Word, Quoted, Number, Other };

struct Tok {
    TokKind          kind = TokKind::Other;
    std::string_view text;   // Quoted: between the quotes, "" still doubled
    std::size_t      end  = 0;
};

bool cur_space(char c) noexcept { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

bool cur_ident(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '$' ||
           static_cast<unsigned char>(c) >= 0x80;
}

bool cur_digit(char c) noexcept { return c >= '0' && c <= '9'; }

bool kw(const Tok& t, const char* k) noexcept {
    const std::size_t n = std::strlen(k);
    if (t.kind != TokKind::Word || t.text.size() != n) return false;
    for (std::size_t i = 0; i < n; ++i) {
        char x = t.text[i];
        if (x >= 'a' && x <= 'z') x = static_cast<char>(x - 32);
        if (x != k[i]) return false;
    }
    return true;
}

// Next token at or after `i`, skipping whitespace, comments and a trailing
// ';'. Returns false at the end of the statement.
bool next_tok(std::string_view s, std::size_t i, Tok& t) noexcept {
    while (i < s.size()) {                                  // bounded by s.size()
        const char c = s[i];
        if (cur_space(c) || c == ';') { ++i; continue; }
        if (c == '-' && i + 1 < s.size() && s[i + 1] == '-') {
            while (i < s.size() && s[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '*') {
            const std::size_t e = s.find("*/", i + 2);
            i = e == std::string_view::npos ? s.size() : e + 2;
            continue;
        }
        break;
    }
    if (i >= s.size()) return false;
    const std::size_t start = i;
    const char c = s[i];
    if (c == '"') {
        ++i;
        while (i < s.size()) {                              // bounded by s.size()
            if (s[i] == '"') {
                if (i + 1 < s.size() && s[i + 1] == '"') { i += 2; continue; }
                break;
            }
            ++i;
        }
        if (i >= s.size()) { t.kind = TokKind::Other; t.end = s.size(); return true; }
        t.kind = TokKind::Quoted;
        t.text = s.substr(start + 1, i - start - 1);
        t.end  = i + 1;
        return true;
    }
    if (cur_digit(c) || ((c == '-' || c == '+') && i + 1 < s.size() && cur_digit(s[i + 1]))) {
        ++i;
        while (i < s.size() && cur_digit(s[i])) ++i;
        t.kind = TokKind::Number;
    } else if (cur_ident(c)) {
        while (i < s.size() && cur_ident(s[i])) ++i;
        t.kind = TokKind::Word;
    } else {
        ++i;
        t.kind = TokKind::Other;
    }
    t.text = s.substr(start, i - start);
    t.end  = i;
    assert(t.end > start);
    return true;
}

CursorVerb refuse(CodecError& err, const char* sqlstate, const char* msg) noexcept {
    err.sqlstate = sqlstate;
    err.message  = msg;
    return CursorVerb::Refused;
}

// Unquoted names fold to lower case; quoted ones keep their bytes with ""
// undoubled. False when the token is not a name or does not fit.
bool take_name(const Tok& t, char (&out)[kMaxCursorName]) noexcept {
    if (t.kind != TokKind::Word && t.kind != TokKind::Quoted) return false;
    std::size_t n = 0;
    for (std::size_t i = 0; i < t.text.size(); ++i) {       // bounded by the token
        char c = t.text[i];
        if (t.kind == TokKind::Quoted && c == '"') ++i;     // "" -> "
        else if (t.kind == TokKind::Word && c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
        if (n + 1 >= kMaxCursorName) return false;
        out[n++] = c;
    }
    out[n] = '\0';
    assert(n < kMaxCursorName);
    return n > 0;
}

// Signed count token; negative means a backward move.
bool take_count(const Tok& t, std::int64_t& v) noexcept {
    if (t.kind != TokKind::Number) return false;
    std::size_t i = 0;
    bool neg = false;
    if (t.text[0] == '-' || t.text[0] == '+') { neg = t.text[0] == '-'; ++i; }
    std::uint64_t acc = 0;
    for (; i < t.text.size(); ++i) {                        // bounded by the token
        acc = acc * 10 + static_cast<std::uint64_t>(t.text[i] - '0');
        if (acc > 0xFFFFFFFFull) acc = 0xFFFFFFFFull;       // row counts are u32
    }
    v = neg ? -static_cast<std::int64_t>(acc) : static_cast<std::int64_t>(acc);
    return true;
}

CursorVerb parse_declare(std::string_view s, std::size_t i, CursorCommand& out,
                         CodecError& err) noexcept {
    Tok t;
    if (!next_tok(s, i, t) || !take_name(t, out.name)) {
        return refuse(err, "42602", "invalid or overlong cursor name");
    }
    i = t.end;
    bool saw_cursor = false;
    for (std::uint32_t k = 0; k < kMaxCursorTokens; ++k) {  // bounded
        if (!next_tok(s, i, t)) break;
        i = t.end;
        if (kw(t, "BINARY")) {
            return refuse(err, "0A000", "BINARY cursors are not supported: request "
                          "binary results with the protocol result format");
        }
        if (kw(t, "SCROLL")) {
            return refuse(err, "0A000", "SCROLL cursors are not supported: this "
                          "endpoint's cursors only move forward");
        }
        if (kw(t, "ASENSITIVE") || kw(t, "INSENSITIVE")) continue;
        if (kw(t, "NO")) {
            if (!next_tok(s, i, t) || !kw(t, "SCROLL")) break;
            i = t.end;
            continue;
        }
        if (kw(t, "CURSOR")) { saw_cursor = true; continue; }
        if (saw_cursor && (kw(t, "WITH") || kw(t, "WITHOUT"))) {
            out.hold = kw(t, "WITH");
            if (!next_tok(s, i, t) || !kw(t, "HOLD")) break;
            i = t.end;
            continue;
        }
        if (saw_cursor && kw(t, "FOR")) {
            std::string_view q = s.substr(i);
            while (!q.empty() && (cur_space(q.front()))) q.remove_prefix(1);
            while (!q.empty() && (cur_space(q.back()) || q.back() == ';')) q.remove_suffix(1);
            if (q.empty()) break;
            out.query = q;
            out.verb  = CursorVerb::Declare;
            return CursorVerb::Declare;
        }
        break;
    }
    return refuse(err, "42601", "syntax error in DECLARE: expected DECLARE name "
                  "[NO SCROLL] CURSOR [WITH[OUT] HOLD] FOR query");
}

// FETCH / MOVE: [direction] [FROM | IN] name.
CursorVerb parse_fetch(std::string_view s, std::size_t i, CursorVerb verb,
                       CursorCommand& out, CodecError& err) noexcept {
    Tok toks[kMaxCursorTokens];
    std::uint32_t n = 0;
    Tok t;
    while (next_tok(s, i, t)) {                             // bounded by kMaxCursorTokens
        if (n == kMaxCursorTokens || t.kind == TokKind::Other) {
            return refuse(err, "42601", "syntax error in FETCH/MOVE");
        }
        toks[n++] = t;
        i = t.end;
    }
    if (n == 0 || !take_name(toks[n - 1], out.name)) {
        return refuse(err, "42601", "FETCH/MOVE needs a cursor name");
    }
    std::uint32_t d = n - 1;
    if (d > 0 && (kw(toks[d - 1], "FROM") || kw(toks[d - 1], "IN"))) --d;
    const Tok* a = d > 0 ? &toks[0] : nullptr;
    const Tok* b = d > 1 ? &toks[1] : nullptr;
    if (d > 2) return refuse(err, "42601", "syntax error in FETCH/MOVE direction");
    out.verb = verb;
    out.count = 1;
    std::int64_t v = 1;
    if (a == nullptr || (d == 1 && (kw(*a, "NEXT") || kw(*a, "FORWARD")))) {
        return verb;
    }
    if (kw(*a, "PRIOR") || kw(*a, "BACKWARD") || kw(*a, "FIRST") || kw(*a, "LAST") ||
        kw(*a, "RELATIVE") || (kw(*a, "ABSOLUTE") && verb == CursorVerb::Fetch)) {
        return refuse(err, "55000", "cursor can only scan forward: only NEXT, "
                      "FORWARD [n|ALL], n and ALL (and MOVE ABSOLUTE n ahead) are "
                      "supported");
    }
    const bool forward = kw(*a, "FORWARD");
    const bool absolute = kw(*a, "ABSOLUTE");
    const Tok* c = (forward || absolute) ? b : a;
    if (c == nullptr || ((forward || absolute) ? d != 2 : d != 1)) {
        return refuse(err, "42601", "syntax error in FETCH/MOVE direction");
    }
    if (kw(*c, "ALL") && !absolute) {
        out.all = true;
        out.count = 0xFFFFFFFFu;
        return verb;
    }
    if (!take_count(*c, v)) return refuse(err, "42601", "syntax error in FETCH/MOVE count");
    if (v < 0) return refuse(err, "55000", "cursor can only scan forward");
    if (v == 0 && !absolute) {
        return refuse(err, "0A000", "FETCH/MOVE 0 (re-read the current row) is not supported");
    }
    out.absolute = absolute;
    out.count = static_cast<std::uint32_t>(v);
    return verb;
}

}  // namespace

CursorVerb classify_cursor_command(std::string_view sql, CursorCommand& out,
                                   CodecError& err) noexcept {
    out = CursorCommand{};
    Tok t;
    if (!next_tok(sql, 0, t) || t.kind != TokKind::Word) return CursorVerb::None;
    if (kw(t, "DECLARE")) {
        const CursorVerb v = parse_declare(sql, t.end, out, err);
        assert(v == CursorVerb::Declare || v == CursorVerb::Refused);
        return v;
    }
    if (kw(t, "FETCH")) return parse_fetch(sql, t.end, CursorVerb::Fetch, out, err);
    if (kw(t, "MOVE")) return parse_fetch(sql, t.end, CursorVerb::Move, out, err);
    if (kw(t, "CLOSE")) {
        Tok n;
        if (!next_tok(sql, t.end, n)) return refuse(err, "42601", "CLOSE needs a cursor name");
        Tok extra;
        if (next_tok(sql, n.end, extra)) return refuse(err, "42601", "syntax error in CLOSE");
        out.verb = CursorVerb::Close;
        if (kw(n, "ALL")) { out.all = true; return CursorVerb::Close; }
        if (!take_name(n, out.name)) return refuse(err, "42602", "invalid or overlong cursor name");
        return CursorVerb::Close;
    }
    return CursorVerb::None;
}

namespace detail {

static_assert(kMaxCursorName == kMaxNameLen, "cursor names are portal names");

ExtendedSession::CursorStep ExtendedSession::cursor_declare(
    const CursorCommand& cc, IQueryExecutor& exec, QueryFailure& qf) noexcept {
    assert(cc.verb == CursorVerb::Declare && !cc.query.empty());
    if (tx_status_ == 'I' && !cc.hold) {
        qf.sqlstate = "25P01";
        qf.message  = "DECLARE CURSOR can only be used in transaction blocks";
        return CursorStep::Failed;
    }
    if (!is_query_shaped(cc.query)) {
        qf.sqlstate = "42601";
        qf.message  = "DECLARE CURSOR needs a SELECT / VALUES / TABLE query";
        return CursorStep::Failed;
    }
    if (cc.query.size() > max_stmt_bytes_) {
        qf.sqlstate = "54000";
        qf.message  = "cursor query exceeds this endpoint's statement capacity";
        return CursorStep::Failed;
    }
    if (find_portal(cc.name) >= 0) {
        qf.sqlstate = "42P03";
        qf.message  = "a cursor with this name already exists";
        return CursorStep::Failed;
    }
    std::int32_t ci = -1;
    for (std::size_t i = 1; i < portals_.size(); ++i) {         // bounded by slots
        if (!portals_[i].used) { ci = static_cast<std::int32_t>(i); break; }
    }
    if (ci < 0) {
        qf.sqlstate = "53000";
        qf.message  = "too many open cursors/portals on this connection -- CLOSE some";
        return CursorStep::Failed;
    }
    FieldDesc fields[kMaxFields];
    std::uint32_t count = 0;
    current_ = -1;
    if (!exec.execute(cc.query, fields, kMaxFields, count, qf)) return CursorStep::Failed;
    Portal& c = portals_[static_cast<std::size_t>(ci)];
    std::memcpy(portal_sql(ci), cc.query.data(), cc.query.size());
    std::memcpy(c.name, cc.name, sizeof(c.name));
    c.sql_len      = cc.query.size();
    c.empty_query  = false;
    c.done         = false;
    c.session_tag  = nullptr;
    c.next_row     = 0;
    c.n_formats    = 0;
    c.cursor       = true;
    c.holdable     = cc.hold;
    c.fetch_from   = -1;
    c.field_count  = count;
    for (std::uint32_t k = 0; k < count; ++k) {                  // bounded by kMaxFields
        c.oids[k] = fields[k].type_oid;
        const std::size_t nl = fields[k].name.size() < kMaxNameLen - 1
            ? fields[k].name.size() : kMaxNameLen - 1;
        std::memcpy(c.names[k], fields[k].name.data(), nl);
        c.names[k][nl] = '\0';
    }
    c.materialized = true;
    c.used         = true;
    current_ = ci;
    return CursorStep::Tagged;
}

ExtendedSession::CursorStep ExtendedSession::cursor_statement(
    std::string_view sql, IQueryExecutor& exec, char* tag, std::size_t tag_cap,
    std::int32_t& cursor, std::uint32_t& count, QueryFailure& qf) noexcept {
    assert(tag != nullptr && tag_cap >= 32);
    CursorCommand cc;
    CodecError ce;
    const CursorVerb v = classify_cursor_command(sql, cc, ce);
    if (v == CursorVerb::None) return CursorStep::Pass;
    if (v == CursorVerb::Refused) {
        qf.sqlstate = ce.sqlstate;
        qf.message  = ce.message;
        return CursorStep::Failed;
    }
    if (v == CursorVerb::Declare) {
        const CursorStep s = cursor_declare(cc, exec, qf);
        if (s == CursorStep::Tagged) std::snprintf(tag, tag_cap, "DECLARE CURSOR");
        return s;
    }
    if (v == CursorVerb::Close && cc.all) {
        for (std::size_t i = 1; i < portals_.size(); ++i) {     // bounded by slots
            if (portals_[i].used && portals_[i].cursor) close_portal(static_cast<std::int32_t>(i));
        }
        std::snprintf(tag, tag_cap, "CLOSE CURSOR ALL");
        return CursorStep::Tagged;
    }
    const std::int32_t ci = find_portal(cc.name);
    if (ci < 0) {
        qf.sqlstate = "34000";
        qf.message  = "cursor does not exist";
        return CursorStep::Failed;
    }
    if (v == CursorVerb::Close) {
        close_portal(ci);
        std::snprintf(tag, tag_cap, "CLOSE CURSOR");
        return CursorStep::Tagged;
    }
    Portal& c = portals_[static_cast<std::size_t>(ci)];
    if (!c.materialized || current_ != ci) {
        qf.sqlstate = "55000";
        qf.message  = "cursor's result was displaced by another query on this "
                      "connection (one materialized result at a time): FETCH "
                      "before running anything else";
        return CursorStep::Failed;
    }
    const std::uint32_t total = exec.row_count();
    if (cc.absolute) {
        if (cc.count < c.next_row) {
            qf.sqlstate = "55000";
            qf.message  = "cursor can only scan forward";
            return CursorStep::Failed;
        }
        c.next_row = cc.count < total ? cc.count : total;
        std::snprintf(tag, tag_cap, "MOVE %u", cc.count >= 1 && cc.count <= total ? 1u : 0u);
        return CursorStep::Tagged;
    }
    if (v == CursorVerb::Move) {
        const std::uint32_t left = total - (c.next_row < total ? c.next_row : total);
        const std::uint32_t moved = cc.count < left ? cc.count : left;
        c.next_row += moved;
        std::snprintf(tag, tag_cap, "MOVE %u", moved);
        assert(c.next_row <= total);
        return CursorStep::Tagged;
    }
    cursor = ci;
    count  = cc.count;
    return CursorStep::Fetch;
}

ExtendedSession::Emit ExtendedSession::emit_rows(const Portal& fmt, std::uint32_t& next_row,
                                                 std::uint64_t end_row, std::int32_t max_rows,
                                                 int fd, MsgWriter& w, IQueryExecutor& exec,
                                                 QueryFailure& qf) noexcept {
    assert(fmt.materialized);
    const std::uint64_t total = exec.row_count();
    const std::uint64_t end = end_row < total ? end_row : total;
    std::string_view values[kMaxFields];
    bool is_null[kMaxFields];
    std::uint8_t cell[512];
    std::uint32_t sent = 0;
    while (next_row < end) {                                      // bounded by row_count()
        if (max_rows > 0 && sent >= static_cast<std::uint32_t>(max_rows)) return Emit::Suspended;
        if (!exec.row(next_row, values, is_null, fmt.field_count)) break;
        w.begin('D');
        w.put_i16(static_cast<std::int16_t>(fmt.field_count));
        for (std::uint32_t c = 0; c < fmt.field_count; ++c) {     // bounded by kMaxFields
            if (is_null[c]) { w.put_i32(-1); continue; }
            if (format_of(fmt, c) == 0 || is_text_like(fmt.oids[c])) {
                w.put_i32(static_cast<std::int32_t>(values[c].size()));
                w.put_bytes(values[c].data(), values[c].size());
                continue;
            }
            CodecError ce;
            std::size_t n = 0;
            if (!text_to_binary_result(values[c], fmt.oids[c], cell, sizeof(cell), n, ce)) {
                qf.sqlstate = ce.sqlstate;
                qf.message  = ce.message;
                return Emit::Failed;
            }
            w.put_i32(static_cast<std::int32_t>(n));
            w.put_bytes(cell, n);
        }
        if (!w.finish()) {
            qf.sqlstate = "54000";
            qf.message  = "a result row exceeded this endpoint's wire buffer and was "
                          "refused rather than sent truncated";
            return Emit::Failed;
        }
        if (!w.send(fd)) return Emit::Dead;
        ++next_row;
        ++sent;
    }
    assert(max_rows <= 0 || sent <= static_cast<std::uint32_t>(max_rows));
    return Emit::Done;
}

ExtendedSession::Emit ExtendedSession::simple_fetch(std::int32_t ci, std::uint32_t count,
                                                    int fd, MsgWriter& w,
                                                    IQueryExecutor& exec,
                                                    QueryFailure& qf) noexcept {
    assert(ci > 0 && static_cast<std::size_t>(ci) < portals_.size());
    Portal& c = portals_[static_cast<std::size_t>(ci)];
    assert(c.used && c.cursor && current_ == ci);
    FieldDesc fields[kMaxFields];
    for (std::uint32_t k = 0; k < c.field_count; ++k) {           // bounded by kMaxFields
        fields[k].name = c.names[k];
        fields[k].type_oid = c.oids[k];
    }
    if (c.field_count > 0) {
        if (!put_row_description(w, fields, c.field_count, nullptr)) {
            qf.sqlstate = "54000";
            qf.message  = "result row is too wide for this endpoint's wire buffer";
            return Emit::Failed;
        }
        if (!w.send(fd)) return Emit::Dead;
    }
    const std::uint32_t before = c.next_row;
    const Emit e = emit_rows(c, c.next_row, static_cast<std::uint64_t>(before) + count, 0,
                             fd, w, exec, qf);
    if (e != Emit::Done) return e;
    char tag[32];
    std::snprintf(tag, sizeof(tag), "FETCH %u", c.next_row - before);
    w.begin('C');
    w.put_cstring(tag);
    if (!w.finish() || !w.send(fd)) return Emit::Dead;
    return Emit::Done;
}

// Extended FETCH: the unnamed (or named) portal borrows the cursor's shape
// and streams the cursor's rows under its own result formats.
bool ExtendedSession::bind_fetch(std::int32_t pi, std::int32_t ci, std::uint32_t count,
                                 QueryFailure& qf) noexcept {
    assert(pi >= 0 && ci > 0 && pi != ci);
    Portal& p = portals_[static_cast<std::size_t>(pi)];
    const Portal& c = portals_[static_cast<std::size_t>(ci)];
    if (p.n_formats > 1 && p.n_formats != c.field_count) {
        qf.sqlstate = "08P01";
        qf.message  = "Bind result-format count does not match the result's columns";
        return false;
    }
    for (std::uint32_t k = 0; k < c.field_count; ++k) {           // bounded by kMaxFields
        p.oids[k] = c.oids[k];
        std::memcpy(p.names[k], c.names[k], kMaxNameLen);
        if (format_of(p, k) == 1 && !binary_result_supported(c.oids[k])) {
            qf.sqlstate = "0A000";
            qf.message  = "binary result format requested for a column type this "
                          "endpoint only sends as text";
            return false;
        }
    }
    p.materialized = true;
    if (c.field_count == 0) {
        std::snprintf(p.tag_buf, sizeof(p.tag_buf), "FETCH 0");
        p.session_tag = p.tag_buf;
        p.field_count = 0;
        return true;
    }
    p.field_count  = c.field_count;
    p.fetch_from   = ci;
    p.fetch_left   = count;
    p.fetch_sent   = 0;
    p.materialized = true;
    assert(p.fetch_from > 0);
    return true;
}

bool ExtendedSession::send_fetch(Portal& p, std::int32_t max_rows, int fd, MsgWriter& w,
                                 IQueryExecutor& exec) noexcept {
    assert(p.fetch_from > 0);
    Portal& c = portals_[static_cast<std::size_t>(p.fetch_from)];
    assert(c.used && c.cursor);
    const std::uint32_t before = c.next_row;
    QueryFailure qf;
    const Emit e = emit_rows(p, c.next_row, static_cast<std::uint64_t>(before) + p.fetch_left,
                             max_rows, fd, w, exec, qf);
    const std::uint32_t moved = c.next_row - before;
    p.fetch_sent += moved;
    p.fetch_left -= p.fetch_left == 0xFFFFFFFFu ? 0 : moved;
    if (e == Emit::Dead) return false;
    if (e == Emit::Failed) return fail(fd, w, qf.sqlstate, qf.message);
    if (e == Emit::Suspended) {
        w.begin('s');
        return w.finish() && w.send(fd);
    }
    p.done = true;
    char tag[32];
    std::snprintf(tag, sizeof(tag), "FETCH %u", p.fetch_sent);
    w.begin('C');
    w.put_cstring(tag);
    return w.finish() && w.send(fd);
}

bool ExtendedSession::describe_fetch(std::string_view sql, int fd, MsgWriter& w) noexcept {
    CursorCommand cc;
    CodecError ce;
    if (classify_cursor_command(sql, cc, ce) != CursorVerb::Fetch) return false;
    const std::int32_t ci = find_portal(cc.name);
    if (ci <= 0 || !portals_[static_cast<std::size_t>(ci)].cursor) return false;
    const Portal& c = portals_[static_cast<std::size_t>(ci)];
    if (c.field_count == 0) return false;
    FieldDesc fields[kMaxFields];
    for (std::uint32_t k = 0; k < c.field_count; ++k) {           // bounded by kMaxFields
        fields[k].name = c.names[k];
        fields[k].type_oid = c.oids[k];
    }
    if (!put_row_description(w, fields, c.field_count, nullptr)) {
        (void)fail(fd, w, "54000", "result row is too wide for this endpoint's wire buffer");
        return true;
    }
    (void)w.send(fd);
    assert(c.field_count <= kMaxFields);
    return true;
}

}  // namespace detail

}  // namespace bolt::api::proto::pgwire

#endif  // BOLTAPI_WITH_PG_WIRE
