// src/proto/postgres_wire_extended.cpp — Extended Query protocol (G2ETL-47).
// See postgres_wire_extended.h and the SCOPE note in postgres_wire.h.

#include "postgres_wire_extended.h"

#if defined(BOLTAPI_WITH_PG_WIRE)

#include "boltapi/proto/postgres_wire_codec.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace bolt::api::proto::pgwire::detail {

namespace {

bool name_eq(const char* stored, std::string_view name) noexcept {
    assert(stored != nullptr);
    return std::strlen(stored) == name.size() &&
           std::memcmp(stored, name.data(), name.size()) == 0;
}

void set_name(char (&dst)[kMaxNameLen], std::string_view name) noexcept {
    assert(name.size() < kMaxNameLen);
    std::memcpy(dst, name.data(), name.size());
    dst[name.size()] = '\0';
}

bool ieq_prefix(std::string_view s, std::size_t at, const char* kw) noexcept {
    const std::size_t n = std::strlen(kw);
    if (at + n > s.size()) return false;
    for (std::size_t i = 0; i < n; ++i) {
        char c = s[at + i];
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
        if (c != kw[i]) return false;
    }
    const std::size_t end = at + n;
    if (end == s.size()) return true;
    const char c = s[end];
    return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
             (c >= '0' && c <= '9'));
}

// Does the statement return rows? Decides whether Describe(statement) may
// ask the executor for a shape (a read) or must answer NoData (a write that
// must not run before Execute).
bool is_query_shaped(std::string_view sql) noexcept {
    std::size_t i = 0;
    while (i < sql.size()) {                                    // bounded by sql.size()
        const char c = sql[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(') { ++i; continue; }
        if (c == '-' && i + 1 < sql.size() && sql[i + 1] == '-') {
            while (i < sql.size() && sql[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < sql.size() && sql[i + 1] == '*') {
            const std::size_t e = sql.find("*/", i + 2);
            i = e == std::string_view::npos ? sql.size() : e + 2;
            continue;
        }
        break;
    }
    static constexpr const char* kReads[] = {"SELECT", "WITH", "VALUES", "TABLE",
                                             "SHOW", "EXPLAIN"};
    for (const char* kw : kReads) {
        if (ieq_prefix(sql, i, kw)) return true;
    }
    return false;
}

bool binary_result_supported(std::int32_t t) noexcept {
    switch (t) {
        case oid::kBool: case oid::kInt2: case oid::kInt4: case oid::kInt8:
        case oid::kOid: case oid::kFloat4: case oid::kFloat8: case oid::kDate:
        case oid::kNumeric: case oid::kText: case oid::kVarchar: case oid::kBpchar:
        case oid::kName: case oid::kUnknown:
            return true;
        default:
            return false;
    }
}

bool is_text_like(std::int32_t t) noexcept {
    return t == oid::kText || t == oid::kVarchar || t == oid::kBpchar ||
           t == oid::kName || t == oid::kUnknown;
}

}  // namespace

ExtendedSession::ExtendedSession(const Config& cfg) noexcept
    : max_stmt_bytes_(cfg.max_statement_bytes),
      stmts_(cfg.max_prepared_statements),
      portals_(cfg.max_portals),
      stmt_pool_(cfg.statement_pool_bytes),
      portal_sql_(static_cast<std::size_t>(cfg.max_portals) * cfg.max_statement_bytes),
      describe_sql_(cfg.max_statement_bytes) {
    assert(cfg.max_prepared_statements >= 1 && cfg.max_portals >= 1);
    assert(cfg.max_statement_bytes >= 1024 &&
           cfg.statement_pool_bytes >= cfg.max_statement_bytes);
}

void ExtendedSession::reset() noexcept {
    for (auto& s : stmts_) s.used = false;
    for (auto& p : portals_) p.used = false;
    pool_used_ = 0;
    current_ = -1;
    in_error_ = false;
    assert(stmts_.size() >= 1 && portals_.size() >= 1);
}

void ExtendedSession::on_simple_query() noexcept {
    close_statement(0);
    close_portal(0);
    current_ = -1;   // the simple query replaces whatever the executor held
    in_error_ = false;
}

std::string_view ExtendedSession::statement_sql(const Statement& st) const noexcept {
    assert(st.used);
    assert(st.sql_off + st.sql_len <= stmt_pool_.size());
    return std::string_view(stmt_pool_.data() + st.sql_off, st.sql_len);
}

char* ExtendedSession::portal_sql(std::int32_t pi) noexcept {
    assert(pi >= 0 && static_cast<std::size_t>(pi) < portals_.size());
    return portal_sql_.data() + static_cast<std::size_t>(pi) * max_stmt_bytes_;
}

std::int32_t ExtendedSession::find_statement(std::string_view name) const noexcept {
    if (name.empty()) return stmts_[0].used ? 0 : -1;
    for (std::size_t i = 1; i < stmts_.size(); ++i) {           // bounded by slots
        if (stmts_[i].used && name_eq(stmts_[i].name, name)) return static_cast<std::int32_t>(i);
    }
    return -1;
}

std::int32_t ExtendedSession::find_portal(std::string_view name) const noexcept {
    if (name.empty()) return portals_[0].used ? 0 : -1;
    for (std::size_t i = 1; i < portals_.size(); ++i) {         // bounded by slots
        if (portals_[i].used && name_eq(portals_[i].name, name)) return static_cast<std::int32_t>(i);
    }
    return -1;
}

void ExtendedSession::close_statement(std::int32_t si) noexcept {
    assert(si >= 0 && static_cast<std::size_t>(si) < stmts_.size());
    stmts_[static_cast<std::size_t>(si)].used = false;
}

void ExtendedSession::close_portal(std::int32_t pi) noexcept {
    assert(pi >= 0 && static_cast<std::size_t>(pi) < portals_.size());
    portals_[static_cast<std::size_t>(pi)].used = false;
    if (current_ == pi) current_ = -1;
}

// Bump-allocate from the pool; when full, slide live statements down in
// offset order (bounded: one pass per live statement) and retry once.
bool ExtendedSession::store_sql(Statement& st, std::string_view sql) noexcept {
    assert(!st.used);
    if (sql.size() > max_stmt_bytes_) return false;
    if (pool_used_ + sql.size() > stmt_pool_.size()) {
        std::size_t write = 0;
        for (auto& s : stmts_) {
            if (s.used && s.sql_len == 0) s.sql_off = 0;
        }
        for (std::size_t pass = 0; pass < stmts_.size(); ++pass) {  // bounded
            Statement* lowest = nullptr;
            for (auto& s : stmts_) {
                if (s.used && s.sql_len > 0 && s.sql_off >= write &&
                    (lowest == nullptr || s.sql_off < lowest->sql_off)) {
                    lowest = &s;
                }
            }
            if (lowest == nullptr) break;
            std::memmove(stmt_pool_.data() + write, stmt_pool_.data() + lowest->sql_off,
                         lowest->sql_len);
            lowest->sql_off = write;
            write += lowest->sql_len;
        }
        pool_used_ = write;
        if (pool_used_ + sql.size() > stmt_pool_.size()) return false;
    }
    if (!sql.empty()) std::memcpy(stmt_pool_.data() + pool_used_, sql.data(), sql.size());
    st.sql_off = pool_used_;
    st.sql_len = sql.size();
    pool_used_ += sql.size();
    assert(pool_used_ <= stmt_pool_.size());
    return true;
}

bool ExtendedSession::fail(int fd, MsgWriter& w, const char* sqlstate,
                           std::string_view msg) noexcept {
    assert(sqlstate != nullptr);
    in_error_ = true;
    send_error(fd, w, sqlstate, msg);
    return true;
}

bool ExtendedSession::handle(char type, const std::uint8_t* body, std::size_t len,
                             int fd, MsgWriter& w, IQueryExecutor& exec) noexcept {
    assert(body != nullptr || len == 0);
    if (type == 'S') {                           // Sync: end of the batch
        in_error_ = false;
        close_portal(0);
        send_ready_for_query(fd, w);
        return true;
    }
    if (type == 'H') return true;                // Flush: every reply is already sent
    if (in_error_) return true;                  // discard until Sync
    BodyReader r(body, len);
    switch (type) {
        case 'P': return on_parse(r, fd, w);
        case 'B': return on_bind(r, fd, w);
        case 'D': return on_describe(r, fd, w, exec);
        case 'E': return on_execute(r, fd, w, exec);
        case 'C': return on_close(r, fd, w);
        default:  return fail(fd, w, "08P01", "unexpected extended-protocol message");
    }
}

bool ExtendedSession::on_parse(BodyReader& r, int fd, MsgWriter& w) noexcept {
    const std::string_view name = r.cstr();
    const std::string_view sql  = r.cstr();
    const std::int16_t ntypes   = r.i16();
    if (!r.ok || ntypes < 0) return fail(fd, w, "08P01", "malformed Parse message");
    if (name.size() >= kMaxNameLen) return fail(fd, w, "42602", "statement name too long");
    if (static_cast<std::uint32_t>(ntypes) > kMaxParams) {
        return fail(fd, w, "54023", "too many parameters for one statement");
    }
    std::int32_t si = 0;
    if (!name.empty()) {
        if (find_statement(name) >= 0) {
            return fail(fd, w, "42P05", "prepared statement already exists");
        }
        si = -1;
        for (std::size_t i = 1; i < stmts_.size(); ++i) {       // bounded by slots
            if (!stmts_[i].used) { si = static_cast<std::int32_t>(i); break; }
        }
        if (si < 0) {
            return fail(fd, w, "53000", "too many prepared statements on this "
                        "connection -- close some (DEALLOCATE / Close)");
        }
    }
    Statement& st = stmts_[static_cast<std::size_t>(si)];
    st.used = false;
    const std::uint32_t refs = max_param_ref(sql);
    if (refs > kMaxParams) return fail(fd, w, "54023", "too many parameters for one statement");
    if (!store_sql(st, sql)) {
        return fail(fd, w, "54000", "statement text exceeds this endpoint's "
                    "prepared-statement capacity");
    }
    st.n_params = refs > static_cast<std::uint32_t>(ntypes) ? refs
                                                            : static_cast<std::uint32_t>(ntypes);
    for (std::uint32_t k = 0; k < st.n_params; ++k) {           // bounded by kMaxParams
        st.param_types[k] = k < static_cast<std::uint32_t>(ntypes) ? r.i32() : 0;
    }
    if (!r.ok) return fail(fd, w, "08P01", "malformed Parse message");
    set_name(st.name, name);
    st.used = true;
    w.begin('1');
    return w.finish() && w.send(fd);
}

bool ExtendedSession::on_bind(BodyReader& r, int fd, MsgWriter& w) noexcept {
    const std::string_view pname = r.cstr();
    const std::string_view sname = r.cstr();
    if (!r.ok) return fail(fd, w, "08P01", "malformed Bind message");
    if (pname.size() >= kMaxNameLen) return fail(fd, w, "42602", "portal name too long");
    const std::int32_t si = find_statement(sname);
    if (si < 0) return fail(fd, w, "26000", "prepared statement does not exist");
    const Statement& st = stmts_[static_cast<std::size_t>(si)];

    const std::int16_t nfmt = r.i16();
    if (nfmt < 0 || static_cast<std::uint32_t>(nfmt) > kMaxParams) {
        return fail(fd, w, "08P01", "malformed Bind parameter formats");
    }
    std::int16_t pfmt[kMaxParams];
    for (std::int16_t k = 0; k < nfmt; ++k) pfmt[k] = r.i16();
    const std::int16_t nparams = r.i16();
    if (!r.ok || nparams < 0 || static_cast<std::uint32_t>(nparams) != st.n_params) {
        return fail(fd, w, "08P01", "Bind supplies a different number of "
                    "parameters than the statement requires");
    }
    if (nfmt > 1 && nfmt != nparams) return fail(fd, w, "08P01", "malformed Bind parameter formats");
    BoundParam params[kMaxParams];
    for (std::int16_t k = 0; k < nparams; ++k) {                 // bounded by kMaxParams
        const std::int32_t plen = r.i32();
        BoundParam& bp = params[k];
        bp.type_oid = st.param_types[k];
        bp.binary   = (nfmt == 1 ? pfmt[0] : (nfmt == 0 ? 0 : pfmt[k])) == 1;
        bp.is_null  = plen < 0;
        if (plen > 0) bp.bytes = r.bytes(static_cast<std::size_t>(plen));
    }
    const std::int16_t nres = r.i16();
    if (!r.ok || nres < 0 || static_cast<std::uint32_t>(nres) > kMaxFields) {
        return fail(fd, w, "08P01", "malformed Bind result formats");
    }
    std::int32_t pi = 0;
    if (!pname.empty()) {
        if (find_portal(pname) >= 0) return fail(fd, w, "42P03", "portal already exists");
        pi = -1;
        for (std::size_t i = 1; i < portals_.size(); ++i) {     // bounded by slots
            if (!portals_[i].used) { pi = static_cast<std::int32_t>(i); break; }
        }
        if (pi < 0) return fail(fd, w, "53000", "too many open portals on this connection");
    }
    close_portal(pi);
    Portal& p = portals_[static_cast<std::size_t>(pi)];
    p.n_formats = static_cast<std::uint32_t>(nres);
    for (std::int16_t k = 0; k < nres; ++k) {
        p.formats[k] = r.i16();
        if (p.formats[k] != 0 && p.formats[k] != 1) {
            return fail(fd, w, "22023", "unsupported result format code");
        }
    }
    if (!r.ok) return fail(fd, w, "08P01", "malformed Bind message");

    CodecError ce;
    std::size_t out_len = 0;
    if (!substitute_params(statement_sql(st), params, st.n_params, portal_sql(pi),
                           max_stmt_bytes_, out_len, ce)) {
        return fail(fd, w, ce.sqlstate, ce.message);
    }
    set_name(p.name, pname);
    p.sql_len      = out_len;
    p.empty_query  = st.sql_len == 0;
    p.materialized = false;
    p.done         = false;
    p.session_tag  = nullptr;
    p.next_row     = 0;
    p.field_count  = 0;
    p.used         = true;
    w.begin('2');
    return w.finish() && w.send(fd);
}

std::int16_t ExtendedSession::format_of(const Portal& p, std::uint32_t col) const noexcept {
    assert(col < kMaxFields);
    if (p.n_formats == 0) return 0;
    if (p.n_formats == 1) return p.formats[0];
    return col < p.n_formats ? p.formats[col] : 0;
}

bool ExtendedSession::materialize(std::int32_t pi, IQueryExecutor& exec,
                                  FieldDesc* fields, QueryFailure& qf) noexcept {
    assert(pi >= 0 && fields != nullptr);
    Portal& p = portals_[static_cast<std::size_t>(pi)];
    assert(p.used && !p.materialized);
    std::uint32_t count = 0;
    const std::string_view sql(portal_sql(pi), p.sql_len);
    CodecError ce;
    const SessionCommand sc = classify_session_command(sql, p.session_tag, ce);
    if (sc == SessionCommand::Refused) {
        qf.sqlstate = ce.sqlstate;
        qf.message  = ce.message;
        return false;
    }
    if (sc == SessionCommand::Accepted) {
        p.field_count  = 0;
        p.materialized = true;
        return true;
    }
    p.session_tag = nullptr;
    current_ = -1;
    if (!exec.execute(sql, fields, kMaxFields, count, qf)) return false;
    if (p.n_formats > 1 && p.n_formats != count) {
        qf.sqlstate = "08P01";
        qf.message  = "Bind result-format count does not match the result's columns";
        return false;
    }
    for (std::uint32_t c = 0; c < count; ++c) {                  // bounded by kMaxFields
        p.oids[c] = fields[c].type_oid;
        const std::size_t nl = fields[c].name.size() < kMaxNameLen - 1
            ? fields[c].name.size() : kMaxNameLen - 1;
        std::memcpy(p.names[c], fields[c].name.data(), nl);
        p.names[c][nl] = '\0';
        if (format_of(p, c) == 1 && !binary_result_supported(fields[c].type_oid)) {
            qf.sqlstate = "0A000";
            qf.message  = "binary result format requested for a column type this "
                          "endpoint only sends as text";
            return false;
        }
    }
    p.field_count  = count;
    p.materialized = true;
    current_ = pi;
    return true;
}

bool ExtendedSession::describe_statement(const Statement& st, int fd, MsgWriter& w,
                                         IQueryExecutor& exec) noexcept {
    w.begin('t');
    w.put_i16(static_cast<std::int16_t>(st.n_params));
    for (std::uint32_t k = 0; k < st.n_params; ++k) {            // bounded by kMaxParams
        w.put_i32(st.param_types[k] != 0 ? st.param_types[k] : oid::kText);
    }
    if (!w.finish() || !w.send(fd)) return false;

    const std::string_view sql = statement_sql(st);
    if (!is_query_shaped(sql)) {
        w.begin('n');
        return w.finish() && w.send(fd);
    }
    // Shape probe: bind every parameter to a type-appropriate placeholder
    // value (NULL for text-like/unknown) so the executor can plan it.
    BoundParam dummies[kMaxParams];
    for (std::uint32_t k = 0; k < st.n_params; ++k) {
        const std::int32_t t = st.param_types[k];
        dummies[k].type_oid = t;
        if (t == oid::kBool) dummies[k].bytes = "false";
        else if (t == oid::kDate) dummies[k].bytes = "2000-01-01";
        else if (t == oid::kInt2 || t == oid::kInt4 || t == oid::kInt8 ||
                 t == oid::kOid || t == oid::kFloat4 || t == oid::kFloat8 ||
                 t == oid::kNumeric) dummies[k].bytes = "0";
        else dummies[k].is_null = true;
    }
    char* scratch = describe_sql_.data();
    CodecError ce;
    std::size_t n = 0;
    if (!substitute_params(sql, dummies, st.n_params, scratch, max_stmt_bytes_, n, ce)) {
        return fail(fd, w, ce.sqlstate, ce.message);
    }
    FieldDesc fields[kMaxFields];
    std::uint32_t count = 0;
    QueryFailure qf;
    current_ = -1;
    if (!exec.describe(std::string_view(scratch, n), fields, kMaxFields, count, qf)) {
        return fail(fd, w, qf.sqlstate, qf.message);
    }
    if (count == 0) {
        w.begin('n');
        return w.finish() && w.send(fd);
    }
    if (!put_row_description(w, fields, count, nullptr)) {
        return fail(fd, w, "54000", "result row is too wide for this endpoint's wire buffer");
    }
    return w.send(fd);
}

bool ExtendedSession::on_describe(BodyReader& r, int fd, MsgWriter& w,
                                  IQueryExecutor& exec) noexcept {
    const std::uint8_t kind = r.u8();
    const std::string_view name = r.cstr();
    if (!r.ok || (kind != 'S' && kind != 'P')) {
        return fail(fd, w, "08P01", "malformed Describe message");
    }
    if (kind == 'S') {
        const std::int32_t si = find_statement(name);
        if (si < 0) return fail(fd, w, "26000", "prepared statement does not exist");
        return describe_statement(stmts_[static_cast<std::size_t>(si)], fd, w, exec);
    }
    const std::int32_t pi = find_portal(name);
    if (pi < 0) return fail(fd, w, "34000", "portal does not exist");
    Portal& p = portals_[static_cast<std::size_t>(pi)];
    if (p.empty_query) {
        w.begin('n');
        return w.finish() && w.send(fd);
    }
    if (p.materialized && current_ != pi && p.session_tag == nullptr) {
        return fail(fd, w, "55000", "portal's result was displaced by another "
                    "portal on this connection");
    }
    FieldDesc fields[kMaxFields];
    if (!p.materialized) {
        QueryFailure qf;
        if (!materialize(pi, exec, fields, qf)) return fail(fd, w, qf.sqlstate, qf.message);
    } else {
        for (std::uint32_t c = 0; c < p.field_count; ++c) {      // bounded by kMaxFields
            fields[c].name = p.names[c];
            fields[c].type_oid = p.oids[c];
        }
    }
    if (p.field_count == 0) {
        w.begin('n');
        return w.finish() && w.send(fd);
    }
    std::int16_t fmts[kMaxFields];
    for (std::uint32_t c = 0; c < p.field_count; ++c) fmts[c] = format_of(p, c);
    if (!put_row_description(w, fields, p.field_count, fmts)) {
        return fail(fd, w, "54000", "result row is too wide for this endpoint's wire buffer");
    }
    return w.send(fd);
}

bool ExtendedSession::send_rows(Portal& p, std::int32_t max_rows, int fd,
                                MsgWriter& w, IQueryExecutor& exec) noexcept {
    assert(p.materialized);
    const std::uint32_t total = exec.row_count();
    std::string_view values[kMaxFields];
    bool is_null[kMaxFields];
    std::uint8_t cell[512];
    std::uint32_t sent = 0;
    while (p.next_row < total) {                                  // bounded by row_count()
        if (max_rows > 0 && sent >= static_cast<std::uint32_t>(max_rows)) break;
        if (!exec.row(p.next_row, values, is_null, p.field_count)) break;
        w.begin('D');
        w.put_i16(static_cast<std::int16_t>(p.field_count));
        for (std::uint32_t c = 0; c < p.field_count; ++c) {       // bounded by kMaxFields
            if (is_null[c]) { w.put_i32(-1); continue; }
            if (format_of(p, c) == 0 || is_text_like(p.oids[c])) {
                w.put_i32(static_cast<std::int32_t>(values[c].size()));
                w.put_bytes(values[c].data(), values[c].size());
                continue;
            }
            CodecError ce;
            std::size_t n = 0;
            if (!text_to_binary_result(values[c], p.oids[c], cell, sizeof(cell), n, ce)) {
                return fail(fd, w, ce.sqlstate, ce.message);
            }
            w.put_i32(static_cast<std::int32_t>(n));
            w.put_bytes(cell, n);
        }
        if (!w.finish()) {
            return fail(fd, w, "54000", "a result row exceeded this endpoint's wire "
                        "buffer and was refused rather than sent truncated");
        }
        if (!w.send(fd)) return false;
        ++p.next_row;
        ++sent;
    }
    if (p.next_row < total) {
        w.begin('s');                                             // PortalSuspended
        return w.finish() && w.send(fd);
    }
    p.done = true;
    char tag[64];
    exec.command_tag(tag, sizeof(tag));
    w.begin('C');
    w.put_cstring(tag);
    return w.finish() && w.send(fd);
}

bool ExtendedSession::on_execute(BodyReader& r, int fd, MsgWriter& w,
                                 IQueryExecutor& exec) noexcept {
    const std::string_view name = r.cstr();
    const std::int32_t max_rows = r.i32();
    if (!r.ok) return fail(fd, w, "08P01", "malformed Execute message");
    const std::int32_t pi = find_portal(name);
    if (pi < 0) return fail(fd, w, "34000", "portal does not exist");
    Portal& p = portals_[static_cast<std::size_t>(pi)];
    if (p.empty_query) {
        w.begin('I');
        return w.finish() && w.send(fd);
    }
    if (p.done) {
        w.begin('C');
        w.put_cstring("SELECT 0");
        return w.finish() && w.send(fd);
    }
    if (!p.materialized) {
        FieldDesc fields[kMaxFields];
        QueryFailure qf;
        if (!materialize(pi, exec, fields, qf)) return fail(fd, w, qf.sqlstate, qf.message);
    } else if (current_ != pi && p.session_tag == nullptr) {
        return fail(fd, w, "55000", "portal's result was displaced by another "
                    "portal on this connection");
    }
    if (p.field_count == 0) {
        p.done = true;
        char tag[64];
        if (p.session_tag != nullptr) std::snprintf(tag, sizeof(tag), "%s", p.session_tag);
        else exec.command_tag(tag, sizeof(tag));
        w.begin('C');
        w.put_cstring(tag);
        return w.finish() && w.send(fd);
    }
    return send_rows(p, max_rows, fd, w, exec);
}

bool ExtendedSession::on_close(BodyReader& r, int fd, MsgWriter& w) noexcept {
    const std::uint8_t kind = r.u8();
    const std::string_view name = r.cstr();
    if (!r.ok || (kind != 'S' && kind != 'P')) {
        return fail(fd, w, "08P01", "malformed Close message");
    }
    // Closing a nonexistent statement/portal is not an error (protocol spec).
    if (kind == 'S') {
        const std::int32_t si = find_statement(name);
        if (si >= 0) close_statement(si);
    } else {
        const std::int32_t pi = find_portal(name);
        if (pi >= 0) close_portal(pi);
    }
    w.begin('3');
    return w.finish() && w.send(fd);
}

}  // namespace bolt::api::proto::pgwire::detail

#endif  // BOLTAPI_WITH_PG_WIRE
