// src/proto/flight_sql_metadata.cpp — see boltapi/proto/flight_sql_metadata.h.

#include "boltapi/proto/flight_sql_metadata.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include "boltapi/proto/flight_sql_arrow.h"
#include "boltapi/proto/flight_sql_codec.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>

namespace bolt::api::proto::flightsql::metadata {

namespace {

namespace cd = codec;
namespace ar = arrow;

constexpr std::string_view kPkg = "arrow.flight.protocol.sql.";
constexpr std::size_t kMaxInfoIds = 256;
constexpr std::size_t kMaxTableTypes = 32;
constexpr std::size_t kMaxFields = 64;

struct Opt {
    std::string_view v;
    bool             has = false;
};

Outcome failed(QueryFailure& f, GrpcCode code, const char* msg) noexcept {
    assert(msg != nullptr);
    f.code = code;
    f.message = msg;
    return Outcome::kFailed;
}

// Reads the string fields numbered 1..n into `out[0..n-1]`; presence kept.
bool decode_strings(std::string_view buf, Opt* out, std::uint32_t n) noexcept {
    assert(out != nullptr && n > 0);
    cd::PbReader r(buf);
    cd::PbField fld;
    for (std::size_t guard = 0; guard < kMaxFields && r.next(&fld); ++guard) {
        if (fld.number >= 1 && fld.number <= n && fld.wire == cd::kWireBytes) {
            out[fld.number - 1] = Opt{fld.bytes, true};
        }
    }
    return r.ok();
}

bool ieq(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x = static_cast<char>(x - 'a' + 'A');
        if (y >= 'a' && y <= 'z') y = static_cast<char>(y - 'a' + 'A');
        if (x != y) return false;
    }
    return true;
}

// Tables have a NULL catalog and schema: an explicit catalog matches only
// when it is "" ("those without a catalog"); a schema pattern matches when
// it matches the empty string.
bool null_catalog_ok(const Opt& c) noexcept { return !c.has || c.v.empty(); }
bool null_schema_ok(const Opt& p) noexcept { return !p.has || ar::like_match(p.v, ""); }

struct Snapshot {
    std::vector<CatalogTable>  tables;
    std::vector<std::uint32_t> index;   // host index of tables[k]
};

Outcome snapshot(IQueryExecutor& exec, Snapshot* s, QueryFailure& f) noexcept {
    assert(s != nullptr);
    const std::uint32_t n = exec.catalog_tables();
    if (n > kMaxCatalogTables) {
        return failed(f, GrpcCode::kResourceExhausted,
                      "catalog has more tables than this endpoint lists (4096)");
    }
    s->tables.reserve(n);
    s->index.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        CatalogTable t;
        if (!exec.catalog_table(i, &t) || t.name.empty() ||
            t.n_key_columns > kMaxKeyColumns) {
            return failed(f, GrpcCode::kInternal, "host returned an invalid catalog entry");
        }
        if (t.table_type.empty()) t.table_type = "TABLE";
        s->tables.push_back(t);
        s->index.push_back(i);
    }
    assert(s->tables.size() == n);
    return Outcome::kOk;
}

std::vector<std::size_t> order_by_name(const Snapshot& s) {
    std::vector<std::size_t> o(s.tables.size());
    for (std::size_t i = 0; i < o.size(); ++i) o[i] = i;
    std::sort(o.begin(), o.end(), [&](std::size_t a, std::size_t b) {
        return s.tables[a].name < s.tables[b].name;
    });
    return o;
}

Outcome sql_info(std::string_view value, const Config& cfg, std::string* out,
                 std::int64_t* rows, QueryFailure& f) noexcept {
    std::uint32_t ids[kMaxInfoIds];
    std::size_t n_ids = 0;
    cd::PbReader r(value);
    cd::PbField fld;
    for (std::size_t guard = 0; guard < kMaxInfoIds && r.next(&fld); ++guard) {
        if (fld.number != 1) continue;
        if (fld.wire == cd::kWireVarint) {
            if (n_ids < kMaxInfoIds) ids[n_ids++] = static_cast<std::uint32_t>(fld.varint);
        } else if (fld.wire == cd::kWireBytes) {
            std::size_t pos = 0;
            std::uint64_t v = 0;
            while (n_ids < kMaxInfoIds && pos < fld.bytes.size()) {   // bounded by kMaxInfoIds
                if (!cd::pb_read_varint(fld.bytes, &pos, &v)) {
                    return failed(f, GrpcCode::kInvalidArgument, "malformed CommandGetSqlInfo");
                }
                ids[n_ids++] = static_cast<std::uint32_t>(v);
            }
        }
    }
    if (!r.ok()) return failed(f, GrpcCode::kInvalidArgument, "malformed CommandGetSqlInfo");

    // Only facts this protocol layer owns (plus the host's name/version).
    using K = ar::InfoKind;
    const ar::SqlInfoRow known[] = {
        {0, K::kString, cfg.server_name, false, 0, 0},     // SERVER_NAME
        {1, K::kString, cfg.server_version, false, 0, 0},  // SERVER_VERSION
        {3, K::kBool, {}, true, 0, 0},       // READ_ONLY: DML is refused
        {4, K::kBool, {}, true, 0, 0},       // SQL
        {5, K::kBool, {}, false, 0, 0},      // SUBSTRAIT
        {8, K::kInt32Bitmask, {}, false, 0, 0},   // TRANSACTION: NONE
        {9, K::kBool, {}, false, 0, 0},      // CANCEL
        {10, K::kBool, {}, false, 0, 0},     // BULK_INGESTION
        {100, K::kInt32Bitmask, {}, false, 0, 0}, // STATEMENT_TIMEOUT: none
        {101, K::kInt32Bitmask, {}, false, 0, 0}, // TRANSACTION_TIMEOUT: none
        {500, K::kBool, {}, false, 0, 0},    // SQL_DDL_CATALOG
        {501, K::kBool, {}, false, 0, 0},    // SQL_DDL_SCHEMA
        {502, K::kBool, {}, false, 0, 0},    // SQL_DDL_TABLE
    };
    constexpr std::size_t kKnown = sizeof(known) / sizeof(known[0]);
    std::vector<ar::SqlInfoRow> sel;
    if (n_ids == 0) {
        sel.assign(known, known + kKnown);
    } else {
        for (std::size_t i = 0; i < n_ids; ++i) {
            for (const ar::SqlInfoRow& k : known) {
                if (k.id == ids[i]) { sel.push_back(k); break; }
            }
        }
    }
    ar::write_sql_info(out, sel.data(), sel.size());
    *rows = static_cast<std::int64_t>(sel.size());
    return Outcome::kOk;
}

Outcome tables(std::string_view value, IQueryExecutor& exec, std::string* out,
               std::int64_t* rows, QueryFailure& f, char* fail_buf,
               std::size_t fail_cap) noexcept {
    Opt str[3];
    std::string_view types[kMaxTableTypes];
    std::size_t n_types = 0;
    bool include_schema = false;
    cd::PbReader r(value);
    cd::PbField fld;
    for (std::size_t guard = 0; guard < kMaxFields && r.next(&fld); ++guard) {
        if (fld.number >= 1 && fld.number <= 3 && fld.wire == cd::kWireBytes) {
            str[fld.number - 1] = Opt{fld.bytes, true};
        } else if (fld.number == 4 && fld.wire == cd::kWireBytes) {
            if (n_types == kMaxTableTypes) {
                return failed(f, GrpcCode::kInvalidArgument, "too many table_types (max 32)");
            }
            types[n_types++] = fld.bytes;
        } else if (fld.number == 5 && fld.wire == cd::kWireVarint) {
            include_schema = fld.varint != 0;
        }
    }
    if (!r.ok()) return failed(f, GrpcCode::kInvalidArgument, "malformed CommandGetTables");

    Snapshot s;
    if (snapshot(exec, &s, f) != Outcome::kOk) return Outcome::kFailed;
    std::vector<ar::TableRow> out_rows;
    std::vector<std::string> schemas;
    std::vector<std::size_t> picked;
    const bool scope_ok = null_catalog_ok(str[0]) && null_schema_ok(str[1]);
    for (const std::size_t k : order_by_name(s)) {
        if (!scope_ok) break;
        const CatalogTable& t = s.tables[k];
        if (str[2].has && !ar::like_match(str[2].v, t.name)) continue;
        bool type_ok = n_types == 0;
        for (std::size_t i = 0; i < n_types && !type_ok; ++i) type_ok = ieq(types[i], t.table_type);
        if (type_ok) picked.push_back(k);
    }
    schemas.resize(include_schema ? picked.size() : 0);
    for (std::size_t j = 0; j < picked.size(); ++j) {
        const CatalogTable& t = s.tables[picked[j]];
        ar::TableRow row{ar::null_str(), ar::null_str(), t.name, t.table_type, {}};
        if (include_schema) {
            std::string ipc;
            if (!exec.catalog_table_schema(s.index[picked[j]], &ipc, f)) {
                std::snprintf(fail_buf, fail_cap, "schema of table %.*s: %s",
                              static_cast<int>(t.name.size() > 64 ? 64 : t.name.size()),
                              t.name.data(), f.message != nullptr ? f.message : "failed");
                f.message = fail_buf;
                return Outcome::kFailed;
            }
            std::size_t pos = 0;
            bool bad = false;
            cd::IpcMessage m;
            if (!cd::ipc_next_message(ipc, &pos, &m, &bad) ||
                m.header_type != cd::kIpcHeaderSchema) {
                return failed(f, GrpcCode::kInternal,
                              "host table schema is not an Arrow IPC stream");
            }
            schemas[j].assign(m.encapsulated.data(), m.encapsulated.size());
            // A stream's schema message carries no body.
        }
        out_rows.push_back(row);
    }
    for (std::size_t j = 0; j < schemas.size(); ++j) out_rows[j].table_schema = schemas[j];
    ar::write_tables(out, out_rows.data(), out_rows.size(), include_schema);
    *rows = static_cast<std::int64_t>(out_rows.size());
    return Outcome::kOk;
}

Outcome table_types(IQueryExecutor& exec, std::string* out, std::int64_t* rows,
                    QueryFailure& f) noexcept {
    Snapshot s;
    if (snapshot(exec, &s, f) != Outcome::kOk) return Outcome::kFailed;
    std::vector<std::string_view> types;
    for (const CatalogTable& t : s.tables) {
        if (std::find(types.begin(), types.end(), t.table_type) == types.end()) {
            types.push_back(t.table_type);
        }
    }
    std::sort(types.begin(), types.end());
    ar::write_table_types(out, types.data(), types.size());
    *rows = static_cast<std::int64_t>(types.size());
    return Outcome::kOk;
}

Outcome primary_keys(std::string_view value, IQueryExecutor& exec, std::string* out,
                     std::int64_t* rows, QueryFailure& f) noexcept {
    Opt str[3];   // catalog, db_schema, table
    if (!decode_strings(value, str, 3)) {
        return failed(f, GrpcCode::kInvalidArgument, "malformed CommandGetPrimaryKeys");
    }
    Snapshot s;
    if (snapshot(exec, &s, f) != Outcome::kOk) return Outcome::kFailed;
    std::vector<ar::PrimaryKeyRow> out_rows;
    const bool scope_ok = null_catalog_ok(str[0]) && (!str[1].has || str[1].v.empty());
    for (std::size_t k = 0; k < s.tables.size() && scope_ok; ++k) {
        const CatalogTable& t = s.tables[k];
        if (t.name != str[2].v) continue;
        for (std::uint16_t c = 0; c < t.n_key_columns; ++c) {
            out_rows.push_back(ar::PrimaryKeyRow{ar::null_str(), ar::null_str(), t.name,
                                                 t.key_columns[c], ar::null_str(),
                                                 static_cast<std::int32_t>(c + 1)});
        }
    }
    ar::write_primary_keys(out, out_rows.data(), out_rows.size());
    *rows = static_cast<std::int64_t>(out_rows.size());
    return Outcome::kOk;
}

}  // namespace

Outcome build(std::string_view type_name, std::string_view value,
              IQueryExecutor& exec, const Config& cfg, std::string* out_ipc,
              std::int64_t* out_rows, QueryFailure& f, char* fail_buf,
              std::size_t fail_cap) noexcept {
    assert(out_ipc != nullptr && out_rows != nullptr);
    assert(fail_buf != nullptr && fail_cap > 0);
    if (type_name.substr(0, kPkg.size()) != kPkg) return Outcome::kNotMetadata;
    const std::string_view cmd = type_name.substr(kPkg.size());
    out_ipc->clear();
    *out_rows = 0;
    if (cmd == "CommandGetSqlInfo") return sql_info(value, cfg, out_ipc, out_rows, f);

    const bool catalog_cmd =
        cmd == "CommandGetCatalogs" || cmd == "CommandGetDbSchemas" ||
        cmd == "CommandGetTables" || cmd == "CommandGetTableTypes" ||
        cmd == "CommandGetPrimaryKeys" || cmd == "CommandGetExportedKeys" ||
        cmd == "CommandGetImportedKeys" || cmd == "CommandGetCrossReference";
    if (!catalog_cmd) return Outcome::kNotMetadata;
    if (!exec.has_catalog()) {
        std::snprintf(fail_buf, fail_cap,
                      "Flight SQL command %.*s is not supported: this host exposes "
                      "no catalog", static_cast<int>(cmd.size()), cmd.data());
        return failed(f, GrpcCode::kUnimplemented, fail_buf);
    }
    if (cmd == "CommandGetCatalogs") {
        ar::write_catalogs(out_ipc, nullptr, 0);   // every table's catalog is NULL
        return Outcome::kOk;
    }
    if (cmd == "CommandGetDbSchemas") {
        Opt str[2];
        if (!decode_strings(value, str, 2)) {
            return failed(f, GrpcCode::kInvalidArgument, "malformed CommandGetDbSchemas");
        }
        // db_schema_name is NOT NULL, so "tables without a schema" is listed
        // as the empty-string schema — the same spelling a filter uses for
        // them. Clients that enumerate schema-first (ADBC GetObjects) need
        // the row to reach the tables at all.
        const ar::SchemaRow none{ar::null_str(), ""};
        const bool listed = exec.catalog_tables() > 0 && null_catalog_ok(str[0]) &&
                            null_schema_ok(str[1]);
        ar::write_db_schemas(out_ipc, &none, listed ? 1 : 0);
        *out_rows = listed ? 1 : 0;
        return Outcome::kOk;
    }
    if (cmd == "CommandGetTables") {
        return tables(value, exec, out_ipc, out_rows, f, fail_buf, fail_cap);
    }
    if (cmd == "CommandGetTableTypes") return table_types(exec, out_ipc, out_rows, f);
    if (cmd == "CommandGetPrimaryKeys") return primary_keys(value, exec, out_ipc, out_rows, f);
    ar::write_foreign_keys_empty(out_ipc);   // CatalogTable carries no foreign keys
    return Outcome::kOk;
}

}  // namespace bolt::api::proto::flightsql::metadata

#endif  // BOLTAPI_WITH_FLIGHT_SQL
