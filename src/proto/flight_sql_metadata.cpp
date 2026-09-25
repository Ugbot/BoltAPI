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

constexpr std::string_view kSqlPkg = "arrow.flight.protocol.sql.";
constexpr std::size_t kMaxFields = 256;
constexpr std::size_t kMaxInfoIds = 1024;

// A proto3 `optional string`: presence matters.
struct OptStr {
    std::string_view v;
    bool             set = false;
};

bool fail(QueryFailure& f, GrpcCode code, const char* msg) noexcept {
    f.code = code;
    f.message = msg;
    return false;
}

// Reads the string fields 1..6 plus the repeated string 4 and bool 5 that
// the metadata commands use. Unknown fields are skipped per proto3.
struct Args {
    OptStr           s[7];
    std::string_view types[kMaxFields];
    std::size_t      n_types = 0;
    bool             include_schema = false;
};

bool parse_args(std::string_view buf, bool repeated_4, Args* a) noexcept {
    assert(a != nullptr);
    cd::PbReader r(buf);
    cd::PbField f;
    std::size_t guard = 0;
    for (; guard < kMaxFields && r.next(&f); ++guard) {
        if (f.wire == cd::kWireBytes && f.number >= 1 && f.number <= 6) {
            if (f.number == 4 && repeated_4) {
                if (a->n_types == kMaxFields) return false;
                a->types[a->n_types++] = f.bytes;
            } else {
                a->s[f.number] = OptStr{f.bytes, true};
            }
        } else if (f.wire == cd::kWireVarint && f.number == 5 && repeated_4) {
            a->include_schema = f.varint != 0;
        }
    }
    assert(a->n_types <= kMaxFields);
    return r.ok() && guard < kMaxFields;
}

// CommandGetSqlInfo{repeated uint32 info = 1}, packed or not.
bool parse_info_ids(std::string_view buf, std::vector<std::uint32_t>* ids) noexcept {
    assert(ids != nullptr && ids->empty());
    cd::PbReader r(buf);
    cd::PbField f;
    for (std::size_t guard = 0; guard < kMaxInfoIds && r.next(&f); ++guard) {
        if (f.number != 1) continue;
        if (f.wire == cd::kWireVarint) {
            ids->push_back(static_cast<std::uint32_t>(f.varint));
        } else if (f.wire == cd::kWireBytes) {
            std::size_t pos = 0;
            for (std::size_t i = 0; i < kMaxInfoIds && pos < f.bytes.size(); ++i) {
                std::uint64_t v = 0;
                if (!cd::pb_read_varint(f.bytes, &pos, &v)) return false;
                ids->push_back(static_cast<std::uint32_t>(v));
            }
            if (pos < f.bytes.size()) return false;
        }
        if (ids->size() > kMaxInfoIds) return false;
    }
    return r.ok();
}

// SqlInfo ids (FlightSql.proto enum SqlInfo).
constexpr std::uint32_t kServerName = 0, kServerVersion = 1, kServerArrowVersion = 2,
                        kReadOnly = 3, kSql = 4, kSubstrait = 5, kTransaction = 8,
                        kCancel = 9, kBulkIngestion = 10, kIngestTransactions = 11,
                        kIdentifierQuoteChar = 504;

std::vector<ar::SqlInfoRow> all_info(const Config& cfg, bool read_only) {
    auto str = [](std::uint32_t id, std::string_view s) {
        ar::SqlInfoRow r;
        r.id = id;
        r.kind = ar::InfoKind::kString;
        r.s = s;
        return r;
    };
    auto boolean = [](std::uint32_t id, bool b) {
        ar::SqlInfoRow r;
        r.id = id;
        r.kind = ar::InfoKind::kBool;
        r.b = b;
        return r;
    };
    ar::SqlInfoRow txn;
    txn.id = kTransaction;
    txn.kind = ar::InfoKind::kInt32Bitmask;
    txn.i32 = 0;   // SQL_SUPPORTED_TRANSACTION_NONE
    return {
        str(kServerName, cfg.server_name),
        str(kServerVersion, cfg.server_version),
        str(kServerArrowVersion, "arrow-ipc-v5"),
        boolean(kReadOnly, read_only),
        boolean(kSql, true),
        boolean(kSubstrait, false),
        txn,
        boolean(kCancel, false),
        boolean(kBulkIngestion, false),
        boolean(kIngestTransactions, false),
        str(kIdentifierQuoteChar, "\""),
    };
}

bool sql_info(std::string_view value, const Config& cfg, bool read_only, std::string* out,
              std::int64_t* rows, QueryFailure& f) {
    std::vector<std::uint32_t> ids;
    if (!parse_info_ids(value, &ids)) {
        return fail(f, GrpcCode::kInvalidArgument, "malformed CommandGetSqlInfo");
    }
    const std::vector<ar::SqlInfoRow> all = all_info(cfg, read_only);
    std::vector<ar::SqlInfoRow> pick;
    if (ids.empty()) {
        pick = all;
    } else {
        for (const std::uint32_t id : ids) {
            for (const ar::SqlInfoRow& r : all) {
                if (r.id == id) pick.push_back(r);
            }
        }
    }
    assert(pick.size() <= std::max(all.size(), ids.size() * all.size()));
    ar::write_sql_info(out, pick.data(), pick.size());
    *rows = static_cast<std::int64_t>(pick.size());
    return true;
}

// Tables have no catalog and no database schema. A named catalog therefore
// matches nothing; "" means "without a catalog", i.e. every table.
bool catalog_matches(const OptStr& c) noexcept { return !c.set || c.v.empty(); }
bool schema_matches(const OptStr& pattern) noexcept {
    return !pattern.set || ar::like_match(pattern.v, "");
}

struct Snapshot {
    std::vector<CatalogTable> tables;
};

bool snapshot(IQueryExecutor& exec, Snapshot* s, QueryFailure& f) {
    assert(s != nullptr && s->tables.empty());
    const std::uint32_t n = std::min(exec.catalog_tables(), kMaxCatalogTables);
    s->tables.resize(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        if (!exec.catalog_table(i, &s->tables[i])) {
            return fail(f, GrpcCode::kInternal, "catalog changed while it was listed");
        }
        assert(s->tables[i].n_key_columns <= kMaxKeyColumns);
    }
    return true;
}

bool tables(std::string_view value, IQueryExecutor& exec, std::string* out,
            std::int64_t* rows, QueryFailure& f) {
    Args a;
    if (!parse_args(value, true, &a)) {
        return fail(f, GrpcCode::kInvalidArgument, "malformed CommandGetTables");
    }
    Snapshot s;
    if (!snapshot(exec, &s, f)) return false;
    std::vector<std::uint32_t> keep;
    const bool scoped = catalog_matches(a.s[1]) && schema_matches(a.s[2]);
    for (std::uint32_t i = 0; scoped && i < s.tables.size(); ++i) {
        const CatalogTable& t = s.tables[i];
        if (a.s[3].set && !ar::like_match(a.s[3].v, t.name)) continue;
        bool type_ok = a.n_types == 0;
        for (std::size_t k = 0; k < a.n_types && !type_ok; ++k) type_ok = a.types[k] == t.table_type;
        if (type_ok) keep.push_back(i);
    }
    std::sort(keep.begin(), keep.end(), [&](std::uint32_t x, std::uint32_t y) {
        const CatalogTable& l = s.tables[x];
        const CatalogTable& r = s.tables[y];
        return l.name < r.name || (l.name == r.name && l.table_type < r.table_type);
    });
    std::vector<std::string> schemas(a.include_schema ? keep.size() : 0);
    std::string scratch;
    std::vector<ar::TableRow> out_rows(keep.size());
    for (std::size_t k = 0; k < keep.size(); ++k) {
        const CatalogTable& t = s.tables[keep[k]];
        out_rows[k] = ar::TableRow{ar::null_str(), ar::null_str(), t.name, t.table_type, {}};
        if (!a.include_schema) continue;
        scratch.clear();
        if (!exec.catalog_table_schema(keep[k], &scratch, f)) return false;
        std::size_t pos = 0;
        bool bad = false;
        cd::IpcMessage m;
        if (!cd::ipc_next_message(scratch, &pos, &m, &bad) ||
            m.header_type != cd::kIpcHeaderSchema) {
            return fail(f, GrpcCode::kInternal, "table schema is not an Arrow IPC schema");
        }
        schemas[k].assign(m.encapsulated.data(), m.encapsulated.size());
        out_rows[k].table_schema = schemas[k];
    }
    ar::write_tables(out, out_rows.data(), out_rows.size(), a.include_schema);
    *rows = static_cast<std::int64_t>(out_rows.size());
    return true;
}

bool table_types(IQueryExecutor& exec, std::string* out, std::int64_t* rows, QueryFailure& f) {
    Snapshot s;
    if (!snapshot(exec, &s, f)) return false;
    std::vector<std::string_view> types;
    for (const CatalogTable& t : s.tables) types.push_back(t.table_type);
    std::sort(types.begin(), types.end());
    types.erase(std::unique(types.begin(), types.end()), types.end());
    assert(types.size() <= s.tables.size());
    ar::write_table_types(out, types.data(), types.size());
    *rows = static_cast<std::int64_t>(types.size());
    return true;
}

bool primary_keys(std::string_view value, IQueryExecutor& exec, std::string* out,
                  std::int64_t* rows, QueryFailure& f) {
    Args a;
    if (!parse_args(value, false, &a)) {
        return fail(f, GrpcCode::kInvalidArgument, "malformed CommandGetPrimaryKeys");
    }
    Snapshot s;
    if (!snapshot(exec, &s, f)) return false;
    std::vector<ar::PrimaryKeyRow> keys;
    // db_schema here is a name, not a pattern: only "" names "no schema".
    const bool scoped = catalog_matches(a.s[1]) && (!a.s[2].set || a.s[2].v.empty());
    for (std::size_t i = 0; scoped && i < s.tables.size(); ++i) {
        const CatalogTable& t = s.tables[i];
        if (t.name != a.s[3].v) continue;
        for (std::uint16_t k = 0; k < t.n_key_columns; ++k) {
            keys.push_back(ar::PrimaryKeyRow{ar::null_str(), ar::null_str(), t.name,
                                             t.key_columns[k], ar::null_str(),
                                             static_cast<std::int32_t>(k + 1)});
        }
    }
    assert(keys.size() <= kMaxKeyColumns * s.tables.size());
    ar::write_primary_keys(out, keys.data(), keys.size());
    *rows = static_cast<std::int64_t>(keys.size());
    return true;
}

bool db_schemas(std::string_view value, std::string* out, std::int64_t* rows,
                QueryFailure& f) {
    Args a;
    if (!parse_args(value, false, &a)) {
        return fail(f, GrpcCode::kInvalidArgument, "malformed CommandGetDbSchemas");
    }
    // One row, db_schema_name "" (it is non-nullable), stands for "tables
    // without a schema", so schema-driven clients still reach them.
    const ar::SchemaRow none{ar::null_str(), ""};
    const bool match = catalog_matches(a.s[1]) && schema_matches(a.s[2]);
    ar::write_db_schemas(out, &none, match ? 1 : 0);
    *rows = match ? 1 : 0;
    return true;
}

// CommandGetXdbcTypeInfo{optional int32 data_type = 1}.
bool xdbc_types(std::string_view value, IQueryExecutor& exec, std::string* out,
                std::int64_t* rows, QueryFailure& f, char* fail_buf, std::size_t fail_cap) {
    bool filtered = false;
    std::int32_t want = 0;
    cd::PbReader r(value);
    cd::PbField fld;
    std::size_t guard = 0;
    for (; guard < kMaxFields && r.next(&fld); ++guard) {
        if (fld.number == 1 && fld.wire == cd::kWireVarint) {
            filtered = true;
            want = static_cast<std::int32_t>(static_cast<std::uint32_t>(fld.varint));
        }
    }
    if (!r.ok() || guard == kMaxFields) {
        return fail(f, GrpcCode::kInvalidArgument, "malformed CommandGetXdbcTypeInfo");
    }
    std::vector<XdbcTypeInfo> all(kMaxXdbcTypes);
    const std::uint32_t n = std::min(exec.xdbc_type_info(all.data(), kMaxXdbcTypes), kMaxXdbcTypes);
    if (n == 0) {
        std::snprintf(fail_buf, fail_cap,
                      "Flight SQL command CommandGetXdbcTypeInfo: this host does not "
                      "describe its types");
        return fail(f, GrpcCode::kUnimplemented, fail_buf);
    }
    std::vector<XdbcTypeInfo> keep;
    for (std::uint32_t i = 0; i < n; ++i) {
        if (!filtered || all[i].data_type == want) keep.push_back(all[i]);
    }
    std::sort(keep.begin(), keep.end(), [](const XdbcTypeInfo& a, const XdbcTypeInfo& b) {
        return a.data_type < b.data_type ||
               (a.data_type == b.data_type && a.type_name < b.type_name);
    });
    assert(keep.size() <= n);
    ar::write_xdbc_type_info(out, keep.data(), keep.size());
    *rows = static_cast<std::int64_t>(keep.size());
    return true;
}

}  // namespace

Outcome build(std::string_view type_name, std::string_view value, IQueryExecutor& exec,
              const Config& cfg, std::string* out_ipc, std::int64_t* out_rows,
              QueryFailure& out_failure, char* fail_buf, std::size_t fail_cap) noexcept {
    assert(out_ipc != nullptr && out_rows != nullptr);
    assert(fail_buf != nullptr && fail_cap > 0);
    if (type_name.substr(0, kSqlPkg.size()) != kSqlPkg) return Outcome::kNotMetadata;
    const std::string_view cmd = type_name.substr(kSqlPkg.size());
    const bool catalog_cmd =
        cmd == "CommandGetCatalogs" || cmd == "CommandGetDbSchemas" ||
        cmd == "CommandGetTables" || cmd == "CommandGetTableTypes" ||
        cmd == "CommandGetPrimaryKeys" || cmd == "CommandGetExportedKeys" ||
        cmd == "CommandGetImportedKeys" || cmd == "CommandGetCrossReference";
    if (!catalog_cmd && cmd != "CommandGetSqlInfo" && cmd != "CommandGetXdbcTypeInfo") {
        return Outcome::kNotMetadata;
    }
    if (catalog_cmd && !exec.has_catalog()) {
        std::snprintf(fail_buf, fail_cap,
                      "Flight SQL command %.*s needs a catalog this host does not expose",
                      static_cast<int>(cmd.size()), cmd.data());
        out_failure.code = GrpcCode::kUnimplemented;
        out_failure.message = fail_buf;
        return Outcome::kFailed;
    }
    out_ipc->clear();
    *out_rows = 0;
    bool ok = true;
    if (cmd == "CommandGetSqlInfo") {
        ok = sql_info(value, cfg, !exec.supports_updates(), out_ipc, out_rows, out_failure);
    } else if (cmd == "CommandGetXdbcTypeInfo") {
        ok = xdbc_types(value, exec, out_ipc, out_rows, out_failure, fail_buf, fail_cap);
    } else if (cmd == "CommandGetCatalogs") {
        ar::write_catalogs(out_ipc, nullptr, 0);
    } else if (cmd == "CommandGetDbSchemas") {
        ok = db_schemas(value, out_ipc, out_rows, out_failure);
    } else if (cmd == "CommandGetTables") {
        ok = tables(value, exec, out_ipc, out_rows, out_failure);
    } else if (cmd == "CommandGetTableTypes") {
        ok = table_types(exec, out_ipc, out_rows, out_failure);
    } else if (cmd == "CommandGetPrimaryKeys") {
        ok = primary_keys(value, exec, out_ipc, out_rows, out_failure);
    } else {
        // No CatalogTable carries a foreign key.
        Args a;
        if (!parse_args(value, false, &a)) {
            (void)fail(out_failure, GrpcCode::kInvalidArgument, "malformed foreign-key command");
            return Outcome::kFailed;
        }
        ar::write_foreign_keys_empty(out_ipc);
    }
    return ok ? Outcome::kOk : Outcome::kFailed;
}

}  // namespace bolt::api::proto::flightsql::metadata

#endif  // BOLTAPI_WITH_FLIGHT_SQL
