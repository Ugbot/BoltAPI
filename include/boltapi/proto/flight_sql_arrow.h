// boltapi/proto/flight_sql_arrow.h — Arrow IPC streams for the Flight SQL
// metadata commands (G2ETL-66): CommandGetSqlInfo, GetCatalogs,
// GetDbSchemas, GetTables, GetTableTypes, GetPrimaryKeys and the three
// foreign-key commands.
//
// Their result schemas are fixed by FlightSql.proto and need types the
// host's general IPC writer (bolt::ingest) does not have — uint32/uint8/
// int32 columns, non-nullable fields, a dense union, a map — so the wire
// layer encodes them itself. A minimal back-to-front flatbuffer builder
// (flatbuffers.dev/internals) writes the Schema and RecordBatch messages
// from arrow/format/{Message,Schema}.fbs; metadata version V5, so a dense
// union carries no validity buffer. Output is one complete IPC stream:
// Schema, one RecordBatch, end-of-stream marker.
//
// Control-plane path (a catalog listing per call), so std::string buffers
// are acceptable here; every loop is bounded by the row count given.
// Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::proto::flightsql::arrow {

// A string cell; `valid == false` is SQL NULL.
struct Str {
    std::string_view v;
    bool             valid = true;
};
inline Str null_str() noexcept { return Str{{}, false}; }

// CommandGetTables row. `table_schema` is an encapsulated IPC Schema
// message; read only when include_schema.
struct TableRow {
    Str              catalog;
    Str              db_schema;
    std::string_view table_name;
    std::string_view table_type;
    std::string_view table_schema;
};

struct SchemaRow {
    Str              catalog;
    std::string_view db_schema;
};

struct PrimaryKeyRow {
    Str              catalog;
    Str              db_schema;
    std::string_view table_name;
    std::string_view column_name;
    Str              key_name;
    std::int32_t     key_sequence = 0;
};

// One CommandGetSqlInfo value. `kind` selects the dense-union member.
enum class InfoKind : std::uint8_t { kString = 0, kBool = 1, kBigint = 2, kInt32Bitmask = 3 };
struct SqlInfoRow {
    std::uint32_t    id = 0;
    InfoKind         kind = InfoKind::kString;
    std::string_view s;
    bool             b = false;
    std::int64_t     i64 = 0;
    std::int32_t     i32 = 0;
};

// Each appends a complete IPC stream to `out`. Rows must already be in the
// order FlightSql.proto asks for.
void write_catalogs(std::string* out, const std::string_view* catalogs, std::size_t n);
void write_db_schemas(std::string* out, const SchemaRow* rows, std::size_t n);
void write_tables(std::string* out, const TableRow* rows, std::size_t n,
                  bool include_schema);
void write_table_types(std::string* out, const std::string_view* types, std::size_t n);
void write_primary_keys(std::string* out, const PrimaryKeyRow* rows, std::size_t n);
// GetExportedKeys / GetImportedKeys / GetCrossReference share one schema.
// Callers without foreign keys pass n == 0.
void write_foreign_keys_empty(std::string* out);
void write_sql_info(std::string* out, const SqlInfoRow* rows, std::size_t n);

// SQL LIKE with only `%` and `_` (FlightSql.proto filter patterns).
bool like_match(std::string_view pattern, std::string_view s) noexcept;

}  // namespace bolt::api::proto::flightsql::arrow
