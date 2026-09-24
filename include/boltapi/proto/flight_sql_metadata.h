// boltapi/proto/flight_sql_metadata.h — the Flight SQL metadata commands
// (G2ETL-66): CommandGetSqlInfo, GetCatalogs, GetDbSchemas, GetTables,
// GetTableTypes, GetPrimaryKeys, GetExportedKeys, GetImportedKeys and
// GetCrossReference, answered from IQueryExecutor's catalog hooks and
// encoded by flight_sql_arrow.h. Row order and filter semantics follow
// FlightSql.proto. Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL.
#pragma once

#include "boltapi/proto/flight_sql.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::proto::flightsql::metadata {

enum class Outcome : std::uint8_t { kOk, kFailed, kNotMetadata };

// `type_name` is the full Any type ("arrow.flight.protocol.sql.X"),
// `value` its payload. kOk: `out_ipc` holds a complete IPC stream and
// `out_rows` its row count. kFailed: `out_failure` is set; a composed
// message lives in `fail_buf`. kNotMetadata: not a metadata command.
Outcome build(std::string_view type_name, std::string_view value, IQueryExecutor& exec,
              const Config& cfg, std::string* out_ipc, std::int64_t* out_rows,
              QueryFailure& out_failure, char* fail_buf, std::size_t fail_cap) noexcept;

}  // namespace bolt::api::proto::flightsql::metadata
