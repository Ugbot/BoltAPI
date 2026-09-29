// boltapi/proto/flight_sql_metadata.h — the Flight SQL metadata commands
// (G2ETL-66): decode the command, ask the host's IQueryExecutor for its
// catalog, filter per FlightSql.proto and encode the result stream with
// flight_sql_arrow.h. Split from the server TU so it is testable without a
// socket. Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL.
#pragma once

#include "boltapi/proto/flight_sql.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::proto::flightsql::metadata {

enum class Outcome : std::uint8_t {
    kNotMetadata,   // `type_name` is not a metadata command
    kOk,            // *out_ipc holds the complete result stream
    kFailed,        // `f` says why
};

// `type_name` is google.protobuf.Any's type name (after the last '/'),
// `value` the command message. On kFailed, f.message points into `fail_buf`
// or at a static string.
Outcome build(std::string_view type_name, std::string_view value,
              IQueryExecutor& exec, const Config& cfg, std::string* out_ipc,
              std::int64_t* out_rows, QueryFailure& f, char* fail_buf,
              std::size_t fail_cap) noexcept;

}  // namespace bolt::api::proto::flightsql::metadata
