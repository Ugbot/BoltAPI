// boltapi/proto/flight_sql.h — an Arrow Flight SQL server (G2ETL-26): the
// BI/analytics-tool front door for any Flight SQL client (ADBC's
// adbc_driver_flightsql, the Flight SQL JDBC driver, pyarrow.flight).
// Same shape as this directory's postgres_wire.h / neo4j_bolt.h: the wire
// layer owns protocol bytes and nothing else; the host supplies the query
// engine through IQueryExecutor/IExecutorFactory.
//
// ============================================================================
// WHY HAND-ROLLED (the design note — no gRPC, no protobuf)
// ============================================================================
// Flight SQL is gRPC: protobuf messages, length-prefixed, over HTTP/2. The
// repo's dependency policy forbids gRPC and protobuf as runtime deps, and the
// surface actually needed is tiny, so every layer is implemented from its
// spec instead:
//   - HTTP/2: cleartext with prior knowledge (h2c, what `grpc://` means), on
//     a dedicated port. Frames are parsed here; header blocks are decoded
//     with boltapi's own HPACK decoder (http/hpack.h). Responses are encoded
//     as HPACK literals without indexing, which needs no encoder state.
//     Connection and stream flow control are honoured in both directions.
//     It does NOT ride the HTTP/1.1+2 engine: that engine is request/response
//     shaped and has no response trailers, which gRPC status needs.
//   - gRPC: the 5-byte length prefix, `grpc-status`/`grpc-message` trailers
//     (trailers-only on error), identity encoding only (a compressed message
//     is refused with UNIMPLEMENTED).
//   - protobuf: a ~100-line varint/length-delimited reader and writer
//     covering FlightDescriptor, FlightInfo, FlightEndpoint, Ticket,
//     FlightData, SchemaResult, google.protobuf.Any, Action/Result and
//     the Flight SQL commands; unknown fields are skipped per proto3.
//   - Arrow IPC: query results are produced by the host's executor
//     (Gestalt2 uses bolt's arrow_ipc writer); this layer splits the stream
//     into messages (flight_sql_codec.h) to fill FlightInfo.schema and
//     FlightData. Metadata-command results have fixed schemas the host
//     writer cannot express (uint32, dense union, map) and are encoded here
//     (flight_sql_arrow.h).
// Codecs are in flight_sql_codec.{h,cpp}, flight_sql_arrow.{h,cpp}, and the
// metadata commands in flight_sql_metadata.{h,cpp}.
//
// ============================================================================
// SCOPE — statements, prepared statements and catalog metadata
// ============================================================================
//   GetFlightInfo(CMD = Any<CommandStatementQuery>)  -> FlightInfo with one
//       endpoint whose ticket is Any<TicketStatementQuery{handle = SQL}>.
//   DoGet(that ticket)                               -> schema + batches.
//   GetSchema(CMD = Any<CommandStatementQuery>)      -> SchemaResult.
//   Handshake                                        -> one empty response.
//   ListFlights                                      -> empty stream.
//   ListActions                                      -> the two actions below.
// The query executes at GetFlightInfo (to answer schema + total_records) and
// again at DoGet: the ticket carries the statement, not a server-side
// result handle, so there is no unbounded result cache to expire.
// G2ETL-66 adds:
//   Metadata commands (GetFlightInfo/GetSchema, then DoGet on a ticket that
//       is the command itself): CommandGetSqlInfo, GetCatalogs,
//       GetDbSchemas, GetTables (incl. include_schema), GetTableTypes,
//       GetPrimaryKeys, and GetExportedKeys/ImportedKeys/CrossReference,
//       which are always empty because CatalogTable has no foreign keys.
//       Result streams are encoded by flight_sql_arrow.h.
//   Prepared statements: DoAction CreatePreparedStatement /
//       ClosePreparedStatement, and CommandPreparedStatementQuery through
//       GetFlightInfo/GetSchema. The handle IS the statement text behind a
//       magic prefix — stateless like the statement ticket, so a client
//       that never closes leaks nothing and any worker can serve any
//       handle.
// G2ETL-75 adds:
//   Updates: DoPut(CommandStatementUpdate) and DoPut(CommandPreparedStatement-
//       Update) run IQueryExecutor::execute_update exactly once (once per
//       bound parameter set) and answer DoPutUpdateResult. Nothing re-runs
//       an update: GetFlightInfo on an update command is refused, and
//       CreatePreparedStatement never executes a statement is_query() calls
//       an update (it answers no dataset_schema, which is how clients tell
//       updates from queries).
//   Parameters: `?` placeholders (flight_sql_params.h). Create answers a
//       parameter_schema of untyped (dense-union) fields; DoPut of
//       CommandPreparedStatementQuery with one parameter row answers
//       DoPutPreparedStatementResult with a NEW handle carrying the bound
//       values (still stateless: the values travel in the handle), which
//       clients use for the following GetFlightInfo. Values are substituted
//       as SQL literals before the executor sees the statement.
//   CommandGetXdbcTypeInfo from IQueryExecutor::xdbc_type_info.
//   grpc+tls: Config::tls_cert_* turns on TLS (ALPN h2) for every
//       connection; OpenSSL is already a hard boltapi dependency.
// Everything else — DoExchange, transactions, Substrait,
// CommandStatementIngest — answers grpc-status UNIMPLEMENTED naming the
// command, never a silently empty result.
//
// Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL (default OFF).
#pragma once

#include "boltapi/core/result.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api::core { class StackedThread; }
namespace bolt::api::net { class TlsContext; }

namespace bolt::api::proto::flightsql {

using Status = core::result<void>;
inline Status ok_status() noexcept { return Status(); }

// gRPC status codes used by this endpoint (grpc/doc/statuscodes.md).
enum class GrpcCode : std::uint8_t {
    kOk = 0,
    kUnknown = 2,
    kInvalidArgument = 3,
    kDeadlineExceeded = 4,
    kNotFound = 5,
    kResourceExhausted = 8,
    kCancelled = 1,
    kUnimplemented = 12,
    kInternal = 13,
    kUnavailable = 14,
    kUnauthenticated = 16,
};

struct QueryFailure {
    GrpcCode    code = GrpcCode::kInternal;
    const char* message = "query execution failed";
};

inline constexpr std::uint32_t kMaxQueryBytes = 64u * 1024u;

// One table of the host's catalog, for the Flight SQL metadata commands.
// Tables carry no catalog or database schema (both answer NULL): `name` is
// exactly what the host's SQL accepts unqualified.
inline constexpr std::uint32_t kMaxCatalogTables = 4096;
inline constexpr std::uint16_t kMaxKeyColumns = 16;

struct CatalogTable {
    std::string_view name;
    std::string_view table_type;                    // "TABLE", "VIEW", ...
    std::uint16_t    n_key_columns = 0;
    std::string_view key_columns[kMaxKeyColumns];   // primary key, key order
};

// One row of CommandGetXdbcTypeInfo (JDBC DatabaseMetaData.getTypeInfo).
// A negative int or an empty string answers NULL. The wire layer fills the
// remaining columns: create_params NULL, nullable = NULLABILITY_NULLABLE,
// auto_increment false, local_type_name = type_name, sql_data_type =
// data_type, datetime_subcode and interval_precision NULL.
inline constexpr std::uint32_t kMaxXdbcTypes = 64;

struct XdbcTypeInfo {
    std::string_view type_name;             // "BIGINT"
    std::int32_t     data_type = 0;         // XdbcDataType (java.sql.Types)
    std::int32_t     column_size = -1;
    std::string_view literal_prefix;
    std::string_view literal_suffix;
    bool             case_sensitive = false;
    std::int32_t     searchable = 3;        // SEARCHABLE_FULL
    std::int8_t      unsigned_attribute = -1;   // -1 NULL, else 0/1
    bool             fixed_prec_scale = false;
    std::int32_t     minimum_scale = -1;
    std::int32_t     maximum_scale = -1;
    std::int32_t     num_prec_radix = -1;
};

// The host's query engine. One instance per worker thread, created once at
// start_background().
class IQueryExecutor {
public:
    virtual ~IQueryExecutor() = default;

    // Compile + run `sql`. On success `*out_ipc` holds a complete Arrow IPC
    // stream (Schema message, >= 1 RecordBatch, end-of-stream marker) and
    // `*out_rows` the total row count; the string is reused across calls.
    // On failure fill `out_failure` (message must stay valid until the next
    // execute on this executor).
    virtual bool execute(std::string_view sql, std::string* out_ipc,
                         std::int64_t* out_rows,
                         QueryFailure& out_failure) noexcept = 0;

    // DDL/DML for CommandStatementUpdate and CommandPreparedStatementUpdate
    // (DoPut). Runs `sql` exactly once; `*out_affected` is the row count
    // (-1 when unknown, 0 for DDL). Same failure contract as execute().
    virtual bool execute_update(std::string_view sql, std::int64_t* out_affected,
                                QueryFailure& out_failure) noexcept {
        (void)sql;
        *out_affected = 0;
        out_failure.code = GrpcCode::kUnimplemented;
        out_failure.message = "this host does not execute updates (CommandStatementUpdate)";
        return false;
    }
    // True when execute_update() is implemented; GetSqlInfo reports the
    // endpoint read-only otherwise.
    virtual bool supports_updates() const noexcept { return false; }
    // Whether `sql` returns a result set. CreatePreparedStatement runs a
    // query once to describe it but never runs an update to do so.
    virtual bool is_query(std::string_view sql) noexcept {
        (void)sql;
        return true;
    }
    // CommandGetXdbcTypeInfo rows, at most `cap`; 0 answers UNIMPLEMENTED.
    virtual std::uint32_t xdbc_type_info(XdbcTypeInfo* out, std::uint32_t cap) noexcept {
        (void)out;
        (void)cap;
        return 0;
    }

    // Catalog for CommandGetTables/GetTableTypes/GetPrimaryKeys/... When
    // false those commands answer UNIMPLEMENTED; GetSqlInfo still works.
    virtual bool has_catalog() const noexcept { return false; }
    // Snapshots the table list and returns its size (<= kMaxCatalogTables).
    virtual std::uint32_t catalog_tables() noexcept { return 0; }
    // Entry i of the last snapshot; the views stay valid until the next
    // catalog_tables() on this executor.
    virtual bool catalog_table(std::uint32_t i, CatalogTable* out) noexcept {
        (void)i; (void)out;
        return false;
    }
    // An Arrow IPC stream whose leading Schema message is table i's schema
    // as a query of it returns. Same failure contract as execute().
    virtual bool catalog_table_schema(std::uint32_t i, std::string* out_ipc,
                                      QueryFailure& out_failure) noexcept {
        (void)i; (void)out_ipc;
        out_failure.code = GrpcCode::kUnimplemented;
        out_failure.message = "this host does not describe table schemas";
        return false;
    }
};

class IExecutorFactory {
public:
    virtual ~IExecutorFactory() = default;
    virtual IQueryExecutor* create() noexcept = 0;
    virtual void destroy(IQueryExecutor* e) noexcept = 0;
};

// Called once per RPC with the request's `authorization` header, split into
// `scheme` ("basic", "bearer", or "none" when absent/unrecognised). For
// basic, `principal`/`credentials` are the decoded user and password; for
// bearer, `credentials` is the token. Return false -> UNAUTHENTICATED.
class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    virtual bool authenticate(std::string_view scheme, std::string_view principal,
                              std::string_view credentials) noexcept = 0;
};

class AllowAllAuthenticator final : public IAuthenticator {
public:
    bool authenticate(std::string_view, std::string_view,
                      std::string_view) noexcept override {
        return true;
    }
};

struct Config {
    std::string   host = "127.0.0.1";
    std::uint16_t port = 0;
    // Worker threads == concurrent connections; each worker serves one
    // connection (all of its multiplexed streams) at a time.
    std::uint16_t max_connections = 8;
    // Workers run the host engine; give them an explicit stack.
    std::size_t   worker_stack_bytes = 32u * 1024u * 1024u;
    int           accept_poll_ms = 100;
    int           idle_timeout_ms = 300000;
    // CommandGetSqlInfo FLIGHT_SQL_SERVER_NAME / _VERSION.
    std::string   server_name = "boltapi Flight SQL";
    std::string   server_version = "0.1.0";
    // grpc+tls: a certificate (file or PEM) turns TLS on for every
    // connection, negotiating ALPN h2; without one the endpoint is h2c.
    std::string   tls_cert_file;
    std::string   tls_key_file;
    std::string   tls_cert_pem;
    std::string   tls_key_pem;

    bool tls_enabled() const noexcept {
        return !tls_cert_file.empty() || !tls_cert_pem.empty();
    }
};

class Listener;

class Protocol final {
public:
    Protocol(const Config& cfg, IExecutorFactory& factory,
             IAuthenticator* auth = nullptr) noexcept;
    ~Protocol();

    Protocol(const Protocol&) = delete;
    Protocol& operator=(const Protocol&) = delete;

    Status start_background() noexcept;
    void   stop() noexcept;

    bool          running() const noexcept { return running_.load(std::memory_order_acquire); }
    std::uint16_t local_port() const noexcept;

private:
    void worker_loop(IQueryExecutor& exec, std::uint16_t worker_id) noexcept;

    Config                 cfg_;
    IExecutorFactory&      factory_;
    IAuthenticator*        auth_;
    AllowAllAuthenticator  default_auth_{};

    std::shared_ptr<net::TlsContext>                   tls_;
    std::unique_ptr<Listener>                          listener_;
    std::vector<std::unique_ptr<core::StackedThread>>  workers_;
    std::vector<IQueryExecutor*>                       execs_;
    std::atomic<bool>                                  running_{false};
    std::atomic<bool>                                  stopping_{false};
};

}  // namespace bolt::api::proto::flightsql
