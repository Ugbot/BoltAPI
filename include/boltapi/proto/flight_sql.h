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
//     FlightData, SchemaResult, google.protobuf.Any, CommandStatementQuery
//     and TicketStatementQuery; unknown fields are skipped per proto3.
//   - Arrow IPC: produced by the host's executor (Gestalt2 uses bolt's
//     arrow_ipc writer); this layer only splits the stream into messages
//     (flight_sql_codec.h) to fill FlightInfo.schema and FlightData.
// Codecs are in flight_sql_codec.{h,cpp}.
//
// ============================================================================
// SCOPE — v1 is ad-hoc statement query
// ============================================================================
//   GetFlightInfo(CMD = Any<CommandStatementQuery>)  -> FlightInfo with one
//       endpoint whose ticket is Any<TicketStatementQuery{handle = SQL}>.
//   DoGet(that ticket)                               -> schema + batches.
//   GetSchema(CMD = Any<CommandStatementQuery>)      -> SchemaResult.
//   Handshake                                        -> one empty response.
//   ListFlights / ListActions                        -> empty streams.
// The query executes at GetFlightInfo (to answer schema + total_records) and
// again at DoGet: the ticket carries the statement, not a server-side
// result handle, so there is no unbounded result cache to expire.
// Everything else — prepared statements (DoAction CreatePreparedStatement),
// catalog commands (CommandGetTables/GetSqlInfo/...), DoPut, DoExchange,
// transactions — answers grpc-status UNIMPLEMENTED naming the command,
// never a silently empty result.
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

    std::unique_ptr<Listener>                          listener_;
    std::vector<std::unique_ptr<core::StackedThread>>  workers_;
    std::vector<IQueryExecutor*>                       execs_;
    std::atomic<bool>                                  running_{false};
    std::atomic<bool>                                  stopping_{false};
};

}  // namespace bolt::api::proto::flightsql
