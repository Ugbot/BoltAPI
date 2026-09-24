// boltapi/proto/postgres_wire.h — the PostgreSQL frontend/backend wire
// protocol (v3.0), server side. G2ETL-35: the BI-tool connectivity door
// (psql / Metabase / any generic `libpq`-speaking driver), modelled directly
// on this same directory's `neo4j_bolt.h` — read that file's header comment
// for the shape this one deliberately repeats: a wire-protocol layer here in
// boltapi with NO query engine of its own, executor-agnostic via
// IQueryExecutor/IExecutorFactory, host supplies the engine.
//
// ============================================================================
// SCOPE — Simple Query AND Extended Query (G2ETL-35 v1, G2ETL-47 v2)
// ============================================================================
// Postgres wire v3 has two ways to run a query:
//   - Simple Query ('Q'): one SQL string in, RowDescription/DataRow*/
//     CommandComplete out. What `psql` uses for plain statements.
//   - Extended Query (Parse/Bind/Describe/Execute/Close/Flush/Sync): prepared
//     statements + portals with typed parameters — what JDBC, psycopg 3,
//     asyncpg and most BI drivers use. Per-connection named/unnamed
//     statements and portals live in fixed, pre-allocated slots
//     (Config::max_prepared_statements / max_portals); overflow is a named
//     ErrorResponse, never a silent eviction. The executor still only sees
//     plain SQL: Bind renders each parameter as a typed SQL literal
//     (postgres_wire_codec.h), outside quotes/comments/dollar-quotes. Text
//     and binary parameter formats are accepted for bool/int2/int4/int8/
//     float4/float8/numeric/date/text-like types; results may be requested
//     in binary for the same set. Execute honours max_rows with
//     PortalSuspended. After an error every message up to Sync is
//     discarded, per the protocol. One portal's rows are buffered at a time
//     (the executor owns one result): executing a portal whose rows were
//     displaced by another portal's execution is refused (55000), not
//     re-run.
//
// Transactions (G2ETL-64): there are none — every statement is applied when
// it runs. The wire layer still answers BEGIN / START TRANSACTION / COMMIT /
// END / ROLLBACK / ABORT itself and reports the block status ('I'/'T'/'E')
// in ReadyForQuery, so drivers that toggle autocommit (pgJDBC, psycopg) and
// cursor fetch over named portals work. It is honest about what it cannot
// do: a write inside a READ ONLY block is refused (25006); after an error
// the block refuses everything but COMMIT/ROLLBACK (25P02); ending a block
// by ROLLBACK (or COMMIT of a failed block) after any write is an error
// (0A000) saying the writes were NOT undone; savepoints, two-phase commit,
// AND CHAIN and REPEATABLE READ/SERIALIZABLE are refused (0A000). Named
// portals close when the block ends.
//
// Authentication is "trust" (no password) or cleartext password — no MD5,
// no SCRAM-SHA-256. TLS negotiation is refused (`SSLRequest`/`GSSENCRequest`
// answered with a single 'N', which is the protocol's own "not offered"
// reply, followed by the client retrying in cleartext — this is a real,
// spec-legal response, not a stub).
//
// ============================================================================
// WHY THIS LIVES IN boltapi
// ============================================================================
// Same reasoning as neo4j_bolt.h: this is raw TCP with its own handshake and
// framing, not an HTTP-level compat surface, so it belongs beside the other
// non-HTTP protocols in boltapi rather than riding the HTTP router. No core
// edit; the HTTP/1.1 + HTTP/2 engine, and the Neo4j Bolt protocol, are both
// untouched by this file's existence.
//
// Compiled ONLY under BOLTAPI_WITH_PG_WIRE (default OFF).
#pragma once

#include "boltapi/net/sys_compat.h"
#include "boltapi/core/result.h"
#include "bolt/api/core/stacked_thread.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace bolt::api {
namespace proto {
namespace pgwire {

using Status = core::result<void>;
inline Status ok_status() noexcept { return Status(); }

// A named failure, reported to the client as an ErrorResponse ('E'). `sqlstate`
// is a 5-character PostgreSQL error code (see Appendix A of the Postgres
// protocol docs); `message` is the human-readable detail.
struct QueryFailure {
    const char* sqlstate = "XX000";               // internal_error, generic
    const char* message  = "query execution failed";
};

inline constexpr std::uint32_t kMaxFields = 256;   // columns per result row

// One output column's wire description (RowDescription 'T').
struct FieldDesc {
    std::string_view name;
    // Postgres OID for the column's type (see pg_type.h "well known" OIDs;
    // 25=text/unknown is always a safe fallback since every value is sent in
    // TEXT format here — the OID mainly steers client-side display/casts).
    std::int32_t type_oid  = 25;
    std::int16_t type_size = -1;   // -1 = variable length
};

// The host's query engine. One instance per WORKER THREAD (bounded by
// Config::max_connections), created once at serve() time — never per
// connection, never per query. Mirrors neo4j_bolt.h's IQueryExecutor.
class IQueryExecutor {
public:
    virtual ~IQueryExecutor() = default;

    // Compile + run `sql` (one Simple-Query-protocol statement — the wire
    // layer does not split a client's ';'-separated multi-statement string;
    // v1 treats it as one statement, matching what chukonu's parser accepts
    // in one call). On success, fills `out_fields[0..out_field_count)` with
    // the result's column descriptions and buffers every output row
    // internally for row()/row_count() below. Returns false and fills
    // `out_failure` to send an ErrorResponse instead.
    //
    // `out_fields` and the `name` string_views inside it must stay valid
    // until the next execute() on this executor.
    virtual bool execute(std::string_view sql, FieldDesc* out_fields,
                         std::uint32_t fields_cap,
                         std::uint32_t& out_field_count,
                         QueryFailure& out_failure) noexcept = 0;

    // Row `index` (0-based, < row_count()). Fills `out_values`/`out_is_null`
    // (both sized by the field count execute() reported); a NULL field's
    // `out_values` entry is unspecified. Returns false if `index` is out of
    // range. Values are already in Postgres TEXT wire format (e.g. dates as
    // "YYYY-MM-DD", decimals as an exact "123.45" — no further formatting).
    virtual bool row(std::uint32_t index, std::string_view* out_values,
                     bool* out_is_null, std::uint32_t cap) noexcept = 0;

    virtual std::uint32_t row_count() const noexcept = 0;

    // Result SHAPE of a query-shaped `sql` (SELECT/WITH/VALUES/...) for an
    // Extended-Query Describe of a not-yet-bound statement, without the
    // caller needing its rows. The default runs execute() — correct but
    // pays for the rows; an engine that can plan without executing should
    // override. Same field-lifetime contract as execute(), and it may
    // discard whatever result execute() last buffered.
    virtual bool describe(std::string_view sql, FieldDesc* out_fields,
                          std::uint32_t fields_cap,
                          std::uint32_t& out_field_count,
                          QueryFailure& out_failure) noexcept {
        return execute(sql, out_fields, fields_cap, out_field_count, out_failure);
    }

    // CommandComplete tag, e.g. "SELECT 3". Called after a successful
    // execute(). `cap` >= 32.
    virtual void command_tag(char* out, std::size_t cap) const noexcept = 0;
};

// Executors are per-worker-thread, so the host supplies a factory. create()
// is called exactly `max_connections` times during start_background().
class IExecutorFactory {
public:
    virtual ~IExecutorFactory() = default;
    virtual IQueryExecutor* create() noexcept = 0;
    virtual void destroy(IQueryExecutor* e) noexcept = 0;
};

// Auth hook. The default accepts every StartupMessage unconditionally with no
// password challenge ("trust"), matching Postgres's own trust auth mode and
// every other compat surface's auth-bypass default in this codebase.
class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    // Whether LOGIN for this connection challenges for a cleartext password
    // (true) or is accepted outright (false, "trust"). Checked once per
    // connection, before `authenticate()` — a host that always trusts can
    // return false unconditionally and never see a non-empty `password`.
    virtual bool requires_password() const noexcept = 0;
    // `user`/`database` come from the StartupMessage parameters; `password`
    // is empty when requires_password() returned false for this connection.
    // Return false to refuse the connection with SQLSTATE 28P01
    // (invalid_password) / 28000 (invalid_authorization_specification).
    virtual bool authenticate(std::string_view user, std::string_view database,
                              std::string_view password) noexcept = 0;
};

class TrustAuthenticator final : public IAuthenticator {
public:
    bool requires_password() const noexcept override { return false; }
    bool authenticate(std::string_view, std::string_view,
                      std::string_view) noexcept override {
        return true;
    }
};

struct Config {
    std::string   host = "127.0.0.1";
    std::uint16_t port = 5432;

    // Fixed worker-thread count, created once in start_background(). Each
    // worker serves one connection at a time (bounded concurrency, no thread
    // spawn on the connection path) — a real BI dashboard rarely opens more
    // than a handful of connections, so this defaults low.
    std::uint16_t max_connections = 16;

    // Explicit worker stack. The host executor runs a whole SQL compile +
    // execute on this thread; a platform-default secondary-thread stack
    // (512 KiB on macOS) is overrun by a recursive planner, which kills the
    // process with no diagnostic.
    std::size_t worker_stack_bytes = core::kDefaultStackBytes;

    // Per-worker buffers, allocated once at start.
    std::uint32_t message_buffer_bytes = 1u << 20;  // largest inbound message
    std::uint32_t write_buffer_bytes   = 1u << 20;  // largest outbound message

    // Extended Query state, per worker, allocated once at start. Prepared
    // statement text shares one compacting pool; each portal slot holds one
    // bound statement of at most max_statement_bytes.
    std::uint16_t max_prepared_statements = 64;    // incl. the unnamed one
    std::uint16_t max_portals             = 8;     // incl. the unnamed one
    std::uint32_t max_statement_bytes     = 64u * 1024u;
    std::uint32_t statement_pool_bytes    = 1u << 20;

    // Sent as the `server_version` ParameterStatus. Some clients parse this
    // to gate feature use, so it must look like a real Postgres version
    // string (e.g. "14.9") even though the two-string form below also names
    // this server honestly.
    std::string server_version = "14.9";
    // Sent as an EXTRA ParameterStatus (`gestaltd_server`), naming this
    // implementation honestly without lying about `server_version` above.
    std::string application_name = "gestaltd (chukonu SQL engine)";

    // How often a blocked accept() or a blocked connection read wakes to
    // re-check stop(). Bounds shutdown latency.
    int accept_poll_ms  = 100;
    int idle_timeout_ms = 300000;
};

// The listening socket. Raw AF_INET stream socket, same shape as this
// directory's Neo4jBoltListener (no chunk framing needed here, so it is
// simpler): bind/listen once at start(), a bounded select()-gated
// accept_one() per worker, stop() closes the fd to wake every blocked accept.
class Listener final {
public:
    explicit Listener(std::string host, std::uint16_t port) noexcept;
    ~Listener();

    Listener(const Listener&)            = delete;
    Listener& operator=(const Listener&) = delete;

    Status start() noexcept;
    void   stop() noexcept;
    bool   is_running() const noexcept;
    std::uint16_t local_port() const noexcept { return port_.load(std::memory_order_acquire); }

    // Wait up to `timeout_ms` for a connection. Returns a connected socket,
    // or -1 on timeout / shutdown / error. Safe to call from several threads.
    int accept_one(int timeout_ms) noexcept;

private:
    std::string          host_;
    std::uint16_t         requested_port_;
    std::atomic<int>      fd_{-1};
    std::atomic<std::uint16_t> port_{0};
};

// The protocol driver: owns a Listener + a fixed worker-thread pool, each
// running the Postgres wire state machine (startup -> auth -> ReadyForQuery
// -> Simple Query loop) against one IQueryExecutor per worker.
class Protocol final {
public:
    Protocol(const Config& cfg, IExecutorFactory& factory,
             IAuthenticator* auth = nullptr) noexcept;
    ~Protocol();

    Protocol(const Protocol&)            = delete;
    Protocol& operator=(const Protocol&) = delete;

    // Bind + start the listener and the worker threads on a background
    // thread; returns once the listener is bound (so local_port() is
    // meaningful) or the bind failed.
    Status start_background() noexcept;
    void   stop() noexcept;

    bool          running() const noexcept { return running_.load(std::memory_order_acquire); }
    std::uint16_t local_port() const noexcept { return listener_ ? listener_->local_port() : 0; }

private:
    void worker_loop(IQueryExecutor& exec, std::uint16_t worker_id) noexcept;

    Config              cfg_;
    IExecutorFactory&   factory_;
    IAuthenticator*     auth_;
    TrustAuthenticator  default_auth_{};

    std::unique_ptr<Listener>       listener_;
    std::vector<core::StackedThread> workers_;
    std::vector<IQueryExecutor*>    execs_;
    std::atomic<bool>               running_{false};
    std::atomic<bool>               stopping_{false};
    std::atomic<std::uint64_t>      conn_seq_{0};
};

}  // namespace pgwire
}  // namespace proto
}  // namespace bolt::api
