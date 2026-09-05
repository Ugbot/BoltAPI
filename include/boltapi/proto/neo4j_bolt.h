// boltapi/proto/neo4j_bolt.h — the Neo4j **Bolt client wire protocol**, server side.
//
// ============================================================================
// NAME COLLISION — READ THIS FIRST
// ============================================================================
// `bolt` (extern/bolt) is OUR columnar core. "Bolt" in this file means Neo4j's
// CLIENT WIRE PROTOCOL — raw TCP, its own 20-byte handshake, its own 2-byte
// chunk framing, PackStream values. The two are unrelated.
//
// ============================================================================
// WHY THIS LIVES IN boltapi
// ============================================================================
// The columnar core must not learn a client wire protocol, and this is not
// HTTP-level compat either (everything in Gestalt2 src/compat/ — Prometheus,
// Elasticsearch, Iceberg REST, S3, Unity — rides the boltapi HTTP *router*).
// Bolt is raw TCP with its own handshake and framing, so it belongs where the
// other non-HTTP protocols live: as an OPTIONAL `IProtocol` extension in
// boltapi, alongside HTTP/3 and WebRTC, registered through ProtocolRegistry.
// No core edit; the HTTP/1.1 + HTTP/2 engine is untouched.
//
// Compiled ONLY under BOLTAPI_WITH_NEO4J_BOLT (default OFF).
//
// ============================================================================
// SCOPE — READ-ONLY, EXECUTOR-AGNOSTIC
// ============================================================================
// This layer speaks the wire and NOTHING else. It has no query engine, no
// Cypher parser and no chukonu coupling; a host supplies an IQueryExecutor.
// BEGIN/COMMIT/ROLLBACK are accepted as no-op successes because the server is
// read-only. ROUTE is answered with the standard single-instance failure so a
// driver falls back to a direct connection, exactly as a non-cluster server does.
//
// Anything this layer cannot serve is a LOUD, named FAILURE or an explicit
// handshake decline — never a silent empty result.

#pragma once

#include "boltapi/proto/packstream.h"
#include "boltapi/protocol.h"
#include "boltapi/transport.h"

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
namespace neo4j {

// The 4-byte preamble every Bolt client sends first (published spec).
inline constexpr std::uint32_t kBoltMagic = 0x6060B017u;

// Message signatures (published Bolt spec). Client->server and server->client.
enum class Signature : std::uint8_t {
    Hello     = 0x01,
    Goodbye   = 0x02,
    Reset     = 0x0F,
    Run       = 0x10,
    Begin     = 0x11,
    Commit    = 0x12,
    Rollback  = 0x13,
    Discard   = 0x2F,
    Pull      = 0x3F,
    Telemetry = 0x54,  // Bolt 5.4+
    Route     = 0x66,
    Logon     = 0x6A,  // Bolt 5.1+
    Logoff    = 0x6B,  // Bolt 5.1+
    Success   = 0x70,
    Record    = 0x71,
    Ignored   = 0x7E,
    Failure   = 0x7F,
};

struct Version {
    std::uint8_t major = 0;
    std::uint8_t minor = 0;

    bool valid() const noexcept { return major != 0; }
    // Auth moved out of HELLO into LOGON at Bolt 5.1.
    bool has_logon() const noexcept { return major > 5 || (major == 5 && minor >= 1); }
};

// Versions this implementation actually IMPLEMENTS and is tested against. We
// advertise only what we serve: negotiation never selects a version outside
// this set, even when a client offers it.
inline constexpr std::uint8_t kMaxBolt5Minor = 4;   // Bolt 5.0 .. 5.4
inline constexpr std::uint8_t kBolt4Minor    = 4;   // Bolt 4.4 only

bool is_supported(Version v) noexcept;

// Negotiate against the client's 16-byte proposal block (four 4-byte entries,
// each `00 <range> <minor> <major>`; a range of R means the client also accepts
// minors [minor-R, minor]). Returns an invalid Version when nothing matches —
// the caller then answers `00 00 00 00` and closes, which is the spec's decline.
//
// Bolt 5.7 added a "handshake manifest" proposal with major 0xFF. We do not
// implement the manifest exchange, so we skip that entry rather than select it;
// drivers always carry plain proposals alongside it.
Version negotiate(const std::uint8_t proposals[16]) noexcept;

// Connection state machine (the published Bolt server states, minus the ones a
// read-only server cannot enter).
enum class State : std::uint8_t {
    Negotiation = 0,
    Authentication,
    Ready,
    Streaming,
    TxReady,
    TxStreaming,
    Failed,
    Defunct,
};

const char* state_name(State s) noexcept;

// A named failure, reported to the client as FAILURE {code, message}. `code`
// uses Neo4j's dotted classification so drivers map it to the right exception.
struct QueryFailure {
    const char* code    = "Neo.ClientError.Statement.ExecutionFailed";
    const char* message = "query execution failed";
};

// Where a query's records go. `emit` returns false when the connection is dead;
// the executor must stop immediately and not treat that as a query error.
class IRecordSink {
public:
    virtual ~IRecordSink() = default;
    virtual bool emit(const packstream::PackValue* values, std::uint32_t n) noexcept = 0;

protected:
    IRecordSink() = default;
};

inline constexpr std::uint32_t kMaxFields = 256;   // columns per result
inline constexpr std::int64_t  kPullAll   = -1;    // PULL {n: -1}

// The host's query engine. One instance per worker thread, created once at
// serve() time — never per connection, never per query.
class IQueryExecutor {
public:
    virtual ~IQueryExecutor() = default;

    // Compile/prepare `cypher` with `params` (a PackStream dictionary, possibly
    // Null). On success fill out_fields[0..out_field_count) with column names
    // that stay valid until the next begin_query/discard on this executor.
    // Return false and fill `out_failure` to send a FAILURE.
    //
    // LIFETIME — load-bearing: `cypher` and `params` are borrowed from the
    // connection's per-MESSAGE decode arena, which is reset before the next
    // message (the PULL that follows). An executor that needs either after
    // begin_query returns MUST copy it. Holding the pointers is a use-after-
    // free that only shows up once a second message arrives.
    virtual bool begin_query(std::string_view cypher,
                             const packstream::PackValue& params,
                             std::string_view* out_fields,
                             std::uint32_t fields_cap,
                             std::uint32_t& out_field_count,
                             QueryFailure& out_failure) noexcept = 0;

    // Stream at most `n` records into `sink` (kPullAll = every remaining one).
    // Set out_has_more when records remain. Return false + out_failure on error.
    virtual bool pull(std::int64_t n, IRecordSink& sink, bool& out_has_more,
                      QueryFailure& out_failure) noexcept = 0;

    // Abandon the current result set. Idempotent; must not throw.
    virtual void discard() noexcept = 0;

protected:
    IQueryExecutor() = default;
};

// Executors are per-worker-thread, so the host supplies a factory. create() is
// called exactly `max_connections` times during serve() startup.
class IExecutorFactory {
public:
    virtual ~IExecutorFactory() = default;
    virtual IQueryExecutor* create() noexcept = 0;
    virtual void destroy(IQueryExecutor* e) noexcept = 0;

protected:
    IExecutorFactory() = default;
};

// Auth hook. The default accepts everything (auth: none), which is what an
// embedded/loopback deployment wants; a host overrides it for basic auth.
class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    // `scheme` is "none" or "basic"; principal/credentials are empty for "none".
    virtual bool authenticate(std::string_view scheme,
                              std::string_view principal,
                              std::string_view credentials) noexcept = 0;

protected:
    IAuthenticator() = default;
};

class AcceptAnyAuthenticator final : public IAuthenticator {
public:
    bool authenticate(std::string_view, std::string_view, std::string_view) noexcept override {
        return true;
    }
};

struct Config {
    transport::Endpoint bind{"127.0.0.1", 7687};

    // Fixed worker-thread count. Threads are created once in serve() and each
    // handles one connection at a time — bounded concurrency, no thread spawn
    // on the connection path.
    std::uint16_t max_connections = 8;

    // Per-worker buffers, allocated once at serve() start.
    std::uint32_t message_buffer_bytes = 1u << 20;  // largest inbound message
    std::uint32_t write_buffer_bytes   = 1u << 20;  // largest outbound message
    std::uint32_t value_arena_bytes    = 1u << 20;  // decoded-value arena

    // Drivers check that the `server` agent starts with "Neo4j/" and refuse the
    // connection otherwise (UnsupportedServerProduct). This field is the
    // protocol's product-identification slot; the SUCCESS metadata also carries
    // an honest `boltapi_server` naming this implementation.
    const char* server_agent = "Neo4j/5.4.0";

    // How often a blocked accept() OR a blocked connection read wakes to
    // re-check stop(). It bounds shutdown latency, so it is deliberately the
    // same knob for both: a slow poll would leave workers parked past stop().
    int accept_poll_ms  = 100;
    int idle_timeout_ms = 60000;  // close a connection that says nothing
};

// ---------------------------------------------------------------------------
// Neo4jBoltListener — the stream ITransport this protocol serves over.
//
// The seam's ITransport has no accept primitive (it is deliberately family
// agnostic), so the accept call lives here on the concrete type and the
// protocol is handed the concrete listener via bind_listener().
// ---------------------------------------------------------------------------
class Neo4jBoltListener final : public transport::ITransport {
public:
    explicit Neo4jBoltListener(transport::Endpoint bind) noexcept;
    ~Neo4jBoltListener() override;

    Neo4jBoltListener(const Neo4jBoltListener&) = delete;
    Neo4jBoltListener& operator=(const Neo4jBoltListener&) = delete;

    transport::Status start() override;
    void stop() noexcept override;
    transport::TransportKind kind() const noexcept override {
        return transport::TransportKind::Stream;
    }
    const transport::Endpoint& local_endpoint() const noexcept override { return bound_; }
    bool is_running() const noexcept override { return fd_ >= 0; }

    // Wait up to `timeout_ms` for a connection. Returns a connected socket, or
    // -1 on timeout / shutdown / error. Safe to call from several threads.
    int accept_one(int timeout_ms) noexcept;

private:
    transport::Endpoint requested_;
    transport::Endpoint bound_;
    std::atomic<int>    fd_{-1};
};

// ---------------------------------------------------------------------------
// Neo4jBoltProtocol — the IProtocol implementation.
// ---------------------------------------------------------------------------
class Neo4jBoltProtocol final : public IProtocol {
public:
    Neo4jBoltProtocol(const Config& cfg, IExecutorFactory& factory,
                      IAuthenticator* auth = nullptr) noexcept;
    ~Neo4jBoltProtocol() override;

    Neo4jBoltProtocol(const Neo4jBoltProtocol&) = delete;
    Neo4jBoltProtocol& operator=(const Neo4jBoltProtocol&) = delete;

    ProtocolId id() const noexcept override { return ProtocolId::Neo4jBolt; }
    transport::TransportKind transport_kind() const noexcept override {
        return transport::TransportKind::Stream;
    }

    // Declare which concrete listener serve() may use. Without RTTI there is no
    // safe downcast from ITransport&, so the binding is explicit and serve()
    // refuses any transport that is not the bound one.
    Status bind_listener(Neo4jBoltListener& listener) noexcept;

    // Blocks until stop(). `source` must be the bound listener, already started.
    Status serve(transport::ITransport& source) override;
    void stop() noexcept override;

    // Convenience: create + start an owned listener on cfg.bind, then serve.
    // Blocks. Use local_port() (valid after start_background()) for port 0.
    Status listen_and_serve();

    // Start listen_and_serve() on a background thread and return once the
    // listener is bound (so local_port() is meaningful) or the bind failed.
    Status start_background();

    std::uint16_t local_port() const noexcept { return port_.load(std::memory_order_acquire); }
    bool running() const noexcept { return running_.load(std::memory_order_acquire); }

private:
    void worker_loop(Neo4jBoltListener& listener, IQueryExecutor& exec,
                     std::uint16_t worker_id) noexcept;

    Config              cfg_;
    IExecutorFactory&   factory_;
    IAuthenticator*     auth_;
    AcceptAnyAuthenticator default_auth_{};
    Neo4jBoltListener*  bound_ = nullptr;

    std::unique_ptr<Neo4jBoltListener> owned_listener_;
    std::thread                        serve_thread_;
    std::vector<std::thread>           workers_;
    std::atomic<bool>                  running_{false};
    std::atomic<bool>                  stopping_{false};
    std::atomic<std::uint16_t>         port_{0};
    std::atomic<std::uint64_t>         conn_seq_{0};
};

// Registers a Neo4jBoltProtocol factory into `reg`. The factory captures
// references that must outlive every protocol instance it produces.
Status register_neo4j_bolt(ProtocolRegistry& reg, const Config& cfg,
                           IExecutorFactory& factory,
                           IAuthenticator* auth = nullptr);

}  // namespace neo4j
}  // namespace proto
}  // namespace bolt::api
