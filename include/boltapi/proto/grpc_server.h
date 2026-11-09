// boltapi/proto/grpc_server.h — a generic gRPC server over h2c / TLS (h2):
// the service-agnostic half of proto/flight_sql.h. The host registers one
// IService that answers calls by their `:path`; this layer owns HTTP/2
// framing, HPACK decode, flow control, gRPC length-prefixed framing,
// trailers and grpc-timeout. No gRPC or protobuf library (see flight_sql.h
// "WHY HAND-ROLLED"); message payloads are opaque bytes to this layer and
// the host decodes them with flight_sql_codec.h's PbReader.
//
// Shapes: unary, server streaming, and client streaming (the request is
// dispatched once the client half-closes, with every request message in
// Call::body). Bidirectional streaming is not offered.
//
// Concurrency: one worker per connection, as Flight SQL. Calls on one
// connection dispatch in stream-id order. While a streaming call is
// sending, frames keep being read; any completed call whose method the
// service marks `nestable` (short control calls such as an interrupt) is
// dispatched between two messages of the running call, so a control call
// does not wait for a long result to drain.
//
// Compiled ONLY under BOLTAPI_WITH_FLIGHT_SQL (the gRPC/HTTP2 option).
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

namespace bolt::api::proto::grpc {

using Status = core::result<void>;

// grpc/doc/statuscodes.md
enum class Code : std::uint8_t {
    kOk = 0,
    kCancelled = 1,
    kUnknown = 2,
    kInvalidArgument = 3,
    kDeadlineExceeded = 4,
    kNotFound = 5,
    kAlreadyExists = 6,
    kPermissionDenied = 7,
    kResourceExhausted = 8,
    kFailedPrecondition = 9,
    kAborted = 10,
    kOutOfRange = 11,
    kUnimplemented = 12,
    kInternal = 13,
    kUnavailable = 14,
    kUnauthenticated = 16,
};

struct Call {
    std::string_view method;          // ":path", e.g. "/pkg.Service/Method"
    std::string_view authorization;   // raw header value, empty when absent
    std::string_view user_agent;
    std::int64_t     timeout_ms = -1; // grpc-timeout, -1 when absent
    // Every request message, still gRPC-framed (5-byte prefix each). Use
    // next_message() to walk them.
    std::string_view body;
};

// Walks Call::body. Returns false at the end; `*malformed` set on a bad or
// compressed frame.
bool next_message(std::string_view body, std::size_t* pos, std::string_view* msg,
                  bool* malformed) noexcept;

// One call's response side. Valid only inside IService::handle.
class Responder {
public:
    virtual ~Responder() = default;
    // Send one response message. False when the peer reset the stream or
    // the connection died; the handler should stop and return.
    virtual bool send(std::string_view message) noexcept = 0;
    // End the call. Must be called exactly once; a handler that returns
    // without finishing is answered INTERNAL.
    virtual void finish(Code code, std::string_view message) noexcept = 0;
    // finish() plus a `grpc-status-details-bin` trailer: `details` is a
    // serialized google.rpc.Status, base64-encoded here.
    virtual void finish_with_details(Code code, std::string_view message,
                                     std::string_view details) noexcept = 0;
    // Peer sent RST_STREAM (client cancelled) or the connection died.
    virtual bool cancelled() const noexcept = 0;
    // Read pending frames without blocking and dispatch completed nestable
    // calls. Called by send() automatically; a handler in a long compute
    // loop may call it to stay responsive.
    virtual void poll() noexcept = 0;
};

// The host's service. One instance per worker thread (IServiceFactory).
class IService {
public:
    virtual ~IService() = default;
    virtual void handle(const Call& call, Responder& out) noexcept = 0;
    // May this method run while another call on the same connection is
    // mid-stream? Must be short and must not itself stream.
    virtual bool nestable(std::string_view method) noexcept {
        (void)method;
        return false;
    }
};

class IServiceFactory {
public:
    virtual ~IServiceFactory() = default;
    virtual IService* create() noexcept = 0;
    virtual void destroy(IService* s) noexcept = 0;
};

struct Config {
    std::string   host = "127.0.0.1";
    std::uint16_t port = 0;
    // Non-empty: listen on this Unix-domain socket path instead of TCP
    // (embedded / local mode; no port opened). POSIX only.
    std::string   unix_path;
    // Worker threads == concurrent connections. A Connect-style client keeps
    // one long-lived connection per session, so size this to sessions.
    std::uint16_t max_connections = 8;
    std::size_t   worker_stack_bytes = 32u * 1024u * 1024u;
    int           accept_poll_ms = 50;
    int           idle_timeout_ms = 600000;
    // Largest request a call may carry (all messages together); past it the
    // call answers RESOURCE_EXHAUSTED. Bodies grow to it on demand.
    std::size_t   max_request_bytes = 128u * 1024u * 1024u;
    // Concurrent open streams per connection (SETTINGS_MAX_CONCURRENT_STREAMS).
    std::uint32_t max_streams = 32;
    std::string   tls_cert_file;
    std::string   tls_key_file;
    std::string   tls_cert_pem;
    std::string   tls_key_pem;

    bool tls_enabled() const noexcept {
        return !tls_cert_file.empty() || !tls_cert_pem.empty();
    }
};

class Listener;
class Conn;

class Server final {
public:
    Server(const Config& cfg, IServiceFactory& factory) noexcept;
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    Status start_background() noexcept;
    void   stop() noexcept;

    bool          running() const noexcept { return running_.load(std::memory_order_acquire); }
    std::uint16_t local_port() const noexcept;

private:
    void worker_loop(IService& svc, std::uint16_t worker_id) noexcept;

    Config                                             cfg_;
    IServiceFactory&                                   factory_;
    std::shared_ptr<net::TlsContext>                   tls_;
    std::unique_ptr<Listener>                          listener_;
    std::vector<std::unique_ptr<core::StackedThread>>  workers_;
    std::vector<IService*>                             services_;
    std::atomic<bool>                                  running_{false};
    std::atomic<bool>                                  stopping_{false};
};

}  // namespace bolt::api::proto::grpc
