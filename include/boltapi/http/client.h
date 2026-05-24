// boltapi/http/client.h — outbound HTTP/1.1 client (gateway upstream forwarding).
//
// Gateway Phase 0 (docs/gateway/GATEWAY_ROADMAP.md): the one primitive BoltAPI
// lacked — a way to make requests, not just serve them. Promoted from the
// benchmark load generator's transport-agnostic client core. Built on the
// engine's own async outbound I/O (net::IODispatcher async_connect/read/write),
// so upstream I/O rides the same event loop as inbound serving.
//
// Three layers, smallest-first so each is independently reusable/testable:
//   1. serialize_request()  — bytes-out, no dispatcher dep.
//   2. ResponseParser       — incremental HTTP/1.1 response parser (status +
//                             headers + Content-Length body framing).
//   3. Client               — keep-alive connection pool + coroutine send().
//
// v1 scope (documented limits, never a crash): cleartext only (TLS-to-upstream is
// a later phase — OpenSSL is already linked); responses must be Content-Length
// framed (chunked => parse error); bounded everything.
//
// TigerStyle: fixed-capacity pools (named constants), bounded loops, >=2 asserts
// per non-trivial fn, explicit error returns (no exceptions). The connection pool
// uses a short-critical-section mutex for v1 correctness; a sharded/lock-free pool
// is a documented perf-pass follow-up (see GATEWAY_ARCHITECTURE.md §7).
#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/net/sys_compat.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api::http {

// --- Bounds (TigerStyle: every limit a named constant) ------------------------
inline constexpr std::size_t kClientRecvChunk    = 16u * 1024;  // per-read scratch
inline constexpr std::size_t kClientMaxRespBytes = 1u << 20;    // 1 MiB resp ceiling
inline constexpr std::size_t kClientMaxRespHeaders = 64;        // parsed resp headers
inline constexpr std::size_t kClientMaxReqHeaders  = 32;        // extra request headers

// --- Request / response models ------------------------------------------------
struct ClientHeader {
    std::string_view name;
    std::string_view value;
};

struct ClientRequest {
    std::string_view method = "GET";
    std::string_view path   = "/";
    std::string_view host   = {};   // Host header; if empty, Client fills "host:port"
    std::string_view body   = {};   // empty => no body / no Content-Length
    std::string_view content_type = "application/octet-stream";
    const ClientHeader* extra_headers = nullptr;  // optional, bounded by caller
    std::size_t         extra_count   = 0;
};

struct ClientResponseHeader {
    std::string name;
    std::string value;
};

struct ClientResponse {
    bool        ok = false;    // transport success: a complete response was read
    int         status = 0;
    bool        keep_alive = true;
    std::string body;          // owned (stable after the connection is recycled)
    std::vector<ClientResponseHeader> headers;  // owned copies

    // Case-insensitive header lookup; returns "" when absent.
    std::string_view header(std::string_view name) const noexcept;
};

// Serialize `req` into `out` (cleared first); keep-alive is implicit (no
// Connection: close). `host_fallback` is used when req.host is empty. Returns
// bytes written.
std::size_t serialize_request(const ClientRequest& req,
                              std::string_view host_fallback,
                              std::string& out);

// --- Incremental response parser ----------------------------------------------
class ResponseParser {
public:
    enum class State : std::uint8_t { NeedMore, Complete, Error };

    void reset() noexcept;
    // Feed newly-read bytes. Bounded: caps total buffered at kClientMaxRespBytes.
    State consume(const char* data, std::size_t len) noexcept;

    int          status()     const noexcept { return status_; }
    bool         keep_alive() const noexcept { return keep_alive_; }
    std::size_t  body_len()   const noexcept { return content_length_ < 0 ? 0 : static_cast<std::size_t>(content_length_); }

    // Valid only after consume() returns Complete (views into the parser buffer).
    std::string_view body() const noexcept;
    std::size_t      header_count() const noexcept { return field_count_; }
    std::string_view header_name(std::size_t i) const noexcept;
    std::string_view header_value(std::size_t i) const noexcept;

private:
    static constexpr std::size_t npos_ = static_cast<std::size_t>(-1);
    struct Field { std::size_t name_off, name_len, val_off, val_len; };

    bool parse_head() noexcept;   // status line + headers; sets framing fields

    std::string buf_;
    Field       fields_[kClientMaxRespHeaders] = {};
    std::size_t field_count_ = 0;
    std::size_t header_end_ = npos_;
    long long   content_length_ = -1;
    int         status_ = 0;
    bool        keep_alive_ = true;
};

// --- Pooled keep-alive connection record (also reused by the benchmark loadgen).
struct ClientConn {
    int            fd = -1;
    std::string    wbuf;
    char           rbuf[kClientRecvChunk] = {};
    ResponseParser parser;
    bool           connected = false;
};

// --- Client: bounded keep-alive connection pool + coroutine send() ------------
class Client {
public:
    struct Config {
        std::size_t   max_targets          = 64;   // distinct host:port upstreams
        std::size_t   max_conns_per_target = 32;   // pooled idle keep-alive conns
    };

    // The dispatcher must outlive the Client and be started before send().
    // (Two ctors instead of a `Config cfg = {}` default arg: a nested struct's
    // default member initializers aren't usable in an in-class default argument.)
    explicit Client(net::IODispatcher* dispatcher) noexcept;
    Client(net::IODispatcher* dispatcher, Config cfg) noexcept;
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Send one request to host:port; returns a ClientResponse (check .ok). A
    // pooled keep-alive connection is reused when available; on a clean keep-alive
    // response the connection is returned to the pool, else closed. Never throws.
    core::coro_task<ClientResponse> send(std::string_view host, std::uint16_t port,
                                         const ClientRequest& req);

    // Close + drop all pooled idle connections (e.g. on shutdown).
    void close_idle() noexcept;

    // Total pooled idle (keep-alive) connections across all targets. Mainly for
    // tests/introspection — proves connection reuse after a request burst.
    std::size_t idle_total() noexcept;

private:
    // One upstream's pool: address + a bounded stack of idle keep-alive fds.
    struct TargetPool {
        std::string   host;
        std::uint16_t port = 0;
        sockaddr_in   addr{};
        bool          addr_ok = false;
        std::mutex    mtx;                 // guards idle[]/idle_count
        std::vector<int> idle;             // bounded by max_conns_per_target
    };

    // Find-or-create the pool slot for host:port. Returns nullptr if at capacity
    // or the host fails to resolve. Resolves + caches the sockaddr once.
    TargetPool* get_target(std::string_view host, std::uint16_t port) noexcept;
    int  pop_idle(TargetPool& tp) noexcept;          // -1 if none
    bool push_idle(TargetPool& tp, int fd) noexcept; // false if pool full (caller closes)

    net::IODispatcher* disp_;
    Config             cfg_;
    std::mutex         targets_mtx_;                  // guards targets_ slot list
    std::vector<std::unique_ptr<TargetPool>> targets_;
};

}  // namespace bolt::api::http
