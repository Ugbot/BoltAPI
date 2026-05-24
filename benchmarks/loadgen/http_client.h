// http_client.h — minimal, transport-agnostic HTTP/1.1 CLIENT core.
//
// This is the outbound counterpart to the engine's server-side parser: a request
// SERIALIZER + an incremental response PARSER + a pooled keep-alive CONNECTION
// record. It deliberately depends on NOTHING from the dispatcher — it is pure
// bytes-in / bytes-out — so it can later be promoted out of benchmarks/ into a
// real `boltapi` outbound HTTP client (the missing piece an API gateway needs to
// forward to upstreams). The async glue (connect/read/write loop) lives in
// loadgen.cpp; this file is the reusable, testable core.
//
// v1 scope: cleartext only (a documented TLS extension point below); responses
// must be Content-Length framed (the bench server never chunks) — a chunked or
// oversized response is reported as a parse Error, never a crash.
//
// TigerStyle: bounded buffers, no recursion, >=2 asserts per non-trivial fn,
// explicit error returns (no exceptions), no allocation on the steady path
// (buffers are owned by ClientConn and reused across requests).
#pragma once

#include "boltapi/net/sys_compat.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::bench::http {

// Largest response (status line + headers + body) the parser will buffer before
// declaring Error. Bench responses are tiny; this is a generous safety ceiling.
inline constexpr std::size_t kMaxRespBytes = 1u << 20;   // 1 MiB
// Per-read scratch size used by the async loop (see ClientConn::rbuf).
inline constexpr std::size_t kRecvChunk    = 16u * 1024; // 16 KiB

// --- Request model (caller-owned views; serializer copies into `out`). --------
struct ClientRequest {
    std::string_view method = "GET";
    std::string_view path   = "/";
    std::string_view host   = "127.0.0.1";
    std::string_view body   = {};            // empty => no body, no Content-Length
    std::string_view content_type = "application/octet-stream";
};

// Serialize `req` into `out` (cleared first). Keep-alive is implicit (HTTP/1.1
// default; we never send Connection: close). Returns bytes written.
std::size_t serialize_request(const ClientRequest& req, std::string& out);

// --- Incremental response parser (one response at a time, reset between). ------
//
// Feed bytes as they arrive; consume() returns NeedMore until a full response
// (headers + Content-Length body) has been seen, then Complete. Because the load
// generator is strictly request/response-serial per connection, a single read
// never straddles two responses, so the parser does not need to retain leftover
// bytes for a following response.
class ResponseParser {
public:
    enum class State : std::uint8_t { NeedMore, Complete, Error };

    // Reset for the next keep-alive request on the same connection.
    void reset() noexcept {
        buf_.clear();
        header_end_ = npos_;
        content_length_ = -1;
        status_ = 0;
        keep_alive_ = true;   // HTTP/1.1 default
    }

    // Feed newly-read bytes. Bounded: caps total buffered at kMaxRespBytes.
    State consume(const char* data, std::size_t len) noexcept;

    int          status()     const noexcept { return status_; }
    std::size_t  body_len()   const noexcept { return content_length_ < 0 ? 0 : static_cast<std::size_t>(content_length_); }
    bool         keep_alive() const noexcept { return keep_alive_; }

private:
    static constexpr std::size_t npos_ = static_cast<std::size_t>(-1);

    // Parse status line + headers once header_end_ is known. Sets status_,
    // content_length_, keep_alive_. Returns false on malformed/unsupported input.
    bool parse_head() noexcept;

    std::string buf_;                       // owned accumulator (reused via reset)
    std::size_t header_end_ = npos_;        // offset of "\r\n\r\n" (start of CRLFCRLF)
    long long   content_length_ = -1;       // -1 = not yet known
    int         status_ = 0;
    bool        keep_alive_ = true;
};

// --- One pooled keep-alive connection. Buffers live HERE so they stay stable
//     across co_await suspension points (the dispatcher resumes coroutines on a
//     worker thread; an awaitable must not point into a coroutine-frame temporary).
struct ClientConn {
    int            fd = -1;                  // socket (int per dispatcher API)
    std::string    wbuf;                     // serialized request (stable during write)
    char           rbuf[kRecvChunk] = {};    // read scratch (stable during read)
    ResponseParser parser;
    bool           connected = false;
};

// --- TLS extension point (NOT implemented in v1) ------------------------------
// A future TlsClientConn would wrap `fd` with an OpenSSL SSL* and replace the raw
// async_read/async_write in the loop with BIO-pumped reads/writes. serialize_request
// and ResponseParser are transport-agnostic and are reused unchanged. OpenSSL is
// already linked by the QUIC/media bench targets, so HTTPS upstreams slot in here
// without any new third-party dependency.

}  // namespace bolt::bench::http
