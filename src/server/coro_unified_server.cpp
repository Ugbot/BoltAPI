/**
 * Coroutine-based Unified HTTP Server Implementation
 *
 * Implements the Seastar-inspired architecture:
 * - 1-2 I/O threads dispatch events
 * - N worker threads execute coroutines
 * - Coroutines yield on blocking I/O
 */

#include "boltapi/server/coro_unified_server.h"
#include "boltapi/net/coro_tls_socket.h"
#include "boltapi/net/tls_cert_generator.h"
#include "boltapi/http/http1_parser.h"
#include "boltapi/http/http2_connection.h"
#include "boltapi/http/request_body_buffer.h"
#include "boltapi/net/sys_compat.h"
#include <algorithm>
#include <iostream>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <charconv>
#include <vector>
#ifndef _WIN32
#include <sys/select.h>
#endif

namespace bolt::api {
namespace http {

namespace {

// Branchless-ish ASCII helpers for the response hot path — NO allocation (the old
// path copied each header name into a std::string just to lowercase-compare).
inline char to_lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}
// Case-insensitive equality: `a` vs a lowercase literal `lower`.
inline bool ieq_ascii(std::string_view a, std::string_view lower) noexcept {
    if (a.size() != lower.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (to_lower_ascii(a[i]) != lower[i]) return false;
    }
    return true;
}
// Case-insensitive substring presence of a lowercase `needle` in `hay`.
inline bool contains_ci(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty() || hay.size() < needle.size()) return false;
    const std::size_t end = hay.size() - needle.size();
    for (std::size_t i = 0; i <= end; ++i) {
        std::size_t k = 0;
        for (; k < needle.size(); ++k) {
            if (to_lower_ascii(hay[i + k]) != needle[k]) break;
        }
        if (k == needle.size()) return true;
    }
    return false;
}
// Append an unsigned integer as decimal via to_chars (stack buffer, no alloc).
inline void append_uint(std::string& out, std::uint64_t v) {
    char tmp[20];
    auto [p, ec] = std::to_chars(tmp, tmp + sizeof(tmp), v);
    (void)ec;
    out.append(tmp, static_cast<std::size_t>(p - tmp));
}

// =====================================================================
// Incremental streaming (STATION-96) — cleartext HTTP/1.1 chunked output.
// =====================================================================

inline int stream_sock_errno() noexcept {
#ifdef _WIN32
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

inline bool stream_would_block(int e) noexcept {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK;
#else
    return e == EWOULDBLOCK || e == EAGAIN;
#endif
}

// Fully send `len` bytes to the connection socket `fd`, blocking until drained.
// Returns false if the peer is gone / a hard error occurred (client disconnect
// mid-stream). Runs on the I/O thread from inside the streaming producer, where
// a synchronous send is correct: the producer (a blocking generate()) already
// owns the thread, and no overlapped op is in flight on this fd meanwhile. A
// non-blocking socket that reports would-block is waited on via select() with a
// bounded retry so a wedged peer cannot hang the reactor forever.
bool stream_send_all(int fd, const void* data, std::size_t len) noexcept {
#ifdef _WIN32
    SOCKET s = static_cast<SOCKET>(fd);
#else
    int s = fd;
#endif
    const char* p = static_cast<const char*>(data);
    std::size_t off = 0;
    int stalls = 0;
    while (off < len) {
        ssize_t n = net::sys::send_bytes(s, p + off, len - off);
        if (n > 0) { off += static_cast<std::size_t>(n); stalls = 0; continue; }
        const int e = stream_sock_errno();
#ifndef _WIN32
        if (n < 0 && e == EINTR) continue;
#endif
        if (n < 0 && stream_would_block(e)) {
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            timeval tv{1, 0};  // 1s writability wait
            const int r = ::select(static_cast<int>(s) + 1, nullptr, &wf, nullptr, &tv);
            if (r <= 0 && ++stalls > 30) return false;  // ~30s wedged → give up
            continue;
        }
        return false;  // peer reset / hard error
    }
    return true;
}

// Drive a chunked, incrementally-flushed streaming response over a cleartext
// (non-TLS) HTTP/1.1 connection. Sends the status line + headers (with the
// handler-set Transfer-Encoding: chunked and NO Content-Length), then invokes
// the producer, framing each sink() call as one chunk and flushing it to the
// wire immediately. Returns false if the client disconnected mid-stream (caller
// closes and does not keep-alive). Synchronous by construction — see
// stream_send_all. TigerStyle: bounded, never emits a premature 0-length chunk.
bool stream_chunked_h1(int fd, CoroHttpResponse& response, bool keep_alive) {
    assert(response.stream_producer != nullptr);
    assert(response.status >= 100);

    // 1) Status line + headers. Transfer-Encoding: chunked is already present
    //    (Response::stream set it); Content-Length must NOT appear with chunked.
    std::string head;
    head.reserve(256);
    head += "HTTP/1.1 ";
    append_uint(head, response.status);
    head += ' ';
    head += response.status_message;
    head += "\r\n";
    bool saw_te = false;
    for (const auto& [name, value] : response.headers) {
        if (ieq_ascii(name, "content-length")) continue;  // invalid with chunked
        if (ieq_ascii(name, "transfer-encoding")) saw_te = true;
        head += name;
        head += ": ";
        head += value;
        head += "\r\n";
    }
    if (!saw_te) head += "Transfer-Encoding: chunked\r\n";  // defensive
    if (!keep_alive) head += "Connection: close\r\n";
    head += "\r\n";
    if (!stream_send_all(fd, head.data(), head.size())) return false;

    // 2) Drive the producer. Each non-empty sink() write becomes one chunk frame
    //    ({hexlen}\r\n{bytes}\r\n) flushed immediately. `alive` latches false on
    //    the first failed write so the rest of the producer's writes become
    //    no-ops (we cannot cancel a synchronous generate(), but we stop touching
    //    a dead socket) — bounded, no UB, no reactor hang.
    bool alive = true;
    char sizebuf[24];
    CoroHttpResponse::StreamSink sink =
        [fd, &alive, &sizebuf](std::string_view s) {
            if (!alive || s.empty()) return;  // never emit a 0-length chunk
            const int m = std::snprintf(sizebuf, sizeof(sizebuf), "%zx\r\n", s.size());
            assert(m > 0 && static_cast<std::size_t>(m) < sizeof(sizebuf));
            if (!stream_send_all(fd, sizebuf, static_cast<std::size_t>(m))) { alive = false; return; }
            if (!stream_send_all(fd, s.data(), s.size()))                    { alive = false; return; }
            if (!stream_send_all(fd, "\r\n", 2))                            { alive = false; return; }
        };
    response.stream_producer(sink);

    // 3) Terminating 0-length chunk (only if the peer is still there).
    if (!alive) return false;
    return stream_send_all(fd, "0\r\n\r\n", 5);
}

// --- Fixed-length (identity) streaming ------------------------------------
// Content-Length: N and NO chunk framing, so 206 Partial Content works (a Range
// reply REQUIRES Content-Length + Content-Range, neither of which can coexist
// with Transfer-Encoding: chunked). Reached only when the handler called
// Response::send_fixed; every other response takes its pre-existing path.
enum class FixedStreamResult : uint8_t {
    kComplete,       // exactly `declared` bytes written; connection reusable
    kPeerGone,       // client vanished mid-body; close
    kLengthMismatch  // producer under/over-produced; MUST close (frame is bad)
};

// Emit status line + headers for an identity fixed-length body. Drops any
// Transfer-Encoding (illegal here) and any caller Content-Length, then writes
// the single authoritative `Content-Length: declared`. Bounded: one pass over a
// fixed-capacity header array.
void build_fixed_head(std::string& head, const CoroHttpResponse& response,
                      uint64_t declared, bool keep_alive) {
    assert(response.status >= 100);
    assert(head.empty());
    head.reserve(256);
    head += "HTTP/1.1 ";
    append_uint(head, response.status);
    head += ' ';
    head += response.status_message;
    head += "\r\n";
    for (const auto& [name, value] : response.headers) {
        // Both are re-derived below; a duplicate or a stale value would
        // mis-frame the body.
        if (ieq_ascii(name, "content-length")) continue;
        if (ieq_ascii(name, "transfer-encoding")) continue;
        head += name;
        head += ": ";
        head += value;
        head += "\r\n";
    }
    head += "Content-Length: ";
    append_uint(head, declared);  // uint64_t: no narrowing on any target
    head += "\r\n";
    if (!keep_alive) head += "Connection: close\r\n";
    head += "\r\n";
    assert(head.size() >= 20);
}

// Drive a fixed-length streaming response over a cleartext HTTP/1.1 connection.
//
// The declared-length guarantee, which is what keeps the connection reusable:
//   * the sink REFUSES any write that would push the running total past
//     `declared` — the server never emits more bytes than it announced, so it
//     can never bleed into the next response on this connection;
//   * the running total is compared to `declared` after the producer returns,
//     and any inequality is reported as kLengthMismatch so the caller closes
//     the connection instead of leaving a short body under a declared length.
// Zero-copy: each sink() write goes straight from the producer's memory to the
// socket. Synchronous by construction (see stream_send_all) — the same contract
// a buffered handler body already runs under, and bounded by `declared`.
FixedStreamResult stream_fixed_h1(int fd, CoroHttpResponse& response, bool keep_alive) {
    assert(response.stream_producer != nullptr);
    assert(response.fixed_stream_length >= 0);

    const uint64_t declared = static_cast<uint64_t>(response.fixed_stream_length);

    std::string head;
    build_fixed_head(head, response, declared, keep_alive);
    if (!stream_send_all(fd, head.data(), head.size())) return FixedStreamResult::kPeerGone;

    uint64_t written   = 0;
    bool     peer_gone = false;
    bool     overrun   = false;
    CoroHttpResponse::StreamSink sink =
        [fd, declared, &written, &peer_gone, &overrun](std::string_view s) {
            if (s.empty() || peer_gone || overrun) return;
            if (s.size() > declared - written) {
                overrun = true;  // refuse: never write past what we announced
                return;
            }
            if (!stream_send_all(fd, s.data(), s.size())) { peer_gone = true; return; }
            written += s.size();
        };
    response.stream_producer(sink);
    response.stream_producer = nullptr;

    assert(written <= declared);  // the sink's refusal makes this total
    if (overrun || written != declared) {
        std::fprintf(stderr,
                     "[boltapi] send_fixed: declared %llu bytes, producer emitted %llu%s "
                     "-- closing connection to avoid a mis-framed response\n",
                     static_cast<unsigned long long>(declared),
                     static_cast<unsigned long long>(written),
                     overrun ? " (overrun refused)" : "");
        return FixedStreamResult::kLengthMismatch;
    }
    return peer_gone ? FixedStreamResult::kPeerGone : FixedStreamResult::kComplete;
}

// Convert a fixed-length streaming response into a buffered one for transports
// that cannot do the per-chunk synchronous socket write (TLS H1, HTTP/2,
// HTTP/3). Reconciles Content-Length with what the producer ACTUALLY emitted so
// the frame is always self-consistent, and reports whether that matched the
// declaration — a mismatch still closes the connection (the frame is fine, but
// the response is wrong and the caller must find out).
bool materialize_fixed(CoroHttpResponse& response) {
    assert(response.fixed_stream_length >= 0);
    assert(response.stream_producer != nullptr);

    const uint64_t declared = static_cast<uint64_t>(response.fixed_stream_length);
    std::string acc;
    acc.reserve(static_cast<std::size_t>(declared));
    response.stream_producer(
        [&acc](std::string_view s) { acc.append(s.data(), s.size()); });
    const bool matched = (acc.size() == declared);

    response.body                = std::move(acc);
    response.stream_producer     = nullptr;
    response.fixed_stream_length = CoroHttpResponse::kNoFixedLength;
    response.headers.remove("Transfer-Encoding");
    char buf[24];
    const int m = std::snprintf(buf, sizeof(buf), "%zu", response.body.size());
    assert(m > 0 && static_cast<std::size_t>(m) < sizeof(buf));
    response.headers.set("Content-Length",
                         std::string_view(buf, static_cast<std::size_t>(m)));
    if (!matched) {
        std::fprintf(stderr,
                     "[boltapi] send_fixed: declared %llu bytes, producer emitted %zu "
                     "-- Content-Length corrected, closing connection\n",
                     static_cast<unsigned long long>(declared), response.body.size());
    }
    assert(response.stream_producer == nullptr);
    return matched;
}

// Run a streaming producer's writes into `response.body` as a flat concatenation
// and clear the producer, converting a streaming response into an equivalent
// BUFFERED one. Used for transports that cannot do a synchronous per-chunk
// socket write on this path (TLS HTTP/1.1 and HTTP/2): the bytes are identical,
// only the incremental flush is lost. For HTTP/2 the hop-by-hop Transfer-Encoding
// header is stripped (H2 frames its own body via DATA frames).
void materialize_stream(CoroHttpResponse& response, bool drop_transfer_encoding) {
    if (!response.stream_producer) return;
    std::string acc;
    response.stream_producer(
        [&acc](std::string_view s) { acc.append(s.data(), s.size()); });
    response.body = std::move(acc);
    response.stream_producer = nullptr;
    if (drop_transfer_encoding) response.headers.remove("Transfer-Encoding");
}

// =====================================================================
// Off-the-I/O-thread streaming (native-reactor fix, STATION-114 follow-up).
//
// A Response::stream producer is a SYNCHRONOUS callable that may loop for the
// whole life of the connection (e.g. an open SSE stream). Driving it inline on
// the connection's single I/O thread (the old stream_chunked_h1 below) wedges
// that thread for the stream's lifetime, starving every other connection. The
// fix: run the producer on a worker-pool BLOCKING thread and hand each framed
// chunk to the I/O thread through a bounded, mutex-guarded buffer, waking the
// I/O coroutine via the reactor's cross-thread post (post_to_io_thread). The
// I/O thread performs the actual socket writes (co_await async_write) and stays
// free to service all other connections between them. Backpressure caps the
// staged bytes so a fast producer + slow client cannot grow memory unbounded.
//
// BUFFERED (non-streaming) responses NEVER reach this code — they take the
// unchanged `if (!streamed)` path in handle_http1_connection, byte-for-byte as
// before. This machinery is entered only when response.stream_producer is set.
// =====================================================================

// Fully write `len` bytes to `fd` via the reactor, yielding the I/O thread
// between partial writes. Returns false if the peer is gone / a hard error.
core::coro_task<bool> stream_co_write_all(net::IODispatcher& io, int fd,
                                          const char* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = co_await io.async_write(fd, data + off, len - off);
        if (n <= 0) co_return false;
        off += static_cast<std::size_t>(n);
    }
    co_return true;
}

// Bounded producer -> I/O-thread handoff. shared_ptr-owned so an orphaned
// producer (client vanished mid-stream, a non-terminating SSE loop) can safely
// outlive the connection coroutine frame without UAF; it drops its ref when it
// finally returns and the handoff is freed then.
struct H1StreamHandoff {
    std::mutex               mtx;
    std::condition_variable  producer_cv;   // producer parks here under backpressure
    std::string              pending;       // chunk-framed bytes awaiting socket write
    bool                     producer_done = false;  // producer returned (no more bytes)
    bool                     cancelled     = false;  // client gone -> stop buffering
    bool                     io_waiting    = false;  // I/O coroutine parked at DataReady
    std::coroutine_handle<>  io_handle{};            // resume target (valid iff io_waiting)
    net::IODispatcher*       io = nullptr;
    std::size_t              io_thread_index = 0;
    // Backpressure high-water: the producer parks once this many unflushed bytes
    // are staged, bounding memory when a fast producer meets a slow client.
    static constexpr std::size_t kHighWaterBytes = 1u << 20;  // 1 MiB
};

// Parks the I/O coroutine until the producer stages bytes OR finishes. Single
// consumer (the I/O coroutine); the handle is captured+cleared under the same
// lock by the one producer wake that fires, so there is exactly one resume per
// park (no lost/double wakeup). Resumes immediately (no park) if bytes are
// already staged or the producer is done — closing the check-then-park race.
struct H1StreamDataReady {
    H1StreamHandoff* h;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(std::coroutine_handle<> co) noexcept {
        std::unique_lock<std::mutex> lk(h->mtx);
        if (!h->pending.empty() || h->producer_done) {
            return false;  // data/done already available -> resume now
        }
        h->io_handle  = co;
        h->io_waiting = true;
        return true;       // park; a producer wake posts us back to the I/O thread
    }
    void await_resume() const noexcept {}
};

// Drive a chunked streaming response with the producer OFFLOADED to the worker
// pool. Returns true if the terminating chunk was written (peer still there),
// false if the client vanished mid-stream. `io_thread_index` is the thread this
// connection is resumed on (0 — the only correct target under num_io_threads==1
// or a shared-engine/IOCP backend; the caller gates on that).
core::coro_task<bool> stream_chunked_h1_offloaded(
        net::IODispatcher& io, int fd, CoroHttpResponse& response,
        bool keep_alive, std::size_t io_thread_index) {
    assert(response.stream_producer != nullptr);
    assert(response.status >= 100);
    assert(io.worker_pool() != nullptr && "streaming needs the worker pool");

    // 1) Status line + headers — byte-identical to the sync path.
    std::string head;
    head.reserve(256);
    head += "HTTP/1.1 ";
    append_uint(head, response.status);
    head += ' ';
    head += response.status_message;
    head += "\r\n";
    bool saw_te = false;
    for (const auto& [name, value] : response.headers) {
        if (ieq_ascii(name, "content-length")) continue;   // invalid with chunked
        if (ieq_ascii(name, "transfer-encoding")) saw_te = true;
        head += name; head += ": "; head += value; head += "\r\n";
    }
    if (!saw_te) head += "Transfer-Encoding: chunked\r\n";  // defensive
    if (!keep_alive) head += "Connection: close\r\n";
    head += "\r\n";
    if (!(co_await stream_co_write_all(io, fd, head.data(), head.size()))) {
        co_return false;  // client already gone; producer never starts
    }

    // 2) Launch the producer on a worker-pool BLOCKING thread. It frames each
    //    sink() write into the shared handoff and wakes this coroutine; it never
    //    touches the socket/fd, so closing the fd at teardown is always safe. The
    //    future is intentionally discarded (fire-and-forget): the producer owns a
    //    shared_ptr ref, so we never join it on the I/O thread.
    auto h = std::make_shared<H1StreamHandoff>();
    h->io = &io;
    h->io_thread_index = io_thread_index;
    auto producer = std::move(response.stream_producer);
    response.stream_producer = nullptr;

    (void)io.worker_pool()->submit_blocking(
        [h, producer = std::move(producer)]() {
            H1StreamHandoff* hp = h.get();
            CoroHttpResponse::StreamSink sink = [hp](std::string_view s) {
                if (s.empty()) return;  // a 0-length chunk would end the stream early
                std::coroutine_handle<> wake{};
                {
                    std::unique_lock<std::mutex> lk(hp->mtx);
                    hp->producer_cv.wait(lk, [hp] {
                        return hp->pending.size() < H1StreamHandoff::kHighWaterBytes
                               || hp->cancelled;
                    });
                    if (hp->cancelled) return;  // client gone -> swallow the rest
                    char sizebuf[24];
                    const int m = std::snprintf(sizebuf, sizeof(sizebuf), "%zx\r\n",
                                                s.size());
                    assert(m > 0 && static_cast<std::size_t>(m) < sizeof(sizebuf));
                    hp->pending.append(sizebuf, static_cast<std::size_t>(m));
                    hp->pending.append(s.data(), s.size());
                    hp->pending.append("\r\n", 2);
                    if (hp->io_waiting) {
                        wake = hp->io_handle;
                        hp->io_waiting = false;
                        hp->io_handle = {};
                    }
                }
                if (wake) hp->io->post_to_io_thread(hp->io_thread_index, wake);
            };
            producer(sink);
            // Producer finished: flag done and wake the I/O coroutine once more.
            std::coroutine_handle<> wake{};
            {
                std::unique_lock<std::mutex> lk(hp->mtx);
                hp->producer_done = true;
                if (hp->io_waiting) {
                    wake = hp->io_handle;
                    hp->io_waiting = false;
                    hp->io_handle = {};
                }
            }
            if (wake) hp->io->post_to_io_thread(hp->io_thread_index, wake);
        });

    // 3) Pump: park until bytes/done, drain them to the socket, repeat. The I/O
    //    thread is FREE between writes (each is a co_await). TigerStyle: every
    //    iteration makes progress (drains >=1 staged byte or observes done).
    bool alive = true;
    std::string to_write;
    for (;;) {
        co_await H1StreamDataReady{h.get()};

        bool done = false;
        {
            std::unique_lock<std::mutex> lk(h->mtx);
            to_write.clear();
            to_write.swap(h->pending);
            done = h->producer_done;
        }
        h->producer_cv.notify_one();  // freed handoff space -> unblock backpressure

        if (!to_write.empty()) {
            if (!(co_await stream_co_write_all(io, fd, to_write.data(),
                                               to_write.size()))) {
                alive = false;  // client vanished mid-stream
            }
        }
        if (!alive) break;
        if (done) {
            std::unique_lock<std::mutex> lk(h->mtx);
            if (h->pending.empty()) break;   // producer done AND fully drained
        }
    }

    // 4) Detach the producer: stop buffering + stop parking. It owns its own
    //    shared_ptr ref, so it may outlive this frame — NO join on the I/O thread,
    //    hence no teardown stall even for a non-terminating producer.
    {
        std::unique_lock<std::mutex> lk(h->mtx);
        h->cancelled  = true;
        h->io_waiting = false;
        h->io_handle  = {};
    }
    h->producer_cv.notify_all();

    // 5) Terminating 0-length chunk when the peer is still connected.
    if (alive) {
        alive = co_await stream_co_write_all(io, fd, "0\r\n\r\n", 5);
    }
    co_return alive;
}

}  // namespace

// =============================================================================
// Static Member Initialization
// =============================================================================

std::unordered_map<std::string, WebSocketHandler> CoroUnifiedServer::s_websocket_handlers_;
std::unordered_map<std::string, CoroSSEHandler> CoroUnifiedServer::s_sse_handlers_;
Http1Connection::UltraFastCallback CoroUnifiedServer::s_ultra_fast_callback_ = nullptr;
CoroUnifiedServer* CoroUnifiedServer::s_instance_ = nullptr;

// ---------------------------------------------------------------------------
// conn_read / conn_write — route connection app I/O through the TLS socket when
// the connection is encrypted (tls != nullptr), else the raw fd. This is what
// makes HTTP/1.1 + HTTP/2 application data go out as TLS records on an HTTPS
// connection: previously only the handshake went through TLS and app data was
// written raw to the fd (plaintext), which a real TLS client rejects as a
// "bad record type". noexcept-free path; bounded by the caller's loops.
// ---------------------------------------------------------------------------
namespace {
core::coro_task<ssize_t> conn_write(net::IODispatcher& io, int fd,
                                    net::CoroTlsSocket* tls,
                                    const void* data, std::size_t len) {
    if (tls != nullptr) co_return co_await tls->write(data, len);
    co_return co_await io.async_write(fd, data, len);
}
core::coro_task<ssize_t> conn_read(net::IODispatcher& io, int fd,
                                   net::CoroTlsSocket* tls,
                                   void* data, std::size_t len) {
    if (tls != nullptr) co_return co_await tls->read(data, len);
    co_return co_await io.async_read(fd, data, len);
}

// Fully write `len` bytes, looping over partial writes and yielding the I/O
// thread between them. Used by the separate-body-write path (send_borrowed /
// send_owned), where headers and body are two writes instead of one
// concatenation — so a partial write must not silently truncate the body.
// Bounded: every iteration either advances `off` or returns.
core::coro_task<bool> conn_write_all(net::IODispatcher& io, int fd,
                                     net::CoroTlsSocket* tls,
                                     const char* data, std::size_t len) {
    assert(data != nullptr || len == 0);
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = co_await conn_write(io, fd, tls, data + off, len - off);
        if (n <= 0) co_return false;
        off += static_cast<std::size_t>(n);
    }
    assert(off == len);
    co_return true;
}
}  // namespace

// =============================================================================
// Constructor / Destructor
// =============================================================================

CoroUnifiedServer::CoroUnifiedServer(const CoroUnifiedServerConfig& config)
    : config_(config) {

    // Auto-detect number of workers
    if (config_.num_workers == 0) {
        config_.num_workers = std::thread::hardware_concurrency();
        if (config_.num_workers == 0) {
            config_.num_workers = 4;
        }
    }
}

CoroUnifiedServer::~CoroUnifiedServer() {
    stop();
}

// =============================================================================
// Handler Configuration
// =============================================================================

void CoroUnifiedServer::set_handler(CoroHttpHandler handler) {
    handler_ = std::move(handler);
}

void CoroUnifiedServer::add_websocket_handler(const std::string& path, WebSocketHandler handler) {
    s_websocket_handlers_[path] = std::move(handler);
    std::cout << "[CoroUnifiedServer] Registered WebSocket handler: " << path << std::endl;
}

WebSocketHandler* CoroUnifiedServer::get_websocket_handler(const std::string& path) {
    auto it = s_websocket_handlers_.find(path);
    if (it != s_websocket_handlers_.end()) {
        return &it->second;
    }
    return nullptr;
}

void CoroUnifiedServer::add_sse_handler(const std::string& path, CoroSSEHandler handler) {
    s_sse_handlers_[path] = std::move(handler);
    std::cout << "[CoroUnifiedServer] Registered SSE handler: " << path << std::endl;
}

CoroSSEHandler* CoroUnifiedServer::get_sse_handler(const std::string& path) {
    auto it = s_sse_handlers_.find(path);
    if (it != s_sse_handlers_.end()) {
        return &it->second;
    }
    return nullptr;
}

// =============================================================================
// Start / Stop
// =============================================================================

int CoroUnifiedServer::start() {
    if (start_background() != 0) {
        return -1;
    }

    // Block until stop requested or shutdown complete
    while (!stop_requested_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // If draining, wait for graceful shutdown to complete
    if (is_draining()) {
        std::unique_lock<std::mutex> lock(shutdown_mutex_);
        auto timeout = std::chrono::milliseconds(config_.shutdown_timeout_ms);
        shutdown_cv_.wait_for(lock, timeout, [this]() {
            return shutdown_state_.load(std::memory_order_acquire) == CoroShutdownState::STOPPED;
        });
    }

    return 0;
}

int CoroUnifiedServer::start_background() {
    CoroShutdownState expected = CoroShutdownState::STOPPED;
    if (!shutdown_state_.compare_exchange_strong(expected, CoroShutdownState::RUNNING)) {
        error_message_ = "Server already running or draining";
        return -1;
    }

    stop_requested_.store(false, std::memory_order_relaxed);

    // Set global instance for signal handlers
    s_instance_ = this;

    // Install signal handlers if enabled
    if (config_.enable_signal_handlers) {
        install_signal_handlers();
    }

    std::cout << "CoroUnifiedServer starting..." << std::endl;
    std::cout << "  I/O threads: " << config_.num_io_threads << std::endl;
    std::cout << "  Worker threads: " << config_.num_workers << std::endl;

    // Create worker thread pool
    core::WorkerPoolConfig worker_config;
    worker_config.num_workers = config_.num_workers;
    // NATIVE-REACTOR FIX: a cleartext streaming response (Response::stream) runs
    // its SYNCHRONOUS producer on a BLOCKING worker thread for the stream's
    // lifetime (off the single I/O thread). Size the blocking pool for the max
    // concurrent streams we intend to serve — the WorkerPoolConfig default of 2
    // would leave a 3rd concurrent stream's producer stuck in the queue. Buffered
    // responses never touch this pool; idle blocking threads park cheaply.
    worker_config.blocking_workers =
        std::max<std::size_t>(worker_config.blocking_workers,
                              config_.num_streaming_workers);
    worker_pool_ = std::make_unique<core::WorkerThreadPool>(worker_config);
    worker_pool_->start();

    // Create I/O dispatcher
    net::IODispatcherConfig io_config;
    io_config.num_io_threads = config_.num_io_threads;
    io_config.worker_pool = worker_pool_.get();
    io_dispatcher_ = std::make_unique<net::IODispatcher>(io_config);
    io_dispatcher_->start();

    // Initialize TLS context if TLS enabled
    if (config_.enable_tls) {
        net::TlsContextConfig tls_config;
        tls_config.alpn_protocols = config_.alpn_protocols;

        // Use configured certificate files if provided, otherwise generate self-signed
        if (!config_.cert_file.empty() && !config_.key_file.empty()) {
            // Use external certificate files
            tls_config.cert_file = config_.cert_file;
            tls_config.key_file = config_.key_file;
            std::cout << "  TLS using certificate: " << config_.cert_file << std::endl;
        } else if (!config_.cert_data.empty() && !config_.key_data.empty()) {
            // Use in-memory certificate data
            tls_config.cert_data = config_.cert_data;
            tls_config.key_data = config_.key_data;
            std::cout << "  TLS using in-memory certificate" << std::endl;
        } else {
            // Generate self-signed certificate as fallback
            net::CertGeneratorConfig cert_config;
            cert_config.common_name = "localhost";
            cert_config.organization = "Bolt API";
            cert_config.validity_days = 365;

            auto generated = net::TlsCertGenerator::generate(cert_config);
            if (!generated.success) {
                error_message_ = "Failed to generate self-signed certificate: " + generated.error;
                std::cerr << error_message_ << std::endl;
                worker_pool_->stop();
                io_dispatcher_->stop();
                shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
                s_instance_ = nullptr;
                return -1;
            }

            tls_config.cert_data = generated.cert_pem;
            tls_config.key_data = generated.key_pem;
            std::cout << "  TLS using self-signed certificate" << std::endl;
        }

        tls_context_ = net::TlsContext::create_server(tls_config);
        if (!tls_context_ || !tls_context_->is_valid()) {
            error_message_ = "Failed to create TLS context: " +
                (tls_context_ ? tls_context_->get_error() : "null context");
            std::cerr << error_message_ << std::endl;
            worker_pool_->stop();
            io_dispatcher_->stop();
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
            s_instance_ = nullptr;
            return -1;
        }

        std::cout << "  TLS enabled, ALPN: "
                  << config_.alpn_protocols.size() << " protocols" << std::endl;

        // Create TLS listener
        net::CoroTcpListenerConfig tls_listener_config;
        tls_listener_config.host = config_.host;
        tls_listener_config.port = config_.tls_port;
        tls_listener_config.backlog = config_.backlog;
        tls_listener_config.num_io_threads = config_.num_io_threads;
        tls_listener_config.num_workers = config_.num_workers;

        // TLS connection handler captures 'this'
        // Note: We pass the shared IODispatcher to avoid creating duplicates
        auto tls_handler = [this](net::IODispatcher& io, int fd) -> core::coro_task<void> {
            co_await handle_tls_connection(io, fd);
        };

        // Pass shared IODispatcher and WorkerThreadPool to avoid duplicates
        tls_listener_ = std::make_unique<net::CoroTcpListener>(
            tls_listener_config, std::move(tls_handler),
            io_dispatcher_.get(), worker_pool_.get());
        if (tls_listener_->start_background() != 0) {
            error_message_ = "Failed to start TLS listener on port " +
                std::to_string(config_.tls_port) + " (errno: " + std::to_string(errno) + ")";
            std::cerr << error_message_ << std::endl;
            worker_pool_->stop();
            io_dispatcher_->stop();
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
            s_instance_ = nullptr;
            return -1;
        }

        std::cout << "  TLS listener: " << config_.host << ":" << config_.tls_port << std::endl;
    }

    // Create cleartext HTTP/1.1 listener
    if (config_.enable_http1_cleartext) {
        net::CoroTcpListenerConfig http1_listener_config;
        http1_listener_config.host = config_.host;
        http1_listener_config.port = config_.http1_port;
        http1_listener_config.backlog = config_.backlog;
        http1_listener_config.num_io_threads = config_.num_io_threads;
        http1_listener_config.num_workers = config_.num_workers;

        // Cleartext HTTP/1.1 handler
        // Note: We pass the shared IODispatcher to avoid creating duplicates
        auto cleartext_handler = [this](net::IODispatcher& io, int fd) -> core::coro_task<void> {
            co_await handle_cleartext_connection(io, fd);
        };

        // Pass shared IODispatcher and WorkerThreadPool to avoid duplicates
        cleartext_listener_ = std::make_unique<net::CoroTcpListener>(
            http1_listener_config, std::move(cleartext_handler),
            io_dispatcher_.get(), worker_pool_.get());
        if (cleartext_listener_->start_background() != 0) {
            error_message_ = "Failed to start cleartext listener on port " +
                std::to_string(config_.http1_port) + " (errno: " + std::to_string(errno) + ")";
            std::cerr << error_message_ << std::endl;
            if (tls_listener_) tls_listener_->stop();
            worker_pool_->stop();
            io_dispatcher_->stop();
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
            s_instance_ = nullptr;
            return -1;
        }

        std::cout << "  HTTP/1.1 cleartext: " << config_.host << ":" << config_.http1_port << std::endl;
    }

    std::cout << "CoroUnifiedServer started" << std::endl;
    return 0;
}

void CoroUnifiedServer::stop() {
    CoroShutdownState expected = CoroShutdownState::RUNNING;
    if (!shutdown_state_.compare_exchange_strong(expected, CoroShutdownState::STOPPED)) {
        // Already stopped or draining
        if (expected == CoroShutdownState::DRAINING) {
            // Force stop from draining state
            shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);
        } else {
            return;  // Already stopped
        }
    }

    stop_requested_.store(true, std::memory_order_release);

    // Stop listeners
    if (tls_listener_) {
        tls_listener_->stop();
    }
    if (cleartext_listener_) {
        cleartext_listener_->stop();
    }

    // Stop I/O dispatcher
    if (io_dispatcher_) {
        io_dispatcher_->stop();
    }

    // Stop worker pool
    if (worker_pool_) {
        worker_pool_->stop();
    }

    // Clear global instance
    if (s_instance_ == this) {
        s_instance_ = nullptr;
    }

    std::cout << "CoroUnifiedServer stopped" << std::endl;
}

// =============================================================================
// Graceful Shutdown
// =============================================================================

bool CoroUnifiedServer::shutdown_gracefully() {
    CoroShutdownState expected = CoroShutdownState::RUNNING;
    if (!shutdown_state_.compare_exchange_strong(expected, CoroShutdownState::DRAINING)) {
        // Not running - either already draining or stopped
        return expected == CoroShutdownState::STOPPED;
    }

    std::cout << "[CoroUnifiedServer] Initiating graceful shutdown..." << std::endl;
    stop_requested_.store(true, std::memory_order_release);

    // Stop accepting new connections
    if (tls_listener_) {
        tls_listener_->stop();
    }
    if (cleartext_listener_) {
        cleartext_listener_->stop();
    }

    // Wait for active connections to drain
    std::unique_lock<std::mutex> lock(shutdown_mutex_);
    auto timeout = std::chrono::milliseconds(config_.shutdown_timeout_ms);
    auto deadline = std::chrono::steady_clock::now() + timeout;

    bool drained = shutdown_cv_.wait_until(lock, deadline, [this]() {
        return connections_active_.load(std::memory_order_relaxed) == 0;
    });

    if (drained) {
        std::cout << "[CoroUnifiedServer] All connections drained, shutdown complete" << std::endl;
    } else {
        std::cout << "[CoroUnifiedServer] Shutdown timeout, forcing close of "
                  << connections_active_.load(std::memory_order_relaxed)
                  << " connections" << std::endl;
    }

    // Complete shutdown
    shutdown_state_.store(CoroShutdownState::STOPPED, std::memory_order_release);

    // Stop I/O dispatcher and worker pool
    if (io_dispatcher_) {
        io_dispatcher_->stop();
    }
    if (worker_pool_) {
        worker_pool_->stop();
    }

    // Clear global instance
    if (s_instance_ == this) {
        s_instance_ = nullptr;
    }

    return drained;
}

// =============================================================================
// Signal Handlers
// =============================================================================

void CoroUnifiedServer::install_signal_handlers() {
    s_instance_ = this;

#ifdef _WIN32
    // Windows has no sigaction; std::signal supports SIGINT/SIGTERM.
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
#endif

    std::cout << "[CoroUnifiedServer] Signal handlers installed (SIGTERM, SIGINT)" << std::endl;
}

void CoroUnifiedServer::signal_handler(int signum) {
    const char* sig_name = (signum == SIGTERM) ? "SIGTERM" : "SIGINT";
    (void)sig_name;
    // Use a raw write for async-signal-safety (no printf/cout in signal handlers)
    const char msg[] = "[CoroUnifiedServer] Received signal, initiating graceful shutdown\n";
#ifdef _WIN32
    (void)_write(STDOUT_FILENO, msg, static_cast<unsigned>(sizeof(msg) - 1));
#else
    (void)::write(STDOUT_FILENO, msg, sizeof(msg) - 1);
#endif

    if (s_instance_) {
        // Initiate graceful shutdown from background thread to avoid
        // blocking in signal handler
        s_instance_->stop_requested_.store(true, std::memory_order_release);

        // Try to transition to draining state
        CoroShutdownState expected = CoroShutdownState::RUNNING;
        s_instance_->shutdown_state_.compare_exchange_strong(
            expected, CoroShutdownState::DRAINING, std::memory_order_release);
    }
}

// =============================================================================
// Ultra-Fast Callback
// =============================================================================

void CoroUnifiedServer::set_ultra_fast_callback(Http1Connection::UltraFastCallback callback) {
    s_ultra_fast_callback_ = callback;
    std::cout << "[CoroUnifiedServer] Ultra-fast callback set" << std::endl;
}

Http1Connection::UltraFastCallback CoroUnifiedServer::get_ultra_fast_callback() noexcept {
    return s_ultra_fast_callback_;
}

// =============================================================================
// TLS Connection Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_tls_connection(net::IODispatcher& io, int fd) {
    connections_accepted_.fetch_add(1, std::memory_order_relaxed);

    // Check if we're accepting new connections (graceful shutdown support)
    if (!track_connection_open()) {
        // Draining - reject new connection
        io.async_close(fd);
        co_return;
    }

    // Create coroutine TLS socket and perform handshake
    auto [tls_socket, handshake_result] = co_await net::accept_tls(
        io, fd, tls_context_);

    if (handshake_result != 0 || !tls_socket) {
        // Handshake failed
        io.async_close(fd);
        track_connection_close();
        co_return;
    }

    // Detect protocol via ALPN
    std::string alpn = tls_socket->get_alpn_protocol();

    if (alpn == "h2") {
        // HTTP/2
        requests_http2_.fetch_add(1, std::memory_order_relaxed);
        co_await handle_http2_connection(io, fd, tls_socket.get());
    } else {
        // Default to HTTP/1.1 (alpn == "http/1.1" or empty)
        requests_http1_.fetch_add(1, std::memory_order_relaxed);
        co_await handle_http1_connection(io, fd, tls_socket.get());
    }

    track_connection_close();
}

// =============================================================================
// Cleartext HTTP/1.1 Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_cleartext_connection(net::IODispatcher& io, int fd) {
    connections_accepted_.fetch_add(1, std::memory_order_relaxed);

    // Check if we're accepting new connections (graceful shutdown support)
    if (!track_connection_open()) {
        // Draining - reject new connection
        io.async_close(fd);
        co_return;
    }

    requests_http1_.fetch_add(1, std::memory_order_relaxed);

    // Set non-blocking
    net::sys::set_nonblocking(fd);

    co_await handle_http1_connection(io, fd, nullptr);

    track_connection_close();
}

// =============================================================================
// HTTP/1.1 Request Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_http1_connection(
    net::IODispatcher& io, int fd, net::CoroTlsSocket* tls) {

    // Two-phase buffer strategy:
    // Phase 1: 8KB stack buffer for headers (zero allocation fast path)
    // Phase 2: RequestBodyBuffer for large bodies (thread-local arena pool)
    static constexpr size_t STACK_BUF_SIZE = 8192;
    uint8_t stack_buf[STACK_BUF_SIZE];
    uint8_t* buf = stack_buf;
    size_t buf_cap = STACK_BUF_SIZE;
    size_t buf_len = 0;
    RequestBodyBuffer body_buf;   // RAII — auto-releases arena buffer on destruction
    bool body_detected = false;   // set when Content-Length found in headers

    HTTP1Parser parser;

    // Timeout tracking
    using clock = std::chrono::steady_clock;
    auto request_timeout = std::chrono::milliseconds(config_.request_timeout_ms);
    auto idle_timeout = std::chrono::milliseconds(config_.idle_timeout_ms);
    bool is_first_request = true;

    bool keep_alive = true;
    // Per-connection reusable response buffer — clear() retains capacity, so
    // response serialization performs NO heap allocation after the first request
    // (TigerStyle: no per-request alloc on the response path).
    std::string resp_buf;
    resp_buf.reserve(4096);
    while (keep_alive && !stop_requested_.load(std::memory_order_relaxed)) {
        // Track start time for timeout
        auto request_start = clock::now();

        // HTTP Pipelining: Try to parse from existing buffer first before reading
        HTTP1Request parsed_req;
        size_t consumed = 0;
        int parse_result = -1;  // Need more data by default

        // Try parsing if we have data in buffer (pipelining case)
        if (buf_len > 0) {
            parse_result = parser.parse(buf, buf_len, parsed_req, consumed);
        }

        // If we need more data, read from socket
        while (parse_result < 0 && !stop_requested_.load(std::memory_order_relaxed)) {
            // Buffer full — need to grow or reject
            if (buf_len >= buf_cap) {
                if (!body_detected) {
                    const char* r = "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
                    co_await conn_write(io, fd, tls,r, strlen(r));
                    io.async_close(fd);
                    co_return;
                }
                const char* r = "HTTP/1.1 413 Payload Too Large\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                co_await conn_write(io, fd, tls,r, strlen(r));
                io.async_close(fd);
                co_return;
            }

            // Header size limit (only before body detected)
            if (!body_detected && buf_len > config_.max_header_size) {
                const char* r = "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                co_await conn_write(io, fd, tls,r, strlen(r));
                io.async_close(fd);
                co_return;
            }

            // Read more data into current buffer. Cleartext takes the dispatcher
            // awaitable DIRECTLY (no conn_read coroutine frame — zero alloc on the
            // hot path); TLS keeps the framed helper.
            ssize_t n = tls ? co_await conn_read(io, fd, tls, buf + buf_len, buf_cap - buf_len)
                            : co_await io.async_read(fd, buf + buf_len, buf_cap - buf_len);
            if (n <= 0) {
                io.async_close(fd);
                co_return;
            }
            buf_len += n;

            // Try parsing again
            parse_result = parser.parse(buf, buf_len, parsed_req, consumed);

            if (parse_result < 0) {
                // Content-Length known but body incomplete → acquire arena buffer
                if (!body_detected && parsed_req.has_content_length) {
                    body_detected = true;
                    if (parsed_req.content_length > config_.max_body_size) {
                        const char* r = "HTTP/1.1 413 Payload Too Large\r\n"
                            "Content-Length: 0\r\nConnection: close\r\n\r\n";
                        co_await conn_write(io, fd, tls,r, strlen(r));
                        io.async_close(fd);
                        co_return;
                    }
                    // Need room for headers + body
                    size_t needed = config_.max_header_size + parsed_req.content_length;
                    if (needed > STACK_BUF_SIZE) {
                        body_buf.reserve(needed, config_.max_body_size + config_.max_header_size);
                        body_buf.adopt(stack_buf, buf_len);
                        buf = body_buf.writable_data();
                        buf_cap = body_buf.capacity();
                    }
                }

                // Chunked without Content-Length — not yet supported
                if (!body_detected && parsed_req.chunked && !parsed_req.has_content_length) {
                    const char* r = "HTTP/1.1 501 Not Implemented\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
                    co_await conn_write(io, fd, tls,r, strlen(r));
                    io.async_close(fd);
                    co_return;
                }

                // Timeout check
                auto elapsed = clock::now() - request_start;
                auto timeout = is_first_request ? request_timeout : idle_timeout;
                if (elapsed > timeout) {
                    const char* r = "HTTP/1.1 408 Request Timeout\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n";
                    co_await conn_write(io, fd, tls,r, strlen(r));
                    io.async_close(fd);
                    co_return;
                }
            }
        }

        if (parse_result > 0) {
            // Parse error - send 400 Bad Request
            const char* bad_request =
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            co_await conn_write(io, fd, tls,bad_request, strlen(bad_request));
            break;
        }

        // Check if we should exit after parsing (stop requested during read loop)
        if (stop_requested_.load(std::memory_order_relaxed)) {
            break;
        }

        // Request completed - no longer first request
        is_first_request = false;

        // Enforce the header-size limit on the COMPLETED parse as well, not just
        // mid-read. The in-loop check (above) only fires when more data is still
        // needed; a request whose oversized headers arrive in a single recv (and
        // fit under the stack buffer) parses on the first attempt and would
        // otherwise bypass the limit. The header block is everything consumed
        // minus the body bytes. Mirrors the post-parse 413 body check below.
        if (config_.max_header_size != 0) {
            const size_t header_bytes =
                consumed > parsed_req.body.size()
                    ? consumed - parsed_req.body.size()
                    : consumed;
            if (header_bytes > config_.max_header_size) {
                const char* too_large =
                    "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                co_await conn_write(io, fd, tls,too_large, strlen(too_large));
                break;
            }
        }

        // Parse successful - convert to CoroHttpRequest (ZERO-COPY).
        // All views below point into `buf` (the connection read buffer on this
        // coroutine frame, or the body arena). That buffer stays alive — the
        // frame is suspended — across the worker-thread handler co_await and is
        // only reset AFTER the response is written (end of this loop iteration),
        // so every view is valid for the whole request, including keep-alive.
        CoroHttpRequest req;
        req.method = std::string_view(parsed_req.method_str);
        req.path = std::string_view(parsed_req.path);
        // Carry the query string through explicitly — the H1 parser strips
        // '?...' from path before view capture, so Request::query() couldn't
        // recover it from path. parsed_req.query is set by parse_url_components.
        req.query = std::string_view(parsed_req.query);
        const size_t hdr_n = std::min(parsed_req.header_count,
                                      CoroHttpRequest::MAX_HEADERS);
        for (size_t i = 0; i < hdr_n; i++) {
            req.add_header(std::string_view(parsed_req.headers[i].name),
                           std::string_view(parsed_req.headers[i].value));
        }
        req.body = std::string_view(parsed_req.body);

        // Check body size limits
        {
            bool has_cl = false;
            std::string_view cl_val = req.find_header("Content-Length", &has_cl);
            if (has_cl) {
                size_t content_length = 0;
                for (char c : cl_val) {
                    if (c < '0' || c > '9') break;
                    content_length = content_length * 10 + static_cast<size_t>(c - '0');
                }
                if (content_length > config_.max_body_size) {
                    // Body too large - send 413 Payload Too Large
                    const char* too_large =
                        "HTTP/1.1 413 Payload Too Large\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    co_await conn_write(io, fd, tls,too_large, strlen(too_large));
                    break;
                }
            }
        }

        // Check if actual body exceeds limit
        if (req.body.size() > config_.max_body_size) {
            const char* too_large =
                "HTTP/1.1 413 Payload Too Large\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            co_await conn_write(io, fd, tls,too_large, strlen(too_large));
            break;
        }

        // Track request
        requests_total_.fetch_add(1, std::memory_order_relaxed);

        // Check for ultra-fast callback (bypasses all routing for maximum performance)
        auto ultra_fast_cb = get_ultra_fast_callback();
        if (ultra_fast_cb) {
            // Build zero-copy request view
            Http1RequestView view;
            view.method = std::string_view(parsed_req.method_str);
            
            // Parse path and query string
            std::string_view full_path(parsed_req.path);
            size_t query_pos = full_path.find('?');
            if (query_pos != std::string_view::npos) {
                view.path = full_path.substr(0, query_pos);
                view.query_string = full_path.substr(query_pos + 1);
            } else {
                view.path = full_path;
                view.query_string = {};
            }
            
            view.body = std::string_view(parsed_req.body);
            
            // Copy headers to view
            view.header_count = std::min(parsed_req.header_count, Http1RequestView::MAX_HEADERS);
            for (size_t i = 0; i < view.header_count; i++) {
                view.headers[i] = {
                    std::string_view(parsed_req.headers[i].name),
                    std::string_view(parsed_req.headers[i].value)
                };
            }
            
            // Prepare response buffer (reuse our existing buffer for output)
            static constexpr size_t RESPONSE_BUFFER_SIZE = 65536;
            uint8_t response_buffer[RESPONSE_BUFFER_SIZE];
            FastResponseWriter writer(response_buffer, RESPONSE_BUFFER_SIZE);
            
            // Call ultra-fast callback
            size_t response_size = ultra_fast_cb(view, writer);
            
            if (response_size > 0) {
                // Send the response
                co_await conn_write(io, fd, tls,response_buffer, response_size);
                
                // Check keep-alive and continue loop
                keep_alive = parsed_req.keep_alive;
                
                // Shift buffer (remove consumed data)
                if (consumed < buf_len) {
                    memmove(buf, buf + consumed, buf_len - consumed);
                    buf_len -= consumed;
                } else {
                    buf_len = 0;
                }

                // Release arena buffer if used, copy leftover back to stack
                if (body_buf.is_arena_backed()) {
                    if (buf_len > 0 && buf_len <= STACK_BUF_SIZE) {
                        std::memcpy(stack_buf, buf, buf_len);
                    } else if (buf_len > STACK_BUF_SIZE) {
                        buf_len = 0;
                    }
                    body_buf.reset();
                    buf = stack_buf;
                    buf_cap = STACK_BUF_SIZE;
                }
                body_detected = false;

                // Reclaim the per-request bolt::Arena (no-op when the arena flag
                // is OFF). Safe here: the response is fully written, req.body was
                // copied out, and any pipelined leftover is already in stack_buf
                // (copied above before body_buf.reset()), so no live view points
                // into the arena.
                thread_body_arena_reset();

                // Reset parser for next request
                parser.reset();
                continue;  // Skip normal handler processing
            }
            // If callback returns 0, fall through to normal routing
        }

        // Check for WebSocket upgrade request
        bool has_upgrade = false, has_ws_key = false;
        std::string_view upgrade_sv  = req.find_header("Upgrade", &has_upgrade);
        std::string_view ws_key_sv   = req.find_header("Sec-WebSocket-Key", &has_ws_key);
        std::string_view conn_sv     = req.find_header("Connection");
        std::string_view ws_ver_sv   = req.find_header("Sec-WebSocket-Version");
        std::string_view ws_proto_sv = req.find_header("Sec-WebSocket-Protocol");

        if (has_upgrade && has_ws_key) {
            std::string upgrade_val(upgrade_sv);
            std::string connection_val(conn_sv);
            std::string ws_version(ws_ver_sv);
            std::string ws_key(ws_key_sv);

            if (websocket::HandshakeUtils::validate_upgrade_request(
                    std::string(req.method), upgrade_val, connection_val, ws_version, ws_key)) {

                // Check if we have a handler for this path
                WebSocketHandler* ws_handler = get_websocket_handler(std::string(req.path));
                if (ws_handler) {
                    // Valid WebSocket upgrade - compute accept key and send 101
                    std::string accept_key = websocket::HandshakeUtils::compute_accept_key(ws_key);

                    // Subprotocol negotiation (RFC 6455 §4.2.2). Browsers
                    // (notably Chrome) refuse the upgrade when they sent a
                    // non-empty `Sec-WebSocket-Protocol` and the 101 response
                    // omits it — even though the RFC says omission means "no
                    // subprotocol selected". For known subprotocols (today:
                    // `mqtt`) we echo the selection; for anything else we
                    // pick the FIRST offered token to keep clients happy.
                    std::string selected_subprotocol =
                        websocket::HandshakeUtils::select_subprotocol(ws_proto_sv);

                    std::string ws_response =
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: " + accept_key + "\r\n";
                    if (!selected_subprotocol.empty()) {
                        ws_response += "Sec-WebSocket-Protocol: " + selected_subprotocol + "\r\n";
                    }
                    ws_response += "\r\n";

                    co_await conn_write(io, fd, tls,ws_response.data(), ws_response.size());

                    std::cout << "[CoroUnifiedServer] WebSocket upgrade for path: " << req.path << std::endl;

                    // Create WebSocket connection
                    static std::atomic<uint64_t> ws_connection_id{0};
                    WebSocketConnection ws_conn(++ws_connection_id);
                    ws_conn.set_socket_fd(fd);
                    ws_conn.set_path(std::string(req.path));

                    // Invoke user handler to set up callbacks
                    (*ws_handler)(ws_conn);

                    // Handle WebSocket frames in coroutine loop
                    co_await handle_websocket_connection(io, fd, ws_conn, tls);

                    // WebSocket connection closed
                    io.async_close(fd);
                    co_return;
                }
                // No handler - fall through to 404
            }
        }

        // Check for SSE request (Accept: text/event-stream).
        // find_header is already case-insensitive, so one lookup suffices.
        std::string_view accept_value = req.find_header("Accept");

        // Match SSE either by Accept header or by registered path (allows curl testing)
        CoroSSEHandler* sse_handler = get_sse_handler(std::string(req.path));
        if (sse_handler && (accept_value.empty() ||
            accept_value.find("text/event-stream") != std::string_view::npos)) {
            {
                // Send SSE headers (include CORS for cross-origin EventSource)
                const char* sse_headers =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: keep-alive\r\n"
                    "X-Accel-Buffering: no\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                    "\r\n";
                co_await conn_write(io, fd, tls,sse_headers, strlen(sse_headers));

                std::cout << "[CoroUnifiedServer] SSE stream for path: " << req.path << std::endl;

                // Call SSE handler (streams events until done or client disconnects)
                co_await (*sse_handler)(io, fd, req);

                // SSE stream ended
                io.async_close(fd);
                co_return;
            }
            // No handler - fall through to regular HTTP handler
        }

        // Call handler for regular HTTP request
        CoroHttpResponse response;
        if (handler_) {
            response = co_await handler_(req);
        } else {
            // Default response
            response.status = 200;
            response.status_message = "OK";
            response.headers.set("Content-Type", "text/plain");
            response.body = "Hello, World!";
        }

        // STATION-96: incremental streaming response. When the handler set a
        // stream producer (Response::stream) on a cleartext HTTP/1.1 connection,
        // drive it here: Transfer-Encoding: chunked headers, then each producer
        // write() flushed to the socket as its own chunk frame — true
        // token-by-token streaming. TLS falls back to a buffered chunked body
        // (a synchronous per-chunk TLS write isn't available on this path); the
        // frames are byte-identical, only the incremental flush is lost. The
        // buffered/chunked path below is UNCHANGED for the non-streaming case.
        // Latched by a fixed-length body whose produced size did not match its
        // declaration. The buffered path below re-reads keep_alive from the
        // request, so the decision has to survive in its own flag.
        bool force_close = false;
        bool streamed = false;
        if (response.is_fixed_stream()) {
            // Fixed-length (identity) streaming: Content-Length, no chunking —
            // the shape a 206 Range reply needs. Never emits more bytes than it
            // declared, and closes the connection rather than leave a short
            // body under a declared length (either would mis-frame whatever
            // response came next on this keep-alive connection).
            if (tls == nullptr) {
                keep_alive = parsed_req.keep_alive;
                const FixedStreamResult r = stream_fixed_h1(fd, response, keep_alive);
                if (r != FixedStreamResult::kComplete) keep_alive = false;
                streamed = true;
            } else {
                if (!materialize_fixed(response)) force_close = true;
                // -> normal buffered path below, Content-Length reconciled.
            }
        } else if (response.stream_producer) {
            if (tls == nullptr) {
                keep_alive = parsed_req.keep_alive;
                // NATIVE-REACTOR FIX: run the synchronous producer OFF the I/O
                // thread (worker pool) and post its framed chunks back for the
                // I/O thread to write, so a long-lived stream never monopolizes
                // the reactor. This is correct only when this connection can be
                // resumed on I/O thread 0: a single I/O thread (the only one), or
                // a shared-engine backend (IOCP) where any thread services any
                // fd. For a per-core backend (epoll/kqueue) with >1 I/O thread we
                // cannot know this connection's owning thread here, so fall back
                // to the inline synchronous drive (correct — it only blocks one of
                // several I/O threads). BUFFERED responses are untouched either way.
                const bool can_offload =
                    io.io_thread_count() == 1 || !io.per_thread_engines();
                bool ok;
                if (can_offload) {
                    ok = co_await stream_chunked_h1_offloaded(
                        io, fd, response, keep_alive, /*io_thread_index=*/0);
                } else {
                    ok = stream_chunked_h1(fd, response, keep_alive);
                }
                if (!ok) {
                    keep_alive = false;  // client gone mid-stream → close
                }
                streamed = true;
            } else {
                materialize_stream(response, /*drop_transfer_encoding=*/false);
                // -> normal buffered chunked path below (TE header retained).
            }
        }

        // Check if chunked transfer encoding is requested (no allocation).
        bool use_chunked = false;
        auto transfer_encoding_it = response.headers.find("Transfer-Encoding");
        if (!streamed && transfer_encoding_it != response.headers.end() &&
            contains_ci(transfer_encoding_it->value, "chunked")) {
            use_chunked = true;
        }
      if (!streamed) {

        // Build the HTTP/1.1 response into the per-connection reusable buffer.
        // clear() keeps capacity -> zero heap allocation after the first request;
        // to_chars / branchless compares replace the old to_string / per-header
        // std::string lowercasing that allocated on every response.
        std::string& resp_str = resp_buf;
        resp_str.clear();
        resp_str += "HTTP/1.1 ";
        append_uint(resp_str, response.status);
        resp_str += ' ';
        resp_str += response.status_message;
        resp_str += "\r\n";

        // The bytes that ARE the body: borrowed (zero-copy, caller-owned) when
        // the handler used send_borrowed, else the owned `body`. Identical to
        // `response.body` for every pre-existing caller.
        const std::string_view out_body = response.body_bytes();

        // Add Content-Length if not present and not chunked. Note the condition:
        // an EXPLICIT Content-Length is never overwritten and is emitted by the
        // header loop below — which is what lets a HEAD reply declare a length
        // with no body at all.
        if (!use_chunked && response.headers.find("Content-Length") == response.headers.end()) {
            resp_str += "Content-Length: ";
            append_uint(resp_str, out_body.size());
            resp_str += "\r\n";
        }

        // Add headers (skip zstd content-encoding as browsers don't support it)
        for (const auto& [name, value] : response.headers) {
            // Skip ANY content-encoding with zstd value (branchless ci key check).
            if (ieq_ascii(name, "content-encoding") && value == "zstd") {
                continue;  // Skip zstd header - browser will fail to decode
            }
            resp_str += name;
            resp_str += ": ";
            resp_str += value;
            resp_str += "\r\n";
        }

        // Check keep-alive. force_close is latched when a fixed-length body's
        // produced size disagreed with its declaration: the frame was corrected
        // but the response is wrong, so the connection does not get reused.
        keep_alive = parsed_req.keep_alive && !force_close;
        if (!keep_alive) {
            resp_str += "Connection: close\r\n";
        }

        resp_str += "\r\n";

        if (use_chunked) {
            // For chunked encoding, send headers first
            co_await conn_write(io, fd, tls,resp_str.data(), resp_str.size());

            // Send body as chunk(s) if there is content
            if (!out_body.empty()) {
                // Format: {size_hex}\r\n{data}\r\n
                char size_buf[32];
                int len = snprintf(size_buf, sizeof(size_buf), "%zx\r\n", out_body.size());
                std::string chunk;
                chunk.reserve(len + out_body.size() + 2);
                chunk.append(size_buf, len);
                chunk.append(out_body);
                chunk.append("\r\n");
                co_await conn_write(io, fd, tls,chunk.data(), chunk.size());
            }

            // Send final empty chunk: 0\r\n\r\n
            const char* final_chunk = "0\r\n\r\n";
            co_await conn_write(io, fd, tls,final_chunk, 5);
        } else if (response.body_separate_write) {
            // Zero/one-copy body (send_borrowed / send_owned): headers and body
            // are two fully-drained writes instead of one concatenation, which
            // is what removes the whole-body copy into resp_str. Both writes
            // loop over partial writes, so a large body cannot be truncated.
            bool wrote = co_await conn_write_all(io, fd, tls, resp_str.data(), resp_str.size());
            if (wrote && !out_body.empty()) {
                wrote = co_await conn_write_all(io, fd, tls, out_body.data(), out_body.size());
            }
            if (!wrote) keep_alive = false;  // peer gone mid-body -> close
        } else {
            // Non-chunked: send headers + body together (cleartext writes via the
            // dispatcher awaitable directly — no conn_write coroutine frame).
            resp_str += response.body;
            if (tls) {
                co_await conn_write(io, fd, tls, resp_str.data(), resp_str.size());
            } else {
                co_await io.async_write(fd, resp_str.data(), resp_str.size());
            }
        }
      }  // if (!streamed)

        // Pipelining timeout check: before processing next request from buffer,
        // verify we haven't exceeded idle timeout since start of this request
        if (buf_len > consumed) {
            auto elapsed = clock::now() - request_start;
            if (elapsed > idle_timeout) {
                const char* r = "HTTP/1.1 408 Request Timeout\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                co_await conn_write(io, fd, tls,r, strlen(r));
                break;
            }
        }

        // Shift buffer (remove consumed data)
        if (consumed < buf_len) {
            memmove(buf, buf + consumed, buf_len - consumed);
            buf_len -= consumed;
        } else {
            buf_len = 0;
        }

        // Release arena buffer if used, copy leftover back to stack
        if (body_buf.is_arena_backed()) {
            if (buf_len > 0 && buf_len <= STACK_BUF_SIZE) {
                std::memcpy(stack_buf, buf, buf_len);
            } else if (buf_len > STACK_BUF_SIZE) {
                buf_len = 0;
            }
            body_buf.reset();
            buf = stack_buf;
            buf_cap = STACK_BUF_SIZE;
        }
        body_detected = false;

        // Reclaim the per-request bolt::Arena (no-op when the arena flag is
        // OFF). Safe here: the response is fully written, req.body / response
        // already hold their own std::string copies, and any pipelined leftover
        // is already in stack_buf (copied above before body_buf.reset()), so no
        // live view points into the arena.
        thread_body_arena_reset();

        // Reset parser for next request
        parser.reset();
    }

    io.async_close(fd);
}

// =============================================================================
// HTTP/2 Request Handler
// =============================================================================

// Pending HTTP/2 request info for async processing
struct PendingH2Request {
    uint32_t stream_id;
    CoroHttpRequest request;
};

core::coro_task<void> CoroUnifiedServer::handle_http2_connection(
    net::IODispatcher& io, int fd, net::CoroTlsSocket* tls) {

    // Create HTTP/2 connection
    http2::Http2Connection h2_conn(true);  // Server mode

    // Buffer for I/O
    static constexpr size_t BUFFER_SIZE = 16384;
    uint8_t buffer[BUFFER_SIZE];

    // Queue for pending requests (populated by callback, processed by main loop)
    std::vector<PendingH2Request> pending_requests;

    // Set request callback to queue requests for async processing
    h2_conn.set_request_callback([this, &pending_requests](http2::Http2Stream* stream) {
        if (!stream) return;

        // Convert stream request to CoroHttpRequest.
        // HTTP/2 SHIM: unlike H1 (whose views point into the long-lived
        // connection read buffer), this request is queued and processed in the
        // I/O loop AFTER subsequent reads, and its source HPACK strings live in
        // the stream object whose lifetime we don't pin here. So H2 OWNS its
        // bytes in req.owned_storage_ and points the views there — stable for
        // the whole request including the handler hop. H1 stays truly zero-copy.
        CoroHttpRequest req;

        // Extract method, path, and headers from request_headers()
        for (const auto& [name, value] : stream->request_headers()) {
            if (name == ":method") {
                req.method = req.own(value);
            } else if (name == ":path") {
                // Own the whole ':path' (may include '?query'); additionally
                // expose the query slice via req.query so Request::query()
                // doesn't have to split on every read. Both views point into
                // the same owned backing string.
                std::string_view owned = req.own(value);
                req.path = owned;
                const auto qpos = owned.find('?');
                req.query = (qpos == std::string_view::npos)
                                ? std::string_view{}
                                : owned.substr(qpos + 1);
            } else if (!name.empty() && name[0] != ':') {
                // Regular header (skip other pseudo-headers like :scheme, :authority)
                std::string_view nv = req.own(name);
                std::string_view vv = req.own(value);
                req.add_header(nv, vv);
            }
        }

        // Get body (owned copy from the stream's body buffer)
        req.body = req.own(stream->request_body());

        // Track request
        requests_total_.fetch_add(1, std::memory_order_relaxed);

        // Queue for async processing (can't call async handler from callback)
        pending_requests.push_back(PendingH2Request{stream->id(), std::move(req)});
    });

    // Main I/O loop
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        // Send any pending output
        const uint8_t* out_data = nullptr;
        size_t out_len = 0;
        while (h2_conn.get_output(&out_data, &out_len)) {
            ssize_t written = co_await conn_write(io, fd, tls,out_data, out_len);
            if (written <= 0) {
                io.async_close(fd);
                co_return;
            }
            h2_conn.commit_output(static_cast<size_t>(written));
        }

        // Read incoming data
        ssize_t n = co_await conn_read(io, fd, tls,buffer, BUFFER_SIZE);
        if (n <= 0) {
            break;  // Connection closed or error
        }

        // Process incoming data (this calls the callback for complete requests)
        auto result = h2_conn.process_input(buffer, static_cast<size_t>(n));
        if (!result) {
            // Protocol error
            break;
        }

        // Process any pending requests asynchronously
        for (auto& pending : pending_requests) {
            CoroHttpResponse response;
            if (handler_) {
                response = co_await handler_(pending.request);
            } else {
                // Default response
                response.status = 200;
                response.status_message = "OK";
                response.headers.set("Content-Type", "text/plain");
                response.body = "Hello, World!";
            }

            // STATION-96: HTTP/2 frames its own body via DATA frames and has no
            // chunked transfer-encoding, so a streaming producer is materialized
            // into a buffered body here (byte-identical frames, not incremental)
            // and the hop-by-hop Transfer-Encoding header is stripped.
            if (response.is_fixed_stream()) {
                // Fixed-length streaming on H2: same bytes, H2's own DATA
                // framing. Content-Length is reconciled to what was produced.
                (void)materialize_fixed(response);
                response.headers.remove("Transfer-Encoding");
            } else if (response.stream_producer) {
                materialize_stream(response, /*drop_transfer_encoding=*/true);
            }
            // send_response takes a std::string, so a borrowed (zero-copy) body
            // is copied in here — H2 costs one copy where H1 costs none.
            if (response.borrowed_data != nullptr) {
                response.body.assign(response.borrowed_data, response.borrowed_size);
                response.borrowed_data = nullptr;
                response.borrowed_size = 0;
            }

            // Send response on the HTTP/2 stream
            h2_conn.send_response(
                pending.stream_id,
                response.status,
                response.headers,
                response.body
            );
        }
        pending_requests.clear();

        // Check connection state
        if (!h2_conn.is_active()) {
            break;
        }
    }

    // Send GOAWAY if we haven't already
    if (h2_conn.is_active()) {
        h2_conn.send_goaway(http2::ErrorCode::NO_ERROR);

        // Flush output
        const uint8_t* out_data = nullptr;
        size_t out_len = 0;
        while (h2_conn.get_output(&out_data, &out_len)) {
            ssize_t written = co_await conn_write(io, fd, tls,out_data, out_len);
            if (written <= 0) break;
            h2_conn.commit_output(static_cast<size_t>(written));
        }
    }

    // Reclaim the per-request bolt::Arena (no-op when the arena flag is OFF).
    // Done at connection teardown rather than per-stream: HTTP/2 multiplexes
    // many streams whose bodies may still be mid-accumulation across reads, so a
    // per-stream reset would risk wiping another stream's live body view. By
    // teardown every stream body has either been copied out to a std::string
    // (stream->request_body() in the request callback) or abandoned, and the
    // self-guarding reset only reclaims once no arena view is outstanding.
    thread_body_arena_reset();

    io.async_close(fd);
}

// =============================================================================
// WebSocket Connection Handler
// =============================================================================

core::coro_task<void> CoroUnifiedServer::handle_websocket_connection(
    net::IODispatcher& io, int fd, WebSocketConnection& ws_conn,
    net::CoroTlsSocket* tls) {

    static constexpr size_t WS_BUFFER_SIZE = 16384;
    uint8_t buffer[WS_BUFFER_SIZE];
    size_t buffer_len = 0;

    while (!stop_requested_.load(std::memory_order_relaxed) && ws_conn.is_open()) {
        // Send any pending output first
        while (ws_conn.has_pending_output()) {
            const std::string* output = ws_conn.get_pending_output();
            if (output && !output->empty()) {
                ssize_t written = co_await conn_write(io, fd, tls,output->data(), output->size());
                if (written <= 0) {
                    // Write failed - close connection
                    ws_conn.close(1001, "write error");
                    co_return;
                }
            }
            ws_conn.pop_pending_output();
        }

        // Read incoming WebSocket frames
        ssize_t n = co_await conn_read(io, fd, tls,buffer + buffer_len, WS_BUFFER_SIZE - buffer_len);
        if (n <= 0) {
            // Connection closed or error
            if (ws_conn.on_close) {
                ws_conn.on_close(1000, "connection closed");
            }
            co_return;
        }
        buffer_len += static_cast<size_t>(n);

        // Process all complete frames in buffer
        while (buffer_len > 0 && ws_conn.is_open()) {
            size_t consumed = 0;
            int result = ws_conn.handle_frame(buffer, buffer_len, consumed);
            
            if (result < 0) {
                // Need more data - keep buffer and read more
                break;
            } else if (result > 0) {
                // Frame processing error
                if (ws_conn.on_error) {
                    ws_conn.on_error("frame processing error");
                }
                co_return;
            }
            
            // result == 0: frame processed successfully
            // Remove consumed bytes from buffer
            if (consumed > 0 && consumed <= buffer_len) {
                if (consumed < buffer_len) {
                    memmove(buffer, buffer + consumed, buffer_len - consumed);
                }
                buffer_len -= consumed;
            } else {
                // No bytes consumed but success - shouldn't happen, but prevent infinite loop
                break;
            }
            
            // Send any responses queued by the handler immediately
            while (ws_conn.has_pending_output()) {
                const std::string* output = ws_conn.get_pending_output();
                if (output && !output->empty()) {
                    ssize_t written = co_await conn_write(io, fd, tls,output->data(), output->size());
                    if (written <= 0) {
                        ws_conn.close(1001, "write error");
                        co_return;
                    }
                }
                ws_conn.pop_pending_output();
            }
        }
    }

    // Send any final pending output
    while (ws_conn.has_pending_output()) {
        const std::string* output = ws_conn.get_pending_output();
        if (output && !output->empty()) {
            co_await conn_write(io, fd, tls,output->data(), output->size());
        }
        ws_conn.pop_pending_output();
    }
}

// =============================================================================
// Statistics
// =============================================================================

CoroUnifiedServer::Stats CoroUnifiedServer::get_stats() const noexcept {
    return Stats{
        .connections_accepted = connections_accepted_.load(std::memory_order_relaxed),
        .connections_active = connections_active_.load(std::memory_order_relaxed),
        .requests_total = requests_total_.load(std::memory_order_relaxed),
        .requests_http1 = requests_http1_.load(std::memory_order_relaxed),
        .requests_http2 = requests_http2_.load(std::memory_order_relaxed),
    };
}

} // namespace http
} // namespace bolt::api
