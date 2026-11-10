// HTTP/2 connections with streamed responses (gRPC server streaming).
//
// Three parties share one connection state under one mutex:
//   reader   - handle_http2_stream_connection: reads the socket, feeds
//              Http2Connection, dispatches requests;
//   writer   - one detached coroutine, the only one that writes the socket;
//   handlers - H2StreamHandler calls on blocking workers; they queue ops
//              (head / data / trailers) and never touch the Http2Connection.
// The writer moves queued ops into the Http2Connection while the stream's
// unsent bytes are under kH2StreamBytes, so a handler blocks (data()) rather
// than buffer past the peer's flow-control window. Cleartext only: a TLS
// socket is not safe to read and write from two coroutines at once.

#include "boltapi/server/coro_unified_server.h"
#include "boltapi/http/http2_connection.h"

#include <cassert>
#include <cerrno>
#include <sys/socket.h>
#include <condition_variable>
#include <coroutine>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace bolt::api {
namespace http {

namespace {
constexpr std::size_t kQueueBytes = 1u << 20;        // per stream, ops not yet framed
constexpr std::size_t kH2StreamBytes = 256u << 10;   // per stream, framed but unsent
constexpr std::size_t kReadBytes = 16384;
}  // namespace

struct H2Shared;

struct H2Op {
    enum class Kind : std::uint8_t { kHead, kData, kTrailers, kReset };
    Kind kind;
    std::uint16_t status = 0;
    std::string bytes;
    CoroResponseHeaders headers;
};

struct H2StreamOut {
    std::uint32_t stream_id = 0;
    H2Shared* conn = nullptr;            // kept alive by `owner`
    std::shared_ptr<H2Shared> owner;
    CoroHttpRequest request;
    std::deque<H2Op> ops;                // guarded by conn->mu
    std::size_t queued = 0;
    std::condition_variable cv;          // handler backpressure
    bool cancelled = false;
    bool head_queued = false;
    bool ended = false;                  // trailers or reset queued
    bool done = false;                   // handler returned
};

struct H2Shared {
    std::mutex mu;
    http2::Http2Connection* h2 = nullptr;   // owned by the reader frame
    std::vector<std::shared_ptr<H2StreamOut>> streams;
    net::IODispatcher* io = nullptr;
    std::size_t io_index = 0;
    bool wake = false;
    bool closing = false;
    bool writer_done = false;
    bool write_failed = false;
    // One party writes the socket at a time: the writer coroutine, or a
    // handler thread writing its own frames straight out (no reactor hop)
    // when nothing else is pending. A short direct write leaves the rest in
    // `backlog` for the writer coroutine, which writes it first.
    bool writing = false;
    bool deferred = false;      // the writer woke while a handler was writing
    std::string backlog;
    int fd = -1;
    std::coroutine_handle<> writer{};
    std::coroutine_handle<> reader{};

    // Caller holds mu; returns the handle to post after unlocking.
    std::coroutine_handle<> signal_writer() noexcept {
        wake = true;
        std::coroutine_handle<> h = writer;
        writer = {};
        return h;
    }
    // Resume `h` on the connection's reactor; a post from that reactor
    // itself is refused by the dispatcher, so it resumes inline there.
    void post(std::coroutine_handle<> h) noexcept {
        if (h && !io->post_to_io_thread(io_index, h)) h.resume();
    }
};

namespace {

struct WriterReady {
    H2Shared* c;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(std::coroutine_handle<> co) noexcept {
        std::lock_guard<std::mutex> lk(c->mu);
        if (c->wake || c->closing) return false;
        c->writer = co;
        return true;
    }
    void await_resume() const noexcept {}
};

struct WriterExited {
    H2Shared* c;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(std::coroutine_handle<> co) noexcept {
        std::lock_guard<std::mutex> lk(c->mu);
        if (c->writer_done) return false;
        c->reader = co;
        return true;
    }
    void await_resume() const noexcept {}
};

std::size_t unsent(http2::Http2Stream* st) noexcept {
    return st->io.send_buf.size() - st->io.send_off;
}

// Move queued ops into the Http2Connection while the stream has room.
// Caller holds mu.
void frame_ops(H2Shared& c) {
    for (auto& sp : c.streams) {
        H2StreamOut& s = *sp;
        bool freed = false;
        while (!s.ops.empty() && !s.cancelled) {
            http2::Http2Stream* st = c.h2->get_stream(s.stream_id);
            if (st == nullptr) { s.cancelled = true; break; }
            if (unsent(st) >= kH2StreamBytes) break;
            H2Op& op = s.ops.front();
            core::result<void> r{};
            switch (op.kind) {
                case H2Op::Kind::kHead: r = c.h2->send_response_head(s.stream_id, op.status, op.headers); break;
                case H2Op::Kind::kData: r = c.h2->send_response_data(s.stream_id, op.bytes); break;
                case H2Op::Kind::kTrailers: r = c.h2->send_response_trailers(s.stream_id, op.headers); break;
                case H2Op::Kind::kReset:
                    r = c.h2->send_rst_stream(s.stream_id, http2::ErrorCode::INTERNAL_ERROR);
                    break;
            }
            s.queued -= op.bytes.size();
            s.ops.pop_front();
            freed = true;
            if (r.is_err()) { s.cancelled = true; break; }
        }
        if (s.cancelled) {
            for (const auto& op : s.ops) s.queued -= op.bytes.size();
            s.ops.clear();
            freed = true;
        }
        if (freed) s.cv.notify_all();
    }
    std::erase_if(c.streams, [](const std::shared_ptr<H2StreamOut>& s) {
        return s->ops.empty() && (s->cancelled || (s->ended && s->done));
    });
}

core::detached_task h2_writer(std::shared_ptr<H2Shared> keep, int fd) {
    H2Shared* c = keep.get();
    std::string out;
    for (;;) {
        co_await WriterReady{c};
        bool closing = false;
        {
            std::lock_guard<std::mutex> lk(c->mu);
            c->wake = false;
            if (c->writing) { c->deferred = true; continue; }   // the handler re-signals
            c->writing = true;
            if (!c->write_failed) frame_ops(*c);
            out.clear();
            out.swap(c->backlog);
            const std::uint8_t* p = nullptr;
            std::size_t n = 0;
            while (c->h2->get_output(&p, &n)) {
                out.append(reinterpret_cast<const char*>(p), n);
                c->h2->commit_output(n);
            }
            closing = c->closing;
        }
        std::size_t off = 0;
        while (off < out.size()) {
            const ssize_t w = co_await c->io->async_write(fd, out.data() + off, out.size() - off);
            if (w <= 0) break;
            off += static_cast<std::size_t>(w);
        }
        {
            std::lock_guard<std::mutex> lk(c->mu);
            c->writing = false;
            if (off < out.size()) {
                c->write_failed = true;
                for (auto& s : c->streams) { s->cancelled = true; s->cv.notify_all(); }
            }
        }
        if (closing && out.empty()) break;
    }
    std::coroutine_handle<> r{};
    {
        std::lock_guard<std::mutex> lk(c->mu);
        c->writer_done = true;
        r = c->reader;
        c->reader = {};
    }
    c->post(r);
}

// Frame what is queued and write it from this (handler) thread without
// blocking; the unwritten rest goes to the backlog. `lk` holds mu on entry
// and exit, released around the send.
void direct_write(H2Shared* c, std::unique_lock<std::mutex>& lk) {
    assert(!c->writing && c->backlog.empty());
    c->writing = true;
    frame_ops(*c);
    std::string out;
    const std::uint8_t* p = nullptr;
    std::size_t n = 0;
    while (c->h2->get_output(&p, &n)) {
        out.append(reinterpret_cast<const char*>(p), n);
        c->h2->commit_output(n);
    }
    lk.unlock();
    std::size_t off = 0;
    bool failed = false;
#ifdef MSG_NOSIGNAL
    constexpr int kFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
    constexpr int kFlags = MSG_DONTWAIT;
#endif
    for (int i = 0; i < 64 && off < out.size(); ++i) {
        const ssize_t w = ::send(c->fd, out.data() + off, out.size() - off, kFlags);
        if (w > 0) { off += static_cast<std::size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        failed = !(w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        break;
    }
    lk.lock();
    c->writing = false;
    if (c->deferred) { c->deferred = false; c->wake = true; }
    if (failed) {
        c->write_failed = true;
        for (auto& s : c->streams) { s->cancelled = true; s->cv.notify_all(); }
    } else if (off < out.size()) {
        c->backlog.append(out, off, std::string::npos);
    }
}

// Queue one op from a handler thread; false when the stream is gone.
bool push(H2StreamOut* s, H2Op op) {
    H2Shared* c = s->conn;
    std::coroutine_handle<> h{};
    {
        std::unique_lock<std::mutex> lk(c->mu);
        s->cv.wait(lk, [&] { return s->queued < kQueueBytes || s->cancelled; });
        if (s->cancelled || s->ended) return false;
        if (op.kind == H2Op::Kind::kTrailers || op.kind == H2Op::Kind::kReset) s->ended = true;
        if (op.kind == H2Op::Kind::kHead) s->head_queued = true;
        s->queued += op.bytes.size();
        s->ops.push_back(std::move(op));
        if (c->writing || c->closing || c->write_failed || !c->backlog.empty() || c->h2 == nullptr) {
            h = c->signal_writer();
        } else {
            direct_write(c, lk);
            if (!c->backlog.empty() || c->wake) h = c->signal_writer();
        }
    }
    c->post(h);
    return true;
}

}  // namespace

bool H2StreamWriter::head(uint16_t status, const CoroResponseHeaders& headers) {
    if (out_->head_queued) return false;
    H2Op op{H2Op::Kind::kHead, status, {}, headers};
    return push(out_, std::move(op));
}

bool H2StreamWriter::data(std::string_view bytes) {
    if (!out_->head_queued) return false;
    if (bytes.empty()) return !cancelled();
    H2Op op{H2Op::Kind::kData, 0, std::string(bytes), {}};
    return push(out_, std::move(op));
}

bool H2StreamWriter::trailers(const CoroResponseHeaders& trailers) {
    if (!out_->head_queued) return false;
    H2Op op{H2Op::Kind::kTrailers, 0, {}, trailers};
    return push(out_, std::move(op));
}

bool H2StreamWriter::cancelled() const noexcept {
    std::lock_guard<std::mutex> lk(out_->conn->mu);
    return out_->cancelled;
}

void CoroUnifiedServer::set_h2_stream_handler(H2StreamRoute route, H2StreamHandler handler) {
    h2_stream_route_ = std::move(route);
    h2_stream_handler_ = std::move(handler);
}

namespace {

CoroHttpRequest request_of(http2::Http2Stream* stream, int fd) {
    CoroHttpRequest req;
    req.client_fd = fd;
    for (const auto& [name, value] : stream->request_headers()) {
        if (name == ":method") {
            req.method = req.own(value);
        } else if (name == ":path") {
            const std::string_view owned = req.own(value);
            req.path = owned;
            const auto q = owned.find('?');
            req.query = q == std::string_view::npos ? std::string_view{} : owned.substr(q + 1);
        } else if (!name.empty() && name[0] != ':') {
            const std::string_view n = req.own(name);
            const std::string_view v = req.own(value);
            req.add_header(n, v);
        }
    }
    req.body = req.own(stream->request_body());
    return req;
}

// The handler on a blocking worker; an unfinished stream is reset.
void run_stream(const std::shared_ptr<H2StreamOut>& s, const H2StreamHandler& handler) {
    H2StreamWriter w(s.get());
    handler(s->request, w);
    H2Shared* c = s->conn;
    std::coroutine_handle<> h{};
    {
        std::lock_guard<std::mutex> lk(c->mu);
        s->done = true;
        if (!s->ended && !s->cancelled) {
            s->ops.push_back(H2Op{H2Op::Kind::kReset, 0, {}, {}});
            s->ended = true;
        }
        h = c->signal_writer();
    }
    c->post(h);
}

}  // namespace

core::coro_task<void> CoroUnifiedServer::handle_http2_stream_connection(
    net::IODispatcher& io, int fd, const uint8_t* initial, size_t initial_len,
    size_t io_thread_index) {
    http2::Http2Connection h2(true);
    h2.set_max_request_body(config_.max_body_size);
    auto shared = std::make_shared<H2Shared>();
    shared->h2 = &h2;
    shared->io = &io;
    shared->io_index = io_thread_index;
    shared->fd = fd;
    std::vector<CoroHttpRequest> pending;
    std::vector<std::uint32_t> pending_ids;
    h2.set_request_callback([&](http2::Http2Stream* stream) {
        if (stream == nullptr) return;
        requests_total_.fetch_add(1, std::memory_order_relaxed);
        pending.push_back(request_of(stream, fd));
        pending_ids.push_back(stream->id());
    });
    {
        auto task = h2_writer(shared, fd);
        task.release().resume();   // runs to its first park
    }

    std::uint8_t buffer[kReadBytes];
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        ssize_t n = 0;
        if (initial_len > 0) {
            assert(initial != nullptr && initial_len <= kReadBytes);
            std::memcpy(buffer, initial, initial_len);
            n = static_cast<ssize_t>(initial_len);
            initial_len = 0;
        } else {
            n = co_await io.async_read(fd, buffer, kReadBytes);
        }
        if (n <= 0) break;
        bool ok = false;
        std::coroutine_handle<> h{};
        {
            std::lock_guard<std::mutex> lk(shared->mu);
            if (shared->write_failed) break;
            ok = static_cast<bool>(h2.process_input(buffer, static_cast<size_t>(n)));
            for (auto& s : shared->streams) {
                if (h2.get_stream(s->stream_id) == nullptr) { s->cancelled = true; s->cv.notify_all(); }
            }
            h = shared->signal_writer();   // SETTINGS/PING acks, opened windows
        }
        shared->post(h);
        if (!ok) break;
        for (std::size_t i = 0; i < pending.size(); ++i) {
            if (h2_stream_route_ && h2_stream_route_(pending[i])) {
                auto s = std::make_shared<H2StreamOut>();
                s->stream_id = pending_ids[i];
                s->conn = shared.get();
                s->owner = shared;
                s->request = std::move(pending[i]);
                {
                    std::lock_guard<std::mutex> lk(shared->mu);
                    shared->streams.push_back(s);
                }
                const H2StreamHandler* handler = &h2_stream_handler_;
                if (!io.worker_pool()->try_submit_blocking([s, handler] { run_stream(s, *handler); })) {
                    std::lock_guard<std::mutex> lk(shared->mu);
                    s->ops.push_back(H2Op{H2Op::Kind::kReset, 0, {}, {}});
                    s->ended = s->done = true;
                }
                continue;
            }
            CoroHttpResponse response;
            if (handler_) response = co_await handler_(pending[i]);
            if (response.borrowed_data != nullptr) {
                response.body.assign(response.borrowed_data, response.borrowed_size);
                response.borrowed_data = nullptr;
            }
            if (response.stream_producer) {
                std::string body;
                response.stream_producer([&](std::string_view b) { body.append(b); });
                response.stream_producer = nullptr;
                response.body = std::move(body);
            }
            std::lock_guard<std::mutex> lk(shared->mu);
            if (h2.get_stream(pending_ids[i]) == nullptr) continue;
            if (h2.send_response(pending_ids[i], response.status, response.headers, response.body).is_err()) {
                (void)h2.send_rst_stream(pending_ids[i], http2::ErrorCode::INTERNAL_ERROR);
            }
        }
        pending.clear();
        pending_ids.clear();
        {
            std::lock_guard<std::mutex> lk(shared->mu);
            h = shared->signal_writer();
            ok = !h2.wants_close();
        }
        shared->post(h);
        if (!ok) break;
    }
    {
        std::coroutine_handle<> h{};
        {
            std::lock_guard<std::mutex> lk(shared->mu);
            shared->closing = true;
            for (auto& s : shared->streams) { s->cancelled = true; s->cv.notify_all(); }
            if (h2.is_active()) (void)h2.send_goaway(http2::ErrorCode::NO_ERROR);
            h = shared->signal_writer();
        }
        shared->post(h);
    }
    co_await WriterExited{shared.get()};
    {
        // Handlers still running hold `shared`; none touches h2 again.
        std::lock_guard<std::mutex> lk(shared->mu);
        shared->h2 = nullptr;
    }
    io.async_close(fd);
}

}  // namespace http
}  // namespace bolt::api
