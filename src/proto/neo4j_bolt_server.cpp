// src/proto/neo4j_bolt_server.cpp — Neo4j Bolt client-wire-protocol server.
//
// Compiled ONLY under BOLTAPI_WITH_NEO4J_BOLT. "Bolt" here is Neo4j's client
// wire protocol; extern/bolt (our columnar core) is a different project that
// happens to share the word.
//
// Layers, bottom to top:
//   1. Neo4jBoltListener   — a stream ITransport owning the listening socket.
//   2. ChunkedIo           — Bolt's 2-byte-length chunk framing + `00 00` end.
//   3. handshake           — 20-byte preamble + 4-byte version negotiation.
//   4. Connection          — the message state machine (HELLO..GOODBYE).
//   5. Neo4jBoltProtocol   — IProtocol: fixed worker threads over the listener.
//
// TigerStyle: every buffer is sized once at serve() start, the connection path
// allocates nothing, every loop is bounded, and every refusal is named (a
// FAILURE with a Neo4j error code, or an explicit handshake decline) rather
// than a silent empty result.

#include "boltapi/proto/neo4j_bolt.h"

#if defined(BOLTAPI_WITH_NEO4J_BOLT)

#include "boltapi/net/sys_compat.h"

#include <cstdio>
#include <cstring>

namespace bolt::api {
namespace proto {
namespace neo4j {

using packstream::PackArena;
using packstream::PackError;
using packstream::PackReader;
using packstream::PackType;
using packstream::PackValue;
using packstream::PackWriter;

namespace {

// Bolt frames every message into chunks of at most 65535 bytes.
constexpr std::size_t kMaxChunk        = 0xFFFF;
constexpr std::size_t kHandshakeBytes  = 20;   // 4 magic + 4 * 4 proposals
constexpr std::uint32_t kMaxChunksPerMessage = 1u << 14;  // bounded reassembly

// select()-based readiness wait. Returns 1 ready, 0 timeout, -1 error.
int wait_readable(int fd, int timeout_ms) noexcept {
    assert(fd >= 0);
    assert(timeout_ms >= 0);
    fd_set rd;
    FD_ZERO(&rd);
#if defined(_WIN32)
    FD_SET(static_cast<SOCKET>(fd), &rd);
#else
    if (fd >= FD_SETSIZE) return -1;  // refuse rather than smash the fd_set
    FD_SET(fd, &rd);
#endif
    timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int r = ::select(fd + 1, &rd, nullptr, nullptr, &tv);
    return (r < 0) ? -1 : r;
}

// Read exactly `n` bytes, honouring an overall idle budget. Returns true on a
// complete read; false on peer close, timeout, error, or shutdown.
bool read_exact(int fd, void* dst, std::size_t n, int poll_ms, int& idle_budget_ms,
                const std::atomic<bool>& stopping) noexcept {
    assert(dst != nullptr || n == 0);
    assert(poll_ms > 0);
    auto* p = static_cast<std::uint8_t*>(dst);
    std::size_t got = 0;
    while (got < n) {
        if (stopping.load(std::memory_order_acquire)) return false;
        const int ready = wait_readable(fd, poll_ms);
        if (ready < 0) return false;
        if (ready == 0) {
            idle_budget_ms -= poll_ms;
            if (idle_budget_ms <= 0) return false;
            continue;
        }
        const ssize_t r = net::sys::recv_bytes(fd, p + got, n - got);
        if (r <= 0) return false;  // peer closed or error
        got += static_cast<std::size_t>(r);
        assert(got <= n);
    }
    return true;
}

bool write_all(int fd, const void* src, std::size_t n) noexcept {
    assert(src != nullptr || n == 0);
    const auto* p = static_cast<const std::uint8_t*>(src);
    std::size_t sent = 0;
    // Bounded: each iteration must make progress or we bail on the error path.
    while (sent < n) {
        const ssize_t w = net::sys::send_bytes(fd, p + sent, n - sent);
        if (w <= 0) return false;
        sent += static_cast<std::size_t>(w);
        assert(sent <= n);
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Version negotiation
// ---------------------------------------------------------------------------
bool is_supported(Version v) noexcept {
    if (v.major == 5) return v.minor <= kMaxBolt5Minor;
    if (v.major == 4) return v.minor == kBolt4Minor;
    return false;
}

Version negotiate(const std::uint8_t proposals[16]) noexcept {
    assert(proposals != nullptr);
    Version best{};
    for (std::size_t k = 0; k < 4; ++k) {
        const std::uint8_t* e = proposals + k * 4;
        // Wire layout: byte0 reserved(0), byte1 range, byte2 minor, byte3 major.
        const std::uint8_t range = e[1];
        const std::uint8_t minor = e[2];
        const std::uint8_t major = e[3];
        if (major == 0 || major == 0xFF) {
            // 0 = empty slot. 0xFF = the Bolt 5.7 handshake-manifest proposal;
            // we do not implement the manifest exchange, so we skip it instead
            // of selecting a mode we cannot then speak.
            continue;
        }
        const std::uint8_t low = (range > minor) ? 0 : static_cast<std::uint8_t>(minor - range);
        // Walk down from the client's highest offered minor to its lowest.
        for (int m = minor; m >= static_cast<int>(low); --m) {
            const Version cand{major, static_cast<std::uint8_t>(m)};
            if (!is_supported(cand)) continue;
            if (!best.valid() || cand.major > best.major ||
                (cand.major == best.major && cand.minor > best.minor)) {
                best = cand;
            }
            break;  // highest supported minor in this entry
        }
    }
    assert(!best.valid() || is_supported(best));
    return best;
}

const char* state_name(State s) noexcept {
    switch (s) {
        case State::Negotiation:    return "negotiation";
        case State::Authentication: return "authentication";
        case State::Ready:          return "ready";
        case State::Streaming:      return "streaming";
        case State::TxReady:        return "tx_ready";
        case State::TxStreaming:    return "tx_streaming";
        case State::Failed:         return "failed";
        case State::Defunct:        return "defunct";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Neo4jBoltListener
// ---------------------------------------------------------------------------
Neo4jBoltListener::Neo4jBoltListener(transport::Endpoint bind) noexcept
    : requested_(std::move(bind)), bound_(requested_) {
    assert(requested_.port <= 65535);
    assert(!requested_.host.empty());
}

Neo4jBoltListener::~Neo4jBoltListener() { stop(); }

transport::Status Neo4jBoltListener::start() {
    assert(fd_.load(std::memory_order_acquire) < 0);
    net::sys::startup();
    const int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return transport::Status(core::error_code::host_error);

    int on = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&on), sizeof(on));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(requested_.port);
    if (::inet_pton(AF_INET, requested_.host.c_str(), &addr.sin_addr) != 1) {
        net::sys::close_socket(fd);
        return transport::Status(core::error_code::invalid_state);
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(fd, 128) != 0) {
        net::sys::close_socket(fd);
        return transport::Status(core::error_code::host_error);
    }

    sockaddr_in actual{};
    socklen_t alen = sizeof(actual);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &alen) == 0) {
        bound_.port = ntohs(actual.sin_port);
    }
    bound_.host = requested_.host;
    fd_.store(fd, std::memory_order_release);
    assert(fd_.load(std::memory_order_acquire) >= 0);
    return transport::ok_status();
}

void Neo4jBoltListener::stop() noexcept {
    const int fd = fd_.exchange(-1, std::memory_order_acq_rel);
    if (fd >= 0) {
        // Closing wakes every worker parked in select() with an error, which is
        // how a bounded shutdown happens without a self-pipe.
        net::sys::close_socket(fd);
    }
    assert(fd_.load(std::memory_order_acquire) < 0);
}

int Neo4jBoltListener::accept_one(int timeout_ms) noexcept {
    assert(timeout_ms >= 0);
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd < 0) return -1;
    const int ready = wait_readable(fd, timeout_ms);
    if (ready <= 0) return -1;
    // Re-check: stop() may have closed the fd between select() and accept().
    if (fd_.load(std::memory_order_acquire) < 0) return -1;
    const int c = static_cast<int>(::accept(fd, nullptr, nullptr));
    return c;
}

// ---------------------------------------------------------------------------
// ChunkedIo — Bolt's message framing.
// ---------------------------------------------------------------------------
namespace {

class ChunkedIo {
public:
    ChunkedIo(int fd, std::uint8_t* in, std::size_t in_cap,
              std::uint8_t* out, std::size_t out_cap,
              int poll_ms, const std::atomic<bool>& stopping) noexcept
        : fd_(fd), in_(in), in_cap_(in_cap), out_(out), out_cap_(out_cap),
          poll_ms_(poll_ms), stopping_(stopping) {
        assert(in != nullptr && out != nullptr);
        assert(in_cap > 0 && out_cap > 0);
    }

    // Reassemble one message. Returns byte count, or -1 on close/timeout/error,
    // or -2 when the message exceeds the buffer (a named refusal, not a clamp).
    std::int64_t read_message(int& idle_budget_ms) noexcept {
        std::size_t n = 0;
        std::uint32_t chunks = 0;
        for (;;) {
            std::uint8_t hdr[2];
            if (!read_exact(fd_, hdr, 2, poll_ms_, idle_budget_ms, stopping_)) return -1;
            const std::size_t len = (static_cast<std::size_t>(hdr[0]) << 8) | hdr[1];
            if (len == 0) break;  // end-of-message marker
            if (++chunks > kMaxChunksPerMessage) return -2;
            if (len > in_cap_ - n) return -2;
            if (!read_exact(fd_, in_ + n, len, poll_ms_, idle_budget_ms, stopping_)) return -1;
            n += len;
            assert(n <= in_cap_);
        }
        return static_cast<std::int64_t>(n);
    }

    // Frame `payload` into chunks and append the end marker.
    bool write_message(const std::uint8_t* payload, std::size_t n) noexcept {
        assert(payload != nullptr || n == 0);
        std::size_t sent = 0;
        std::uint32_t chunks = 0;
        while (sent < n) {
            if (++chunks > kMaxChunksPerMessage) return false;
            const std::size_t take = (n - sent > kMaxChunk) ? kMaxChunk : (n - sent);
            std::uint8_t hdr[2] = {static_cast<std::uint8_t>(take >> 8),
                                   static_cast<std::uint8_t>(take & 0xFF)};
            if (!write_all(fd_, hdr, 2)) return false;
            if (!write_all(fd_, payload + sent, take)) return false;
            sent += take;
        }
        static const std::uint8_t kEnd[2] = {0, 0};
        return write_all(fd_, kEnd, 2);
    }

    std::uint8_t* in_buffer() noexcept { return in_; }
    std::uint8_t* out_buffer() noexcept { return out_; }
    std::size_t out_capacity() const noexcept { return out_cap_; }

private:
    int                        fd_;
    std::uint8_t*              in_;
    std::size_t                in_cap_;
    std::uint8_t*              out_;
    std::size_t                out_cap_;
    int                        poll_ms_;
    const std::atomic<bool>&   stopping_;
};

// ---------------------------------------------------------------------------
// Connection — the Bolt message state machine.
// ---------------------------------------------------------------------------
class Connection final : public IRecordSink {
public:
    Connection(int fd, const Config& cfg, IQueryExecutor& exec, IAuthenticator& auth,
               ChunkedIo& io, PackArena& arena, std::uint64_t conn_id,
               const std::atomic<bool>& stopping) noexcept
        : fd_(fd), cfg_(cfg), exec_(exec), auth_(auth), io_(io), arena_(arena),
          conn_id_(conn_id), stopping_(stopping) {
        assert(fd >= 0);
        assert(cfg.write_buffer_bytes > 0);
        std::snprintf(conn_name_, sizeof(conn_name_), "bolt-%llu",
                      static_cast<unsigned long long>(conn_id_));
    }

    // Drive handshake + message loop until the peer leaves. Never throws.
    void run() noexcept;

    // IRecordSink: one RECORD message per emitted row.
    bool emit(const PackValue* values, std::uint32_t n) noexcept override;

private:
    bool do_handshake() noexcept;
    bool dispatch(const PackValue& msg) noexcept;

    bool on_hello(const PackValue& msg) noexcept;
    bool on_logon(const PackValue& msg) noexcept;
    bool on_run(const PackValue& msg) noexcept;
    bool on_pull(const PackValue& msg, bool discard) noexcept;

    bool send_success_empty() noexcept;
    bool send_failure(const QueryFailure& f) noexcept;
    bool send_ignored() noexcept;
    bool flush(PackWriter& w) noexcept;

    // Is `sig` allowed to run while the connection is in Failed state? Only
    // RESET and GOODBYE are; everything else must be IGNORED, per the spec.
    static bool allowed_when_failed(Signature sig) noexcept {
        return sig == Signature::Reset || sig == Signature::Goodbye;
    }

    int                      fd_;
    const Config&            cfg_;
    IQueryExecutor&          exec_;
    IAuthenticator&          auth_;
    ChunkedIo&               io_;
    PackArena&               arena_;
    std::uint64_t            conn_id_;
    const std::atomic<bool>& stopping_;

    Version      version_{};
    State        state_ = State::Negotiation;
    char         conn_name_[32] = {0};
    std::string_view fields_[kMaxFields]{};
    std::uint32_t    field_count_ = 0;
    bool             write_failed_ = false;
    int              idle_budget_ms_ = 0;
};

bool Connection::do_handshake() noexcept {
    std::uint8_t hs[kHandshakeBytes];
    if (!read_exact(fd_, hs, kHandshakeBytes, cfg_.accept_poll_ms, idle_budget_ms_, stopping_)) {
        return false;
    }
    const std::uint32_t magic = (static_cast<std::uint32_t>(hs[0]) << 24) |
                                (static_cast<std::uint32_t>(hs[1]) << 16) |
                                (static_cast<std::uint32_t>(hs[2]) << 8) |
                                static_cast<std::uint32_t>(hs[3]);
    if (magic != kBoltMagic) {
        // Not a Bolt client. Close without a reply — there is no framing yet in
        // which an error could be expressed.
        return false;
    }
    version_ = negotiate(hs + 4);
    std::uint8_t reply[4] = {0, 0, 0, 0};
    if (version_.valid()) {
        reply[2] = version_.minor;
        reply[3] = version_.major;
    }
    if (!write_all(fd_, reply, 4)) return false;
    if (!version_.valid()) return false;  // declined: `00 00 00 00`, then close
    assert(is_supported(version_));
    state_ = State::Authentication;
    return true;
}

bool Connection::flush(PackWriter& w) noexcept {
    if (w.overflowed()) {
        // The response did not fit its buffer. Sending the truncated bytes
        // would desynchronise the stream; refuse loudly instead.
        write_failed_ = true;
        return false;
    }
    if (!io_.write_message(w.data(), w.size())) {
        write_failed_ = true;
        return false;
    }
    return true;
}

bool Connection::send_success_empty() noexcept {
    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Success), 1) != PackError::Ok) return false;
    if (w.begin_dict(0) != PackError::Ok) return false;
    return flush(w);
}

bool Connection::send_failure(const QueryFailure& f) noexcept {
    assert(f.code != nullptr && f.message != nullptr);
    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Failure), 1) != PackError::Ok) return false;
    if (w.begin_dict(2) != PackError::Ok) return false;
    (void)w.put_string("code");    (void)w.put_string(f.code);
    (void)w.put_string("message"); (void)w.put_string(f.message);
    state_ = State::Failed;
    return flush(w);
}

bool Connection::send_ignored() noexcept {
    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Ignored), 0) != PackError::Ok) return false;
    return flush(w);
}

bool Connection::emit(const PackValue* values, std::uint32_t n) noexcept {
    assert(values != nullptr || n == 0);
    if (write_failed_) return false;
    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Record), 1) != PackError::Ok) return false;
    if (w.begin_list(n) != PackError::Ok) return false;
    for (std::uint32_t k = 0; k < n; ++k) {
        if (w.put_value(values[k]) != PackError::Ok) return false;
    }
    return flush(w);
}

bool Connection::on_hello(const PackValue& msg) noexcept {
    assert(msg.type == PackType::Struct);
    const PackValue* extra = (msg.len >= 1) ? &msg.items[0] : nullptr;
    if (extra != nullptr && !extra->is_dict() && !extra->is_null()) {
        return send_failure({"Neo.ClientError.Request.Invalid",
                             "HELLO extra must be a dictionary"});
    }
    // Bolt < 5.1 carries auth in HELLO; 5.1+ defers it to LOGON.
    if (!version_.has_logon() && extra != nullptr && extra->is_dict()) {
        const std::string_view scheme = extra->find_str("scheme");
        if (!auth_.authenticate(scheme.empty() ? std::string_view("none") : scheme,
                                extra->find_str("principal"),
                                extra->find_str("credentials"))) {
            return send_failure({"Neo.ClientError.Security.Unauthorized",
                                 "authentication failed"});
        }
    }

    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Success), 1) != PackError::Ok) return false;
    if (w.begin_dict(3) != PackError::Ok) return false;
    // Drivers refuse a server whose agent does not start with "Neo4j/" (the
    // official driver raises UnsupportedServerProduct), so this field carries
    // the protocol's product identification and `boltapi_server` names us.
    (void)w.put_string("server");          (void)w.put_string(cfg_.server_agent);
    (void)w.put_string("connection_id");   (void)w.put_string(conn_name_);
    (void)w.put_string("boltapi_server");  (void)w.put_string("boltapi/neo4j-bolt");
    state_ = version_.has_logon() ? State::Authentication : State::Ready;
    return flush(w);
}

bool Connection::on_logon(const PackValue& msg) noexcept {
    const PackValue* extra = (msg.len >= 1) ? &msg.items[0] : nullptr;
    const std::string_view scheme =
        (extra != nullptr && extra->is_dict()) ? extra->find_str("scheme") : std::string_view();
    const std::string_view principal =
        (extra != nullptr && extra->is_dict()) ? extra->find_str("principal") : std::string_view();
    const std::string_view creds =
        (extra != nullptr && extra->is_dict()) ? extra->find_str("credentials") : std::string_view();
    if (!auth_.authenticate(scheme.empty() ? std::string_view("none") : scheme, principal, creds)) {
        return send_failure({"Neo.ClientError.Security.Unauthorized", "authentication failed"});
    }
    state_ = State::Ready;
    return send_success_empty();
}

bool Connection::on_run(const PackValue& msg) noexcept {
    assert(msg.type == PackType::Struct);
    if (msg.len < 2 || msg.items[0].type != PackType::String) {
        return send_failure({"Neo.ClientError.Request.Invalid",
                             "RUN requires [query, parameters, extra]"});
    }
    const PackValue& params = msg.items[1];
    QueryFailure fail{};
    field_count_ = 0;
    if (!exec_.begin_query(msg.items[0].str(), params, fields_, kMaxFields,
                           field_count_, fail)) {
        return send_failure(fail);
    }
    if (field_count_ > kMaxFields) {
        // The executor over-reported; refuse rather than read past the array.
        assert(false && "executor returned more fields than the declared cap");
        return send_failure({"Neo.ClientError.Statement.ExecutionFailed",
                             "result has more columns than the server supports"});
    }

    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Success), 1) != PackError::Ok) return false;
    if (w.begin_dict(2) != PackError::Ok) return false;
    (void)w.put_string("fields");
    (void)w.begin_list(field_count_);
    for (std::uint32_t k = 0; k < field_count_; ++k) (void)w.put_string(fields_[k]);
    (void)w.put_string("t_first"); (void)w.put_int(0);
    state_ = (state_ == State::TxReady) ? State::TxStreaming : State::Streaming;
    return flush(w);
}

bool Connection::on_pull(const PackValue& msg, bool discard) noexcept {
    const PackValue* extra = (msg.len >= 1) ? &msg.items[0] : nullptr;
    std::int64_t n = kPullAll;
    if (extra != nullptr && extra->is_dict()) n = extra->find_int("n", kPullAll);

    bool has_more = false;
    QueryFailure fail{};
    if (discard) {
        exec_.discard();
    } else if (!exec_.pull(n, *this, has_more, fail)) {
        if (write_failed_) return false;
        return send_failure(fail);
    }
    if (write_failed_) return false;

    PackWriter w(io_.out_buffer(), io_.out_capacity());
    if (w.begin_struct(static_cast<std::uint8_t>(Signature::Success), 1) != PackError::Ok) return false;
    if (has_more) {
        if (w.begin_dict(1) != PackError::Ok) return false;
        (void)w.put_string("has_more"); (void)w.put_bool(true);
        // State is unchanged: more PULLs may follow.
    } else {
        if (w.begin_dict(2) != PackError::Ok) return false;
        (void)w.put_string("type");   (void)w.put_string("r");  // read-only
        (void)w.put_string("t_last"); (void)w.put_int(0);
        state_ = (state_ == State::TxStreaming) ? State::TxReady : State::Ready;
    }
    return flush(w);
}

bool Connection::dispatch(const PackValue& msg) noexcept {
    if (msg.type != PackType::Struct) {
        return send_failure({"Neo.ClientError.Request.Invalid",
                             "expected a PackStream structure"});
    }
    const auto sig = static_cast<Signature>(msg.signature);

    if (state_ == State::Failed && !allowed_when_failed(sig)) {
        return send_ignored();
    }

    switch (sig) {
        case Signature::Hello:
            if (state_ != State::Authentication) {
                return send_failure({"Neo.ClientError.Request.Invalid",
                                     "HELLO is only valid once, right after the handshake"});
            }
            return on_hello(msg);

        case Signature::Logon:
            if (state_ != State::Authentication) {
                return send_failure({"Neo.ClientError.Request.Invalid",
                                     "LOGON is only valid in the authentication state"});
            }
            return on_logon(msg);

        case Signature::Logoff:
            state_ = State::Authentication;
            return send_success_empty();

        case Signature::Run:
            if (state_ != State::Ready && state_ != State::TxReady) {
                return send_failure({"Neo.ClientError.Request.Invalid",
                                     "RUN requires a ready connection"});
            }
            return on_run(msg);

        case Signature::Pull:
        case Signature::Discard:
            if (state_ != State::Streaming && state_ != State::TxStreaming) {
                return send_failure({"Neo.ClientError.Request.Invalid",
                                     "PULL/DISCARD requires a streaming result"});
            }
            return on_pull(msg, sig == Signature::Discard);

        case Signature::Begin:
            if (state_ != State::Ready) {
                return send_failure({"Neo.ClientError.Request.Invalid",
                                     "BEGIN requires a ready connection"});
            }
            // Read-only server: a transaction is a no-op scope, honestly
            // acknowledged rather than silently ignored.
            state_ = State::TxReady;
            return send_success_empty();

        case Signature::Commit:
        case Signature::Rollback:
            if (state_ != State::TxReady) {
                return send_failure({"Neo.ClientError.Request.Invalid",
                                     "COMMIT/ROLLBACK requires an open transaction"});
            }
            state_ = State::Ready;
            return send_success_empty();

        case Signature::Reset:
            exec_.discard();
            field_count_ = 0;
            state_ = State::Ready;
            return send_success_empty();

        case Signature::Telemetry:  // Bolt 5.4+; nothing to record.
            return send_success_empty();

        case Signature::Route:
            // A single instance has no routing table. This is exactly what a
            // non-cluster Neo4j answers, and it makes a driver fall back to a
            // direct connection rather than hang.
            return send_failure({"Neo.ClientError.Procedure.ProcedureNotFound",
                                 "routing is not supported by this server"});

        case Signature::Goodbye:
            state_ = State::Defunct;
            return false;  // close without a reply, per the spec

        default:
            return send_failure({"Neo.ClientError.Request.Invalid",
                                 "unsupported Bolt message signature"});
    }
}

void Connection::run() noexcept {
    idle_budget_ms_ = cfg_.idle_timeout_ms;
    if (!do_handshake()) return;

    // Bounded: the loop exits on peer close, idle timeout, protocol error or
    // shutdown. There is no unbounded wait anywhere inside it.
    while (!stopping_.load(std::memory_order_acquire) && state_ != State::Defunct) {
        idle_budget_ms_ = cfg_.idle_timeout_ms;
        const std::int64_t n = io_.read_message(idle_budget_ms_);
        if (n < 0) {
            if (n == -2) {
                (void)send_failure({"Neo.ClientError.Request.Invalid",
                                    "message exceeds the server's bounded buffer"});
            }
            return;
        }
        arena_.reset();
        PackValue msg{};
        PackReader reader(io_.in_buffer(), static_cast<std::size_t>(n), arena_);
        const PackError e = reader.read(msg);
        if (e != PackError::Ok) {
            (void)send_failure({"Neo.ClientError.Request.Invalid",
                                packstream::pack_error_name(e)});
            return;
        }
        if (!dispatch(msg)) return;
        if (write_failed_) return;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Neo4jBoltProtocol
// ---------------------------------------------------------------------------
Neo4jBoltProtocol::Neo4jBoltProtocol(const Config& cfg, IExecutorFactory& factory,
                                     IAuthenticator* auth) noexcept
    : cfg_(cfg), factory_(factory), auth_(auth) {
    assert(cfg_.max_connections > 0);
    assert(cfg_.message_buffer_bytes > 0 && cfg_.write_buffer_bytes > 0);
}

Neo4jBoltProtocol::~Neo4jBoltProtocol() { stop(); }

Status Neo4jBoltProtocol::bind_listener(Neo4jBoltListener& listener) noexcept {
    assert(listener.kind() == transport::TransportKind::Stream);
    if (running_.load(std::memory_order_acquire)) {
        return Status(core::error_code::invalid_state);
    }
    bound_ = &listener;
    return ok_status();
}

void Neo4jBoltProtocol::worker_loop(Neo4jBoltListener& listener, IQueryExecutor& exec,
                                    std::uint16_t worker_id) noexcept {
    assert(worker_id < cfg_.max_connections);
    // Per-worker buffers, allocated ONCE here — never on the connection path.
    std::vector<std::uint8_t> in(cfg_.message_buffer_bytes);
    std::vector<std::uint8_t> out(cfg_.write_buffer_bytes);
    std::vector<std::uint8_t> arena_mem(cfg_.value_arena_bytes);

    while (!stopping_.load(std::memory_order_acquire)) {
        const int fd = listener.accept_one(cfg_.accept_poll_ms);
        if (fd < 0) continue;
        {
            PackArena arena(arena_mem.data(), arena_mem.size());
            ChunkedIo io(fd, in.data(), in.size(), out.data(), out.size(),
                         cfg_.accept_poll_ms, stopping_);
            IAuthenticator& a = (auth_ != nullptr) ? *auth_ : default_auth_;
            const std::uint64_t id = conn_seq_.fetch_add(1, std::memory_order_relaxed);
            Connection conn(fd, cfg_, exec, a, io, arena, id, stopping_);
            conn.run();
        }
        exec.discard();  // a dropped connection must not leak a live result set
        net::sys::close_socket(fd);
    }
}

Status Neo4jBoltProtocol::serve(transport::ITransport& source) {
    // No RTTI in this build, so the concrete listener is declared up front via
    // bind_listener() and verified by identity here rather than downcast.
    if (bound_ == nullptr || &source != static_cast<transport::ITransport*>(bound_)) {
        return Status(core::error_code::invalid_state);
    }
    if (!source.is_running()) return Status(core::error_code::invalid_state);
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return Status(core::error_code::invalid_state);
    }
    stopping_.store(false, std::memory_order_release);
    port_.store(bound_->local_endpoint().port, std::memory_order_release);

    // Fixed worker set, created once. Bounded concurrency by construction: a
    // connection past max_connections simply waits in the listen backlog.
    std::vector<IQueryExecutor*> execs;
    execs.reserve(cfg_.max_connections);
    workers_.reserve(cfg_.max_connections);
    for (std::uint16_t k = 0; k < cfg_.max_connections; ++k) {
        IQueryExecutor* e = factory_.create();
        if (e == nullptr) break;
        execs.push_back(e);
        workers_.emplace_back([this, k, e]() noexcept { worker_loop(*bound_, *e, k); });
    }
    if (execs.empty()) {
        running_.store(false, std::memory_order_release);
        return Status(core::error_code::internal_error);
    }

    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
    for (IQueryExecutor* e : execs) factory_.destroy(e);
    running_.store(false, std::memory_order_release);
    return ok_status();
}

void Neo4jBoltProtocol::stop() noexcept {
    stopping_.store(true, std::memory_order_release);
    if (bound_ != nullptr) bound_->stop();
    if (serve_thread_.joinable()) serve_thread_.join();
    // serve() joins its own workers; after the serve thread is gone they are
    // guaranteed reaped. When serve() was called inline, the caller's thread
    // does the join and this is a no-op.
    assert(!serve_thread_.joinable());
}

Status Neo4jBoltProtocol::listen_and_serve() {
    if (owned_listener_ == nullptr) {
        owned_listener_ = std::make_unique<Neo4jBoltListener>(cfg_.bind);
        const Status s = owned_listener_->start();
        if (s.is_err()) return s;
        const Status b = bind_listener(*owned_listener_);
        if (b.is_err()) return b;
    }
    assert(owned_listener_ != nullptr);
    return serve(*owned_listener_);
}

Status Neo4jBoltProtocol::start_background() {
    if (owned_listener_ != nullptr) return Status(core::error_code::invalid_state);
    owned_listener_ = std::make_unique<Neo4jBoltListener>(cfg_.bind);
    const Status s = owned_listener_->start();
    if (s.is_err()) {
        owned_listener_.reset();
        return s;
    }
    const Status b = bind_listener(*owned_listener_);
    if (b.is_err()) return b;
    // Bound already, so local_port() is meaningful the moment we return.
    port_.store(owned_listener_->local_endpoint().port, std::memory_order_release);
    assert(port_.load(std::memory_order_acquire) != 0);
    serve_thread_ = std::thread([this]() noexcept { (void)serve(*owned_listener_); });
    return ok_status();
}

Status register_neo4j_bolt(ProtocolRegistry& reg, const Config& cfg,
                           IExecutorFactory& factory, IAuthenticator* auth) {
    return reg.register_protocol(ProtocolId::Neo4jBolt,
                                 [&cfg, &factory, auth]() -> std::unique_ptr<IProtocol> {
                                     return std::make_unique<Neo4jBoltProtocol>(cfg, factory, auth);
                                 });
}

}  // namespace neo4j
}  // namespace proto
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_NEO4J_BOLT
