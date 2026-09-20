// src/proto/postgres_wire_server.cpp — PostgreSQL frontend/backend wire
// protocol (v3.0) server. See boltapi/proto/postgres_wire.h for scope.
//
// Compiled ONLY under BOLTAPI_WITH_PG_WIRE. Structure mirrors
// neo4j_bolt_server.cpp: raw blocking sockets, select()-gated bounded reads,
// a fixed worker-thread pool (one connection at a time per worker), nothing
// allocated on the connection path (every buffer sized once at
// start_background()).

#include "boltapi/proto/postgres_wire.h"

#if defined(BOLTAPI_WITH_PG_WIRE)

#include "boltapi/net/sys_compat.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace bolt::api {
namespace proto {
namespace pgwire {

namespace {

// ---------------------------------------------------------------------------
// Socket helpers (same shape as neo4j_bolt_server.cpp's).
// ---------------------------------------------------------------------------
int wait_readable(int fd, int timeout_ms) noexcept {
    assert(fd >= 0);
    assert(timeout_ms >= 0);
    fd_set rd;
    FD_ZERO(&rd);
#if defined(_WIN32)
    FD_SET(static_cast<SOCKET>(fd), &rd);
#else
    if (fd >= FD_SETSIZE) return -1;
    FD_SET(fd, &rd);
#endif
    timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int r = ::select(fd + 1, &rd, nullptr, nullptr, &tv);
    return (r < 0) ? -1 : r;
}

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
        if (r <= 0) return false;
        got += static_cast<std::size_t>(r);
        assert(got <= n);
    }
    return true;
}

bool write_all(int fd, const void* src, std::size_t n) noexcept {
    assert(src != nullptr || n == 0);
    const auto* p = static_cast<const std::uint8_t*>(src);
    std::size_t sent = 0;
    while (sent < n) {
        const ssize_t w = net::sys::send_bytes(fd, p + sent, n - sent);
        if (w <= 0) return false;
        sent += static_cast<std::size_t>(w);
        assert(sent <= n);
    }
    return true;
}

std::int32_t read_be_i32(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return static_cast<std::int32_t>(
        (static_cast<std::uint32_t>(p[0]) << 24) |
        (static_cast<std::uint32_t>(p[1]) << 16) |
        (static_cast<std::uint32_t>(p[2]) << 8) |
        static_cast<std::uint32_t>(p[3]));
}

// Locate a NUL-terminated string starting at `off` within `[buf, buf+len)`.
// On success, `*out` views the bytes before the NUL and `*next_off` is the
// offset just past it. Returns false if no NUL is found within bounds.
bool read_cstring(const std::uint8_t* buf, std::size_t len, std::size_t off,
                  std::string_view* out, std::size_t* next_off) noexcept {
    assert(buf != nullptr && out != nullptr && next_off != nullptr);
    if (off > len) return false;
    std::size_t i = off;
    while (i < len && buf[i] != 0) ++i;      // bounded by len
    if (i >= len) return false;              // no terminator found
    *out = std::string_view(reinterpret_cast<const char*>(buf + off), i - off);
    *next_off = i + 1;
    return true;
}

// ---------------------------------------------------------------------------
// MsgWriter — one bounded, reusable send buffer per connection. Every backend
// message is TYPE-BYTE + BIG-ENDIAN INT32 LENGTH (length includes itself, not
// the type byte) + payload. begin()/finish() backpatch the length so a
// variable-width message (RowDescription, DataRow) never needs a second pass.
// A write past capacity sets `overflowed_` and every subsequent put_* is a
// no-op — the caller checks ok() before finish()/send() and refuses to send a
// truncated message (bounded, refuse-don't-corrupt, matching the rest of this
// codebase's "never a silently short answer" rule).
// ---------------------------------------------------------------------------
class MsgWriter {
public:
    MsgWriter(std::uint8_t* buf, std::size_t cap) noexcept : buf_(buf), cap_(cap) {
        assert(buf != nullptr && cap >= 16);
    }

    void begin(char type) noexcept {
        assert(pos_ == 0);
        put_u8(static_cast<std::uint8_t>(type));
        len_start_ = pos_;
        pos_ += 4;  // reserved for the length, backpatched in finish()
        if (pos_ > cap_) overflowed_ = true;
    }

    void put_u8(std::uint8_t v) noexcept {
        if (overflowed_ || pos_ + 1 > cap_) { overflowed_ = true; return; }
        buf_[pos_++] = v;
    }
    void put_i16(std::int16_t v) noexcept {
        if (overflowed_ || pos_ + 2 > cap_) { overflowed_ = true; return; }
        const auto u = static_cast<std::uint16_t>(v);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 8);
        buf_[pos_++] = static_cast<std::uint8_t>(u);
    }
    void put_i32(std::int32_t v) noexcept {
        if (overflowed_ || pos_ + 4 > cap_) { overflowed_ = true; return; }
        const auto u = static_cast<std::uint32_t>(v);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 24);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 16);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 8);
        buf_[pos_++] = static_cast<std::uint8_t>(u);
    }
    void put_bytes(const void* p, std::size_t n) noexcept {
        if (overflowed_ || pos_ + n > cap_) { overflowed_ = true; return; }
        std::memcpy(buf_ + pos_, p, n);
        pos_ += n;
    }
    void put_cstring(std::string_view s) noexcept {
        put_bytes(s.data(), s.size());
        put_u8(0);
    }

    bool ok() const noexcept { return !overflowed_; }

    // Backpatch the length field. Returns false (and does not touch `buf_`)
    // on overflow — the caller must not send() in that case.
    bool finish() noexcept {
        if (overflowed_) return false;
        assert(pos_ >= len_start_ + 4);
        const std::uint32_t len = static_cast<std::uint32_t>(pos_ - len_start_);
        buf_[len_start_ + 0] = static_cast<std::uint8_t>(len >> 24);
        buf_[len_start_ + 1] = static_cast<std::uint8_t>(len >> 16);
        buf_[len_start_ + 2] = static_cast<std::uint8_t>(len >> 8);
        buf_[len_start_ + 3] = static_cast<std::uint8_t>(len);
        return true;
    }

    bool send(int fd) noexcept {
        assert(pos_ <= cap_);
        const bool sent = write_all(fd, buf_, pos_);
        pos_ = 0;
        overflowed_ = false;
        return sent;
    }

private:
    std::uint8_t* buf_;
    std::size_t   cap_;
    std::size_t   pos_ = 0;
    std::size_t   len_start_ = 0;
    bool          overflowed_ = false;
};

// Protocol version / special startup codes (published Postgres wire spec).
constexpr std::int32_t kProtocolV3      = 196608;   // 3 << 16 | 0
constexpr std::int32_t kSslRequestCode  = 80877103;
constexpr std::int32_t kGssRequestCode  = 80877104;
constexpr std::int32_t kCancelCode      = 80877102;

constexpr std::size_t kMaxStartupPairs   = 16;
constexpr std::size_t kMaxStartupPacket  = 8192;   // startup params are tiny

struct StartupParams {
    std::string_view names[kMaxStartupPairs];
    std::string_view values[kMaxStartupPairs];
    std::uint32_t     count = 0;
    std::string_view user;
    std::string_view database;
};

std::string_view find_param(const StartupParams& p, std::string_view key) noexcept {
    for (std::uint32_t i = 0; i < p.count; ++i) {     // bounded by kMaxStartupPairs
        if (p.names[i] == key) return p.values[i];
    }
    return {};
}

void send_error(int fd, MsgWriter& w, const char* sqlstate,
                std::string_view message) noexcept {
    assert(sqlstate != nullptr);
    w.begin('E');
    w.put_u8('S'); w.put_cstring("ERROR");
    w.put_u8('V'); w.put_cstring("ERROR");
    w.put_u8('C'); w.put_cstring(sqlstate);
    w.put_u8('M'); w.put_cstring(message);
    w.put_u8(0);   // terminator
    if (w.finish()) (void)w.send(fd);
    else w.send(fd);  // reset state even if a giant message overflowed
}

void send_ready_for_query(int fd, MsgWriter& w) noexcept {
    w.begin('Z');
    w.put_u8('I');   // always "idle" — this bridge has no real transactions
    if (w.finish()) (void)w.send(fd);
}

// One Simple-Query round trip: RowDescription (if any columns) + DataRow* +
// CommandComplete, or ErrorResponse on failure — then ALWAYS ReadyForQuery,
// which is what lets a client keep issuing queries on the same connection
// after either outcome.
void handle_simple_query(int fd, MsgWriter& w, IQueryExecutor& exec,
                         std::string_view sql) noexcept {
    if (sql.empty()) {
        w.begin('I');
        if (w.finish()) (void)w.send(fd);
        send_ready_for_query(fd, w);
        return;
    }
    FieldDesc fields[kMaxFields];
    std::uint32_t field_count = 0;
    QueryFailure failure;
    const bool ok = exec.execute(sql, fields, kMaxFields, field_count, failure);
    if (!ok) {
        send_error(fd, w, failure.sqlstate, failure.message);
        send_ready_for_query(fd, w);
        return;
    }
    if (field_count > 0) {
        w.begin('T');
        w.put_i16(static_cast<std::int16_t>(field_count));
        for (std::uint32_t c = 0; c < field_count; ++c) {   // bounded by kMaxFields
            w.put_cstring(fields[c].name);
            w.put_i32(0);                     // table OID: none
            w.put_i16(0);                     // column attr number: none
            w.put_i32(fields[c].type_oid);
            w.put_i16(fields[c].type_size);
            w.put_i32(-1);                    // type modifier: none
            w.put_i16(0);                     // format code: text
        }
        if (!w.finish()) {
            send_error(fd, w, "54000", "result row is too wide for this "
                       "endpoint's wire buffer");
            send_ready_for_query(fd, w);
            return;
        }
        if (!w.send(fd)) return;

        const std::uint32_t rows = exec.row_count();
        std::string_view values[kMaxFields];
        bool is_null[kMaxFields];
        for (std::uint32_t r = 0; r < rows; ++r) {          // bounded by row_count()
            if (!exec.row(r, values, is_null, field_count)) break;
            w.begin('D');
            w.put_i16(static_cast<std::int16_t>(field_count));
            for (std::uint32_t c = 0; c < field_count; ++c) {
                if (is_null[c]) { w.put_i32(-1); continue; }
                w.put_i32(static_cast<std::int32_t>(values[c].size()));
                w.put_bytes(values[c].data(), values[c].size());
            }
            if (!w.finish()) {
                send_error(fd, w, "54000",
                          "a result row exceeded this endpoint's wire buffer "
                          "and was refused rather than sent truncated");
                send_ready_for_query(fd, w);
                return;
            }
            if (!w.send(fd)) return;
        }
    }
    char tag[64];
    exec.command_tag(tag, sizeof(tag));
    w.begin('C');
    w.put_cstring(tag);
    if (w.finish()) {
        if (!w.send(fd)) return;
    }
    send_ready_for_query(fd, w);
}

}  // namespace

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------
Listener::Listener(std::string host, std::uint16_t port) noexcept
    : host_(std::move(host)), requested_port_(port) {
    assert(!host_.empty());
}

Listener::~Listener() { stop(); }

Status Listener::start() noexcept {
    assert(fd_.load(std::memory_order_acquire) < 0);
    net::sys::startup();
    const int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return Status(core::error_code::host_error);

    int on = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&on), sizeof(on));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(requested_port_);
    if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1) {
        net::sys::close_socket(fd);
        return Status(core::error_code::invalid_state);
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(fd, 128) != 0) {
        net::sys::close_socket(fd);
        return Status(core::error_code::host_error);
    }

    sockaddr_in actual{};
    socklen_t alen = sizeof(actual);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &alen) == 0) {
        port_.store(ntohs(actual.sin_port), std::memory_order_release);
    }
    fd_.store(fd, std::memory_order_release);
    assert(fd_.load(std::memory_order_acquire) >= 0);
    return ok_status();
}

void Listener::stop() noexcept {
    const int fd = fd_.exchange(-1, std::memory_order_acq_rel);
    if (fd >= 0) net::sys::close_socket(fd);
    assert(fd_.load(std::memory_order_acquire) < 0);
}

bool Listener::is_running() const noexcept {
    return fd_.load(std::memory_order_acquire) >= 0;
}

int Listener::accept_one(int timeout_ms) noexcept {
    assert(timeout_ms >= 0);
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd < 0) return -1;
    const int ready = wait_readable(fd, timeout_ms);
    if (ready <= 0) return -1;
    if (fd_.load(std::memory_order_acquire) < 0) return -1;
    return static_cast<int>(::accept(fd, nullptr, nullptr));
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------
Protocol::Protocol(const Config& cfg, IExecutorFactory& factory,
                   IAuthenticator* auth) noexcept
    : cfg_(cfg), factory_(factory), auth_(auth) {
    assert(cfg_.max_connections > 0);
    assert(cfg_.message_buffer_bytes >= kMaxStartupPacket);
}

Protocol::~Protocol() { stop(); }

void Protocol::worker_loop(IQueryExecutor& exec, std::uint16_t worker_id) noexcept {
    assert(worker_id < cfg_.max_connections);
    std::vector<std::uint8_t> in(cfg_.message_buffer_bytes);
    std::vector<std::uint8_t> out(cfg_.write_buffer_bytes);

    while (!stopping_.load(std::memory_order_acquire)) {
        const int fd = listener_->accept_one(cfg_.accept_poll_ms);
        if (fd < 0) continue;
        (void)conn_seq_.fetch_add(1, std::memory_order_relaxed);

        int idle_budget = cfg_.idle_timeout_ms;
        MsgWriter w(out.data(), out.size());
        StartupParams params;
        bool ready = false;
        // Owned copies of user/database: `params.user`/`params.database`
        // start as string_views INTO `in` (see read_cstring below), but `in`
        // is the SAME buffer reused to read the cleartext-password challenge
        // response a few lines down -- without copying here, authenticate()
        // would see a user/database view clobbered by the password bytes
        // that just overwrote the memory it points into.
        char user_buf[128];
        char db_buf[128];

        // Up to 3 rounds: SSLRequest deny, GSSENCRequest deny, then the real
        // StartupMessage. A client that keeps negotiating past that is
        // refused rather than looped on forever.
        for (int round = 0; round < 3 && !ready; ++round) {
            std::uint8_t lenb[4];
            if (!read_exact(fd, lenb, 4, cfg_.accept_poll_ms, idle_budget, stopping_)) break;
            const std::int32_t total_len = read_be_i32(lenb);
            if (total_len < 8 || static_cast<std::size_t>(total_len) > in.size()) break;
            const std::size_t body_len = static_cast<std::size_t>(total_len) - 4;
            if (!read_exact(fd, in.data(), body_len, cfg_.accept_poll_ms, idle_budget,
                            stopping_)) break;
            const std::int32_t code = read_be_i32(in.data());

            if (code == kSslRequestCode || code == kGssRequestCode) {
                const char deny = 'N';
                if (!write_all(fd, &deny, 1)) break;
                continue;  // client will resend a real StartupMessage next
            }
            if (code == kCancelCode) break;  // no real query-cancel in v1
            if (code != kProtocolV3) {
                send_error(fd, w, "08P01",
                          "gestaltd's Postgres-wire endpoint speaks protocol "
                          "3.0 only");
                break;
            }
            // Real StartupMessage: key\0value\0 pairs, terminated by a lone
            // NUL. `body_len - 4` is the byte range after the protocol int32.
            std::size_t off = 4;
            bool terminated = false;
            while (off < body_len && params.count < kMaxStartupPairs) {
                if (in[off] == 0) { terminated = true; ++off; break; }
                std::string_view key, val;
                std::size_t next = 0;
                if (!read_cstring(in.data(), body_len, off, &key, &next)) break;
                off = next;
                if (!read_cstring(in.data(), body_len, off, &val, &next)) break;
                off = next;
                params.names[params.count] = key;
                params.values[params.count] = val;
                ++params.count;
            }
            (void)terminated;  // best-effort: a malformed tail just yields fewer params
            {
                const std::string_view u = find_param(params, "user");
                const std::string_view d = find_param(params, "database");
                const std::size_t un = u.size() < sizeof(user_buf) - 1 ? u.size() : sizeof(user_buf) - 1;
                const std::size_t dn = d.size() < sizeof(db_buf) - 1 ? d.size() : sizeof(db_buf) - 1;
                std::memcpy(user_buf, u.data(), un); user_buf[un] = 0;
                std::memcpy(db_buf, d.data(), dn); db_buf[dn] = 0;
                params.user = std::string_view(user_buf, un);
                params.database = std::string_view(db_buf, dn);
            }
            ready = true;
        }

        if (ready) {
            IAuthenticator& a = (auth_ != nullptr) ? *auth_ : default_auth_;
            bool authed = false;
            if (!a.requires_password()) {
                authed = a.authenticate(params.user, params.database, "");
            } else {
                w.begin('R');
                w.put_i32(3);   // AuthenticationCleartextPassword
                if (w.finish() && w.send(fd)) {
                    std::uint8_t hdr[5];
                    if (read_exact(fd, hdr, 5, cfg_.accept_poll_ms, idle_budget,
                                   stopping_) &&
                        hdr[0] == 'p') {
                        const std::int32_t plen = read_be_i32(hdr + 1);
                        if (plen >= 4 &&
                            static_cast<std::size_t>(plen) - 4 <= in.size()) {
                            const std::size_t n = static_cast<std::size_t>(plen) - 4;
                            if (read_exact(fd, in.data(), n, cfg_.accept_poll_ms,
                                          idle_budget, stopping_)) {
                                std::string_view pw(
                                    reinterpret_cast<const char*>(in.data()),
                                    n > 0 && in[n - 1] == 0 ? n - 1 : n);
                                authed = a.authenticate(params.user, params.database, pw);
                            }
                        }
                    }
                }
            }
            if (!authed) {
                send_error(fd, w, "28P01",
                          "password authentication failed (or the user/"
                          "credentials were refused)");
            } else {
                w.begin('R');
                w.put_i32(0);   // AuthenticationOk
                if (w.finish()) (void)w.send(fd);

                w.begin('S');
                w.put_cstring("server_version");
                w.put_cstring(cfg_.server_version);
                if (w.finish()) (void)w.send(fd);

                w.begin('S');
                w.put_cstring("client_encoding");
                w.put_cstring("UTF8");
                if (w.finish()) (void)w.send(fd);

                w.begin('S');
                w.put_cstring("gestaltd_server");
                w.put_cstring(cfg_.application_name);
                if (w.finish()) (void)w.send(fd);

                w.begin('K');
                w.put_i32(static_cast<std::int32_t>(worker_id) + 1);   // fabricated pid
                w.put_i32(static_cast<std::int32_t>(
                    conn_seq_.load(std::memory_order_relaxed)));       // fabricated secret
                if (w.finish()) (void)w.send(fd);

                send_ready_for_query(fd, w);

                // Simple-Query loop, until Terminate/error/idle-timeout.
                bool alive = true;
                while (alive && !stopping_.load(std::memory_order_acquire)) {
                    std::uint8_t hdr[5];
                    if (!read_exact(fd, hdr, 5, cfg_.accept_poll_ms, idle_budget,
                                    stopping_)) {
                        break;
                    }
                    const char type = static_cast<char>(hdr[0]);
                    const std::int32_t mlen = read_be_i32(hdr + 1);
                    if (mlen < 4 || static_cast<std::size_t>(mlen) - 4 > in.size()) break;
                    const std::size_t plen = static_cast<std::size_t>(mlen) - 4;
                    if (plen > 0 && !read_exact(fd, in.data(), plen, cfg_.accept_poll_ms,
                                                idle_budget, stopping_)) {
                        break;
                    }
                    switch (type) {
                        case 'Q': {
                            std::string_view sql(
                                reinterpret_cast<const char*>(in.data()),
                                plen > 0 && in[plen - 1] == 0 ? plen - 1 : plen);
                            handle_simple_query(fd, w, exec, sql);
                            break;
                        }
                        case 'S':   // Sync (extended protocol) — harmless alone
                            send_ready_for_query(fd, w);
                            break;
                        case 'X':   // Terminate
                            alive = false;
                            break;
                        case 'P': case 'B': case 'D': case 'E': case 'H': case 'C':
                            // Extended query protocol — v1 scope, see the
                            // header comment. Named, recoverable refusal.
                            send_error(fd, w, "0A000",
                                      "the extended query protocol (prepared "
                                      "statements: Parse/Bind/Describe/Execute)"
                                      " is not supported yet on this endpoint "
                                      "-- use simple-query execution");
                            send_ready_for_query(fd, w);
                            break;
                        default:
                            // Unrecognized message: cannot safely resync the
                            // framing, so the connection ends rather than
                            // risk misreading a later message as this one's
                            // stray payload.
                            alive = false;
                            break;
                    }
                }
            }
        }
        net::sys::close_socket(fd);
    }
}

Status Protocol::start_background() noexcept {
    if (listener_ != nullptr) return Status(core::error_code::invalid_state);
    listener_ = std::make_unique<Listener>(cfg_.host, cfg_.port);
    const Status s = listener_->start();
    if (s.is_err()) { listener_.reset(); return s; }
    assert(listener_->local_port() != 0);

    stopping_.store(false, std::memory_order_release);
    execs_.reserve(cfg_.max_connections);
    workers_.reserve(cfg_.max_connections);
    for (std::uint16_t k = 0; k < cfg_.max_connections; ++k) {   // bounded
        IQueryExecutor* e = factory_.create();
        if (e == nullptr) break;
        execs_.push_back(e);
        workers_.emplace_back([this, k, e]() noexcept { worker_loop(*e, k); });
    }
    if (execs_.empty()) {
        listener_->stop();
        listener_.reset();
        return Status(core::error_code::internal_error);
    }
    running_.store(true, std::memory_order_release);
    return ok_status();
}

void Protocol::stop() noexcept {
    stopping_.store(true, std::memory_order_release);
    if (listener_ != nullptr) listener_->stop();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
    for (IQueryExecutor* e : execs_) factory_.destroy(e);
    execs_.clear();
    listener_.reset();
    running_.store(false, std::memory_order_release);
}

}  // namespace pgwire
}  // namespace proto
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_PG_WIRE
