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
#include "boltapi/proto/postgres_wire_codec.h"
#include "postgres_wire_extended.h"
#include "postgres_wire_internal.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace bolt::api {
namespace proto {
namespace pgwire {

using namespace detail;

namespace {

// Protocol version / special startup codes (published Postgres wire spec).
constexpr std::int32_t kProtocolV3      = 196608;   // 3 << 16 | 0
constexpr std::int32_t kSslRequestCode  = 80877103;
constexpr std::int32_t kGssRequestCode  = 80877104;
constexpr std::int32_t kCancelCode      = 80877102;

constexpr std::size_t kMaxStartupPairs   = 16;
[[maybe_unused]] constexpr std::size_t kMaxStartupPacket = 8192;   // startup params are tiny

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

// ErrorResponse + ReadyForQuery, failing an open transaction block.
void simple_fail(int fd, MsgWriter& w, ExtendedSession& ext, const char* sqlstate,
                 std::string_view message) noexcept {
    assert(sqlstate != nullptr);
    send_error(fd, w, sqlstate, message);
    ext.tx_on_error();
    assert(ext.tx_status() != 'T');
    send_ready_for_query(fd, w, ext.tx_status());
}

void simple_tag(int fd, MsgWriter& w, ExtendedSession& ext, const char* tag) noexcept {
    assert(tag != nullptr);
    w.begin('C');
    w.put_cstring(tag);
    if (w.finish() && !w.send(fd)) return;
    send_ready_for_query(fd, w, ext.tx_status());
}

// One Simple-Query round trip: RowDescription (if any columns) + DataRow* +
// CommandComplete, or ErrorResponse on failure — then ALWAYS ReadyForQuery,
// which is what lets a client keep issuing queries on the same connection
// after either outcome.
void handle_simple_query(int fd, MsgWriter& w, ExtendedSession& ext,
                         IQueryExecutor& exec, std::string_view sql) noexcept {
    if (sql.empty()) {
        w.begin('I');
        if (w.finish()) (void)w.send(fd);
        send_ready_for_query(fd, w, ext.tx_status());
        return;
    }
    {
        const char* tag = nullptr;
        QueryFailure qf;
        const ExtendedSession::TxStep ts = ext.tx_statement(sql, fd, w, tag, qf);
        if (ts == ExtendedSession::TxStep::Failed) {
            simple_fail(fd, w, ext, qf.sqlstate, qf.message);
            return;
        }
        if (ts == ExtendedSession::TxStep::Tagged) {
            simple_tag(fd, w, ext, tag);
            return;
        }
        char cursor_tag[32];
        std::int32_t cursor = -1;
        std::uint32_t fetch_n = 0;
        const ExtendedSession::CursorStep cs =
            ext.cursor_statement(sql, exec, cursor_tag, sizeof(cursor_tag), cursor, fetch_n, qf);
        if (cs == ExtendedSession::CursorStep::Failed) {
            simple_fail(fd, w, ext, qf.sqlstate, qf.message);
            return;
        }
        if (cs == ExtendedSession::CursorStep::Tagged) {
            simple_tag(fd, w, ext, cursor_tag);
            return;
        }
        if (cs == ExtendedSession::CursorStep::Fetch) {
            const ExtendedSession::Emit e = ext.simple_fetch(cursor, fetch_n, fd, w, exec, qf);
            if (e == ExtendedSession::Emit::Failed) simple_fail(fd, w, ext, qf.sqlstate, qf.message);
            else if (e == ExtendedSession::Emit::Done) send_ready_for_query(fd, w, ext.tx_status());
            return;
        }
        CodecError ce;
        const SessionCommand sc = classify_session_command(sql, tag, ce);
        if (sc == SessionCommand::Refused) {
            simple_fail(fd, w, ext, ce.sqlstate, ce.message);
            return;
        }
        if (sc == SessionCommand::Accepted) {
            simple_tag(fd, w, ext, tag);
            return;
        }
        if (!ext.tx_admit(sql, qf)) {
            simple_fail(fd, w, ext, qf.sqlstate, qf.message);
            return;
        }
    }
    FieldDesc fields[kMaxFields];
    std::uint32_t field_count = 0;
    QueryFailure failure;
    ext.displace();
    const bool ok = exec.execute(sql, fields, kMaxFields, field_count, failure);
    if (!ok) {
        simple_fail(fd, w, ext, failure.sqlstate, failure.message);
        return;
    }
    if (field_count > 0) {
        if (!put_row_description(w, fields, field_count, nullptr)) {
            simple_fail(fd, w, ext, "54000", "result row is too wide for this "
                        "endpoint's wire buffer");
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
                simple_fail(fd, w, ext, "54000",
                            "a result row exceeded this endpoint's wire buffer "
                            "and was refused rather than sent truncated");
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
    send_ready_for_query(fd, w, ext.tx_status());
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
    assert(cfg_.worker_stack_bytes >= 256u * 1024u);
}

Protocol::~Protocol() { stop(); }

void Protocol::worker_loop(IQueryExecutor& exec, std::uint16_t worker_id) noexcept {
    assert(worker_id < cfg_.max_connections);
    std::vector<std::uint8_t> in(cfg_.message_buffer_bytes);
    std::vector<std::uint8_t> out(cfg_.write_buffer_bytes);
    ExtendedSession ext(cfg_);

    while (!stopping_.load(std::memory_order_acquire)) {
        const int fd = listener_->accept_one(cfg_.accept_poll_ms);
        if (fd < 0) continue;
        (void)conn_seq_.fetch_add(1, std::memory_order_relaxed);
        ext.reset();

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

                // Session settings drivers read at connect (pgJDBC checks
                // DateStyle/integer_datetimes; psycopg reads the encoding and
                // standard_conforming_strings to decide literal escaping).
                static constexpr const char* kStatus[][2] = {
                    {"client_encoding", "UTF8"},
                    {"server_encoding", "UTF8"},
                    {"DateStyle", "ISO, MDY"},
                    {"integer_datetimes", "on"},
                    {"standard_conforming_strings", "on"},
                    {"TimeZone", "UTC"},
                    {"IntervalStyle", "postgres"},
                    {"is_superuser", "off"},
                };
                for (const auto& kv : kStatus) {
                    w.begin('S');
                    w.put_cstring(kv[0]);
                    w.put_cstring(kv[1]);
                    if (w.finish()) (void)w.send(fd);
                }

                w.begin('S');
                w.put_cstring("gestaltd_server");
                w.put_cstring(cfg_.application_name);
                if (w.finish()) (void)w.send(fd);

                w.begin('K');
                w.put_i32(static_cast<std::int32_t>(worker_id) + 1);   // fabricated pid
                w.put_i32(static_cast<std::int32_t>(
                    conn_seq_.load(std::memory_order_relaxed)));       // fabricated secret
                if (w.finish()) (void)w.send(fd);

                send_ready_for_query(fd, w, 'I');

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
                            ext.on_simple_query();
                            handle_simple_query(fd, w, ext, exec, sql);
                            break;
                        }
                        case 'X':   // Terminate
                            alive = false;
                            break;
                        case 'P': case 'B': case 'D': case 'E':
                        case 'C': case 'H': case 'S':
                            alive = ext.handle(type, in.data(), plen, fd, w, exec);
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
    if (cfg_.max_prepared_statements < 1 || cfg_.max_portals < 1 ||
        cfg_.max_statement_bytes < 1024 ||
        cfg_.statement_pool_bytes < cfg_.max_statement_bytes) {
        return Status(core::error_code::invalid_state);
    }
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
        workers_.emplace_back(cfg_.worker_stack_bytes,
                              [this, k, e]() noexcept { worker_loop(*e, k); });
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
