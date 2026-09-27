// pg_session — one Postgres wire connection (startup, auth, simple and
// extended query, cursors, transactions) through Protocol::serve_socket.
// First input byte: bit0 selects cleartext-password auth, the rest is the
// client's byte stream.
#include "fuzz_util.h"
#include "pg_wire_echo_executor.h"

#include "boltapi/proto/postgres_wire.h"

namespace pg = bolt::api::proto::pgwire;

namespace {

class PasswordAuth final : public pg::IAuthenticator {
public:
    bool requires_password() const noexcept override { return true; }
    bool authenticate(std::string_view user, std::string_view,
                      std::string_view password) noexcept override {
        return user.size() < 64 && password == "pw";
    }
};

pg::Config make_config() {
    pg::Config c;
    c.max_connections = 1;
    c.message_buffer_bytes = 64u * 1024u;
    c.write_buffer_bytes = 64u * 1024u;
    c.max_prepared_statements = 8;
    c.max_portals = 4;
    c.max_statement_bytes = 4096;
    c.statement_pool_bytes = 16u * 1024u;
    c.tx_pending_bytes = 8192;
    c.max_tx_pending_writes = 16;
    c.accept_poll_ms = 50;
    c.idle_timeout_ms = 2000;
    return c;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static boltapi_test::PgEchoFactory factory;
    static PasswordAuth password_auth;
    static pg::Protocol trust(make_config(), factory);
    static pg::Protocol pass(make_config(), factory, &password_auth);
    static boltapi_test::PgEchoExecutor exec;
    exec.max_rows = 64;
    if (size < 1) return 0;
    pg::Protocol& proto = (data[0] & 1) ? pass : trust;
    boltapi_fuzz::run_session(data + 1, size - 1,
                              [&](int fd) { proto.serve_socket(fd, exec); });
    exec.applied.clear();
    return 0;
}
