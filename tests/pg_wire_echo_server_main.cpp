// tests/pg_wire_echo_server_main.cpp — a standalone Postgres-wire echo server
// (see pg_wire_echo_executor.h). TEST HARNESS ONLY: lets real drivers
// (psycopg 3, pgJDBC, psql) be pointed at the wire layer with no SQL engine.
//
// Usage:  pg_wire_echo_server [--port N]   (0 = ephemeral, the default)
// Prints  "PORT <n>" on stdout, flushed, then serves until SIGTERM/SIGINT.

#include "boltapi/proto/postgres_wire.h"
#include "pg_wire_echo_executor.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {
std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true, std::memory_order_release); }
}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        }
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    bolt::api::proto::pgwire::Config cfg;
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.max_connections = 4;
    cfg.accept_poll_ms = 50;
    cfg.idle_timeout_ms = 30000;

    boltapi_test::PgEchoFactory factory;
    bolt::api::proto::pgwire::Protocol proto(cfg, factory);
    if (proto.start_background().is_err()) {
        std::fprintf(stderr, "bind failed\n");
        return 2;
    }
    std::printf("PORT %u\n", static_cast<unsigned>(proto.local_port()));
    std::fflush(stdout);
    while (!g_stop.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    proto.stop();
    return 0;
}
