// tests/flight_sql_echo_server_main.cpp — a standalone Flight SQL server with
// a synthetic executor, so real Flight SQL clients (pyarrow.flight, ADBC)
// can be pointed at the wire layer alone.
//
// TEST HARNESS ONLY. Executor contract:
//   "SELECT <n>"   -> n rows (default 3): id int64 = i, name utf8 = "row<i>",
//                     score float64 = i * 0.5, in 8192-row batches.
//   "FAIL ..."     -> INVALID_ARGUMENT naming the statement.
//   "ECHO ..."     -> one row, sql utf8 = the statement as received (shows
//                     what parameter binding substituted).
//   "UPDATES"      -> as "SELECT <updates run so far>" (proves an update ran
//                     once, and that preparing it did not run it).
// Updates (DoPut): "UPSERT <n>" affects n rows; "FAILU ..." fails.
// Placeholder types: exactly "SELECT ?" and "UPSERT ?" type theirs bigint,
// "ECHO ?" utf8 (and describes its result itself; "SELECT ?" is described
// by the wire layer's stand-in run); every other `?` stays untyped.
// Catalog: tables "orders" (pk id), "customers" (pk region, id) and view
// "top_orders" (no pk), each with the "SELECT 0" schema.
// Usage: flight_sql_echo_server [--port N] [--token T] [--tls-cert F --tls-key F]
// Prints "PORT <n>" on stdout, then serves until SIGTERM/SIGINT. With
// --token, only "Bearer T" (or Basic user:T) is accepted.

#include "flight_sql_echo_executor.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

namespace fs = bolt::api::proto::flightsql;
using boltapi_test::EchoFactory;
using boltapi_test::TokenAuth;

namespace {
std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true, std::memory_order_release); }
}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    std::string token;
    std::string tls_cert;
    std::string tls_key;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (std::strcmp(argv[i], "--tls-cert") == 0 && i + 1 < argc) {
            tls_cert = argv[++i];
        } else if (std::strcmp(argv[i], "--tls-key") == 0 && i + 1 < argc) {
            tls_key = argv[++i];
        }
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    fs::Config cfg;
    cfg.port = port;
    cfg.max_connections = 4;
    cfg.accept_poll_ms = 50;
    cfg.idle_timeout_ms = 30000;
    cfg.server_name = "boltapi-echo";
    cfg.server_version = "9.9.9";
    cfg.tls_cert_file = tls_cert;
    cfg.tls_key_file = tls_key;
    EchoFactory factory;
    TokenAuth auth(token);
    fs::Protocol proto(cfg, factory, &auth);
    if (proto.start_background().is_err()) {
        std::fprintf(stderr, "bind failed on %s:%u\n", cfg.host.c_str(),
                     static_cast<unsigned>(cfg.port));
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
