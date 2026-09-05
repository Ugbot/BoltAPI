// tests/neo4j_bolt_echo_server_main.cpp — a standalone Bolt echo server.
//
// TEST HARNESS ONLY. Exists so the OFFICIAL neo4j Python driver can be pointed
// at a real socket: conformance has to be judged by a client we did not write.
//
// Usage:  neo4j_bolt_echo_server [--port N]   (0 = ephemeral, the default)
// Prints  "PORT <n>" on stdout, flushed, then serves until SIGTERM/SIGINT.

#include "boltapi/proto/neo4j_bolt.h"
#include "neo4j_bolt_echo_executor.h"

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

    bolt::api::proto::neo4j::Config cfg;
    cfg.bind.host = "127.0.0.1";
    cfg.bind.port = port;
    cfg.max_connections = 8;      // the driver pools connections
    cfg.accept_poll_ms = 50;
    cfg.idle_timeout_ms = 30000;

    boltapi_test::EchoFactory factory;
    bolt::api::proto::neo4j::Neo4jBoltProtocol proto(cfg, factory);
    const auto s = proto.start_background();
    if (s.is_err()) {
        std::fprintf(stderr, "bind failed on %s:%u\n", cfg.bind.host.c_str(),
                     static_cast<unsigned>(cfg.bind.port));
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
