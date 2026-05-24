// bench_server.cpp — TechEmpower-style benchmark server over the real App facade.
//
// A long-lived cleartext HTTP/1.1 server the load generator (boltapi_loadgen)
// hits over real loopback sockets, so we measure the ACTUAL framework path
// (router + middleware fold + Request/Response) rather than a toy. Routes mirror
// the TechEmpower test types, with one honest deviation: BoltAPI dropped the
// PostgreSQL dependency, so `/db` and `/queries` are a SYNTHETIC CPU proxy (a
// bounded xorshift generator), NOT a real database round-trip.
//
//   boltapi_bench_server [port] [--io-threads N] [--workers N]
//
// Run in the background by the orchestration scripts; killed when the run ends.
//
// TigerStyle: every handler trivial + bounded; the synthetic generators clamp
// their inputs (>=2 asserts) and loop a fixed, bounded number of times.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace api = bolt::api;

namespace {

// TechEmpower caps queries at 500 rows; we honor the same bound.
constexpr int kMaxRows = 500;

// Deterministic xorshift64 — a cheap, branch-light stand-in for "fetch a row".
std::uint64_t xorshift64(std::uint64_t& s) noexcept {
    assert(s != 0);
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

// One synthetic "World" row: {"id":N,"randomNumber":M}. Bounded id in [1,10000].
void append_row(std::string& out, std::uint64_t& seed) {
    const int id  = static_cast<int>(xorshift64(seed) % 10000) + 1;
    const int rnd = static_cast<int>(xorshift64(seed) % 10000) + 1;
    assert(id >= 1 && id <= 10000);
    assert(rnd >= 1 && rnd <= 10000);
    char tmp[64];
    const int n = std::snprintf(tmp, sizeof(tmp),
                                "{\"id\":%d,\"randomNumber\":%d}", id, rnd);
    assert(n > 0 && n < static_cast<int>(sizeof(tmp)));
    out.append(tmp, static_cast<std::size_t>(n));
}

// Parse "n" query param, clamped to [1, kMaxRows]; default 1 (TechEmpower rule).
int clamp_queries(const std::string& raw) noexcept {
    if (raw.empty()) return 1;
    const long long v = std::atoll(raw.c_str());
    if (v < 1) return 1;
    if (v > kMaxRows) return kMaxRows;
    return static_cast<int>(v);
}

}  // namespace

int main(int argc, char** argv) {
    api::net::sys::startup();

    std::uint16_t port = 8080;
    if (argc > 1 && argv[1][0] != '-') {
        const long long p = std::atoll(argv[1]);
        if (p > 0 && p < 65536) port = static_cast<std::uint16_t>(p);
    }
    // Optional thread overrides.
    api::App::Config cfg;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--io-threads") == 0) {
            cfg.server.num_io_threads = static_cast<std::size_t>(std::atoll(argv[i + 1]));
        } else if (std::strcmp(argv[i], "--workers") == 0) {
            cfg.server.num_workers = static_cast<std::size_t>(std::atoll(argv[i + 1]));
        }
    }

    api::App app(std::move(cfg));

    // /plaintext — TechEmpower "Plaintext": fixed text body.
    app.get("/plaintext", [](api::Request&, api::Response& res) {
        res.ok().text("Hello, World!");
    });

    // /json — TechEmpower "JSON serialization": a small fixed object. We hand-build
    // the bytes (the response path just needs a std::string; fionn is the parser).
    app.get("/json", [](api::Request&, api::Response& res) {
        res.ok().json("{\"message\":\"Hello, World!\"}");
    });

    // /db — TechEmpower "Single database query" (SYNTHETIC: no real DB).
    app.get("/db", [](api::Request&, api::Response& res) {
        std::uint64_t seed = 0x9E3779B97F4A7C15ull;
        std::string body;
        body.reserve(48);
        append_row(body, seed);
        res.ok().json(body);
    });

    // /queries?n=K — TechEmpower "Multiple queries" (SYNTHETIC). K clamped [1,500].
    app.get("/queries", [](api::Request& req, api::Response& res) {
        const int k = clamp_queries(req.query_param("n"));
        std::uint64_t seed = 0xD1B54A32D192ED03ull;
        std::string body;
        body.reserve(static_cast<std::size_t>(k) * 32 + 2);
        body.push_back('[');
        for (int i = 0; i < k; ++i) {
            if (i != 0) body.push_back(',');
            append_row(body, seed);
        }
        body.push_back(']');
        res.ok().json(body);
    });

    // /route/{id} — parametric-routing echo (exercises the trie param path).
    app.get("/route/{id}", [](api::Request& req, api::Response& res) {
        res.ok().text(std::string(req.path_param_view("id")));
    });

    std::printf("boltapi_bench_server listening on http://127.0.0.1:%u\n", port);
    std::printf("routes: /plaintext /json /db /queries?n=K /route/{id}\n");
    std::fflush(stdout);

    return app.run("127.0.0.1", port);  // blocking; the scripts kill the process
}
