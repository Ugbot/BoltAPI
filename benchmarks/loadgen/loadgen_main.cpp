// loadgen_main.cpp — CLI for the async HTTP/1.1 load generator.
//
// Usage:
//   boltapi_loadgen --host 127.0.0.1 --port 18080 --path /json \
//                   --connections 64 --duration 10 [--method POST --body '...'] \
//                   [--io-threads 1] [--workers 0]
//
// Prints a human-readable result block AND a single machine-scrapable line
// beginning with "RESULT " that the orchestration scripts parse. Always exits 0
// (this is a benchmark, never a CI gate).

#include "loadgen.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

using bolt::bench::LoadGen;
using bolt::bench::LoadGenConfig;
using bolt::bench::LoadGenResult;

// Find the value following `--key`; returns def if absent. Bounded by argc.
const char* arg_str(int argc, char** argv, const char* key, const char* def) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], key) == 0) return argv[i + 1];
    }
    return def;
}

std::uint32_t arg_u32(int argc, char** argv, const char* key, std::uint32_t def) {
    const char* v = arg_str(argc, argv, key, nullptr);
    if (v == nullptr) return def;
    const long long x = std::atoll(v);
    return x < 0 ? def : static_cast<std::uint32_t>(x);
}

double us(std::uint64_t ns) { return static_cast<double>(ns) / 1000.0; }

}  // namespace

int main(int argc, char** argv) {
    LoadGenConfig cfg;
    cfg.host        = arg_str(argc, argv, "--host", "127.0.0.1");
    cfg.port        = static_cast<std::uint16_t>(arg_u32(argc, argv, "--port", 8080));
    cfg.path        = arg_str(argc, argv, "--path", "/plaintext");
    cfg.method      = arg_str(argc, argv, "--method", "GET");
    cfg.body        = arg_str(argc, argv, "--body", "");
    cfg.connections = arg_u32(argc, argv, "--connections", 64);
    cfg.duration_s  = arg_u32(argc, argv, "--duration", 10);
    cfg.io_threads  = arg_u32(argc, argv, "--io-threads", 1);
    cfg.workers     = arg_u32(argc, argv, "--workers", 0);

    // Clamp to the generator's bounded capacity.
    if (cfg.connections < 1) cfg.connections = 1;
    if (cfg.connections > LoadGen::kMaxConnections) cfg.connections = LoadGen::kMaxConnections;
    if (cfg.duration_s < 1) cfg.duration_s = 1;

    std::printf("== boltapi loadgen ==\n");
    std::printf("target      http://%s:%u%s  (%s)\n",
                cfg.host.c_str(), cfg.port, cfg.path.c_str(), cfg.method.c_str());
    std::printf("conns=%u  duration=%us  io-threads=%u  workers=%u\n\n",
                cfg.connections, cfg.duration_s, cfg.io_threads, cfg.workers);

    LoadGen gen(std::move(cfg));
    const LoadGenResult r = gen.run();

    std::printf("[results]\n");
    std::printf("  ok            %llu\n", static_cast<unsigned long long>(r.ok));
    std::printf("  failed        %llu\n", static_cast<unsigned long long>(r.failed));
    std::printf("  wall          %.3f s\n", r.wall_s);
    std::printf("  throughput    %.0f req/s\n", r.rps);
    std::printf("  bandwidth     %.2f MiB/s\n", r.bytes_per_s / (1024.0 * 1024.0));
    std::printf("  latency (us)  p50=%.1f p90=%.1f p99=%.1f p99.9=%.1f min=%.1f max=%.1f\n",
                us(r.p50_ns), us(r.p90_ns), us(r.p99_ns), us(r.p999_ns),
                us(r.min_ns), us(r.max_ns));

    // Machine-scrapable line for the orchestration scripts.
    std::printf("RESULT path=%s rps=%.0f bytes_per_s=%.0f ok=%llu failed=%llu "
                "p50_us=%.1f p90_us=%.1f p99_us=%.1f p999_us=%.1f max_us=%.1f\n",
                arg_str(argc, argv, "--path", "/plaintext"),
                r.rps, r.bytes_per_s,
                static_cast<unsigned long long>(r.ok),
                static_cast<unsigned long long>(r.failed),
                us(r.p50_ns), us(r.p90_ns), us(r.p99_ns), us(r.p999_ns), us(r.max_ns));
    return 0;
}
