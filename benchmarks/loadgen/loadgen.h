// loadgen.h — async HTTP/1.1 load generator built on BoltAPI's own outbound
// primitives (IODispatcher async_connect/read/write + WorkerThreadPool).
//
// Fires N keep-alive connections, each running a serial request/response loop as
// a coroutine, until a wall-clock deadline. Records per-request latency into a
// per-connection histogram (no cross-connection sharing => no atomics on the hot
// path), then merges + reports req/s, bytes/s, and p50/p90/p99/p999.
//
// This is a benchmark tool: it is bounded, self-terminating (always returns
// within duration + a safety margin, even if the server dies mid-run), and never
// hard-fails. Zero third-party deps.
//
// TigerStyle: fixed connection cap, bounded loops, >=2 asserts per non-trivial
// fn, explicit error returns, no steady-state allocation (buffers pre-sized).
#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/net/sys_compat.h"

#include "http_client.h"
#include "latency_histogram.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bolt::bench {

namespace api = ::bolt::api;  // engine primitives live under bolt::api::{core,net}

struct LoadGenConfig {
    std::string   host        = "127.0.0.1";
    std::uint16_t port        = 8080;
    std::string   method      = "GET";
    std::string   path        = "/plaintext";
    std::string   body        = {};        // non-empty => POST-style body
    std::uint32_t connections = 64;        // keep-alive conns (<= kMaxConnections)
    std::uint32_t duration_s  = 10;        // wall-clock bound
    std::uint32_t io_threads  = 1;         // dispatcher I/O threads
    std::uint32_t workers     = 0;         // worker threads (0 = hw concurrency)
};

struct LoadGenResult {
    std::uint64_t ok = 0;
    std::uint64_t failed = 0;
    std::uint64_t bytes_in = 0;
    double        wall_s = 0.0;
    double        rps = 0.0;
    double        bytes_per_s = 0.0;
    std::uint64_t p50_ns = 0, p90_ns = 0, p99_ns = 0, p999_ns = 0;
    std::uint64_t min_ns = 0, max_ns = 0;
};

class LoadGen {
public:
    // Fixed upper bound on concurrent connections (TigerStyle: bounded resource).
    static constexpr std::uint32_t kMaxConnections = 1024;

    explicit LoadGen(LoadGenConfig cfg);

    // Run the full measurement. Always returns (bounded by duration + margin).
    LoadGenResult run();

private:
    // One keep-alive connection's serial request/response loop.
    api::core::coro_task<void> connection_loop(std::uint32_t index);

    LoadGenConfig cfg_;
    sockaddr_in   addr_{};                  // resolved target (set in run())

    api::net::IODispatcher* dispatcher_ = nullptr;  // borrowed during run()
    http::ClientRequest     req_{};         // built once, shared (views into cfg_)

    std::atomic<bool>          deadline_hit_{false};
    std::atomic<std::uint32_t> active_{0};
    std::atomic<std::uint64_t> ok_{0};
    std::atomic<std::uint64_t> failed_{0};
    std::atomic<std::uint64_t> bytes_in_{0};

    std::vector<http::ClientConn>  conns_;  // sized to cfg_.connections at startup
    std::vector<LatencyHistogram>  hist_;   // one per connection (serial access)
};

}  // namespace bolt::bench
