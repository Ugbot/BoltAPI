// loadgen.cpp — the dispatcher-coupled engine for the load generator.

#include "loadgen.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>

namespace bolt::bench {

namespace sys = ::bolt::api::net::sys;
using clock_t_ = std::chrono::steady_clock;

LoadGen::LoadGen(LoadGenConfig cfg) : cfg_(std::move(cfg)) {
    assert(cfg_.connections >= 1);
    assert(cfg_.connections <= kMaxConnections);
    conns_.resize(cfg_.connections);
    hist_.resize(cfg_.connections);
    // Shared request template (views into cfg_ strings, which outlive the run).
    req_.method = cfg_.method;
    req_.path   = cfg_.path;
    req_.host   = cfg_.host;
    req_.body   = cfg_.body;
}

api::core::coro_task<void> LoadGen::connection_loop(std::uint32_t index) {
    assert(index < conns_.size());
    http::ClientConn& c = conns_[index];
    LatencyHistogram& h = hist_[index];

    const int cr = co_await dispatcher_->async_connect(
        c.fd, reinterpret_cast<sockaddr*>(&addr_), sizeof(addr_));
    if (cr != 0) {
        failed_.fetch_add(1, std::memory_order_relaxed);
        if (c.fd >= 0) { sys::close_socket(c.fd); c.fd = -1; }
        active_.fetch_sub(1, std::memory_order_acq_rel);
        co_return;
    }
    c.connected = true;

    while (!deadline_hit_.load(std::memory_order_relaxed)) {
        const auto t0 = clock_t_::now();
        bool broken = false;

        // --- write the full request (handle partial writes) ---
        std::size_t sent = 0;
        const std::size_t want = c.wbuf.size();
        while (sent < want) {
            const ssize_t n = co_await dispatcher_->async_write(
                c.fd, c.wbuf.data() + sent, want - sent);
            if (n <= 0) { broken = true; break; }
            sent += static_cast<std::size_t>(n);
        }
        if (broken) { failed_.fetch_add(1, std::memory_order_relaxed); break; }

        // --- read until one full response is parsed ---
        c.parser.reset();
        bool complete = false;
        while (!complete) {
            const ssize_t n = co_await dispatcher_->async_read(
                c.fd, c.rbuf, http::kRecvChunk);
            if (n <= 0) { broken = true; break; }
            bytes_in_.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
            const auto st = c.parser.consume(c.rbuf, static_cast<std::size_t>(n));
            if (st == http::ResponseParser::State::Complete) { complete = true; }
            else if (st == http::ResponseParser::State::Error) { broken = true; break; }
        }
        if (broken || !complete) { failed_.fetch_add(1, std::memory_order_relaxed); break; }

        const auto t1 = clock_t_::now();
        const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        h.record(static_cast<std::uint64_t>(ns < 0 ? 0 : ns));
        ok_.fetch_add(1, std::memory_order_relaxed);

        if (!c.parser.keep_alive()) break;  // server asked to close
    }

    if (c.fd >= 0) { sys::close_socket(c.fd); c.fd = -1; }
    active_.fetch_sub(1, std::memory_order_acq_rel);
    co_return;
}

LoadGenResult LoadGen::run() {
    assert(cfg_.connections >= 1);
    assert(!cfg_.path.empty());
    sys::startup();

    // Resolve target address once.
    std::memset(&addr_, 0, sizeof(addr_));
    addr_.sin_family = AF_INET;
    addr_.sin_port = htons(cfg_.port);
    if (::inet_pton(AF_INET, cfg_.host.c_str(), &addr_.sin_addr) != 1) {
        return LoadGenResult{};  // bad host: nothing measured
    }

    // Build the shared request wire bytes once; copy into each connection buffer.
    std::string wire;
    http::serialize_request(req_, wire);
    for (auto& c : conns_) c.wbuf = wire;

    // Worker pool + dispatcher (private, not the noisy global).
    auto pool = std::make_unique<api::core::WorkerThreadPool>(static_cast<std::size_t>(cfg_.workers));
    pool->start();
    api::net::IODispatcherConfig dcfg;
    dcfg.num_io_threads = cfg_.io_threads == 0 ? 1 : cfg_.io_threads;
    dcfg.worker_pool = pool.get();
    auto disp = std::make_unique<api::net::IODispatcher>(dcfg);
    disp->start();
    dispatcher_ = disp.get();

    // Create non-blocking sockets.
    for (auto& c : conns_) {
        c.fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (c.fd >= 0) sys::set_nonblocking(c.fd);
    }

    // Launch one coroutine per connection; keep tasks alive for the whole run.
    active_.store(cfg_.connections, std::memory_order_release);
    std::vector<api::core::coro_task<void>> tasks;
    tasks.reserve(cfg_.connections);
    const auto t0 = clock_t_::now();
    for (std::uint32_t i = 0; i < cfg_.connections; ++i) {
        tasks.push_back(connection_loop(i));
        tasks.back().resume();  // run to first co_await (registers the connect)
    }

    // Run for the configured duration, then signal the connections to stop.
    const auto deadline = t0 + std::chrono::seconds(cfg_.duration_s);
    while (clock_t_::now() < deadline && active_.load(std::memory_order_acquire) > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    const auto t_signal = clock_t_::now();
    deadline_hit_.store(true, std::memory_order_release);

    // Wind-down: wait for in-flight requests to finish (bounded safety margin).
    const auto hard = t_signal + std::chrono::seconds(3);
    while (active_.load(std::memory_order_acquire) > 0 && clock_t_::now() < hard) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    // Last-resort: force-close any sockets still open so stuck coroutines error out.
    if (active_.load(std::memory_order_acquire) > 0) {
        for (auto& c : conns_) { if (c.fd >= 0) sys::close_socket(c.fd); }
        const auto hard2 = clock_t_::now() + std::chrono::seconds(2);
        while (active_.load(std::memory_order_acquire) > 0 && clock_t_::now() < hard2) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    disp->stop();
    pool->stop();
    dispatcher_ = nullptr;
    // tasks destruct here — all coroutines are done() (active_ == 0 in practice).

    // Aggregate.
    LatencyHistogram agg;
    for (std::uint32_t i = 0; i < cfg_.connections; ++i) agg.merge(hist_[i]);

    LoadGenResult r;
    r.ok = ok_.load();
    r.failed = failed_.load();
    r.bytes_in = bytes_in_.load();
    r.wall_s = std::chrono::duration_cast<std::chrono::duration<double>>(t_signal - t0).count();
    r.rps = r.wall_s > 0.0 ? static_cast<double>(r.ok) / r.wall_s : 0.0;
    r.bytes_per_s = r.wall_s > 0.0 ? static_cast<double>(r.bytes_in) / r.wall_s : 0.0;
    r.p50_ns = agg.percentile(50.0);
    r.p90_ns = agg.percentile(90.0);
    r.p99_ns = agg.percentile(99.0);
    r.p999_ns = agg.percentile(99.9);
    r.min_ns = agg.min();
    r.max_ns = agg.max();
    return r;
}

}  // namespace bolt::bench
