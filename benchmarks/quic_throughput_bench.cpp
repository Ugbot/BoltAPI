// benchmarks/quic_throughput_bench.cpp — loopback QUIC 1-RTT throughput bench.
//
// WHAT THIS MEASURES (an A/B harness for the W5f hot-path work):
//   * HANDSHAKES/s  — full 1-RTT handshakes to ESTABLISHED, driven back-to-back
//                     over real UDP loopback (client + server QuicConnection,
//                     each on its own net::UdpTransport on the shared engine
//                     IODispatcher — the SAME inline-on-the-I/O-thread datagram
//                     path the App uses for HTTP/3).
//   * BULK MB/s     — sustained one-way bulk STREAM transfer over an established
//                     1-RTT connection (client opens a uni stream, writes a
//                     fixed payload in chunks; server reassembles to completion).
//   * CPU per byte  — process CPU time (user+kernel) over the bulk phase / bytes,
//                     so a hot-path change that trades wall-clock for CPU shows.
//
// NOT registered with ctest (gated by BOLTAPI_BUILD_BENCHMARKS, manual bench
// leg). Bounded by wall-clock deadlines throughout — no hang. Reports stable
// numbers usable for before/after comparison on one machine.
//
// TigerStyle: fixed bounds (kHandshakeReps, kBulkBytes), preallocated payload,
// no exceptions, asserts on invariants, deadline-guarded loops.

#include "boltapi/quic/connection.h"
#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace q    = bolt::api::quic;
namespace net  = bolt::api::net;
namespace core = bolt::api::core;

namespace {

// ---------------------------------------------------------------------------
// Fixed bounds (TigerStyle: explicit, bounded).
// ---------------------------------------------------------------------------
constexpr int           kHandshakeReps   = 200;            // handshakes timed
// A QUIC Stream carries a fixed 256 KiB send buffer (kStreamBufferSize) with no
// in-place reclaim, so one stream tops out at 256 KiB. We move that much per
// stream across kBulkStreams streams to get a sustained bulk figure (bounded by
// kMaxStreams=16 and the peer's initial_max_streams_uni). Total bytes is fixed,
// so the bench is a stable A/B regardless of where the per-stream cap lands.
constexpr std::size_t   kStreamPayload   = 256u * 1024;    // == kStreamBufferSize
constexpr int           kBulkStreams     = 8;              // <= peer uni budget over time
constexpr std::size_t   kWriteChunk      = 32u * 1024;     // per stream_write
constexpr int           kHandshakeBudgetMs = 4000;         // per-handshake cap
constexpr int           kBulkBudgetMs    = 20000;          // total bulk cap (deadline)

// Shared engine event loop (worker pool + IODispatcher) — the production wiring.
struct EventLoop {
    std::unique_ptr<core::WorkerThreadPool> pool;
    std::unique_ptr<net::IODispatcher>      disp;
    EventLoop() {
        pool = std::make_unique<core::WorkerThreadPool>(core::WorkerPoolConfig{});
        pool->start();
        disp = std::make_unique<net::IODispatcher>(pool.get());
        disp->start();
    }
    ~EventLoop() { disp->stop(); pool->stop(); }
};

net::IODispatcher& shared_dispatcher() {
    static EventLoop loop;
    return *loop.disp;
}

sockaddr_in loopback(std::uint16_t port) noexcept {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

// Process CPU time (user+kernel) in seconds, for CPU/byte accounting.
double process_cpu_seconds() noexcept {
#ifdef _WIN32
    FILETIME c, e, k, u;
    if (!::GetProcessTimes(::GetCurrentProcess(), &c, &e, &k, &u)) return 0.0;
    auto to_s = [](const FILETIME& f) noexcept {
        ULARGE_INTEGER v;
        v.LowPart = f.dwLowDateTime;
        v.HighPart = f.dwHighDateTime;
        return static_cast<double>(v.QuadPart) * 1e-7;  // 100ns ticks -> s
    };
    return to_s(k) + to_s(u);
#else
    return static_cast<double>(std::clock()) / CLOCKS_PER_SEC;
#endif
}

// One client+server connection pair over two loopback UdpTransports, with the
// SAME inline-on-the-I/O-thread datagram path the App uses. The transports' recv
// callbacks feed each connection directly (no per-packet worker hop).
struct Pair {
    net::UdpTransport client_udp{shared_dispatcher()};
    net::UdpTransport server_udp{shared_dispatcher()};
    q::QuicConnection client, server;
    std::mutex cmtx, smtx;

    bool setup() noexcept {
        if (!client_udp.bind("127.0.0.1", 0)) return false;
        if (!server_udp.bind("127.0.0.1", 0)) return false;
        const auto saddr = loopback(server_udp.bound_port());
        const auto caddr = loopback(client_udp.bound_port());
        auto csend = [this, saddr](const std::uint8_t* d, std::size_t n) {
            client_udp.send(reinterpret_cast<const sockaddr*>(&saddr),
                            sizeof(saddr), d, n);
        };
        auto ssend = [this, caddr](const std::uint8_t* d, std::size_t n) {
            server_udp.send(reinterpret_cast<const sockaddr*>(&caddr),
                            sizeof(caddr), d, n);
        };
        if (!client.init(false, csend)) return false;
        if (!server.init(true, ssend)) return false;
        // INLINE datagram path: the I/O-thread recv callback feeds the owning
        // connection directly (mirrors App HTTP/3 wiring). No worker handoff.
        client_udp.set_datagram_handler(
            [this](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
                std::lock_guard<std::mutex> lk(cmtx);
                client.feed_datagram(d, n);
            });
        server_udp.set_datagram_handler(
            [this](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
                std::lock_guard<std::mutex> lk(smtx);
                server.feed_datagram(d, n);
            });
        if (!client_udp.start() || !server_udp.start()) return false;
        return true;
    }

    bool handshake(int budget_ms) noexcept {
        {
            std::lock_guard<std::mutex> lk(cmtx);
            if (!client.start()) return false;
        }
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(budget_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            bool ce, se;
            { std::lock_guard<std::mutex> lk(cmtx); client.tick(); ce = client.is_established(); }
            { std::lock_guard<std::mutex> lk(smtx); server.tick(); se = server.is_established(); }
            if (ce && se) return true;
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        return false;
    }

    void stop() noexcept { client_udp.stop(); server_udp.stop(); }
};

// ---------------------------------------------------------------------------
// RelayPair — a deterministic in-process datagram relay (no sockets/I/O thread)
// for the BULK CPU measurement. Outbound datagrams are queued to in-order FIFOs
// and drained on the driver thread, so the bulk number isolates the QUIC build/
// seal/parse/open + framing CPU cost from loopback scheduling jitter (which is
// what the W5f framing/crypto hot-path work targets). The HANDSHAKE bench uses
// the real UdpTransport inline I/O path; this one measures pure protocol CPU.
// ---------------------------------------------------------------------------
struct RelayPair {
    q::QuicConnection client, server;
    std::vector<std::uint8_t> to_client_buf;  // bytes destined for the client
    std::vector<std::uint8_t> to_server_buf;  // bytes destined for the server
    std::vector<std::size_t>  to_client_len;  // per-datagram lengths (in order)
    std::vector<std::size_t>  to_server_len;

    bool setup() noexcept {
        to_client_buf.reserve(1u << 20);
        to_server_buf.reserve(1u << 20);
        auto csend = [this](const std::uint8_t* d, std::size_t n) {
            to_server_buf.insert(to_server_buf.end(), d, d + n);
            to_server_len.push_back(n);
        };
        auto ssend = [this](const std::uint8_t* d, std::size_t n) {
            to_client_buf.insert(to_client_buf.end(), d, d + n);
            to_client_len.push_back(n);
        };
        if (!client.init(false, csend)) return false;
        if (!server.init(true, ssend)) return false;
        return true;
    }

    // Deliver every queued datagram, in order, to its destination connection.
    // Returns total datagrams delivered this round.
    std::size_t drain() noexcept {
        std::size_t delivered = 0;
        std::size_t off = 0;
        for (std::size_t n : to_server_len) {
            server.feed_datagram(to_server_buf.data() + off, n);
            off += n; ++delivered;
        }
        to_server_buf.clear(); to_server_len.clear();
        off = 0;
        for (std::size_t n : to_client_len) {
            client.feed_datagram(to_client_buf.data() + off, n);
            off += n; ++delivered;
        }
        to_client_buf.clear(); to_client_len.clear();
        return delivered;
    }

    void pump_once() noexcept { drain(); client.tick(); server.tick(); }

    bool handshake(int budget_ms) noexcept {
        if (!client.start()) return false;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(budget_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            pump_once();
            if (client.is_established() && server.is_established()) return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Handshake throughput: kHandshakeReps full handshakes, each on a fresh pair.
// ---------------------------------------------------------------------------
double bench_handshakes() noexcept {
    int ok = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kHandshakeReps; ++i) {
        Pair p;
        if (!p.setup()) { p.stop(); break; }
        if (p.handshake(kHandshakeBudgetMs)) ++ok;
        p.stop();
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double secs =
        std::chrono::duration<double>(t1 - t0).count();
    assert(secs > 0.0 && "handshake timing non-positive");
    std::fprintf(stderr, "  handshakes: %d/%d completed in %.3fs\n",
                 ok, kHandshakeReps, secs);
    return (secs > 0.0) ? (ok / secs) : 0.0;
}

// ---------------------------------------------------------------------------
// Bulk one-way stream throughput over one established connection. The client
// drives kBulkStreams uni streams, each carrying kStreamPayload bytes, writing
// in kWriteChunk pieces under flow control and pumping both endpoints' tick()
// so the wire drains. The server's stream-data handler counts reassembled
// bytes. Target total = kBulkStreams * kStreamPayload.
// ---------------------------------------------------------------------------
struct BulkResult { double mbps = 0.0; double cpu_per_byte = 0.0; };

BulkResult bench_bulk() noexcept {
    RelayPair p;
    if (!p.setup() || !p.handshake(kHandshakeBudgetMs)) {
        std::fprintf(stderr, "  bulk: handshake failed\n");
        return {};
    }

    std::uint64_t got = 0;
    p.server.set_stream_data_handler(
        [&got](std::uint64_t, const std::uint8_t*, std::size_t len, bool) noexcept {
            got += len;
        });

    static std::vector<std::uint8_t> payload(kWriteChunk, 0xAB);  // preallocated
    assert(payload.size() == kWriteChunk && "payload size invariant");

    const std::uint64_t target =
        static_cast<std::uint64_t>(kBulkStreams) * kStreamPayload;
    const double cpu0 = process_cpu_seconds();
    const auto   t0   = std::chrono::steady_clock::now();
    const auto   deadline = t0 + std::chrono::milliseconds(kBulkBudgetMs);

    std::uint64_t queued = 0;
    int           opened = 0;
    std::size_t   cur_on_stream = 0;
    std::uint64_t sid = 0;
    bool          have_stream = false;

    while (queued < target && std::chrono::steady_clock::now() < deadline) {
        if (!have_stream) {
            if (opened >= kBulkStreams) break;
            sid = p.client.open_uni();
            ++opened;
            cur_on_stream = 0;
            have_stream = true;
        }
        const std::size_t remain = kStreamPayload - cur_on_stream;
        const std::size_t want = (remain < kWriteChunk) ? remain : kWriteChunk;
        const std::size_t w = p.client.stream_write(
            sid, payload.data(), want,
            /*fin=*/cur_on_stream + want >= kStreamPayload);
        if (w == 0) { p.pump_once(); continue; }  // flow/buffer back-pressure
        cur_on_stream += w;
        queued += w;
        if (cur_on_stream >= kStreamPayload) have_stream = false;
        p.pump_once();  // deterministically drain the flight + reopen windows
    }

    // Drain to completion (or deadline) — pure protocol CPU on the driver thread.
    while (got < queued && std::chrono::steady_clock::now() < deadline) {
        p.pump_once();
    }

    const auto   t1   = std::chrono::steady_clock::now();
    const double cpu1 = process_cpu_seconds();
    const double secs = std::chrono::duration<double>(t1 - t0).count();

    assert(secs > 0.0 && "bulk timing non-positive");
    std::fprintf(stderr,
                 "  bulk: queued %llu, server got %llu bytes in %.3fs\n",
                 static_cast<unsigned long long>(queued),
                 static_cast<unsigned long long>(got), secs);
    BulkResult r;
    r.mbps = (secs > 0.0)
                 ? (static_cast<double>(got) / (1024.0 * 1024.0)) / secs
                 : 0.0;
    r.cpu_per_byte =
        (got > 0) ? (cpu1 - cpu0) / static_cast<double>(got) : 0.0;
    return r;
}

}  // namespace

int main() {
    std::fprintf(stderr, "=== QUIC loopback throughput bench ===\n");

    std::fprintf(stderr, "[handshakes]\n");
    const double hs = bench_handshakes();

    std::fprintf(stderr, "[bulk stream]\n");
    const BulkResult bulk = bench_bulk();

    std::fprintf(stderr, "\n--- RESULTS ---\n");
    std::printf("handshakes_per_sec %.1f\n", hs);
    std::printf("bulk_MBps          %.2f\n", bulk.mbps);
    std::printf("cpu_ns_per_byte    %.3f\n", bulk.cpu_per_byte * 1e9);
    std::fflush(stdout);
    return 0;
}
