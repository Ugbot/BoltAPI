// benchmarks/udp_echo_bench.cpp — UDP echo throughput: event-loop UdpTransport
// (coroutine on IODispatcher, the new unified path) vs a dedicated-thread
// blocking-recvfrom echo server (the OLD model). Same client driver, same
// machine, back-to-back — a fair before/after for the engine refactor.
//
// Not registered with ctest (manual bench leg). Reports datagrams/sec for a
// fixed number of synchronous request->echo round-trips on loopback.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

namespace net  = bolt::api::net;
namespace sys  = bolt::api::net::sys;
namespace core = bolt::api::core;

namespace {

constexpr int    kRoundTrips = 20000;     // synchronous echo round-trips
constexpr int    kPayload    = 64;        // datagram payload bytes

// A client UDP socket on loopback with a short recv timeout.
struct Client {
    net::socket_t fd = net::kInvalidSocket;
    bool open() {
        sys::startup();
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == net::kInvalidSocket) return false;
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        any.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&any), sizeof(any)) != 0) return false;
#ifdef _WIN32
        DWORD tmo = 2000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
        timeval tmo{2, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif
        return true;
    }
    ~Client() { if (fd != net::kInvalidSocket) sys::close_socket(fd); }
};

// Drive `n` synchronous round-trips against a server bound on `port`; returns
// datagrams/sec (round-trips/sec). First byte 0x01 keeps it STUN-classified.
double drive(std::uint16_t port, int n) {
    Client c;
    if (!c.open()) { std::fprintf(stderr, "client open failed\n"); return 0; }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);

    std::uint8_t buf[kPayload];
    std::memset(buf, 0xAB, sizeof(buf));
    buf[0] = 0x01;  // STUN-classified (0..3) so the transport's STUN handler echoes

    std::uint8_t rbuf[kPayload + 8];

    const auto t0 = std::chrono::steady_clock::now();
    int ok = 0;
    for (int i = 0; i < n; ++i) {
        if (::sendto(c.fd, reinterpret_cast<const char*>(buf), sizeof(buf), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) break;
        sockaddr_in from{}; socklen_t fl = sizeof(from);
        ssize_t r = ::recvfrom(c.fd, reinterpret_cast<char*>(rbuf), sizeof(rbuf), 0,
                               reinterpret_cast<sockaddr*>(&from), &fl);
        if (r <= 0) break;
        ++ok;
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(t1 - t0).count();
    std::fprintf(stderr, "  completed %d/%d round-trips in %.3f s\n", ok, n, secs);
    return ok / secs;
}

// Pipelined driver: keep up to `window` datagrams in flight, draining echoes as
// they arrive. This is the throughput regime (vs the latency-bound ping-pong of
// drive()) where the unified event loop's batching pays off. Returns rt/s.
double drive_pipelined(std::uint16_t port, int n, int window) {
    Client c;
    if (!c.open()) { std::fprintf(stderr, "client open failed\n"); return 0; }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);

    std::uint8_t buf[kPayload];
    std::memset(buf, 0xAB, sizeof(buf));
    buf[0] = 0x01;
    std::uint8_t rbuf[kPayload + 8];

    const auto t0 = std::chrono::steady_clock::now();
    int sent = 0, recv = 0;
    // Prime the window.
    for (int i = 0; i < window && sent < n; ++i) {
        ::sendto(c.fd, reinterpret_cast<const char*>(buf), sizeof(buf), 0,
                 reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        ++sent;
    }
    while (recv < n) {
        sockaddr_in from{}; socklen_t fl = sizeof(from);
        ssize_t r = ::recvfrom(c.fd, reinterpret_cast<char*>(rbuf), sizeof(rbuf), 0,
                               reinterpret_cast<sockaddr*>(&from), &fl);
        if (r <= 0) break;
        ++recv;
        if (sent < n) {
            ::sendto(c.fd, reinterpret_cast<const char*>(buf), sizeof(buf), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
            ++sent;
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(t1 - t0).count();
    std::fprintf(stderr, "  pipelined %d/%d echoes (window=%d) in %.3f s\n",
                 recv, n, window, secs);
    return recv / secs;
}

// ---- NEW path: UdpTransport receive coroutine on the IODispatcher ----
double bench_event_loop() {
    core::WorkerThreadPool pool(core::WorkerPoolConfig{});
    pool.start();
    net::IODispatcher disp(&pool);
    disp.start();

    net::UdpTransport t(disp);
    if (!t.bind("127.0.0.1", 0)) { std::fprintf(stderr, "bind failed\n"); return 0; }
    const std::uint16_t port = t.bound_port();
    // Echo the payload straight back to the peer (the unified-loop demux path).
    t.set_stun_handler([&t](const sockaddr* peer, int plen,
                            const std::uint8_t* data, std::size_t len) {
        t.send(peer, plen, data, len);
    });
    t.start();

    const double sync_rps = drive(port, kRoundTrips);
    const double pipe_rps = drive_pipelined(port, kRoundTrips, 64);
    std::fprintf(stderr, "  (sync ping-pong %.0f rt/s, pipelined %.0f rt/s)\n",
                 sync_rps, pipe_rps);

    t.stop();
    disp.stop();
    pool.stop();
    return pipe_rps;
}

// ---- OLD path: dedicated blocking-recvfrom echo thread ----
double bench_dedicated_thread() {
    sys::startup();
    net::socket_t s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    sockaddr_in bound{}; socklen_t bl = sizeof(bound);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bl);
    const std::uint16_t port = ntohs(bound.sin_port);

    std::atomic<bool> stop{false};
    std::thread th([&]() {
        std::uint8_t b[2048];
        while (!stop.load(std::memory_order_acquire)) {
            sockaddr_storage src{}; socklen_t sl = sizeof(src);
            // Short recv timeout so the thread can observe the stop flag.
#ifdef _WIN32
            DWORD tmo = 100;
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
            timeval tmo{0, 100000};
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif
            ssize_t n = ::recvfrom(s, reinterpret_cast<char*>(b), sizeof(b), 0,
                                   reinterpret_cast<sockaddr*>(&src), &sl);
            if (n <= 0) continue;
            ::sendto(s, reinterpret_cast<const char*>(b), static_cast<int>(n), 0,
                     reinterpret_cast<sockaddr*>(&src), sl);
        }
    });

    const double sync_rps = drive(port, kRoundTrips);
    const double pipe_rps = drive_pipelined(port, kRoundTrips, 64);
    std::fprintf(stderr, "  (sync ping-pong %.0f rt/s, pipelined %.0f rt/s)\n",
                 sync_rps, pipe_rps);

    stop.store(true, std::memory_order_release);
    th.join();
    sys::close_socket(s);
    return pipe_rps;
}

}  // namespace

int main() {
    std::fprintf(stderr, "UDP echo throughput bench (%d round-trips, %d-byte payload)\n",
                 kRoundTrips, kPayload);

    std::fprintf(stderr, "[OLD] dedicated-thread blocking recvfrom echo:\n");
    const double old_rps = bench_dedicated_thread();

    std::fprintf(stderr, "[NEW] UdpTransport coroutine on IODispatcher (unified loop):\n");
    const double new_rps = bench_event_loop();

    std::fprintf(stderr, "\nRESULTS (pipelined round-trips/sec, higher is better):\n");
    std::fprintf(stderr, "  OLD dedicated-thread : %10.0f rt/s\n", old_rps);
    std::fprintf(stderr, "  NEW event-loop       : %10.0f rt/s\n", new_rps);
    if (old_rps > 0)
        std::fprintf(stderr, "  ratio NEW/OLD        : %.2fx\n", new_rps / old_rps);
    return 0;
}
