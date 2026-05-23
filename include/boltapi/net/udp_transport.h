// boltapi/net/udp_transport.h — real async UDP transport for WebRTC (+ HTTP/3).
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A protocol-agnostic UDP transport that owns its OWN UDP socket and runs its
// receive loop as a COROUTINE on the engine's unified async event loop
// (IODispatcher / async_io). This is the fastest unified multi-protocol path:
// the same epoll/kqueue/IOCP loop that backs TCP/HTTP also drives UDP datagram
// I/O — one fewer thread, no dedicated select() poller.
//
// Previously this owned a dedicated receive thread; that has been removed. The
// receive loop is now:
//     while (running) {
//         n = co_await io.async_recvfrom(fd, buf, &peer, &len);
//         demux(buf, n, peer);
//     }
// scheduled on the IODispatcher when start() is called. Datagrams are sent with
// a direct sendto on the owned socket (sendto rarely blocks and is thread-safe
// per-socket), which keeps send() callable inline from a STUN handler.
//
// DEMUX (RFC 7983, by the first byte of each datagram):
//   * 0..3    -> STUN  -> routed to the registered STUN handler (the IceAgent).
//   * 20..63  -> DTLS  -> routed to the registered datagram handler.
//   * else    -> dropped with a counter.
//
// COMPILED UNCONDITIONALLY into boltapi: it depends only on the engine's
// IODispatcher (also unconditional), so the DEFAULT test suite covers it. Only
// the App-level "start WebRTC serving" wiring lives behind BOLTAPI_WITH_WEBRTC.
//
// TigerStyle: preallocated receive buffer, fixed bounds, cache-line-padded
// atomic counters, a clean coroutine shutdown (atomic stop flag + socket close
// to unblock a pending recvfrom — no hang, no leak, no use-after-free), no
// exceptions.

#pragma once

#include "boltapi/net/sys_compat.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/coro_task.h"

#include <atomic>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <new>
#include <string>

namespace bolt::api {
namespace net {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle: explicit). A UDP datagram on the Internet is bounded by
// the path MTU; 2048 generously covers a 1500-byte Ethernet MTU plus headroom,
// and any WebRTC packet (STUN/DTLS/SCTP) fits well under it.
// ----------------------------------------------------------------------------
inline constexpr std::size_t kUdpRecvBufferSize = 2048;

// Cross-platform socket handle alias (SOCKET on Windows, int on POSIX).
#ifdef _WIN32
using socket_t = SOCKET;
inline constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
inline constexpr socket_t kInvalidSocket = -1;
#endif

// ----------------------------------------------------------------------------
// Handler signatures. Both receive the source address (the datagram's 4-tuple
// peer end) plus the payload view. Handlers run ON a worker thread (where the
// receive coroutine is resumed) — keep them allocation-light; for ICE-lite the
// STUN response is computed + sent inline here, which is cheap and correct.
// ----------------------------------------------------------------------------
using StunHandler = std::function<void(const sockaddr* peer, int peer_len,
                                       const std::uint8_t* data,
                                       std::size_t len)>;
using DatagramHandler = std::function<void(const sockaddr* peer, int peer_len,
                                           const std::uint8_t* data,
                                           std::size_t len)>;

// ----------------------------------------------------------------------------
// UdpTransport — owns a UDP socket; runs its receive loop as a coroutine on an
// IODispatcher (the engine's unified async event loop).
// ----------------------------------------------------------------------------
class UdpTransport {
public:
    // Default ctor: uses the global IODispatcher (lazily started) on start().
    UdpTransport() noexcept = default;

    // Explicit ctor: run on a specific dispatcher (e.g. the App's server loop).
    // The dispatcher must outlive this transport.
    explicit UdpTransport(IODispatcher& dispatcher) noexcept
        : dispatcher_(&dispatcher) {}

    ~UdpTransport() { stop(); }

    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    // Bind a UDP socket to host:port (IPv4). Pass port 0 for an ephemeral port;
    // bound_port() then reports the OS-assigned port. On error returns false and
    // leaves the transport unbound.
    bool bind(const char* host, std::uint16_t port) noexcept;

    // Start the receive coroutine on the IODispatcher. Requires a successful
    // bind() first. Returns false if not bound or already running.
    bool start() noexcept;

    // Stop the receive coroutine and close the socket. Idempotent, noexcept.
    // Cleanly cancels: sets the stop flag and closes the socket to unblock any
    // pending recvfrom, then waits for the coroutine to finish before freeing.
    // No hang, no leak, no use-after-free.
    void stop() noexcept;

    bool is_running() const noexcept { return running_.load(std::memory_order_acquire); }

    // The actually-bound local port (valid after bind()); 0 if unbound.
    std::uint16_t bound_port() const noexcept { return bound_port_; }

    // Send a datagram to `peer`. Thread-safe (direct sendto on the owned
    // socket). Returns the bytes sent or -1.
    ssize_t send(const sockaddr* peer, int peer_len,
                 const std::uint8_t* data, std::size_t len) noexcept;

    // Registration hooks (set before start(), or while stopped). The STUN
    // handler receives first-byte 0..3 datagrams; the datagram handler receives
    // first-byte 20..63 (DTLS) datagrams.
    void set_stun_handler(StunHandler fn) noexcept { stun_handler_ = std::move(fn); }
    void set_datagram_handler(DatagramHandler fn) noexcept {
        datagram_handler_ = std::move(fn);
    }

    // Counters (cache-line-padded atomics) — observability, no hot-path cost.
    std::uint64_t received() const noexcept { return rx_count_.v.load(std::memory_order_relaxed); }
    std::uint64_t sent()     const noexcept { return tx_count_.v.load(std::memory_order_relaxed); }
    std::uint64_t dropped()  const noexcept { return drop_count_.v.load(std::memory_order_relaxed); }

    socket_t native_handle() const noexcept { return sock_; }

private:
    // The receive coroutine: loops co_await async_recvfrom + demux until the
    // stop flag is set (or the socket is closed under it).
    core::coro_task<void> receive_loop() noexcept;

    void demux(const sockaddr* peer, int peer_len,
               const std::uint8_t* data, std::size_t len) noexcept;

    // Cache-line-padded atomic to avoid false sharing between the counters the
    // rx coroutine bumps and any reader thread.
    struct alignas(64) PaddedCounter {
        std::atomic<std::uint64_t> v{0};
        char pad[64 - sizeof(std::atomic<std::uint64_t>)]{};
    };

    IODispatcher*     dispatcher_ = nullptr;  // null => global on start()
    socket_t          sock_       = kInvalidSocket;
    std::uint16_t     bound_port_ = 0;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_flag_{false};
    // Set true by the coroutine just before it returns — stop() waits on this so
    // the socket/buffers outlive the last recvfrom completion.
    std::atomic<bool> rx_done_{true};

    // The detached receive coroutine's handle (owned here; destroyed in stop()
    // after the coroutine reaches its final suspend).
    std::coroutine_handle<> rx_handle_{};

    StunHandler     stun_handler_;
    DatagramHandler datagram_handler_;

    // Preallocated receive buffer (rx coroutine only — no per-packet malloc).
    std::uint8_t rx_buf_[kUdpRecvBufferSize]{};

    // Peer-address out-params for async_recvfrom; live for the transport's
    // lifetime so they outlive each pending recvfrom op.
    sockaddr_storage peer_addr_{};
    socklen_t        peer_len_ = sizeof(sockaddr_storage);

    PaddedCounter rx_count_;
    PaddedCounter tx_count_;
    PaddedCounter drop_count_;
};

}  // namespace net
}  // namespace bolt::api
