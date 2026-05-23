// boltapi/net/udp_transport.h — real async UDP transport for WebRTC (+ HTTP/3).
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A standalone, protocol-agnostic UDP transport that owns its OWN UDP socket
// and a dedicated receive-loop thread. It is DELIBERATELY independent of the
// engine's IODispatcher / async_io coroutine machinery:
//
//   * The engine's IODispatcher exposes only read/write/accept/connect
//     awaitables — there is NO recvfrom/sendto datagram path, and we MUST NOT
//     modify it (it backs the live HTTP/1.1+HTTP/2 server). So UdpTransport
//     runs its own non-blocking-socket + short-poll receive loop on a private
//     thread, fully isolated from the HTTP core.
//
// DEMUX (RFC 7983, by the first byte of each datagram):
//   * 0..3    -> STUN  -> routed to the registered STUN handler (the IceAgent).
//   * 20..63  -> DTLS  -> routed to the registered datagram handler (none yet
//                         in this wave; dropped with a counter).
//   * else    -> dropped with a counter.
//
// SEND: send(peer, data, len) -> a single sendto on the owned socket. Safe to
// call from any thread (sendto is thread-safe per-socket on both winsock and
// POSIX for distinct buffers).
//
// COMPILED UNCONDITIONALLY into boltapi: it has no engine deps and zero runtime
// cost unless start()ed, so the DEFAULT test suite covers it. Only the App-level
// "start WebRTC serving" wiring lives behind BOLTAPI_WITH_WEBRTC.
//
// TigerStyle: preallocated receive buffer, fixed bounds, cache-line-padded
// atomic counters, a clean thread shutdown (atomic stop flag + non-blocking
// poll loop — no hang, no leak), no exceptions.

#pragma once

#include "boltapi/net/sys_compat.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <new>
#include <string>
#include <thread>

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
// peer end) plus the payload view. Handlers run ON the receive thread — keep
// them allocation-light; for ICE-lite the STUN response is computed + sent
// inline here, which is cheap and correct.
// ----------------------------------------------------------------------------
using StunHandler = std::function<void(const sockaddr* peer, int peer_len,
                                       const std::uint8_t* data,
                                       std::size_t len)>;
using DatagramHandler = std::function<void(const sockaddr* peer, int peer_len,
                                           const std::uint8_t* data,
                                           std::size_t len)>;

// ----------------------------------------------------------------------------
// UdpTransport — owns a UDP socket + a private receive thread.
// ----------------------------------------------------------------------------
class UdpTransport {
public:
    UdpTransport() noexcept = default;
    ~UdpTransport() { stop(); }

    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    // Bind a UDP socket to host:port (IPv4). Pass port 0 for an ephemeral port;
    // bound_port() then reports the OS-assigned port. Idempotent failure-safe:
    // on error returns false and leaves the transport unbound. IPv6 is a TODO
    // hook (see bind()).
    bool bind(const char* host, std::uint16_t port) noexcept;

    // Start the receive thread. Requires a successful bind() first. Returns
    // false if not bound or already running.
    bool start() noexcept;

    // Stop the receive thread and close the socket. Idempotent, noexcept, joins
    // the thread cleanly (the stop flag breaks the poll loop within one poll
    // interval). No hang, no leak.
    void stop() noexcept;

    bool is_running() const noexcept { return running_.load(std::memory_order_acquire); }

    // The actually-bound local port (valid after bind()); 0 if unbound.
    std::uint16_t bound_port() const noexcept { return bound_port_; }

    // Send a datagram to `peer`. Thread-safe. Returns the bytes sent or -1.
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
    void receive_loop() noexcept;

    // Cache-line-padded atomic to avoid false sharing between the counters the
    // rx thread bumps and any reader thread.
    struct alignas(64) PaddedCounter {
        std::atomic<std::uint64_t> v{0};
        char pad[64 - sizeof(std::atomic<std::uint64_t>)]{};
    };

    socket_t          sock_       = kInvalidSocket;
    std::uint16_t     bound_port_ = 0;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_flag_{false};
    std::thread       rx_thread_;

    StunHandler     stun_handler_;
    DatagramHandler datagram_handler_;

    // Preallocated receive buffer (rx thread only — no per-packet malloc).
    std::uint8_t rx_buf_[kUdpRecvBufferSize]{};

    PaddedCounter rx_count_;
    PaddedCounter tx_count_;
    PaddedCounter drop_count_;
};

}  // namespace net
}  // namespace bolt::api
