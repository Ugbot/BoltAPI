// boltapi/net/udp_transport.h — real async UDP transport for WebRTC (+ HTTP/3).
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A protocol-agnostic UDP transport that owns its OWN UDP socket and drives its
// receive path INLINE on the engine's unified async event loop (IODispatcher /
// async_io). This is the fastest unified multi-protocol path: the same
// epoll/kqueue/IOCP loop that backs TCP/HTTP also drives UDP datagram I/O — one
// fewer thread, no dedicated select() poller.
//
// ============================================================================
// INLINE FAST PATH (no per-packet worker handoff)
// ============================================================================
// The receive path uses the RAW async_io callback model directly:
//     io.recvfrom_async(fd, buf, src, srclen, callback, this);
// whose `callback` is invoked INLINE on the I/O thread inside poll(). The
// callback demuxes the datagram (RFC 7983 first byte), handles STUN/control
// INLINE (the handler computes the response and sendto's it right there — cheap)
// and then RE-ARMS another recvfrom_async. There is NO coroutine and NO worker
// thread resume on the recv -> demux -> control-response path. This closes the
// regression where the coroutine awaitable bounced EVERY datagram through the
// worker pool (queue + busy-yield + coroutine resume).
//
// On IOCP we keep multiple WSARecvFrom operations in flight concurrently to
// pipeline completions (one in-flight op cannot overlap with demux of the
// previous one); each in-flight op has its OWN receive slot (buffer + sockaddr).
// On POSIX (epoll/kqueue) readiness, the callback DRAINS the socket — recvfrom
// in a loop until EWOULDBLOCK — to amortize the wakeup cost (batching).
//
// HEAVY/HANDOFF HOOK: control packets (STUN) and the recv/demux itself stay on
// the I/O thread (default, inline). The registered datagram handler MAY itself
// dispatch heavy work (DTLS / data-channel) to the worker pool if it needs to —
// that decision lives in the handler, not in the transport hot path.
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
// CLEAN SHUTDOWN: stop() sets an atomic stop flag and closes the socket. The
// close completes every in-flight recvfrom (with an error result); each
// completion runs the callback, which observes the stop flag and does NOT
// re-arm, then decrements the in-flight counter. stop() waits for the in-flight
// counter to reach zero before returning, so the per-slot buffers + sockaddr
// out-params (which the kernel may write into) always outlive every in-flight
// op. No hang, no leak, no use-after-free.
//
// TigerStyle: preallocated per-slot receive buffers, fixed bounds, cache-line-
// padded atomic counters, a clean inline-callback shutdown, no exceptions.

#pragma once

#include "boltapi/net/sys_compat.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/async_io.h"

#include <atomic>
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

// Number of concurrent in-flight receive operations. On a completion-based
// backend (IOCP) keeping several WSARecvFrom ops posted lets the kernel deliver
// the next datagram while we demux the previous one — this pipelines the recv
// path. On a readiness-based backend (epoll/kqueue) we drain the socket in a
// loop per wakeup instead, so a single armed op suffices, but the slot array is
// still sized to this for a uniform shutdown accounting. Keep a small fixed
// bound (TigerStyle). 4 posted receives keep the IOCP completion pipeline busy
// on loopback/echo without the per-op churn of a large pool; measured to be the
// sweet spot (more posted ops added overhead without raising throughput). Each
// slot is ~2 KiB so the array is ~8 KiB.
inline constexpr std::size_t kUdpRecvInFlight = 4;

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
// peer end) plus the payload view. Handlers run INLINE on the I/O thread (inside
// the recvfrom completion callback) — keep them allocation-light; for ICE-lite
// the STUN response is computed + sent inline here, which is cheap and correct.
// A handler that needs to do heavy work (e.g. DTLS) may itself hand off to a
// worker pool; the recv/demux/STUN-response path stays on the I/O thread.
// The payload view (`data`) is only valid for the duration of the call.
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
    // A single in-flight receive op's storage. Each concurrent recvfrom_async
    // points the backend at THIS slot's buffer + peer-addr out-params, which
    // therefore must outlive the op (they live for the transport's lifetime,
    // and stop() waits for all in-flight ops to drain before returning).
    struct alignas(64) RecvSlot {
        UdpTransport*    owner = nullptr;          // back-pointer for the callback
        std::uint8_t     buf[kUdpRecvBufferSize]{};
        sockaddr_storage peer_addr{};
        socklen_t        peer_len = sizeof(sockaddr_storage);
    };

    // Arm one recvfrom_async on `slot`. Safe to call from the I/O thread (re-arm
    // path) or from another thread (initial arm in start()) — recvfrom_async is
    // thread-safe to submit. Returns true if the op was submitted.
    bool arm_recv(RecvSlot& slot) noexcept;

    // Completion callback for a recvfrom op (runs INLINE on the I/O thread).
    void on_recv(RecvSlot& slot, ssize_t n) noexcept;

    void demux(const sockaddr* peer, int peer_len,
               const std::uint8_t* data, std::size_t len) noexcept;

    // Cache-line-padded atomic to avoid false sharing between the counters the
    // rx callback bumps and any reader thread.
    struct alignas(64) PaddedCounter {
        std::atomic<std::uint64_t> v{0};
        char pad[64 - sizeof(std::atomic<std::uint64_t>)]{};
    };

    IODispatcher*     dispatcher_ = nullptr;  // null => global on start()
    core::async_io*   io_         = nullptr;  // resolved from dispatcher on start()
    socket_t          sock_       = kInvalidSocket;
    std::uint16_t     bound_port_ = 0;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_flag_{false};

    // Number of recvfrom ops currently submitted to the backend (incremented on
    // arm, decremented when a completion does NOT re-arm). stop() waits for this
    // to reach zero so the per-slot buffers outlive every in-flight op.
    std::atomic<std::uint32_t> in_flight_{0};

    StunHandler     stun_handler_;
    DatagramHandler datagram_handler_;

    // Preallocated per-op receive slots (no per-packet malloc).
    RecvSlot slots_[kUdpRecvInFlight];

    PaddedCounter rx_count_;
    PaddedCounter tx_count_;
    PaddedCounter drop_count_;
};

}  // namespace net
}  // namespace bolt::api
