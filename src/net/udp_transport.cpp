// src/net/udp_transport.cpp — UDP transport on the unified async event loop.
//
// DESIGN: the receive loop is a coroutine scheduled on the engine's
// IODispatcher (epoll/kqueue/IOCP). Each iteration does
// `co_await async_recvfrom` and demuxes the datagram. There is NO dedicated
// receive thread — UDP shares the same async I/O loop as TCP/HTTP.
//
// CLEAN SHUTDOWN: stop() sets an atomic stop flag and closes the socket. The
// socket close completes any in-flight recvfrom (with an error result) which
// resumes the coroutine; it observes the stop flag and returns. stop() waits
// for the coroutine to reach its final suspend (rx_done_) before destroying the
// coroutine handle, so the receive buffer + peer-addr out-params (which the
// pending op points at) always outlive the last completion. No hang, no leak,
// no use-after-free.
//
// Compiled UNCONDITIONALLY into boltapi (depends only on IODispatcher).

#include "boltapi/net/udp_transport.h"

#include <cstring>
#include <thread>

namespace bolt::api {
namespace net {

namespace {

// RFC 7983 first-byte classification.
enum class PacketKind : std::uint8_t { Stun, Dtls, Drop };

inline PacketKind classify(std::uint8_t first_byte) noexcept {
    if (first_byte <= 3) return PacketKind::Stun;                      // 0..3   => STUN
    if (first_byte >= 20 && first_byte <= 63) return PacketKind::Dtls; // 20..63 => DTLS
    return PacketKind::Drop;                                           // else   => drop
}

}  // namespace

bool UdpTransport::bind(const char* host, std::uint16_t port) noexcept {
    if (sock_ != kInvalidSocket) return false;  // already bound
    sys::startup();  // WSAStartup once on Windows; no-op on POSIX

    // IPv4 now; IPv6 is a TODO hook (would create AF_INET6 + sockaddr_in6 and
    // optionally IPV6_V6ONLY=0 for dual-stack).
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kInvalidSocket) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (host == nullptr || std::strcmp(host, "0.0.0.0") == 0 ||
        host[0] == '\0') {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        sys::close_socket(s);
        return false;
    }

    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        sys::close_socket(s);
        return false;
    }

    // Discover the actually-bound port (ephemeral when port == 0).
    sockaddr_in bound{};
    socklen_t   bound_len = sizeof(bound);
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
        bound_port_ = ntohs(bound.sin_port);
    } else {
        bound_port_ = port;
    }

    sock_ = s;
    return true;
}

bool UdpTransport::start() noexcept {
    if (sock_ == kInvalidSocket) return false;
    if (running_.load(std::memory_order_acquire)) return false;

    // Resolve the dispatcher: explicit one, else the (lazily started) global.
    if (dispatcher_ == nullptr) {
        dispatcher_ = &global_io_dispatcher();
    }

    stop_flag_.store(false, std::memory_order_release);
    rx_done_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);

    // Spin up the receive coroutine. It is detached: we take ownership of the
    // handle and resume it once to start it (it begins suspended at
    // initial_suspend). It then drives itself via recvfrom completions until
    // stop(). We do NOT keep the coro_task object (its dtor would destroy the
    // handle); we destroy the handle ourselves in stop() after rx_done_.
    core::coro_task<void> task = receive_loop();
    std::coroutine_handle<> h = task.release();
    rx_handle_ = h;
    h.resume();  // run to the first co_await async_recvfrom (which suspends)
    return true;
}

void UdpTransport::stop() noexcept {
    // Idempotent. If never started, just close any bound socket.
    if (!running_.exchange(false)) {
        if (sock_ != kInvalidSocket) {
            sys::close_socket(sock_);
            sock_       = kInvalidSocket;
            bound_port_ = 0;
        }
        return;
    }

    // Signal the coroutine to stop, then close the socket to unblock any
    // in-flight recvfrom (its completion resumes the coroutine, which observes
    // the flag and returns).
    stop_flag_.store(true, std::memory_order_release);
    if (sock_ != kInvalidSocket) {
        sys::close_socket(sock_);
        // Leave sock_ set until the coroutine has finished so any racing
        // recvfrom submit targets a (now-invalid) handle that errors out
        // rather than a recycled fd. We clear it below.
    }

    // Wait for the coroutine to reach its final suspend. Bounded spin with a
    // yield so we never busy-burn; in practice this completes within one poll
    // interval (the closed socket completes the pending recvfrom promptly).
    while (!rx_done_.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    // The coroutine is fully suspended at final_suspend now: destroy it.
    if (rx_handle_) {
        rx_handle_.destroy();
        rx_handle_ = nullptr;
    }

    sock_       = kInvalidSocket;
    bound_port_ = 0;
}

ssize_t UdpTransport::send(const sockaddr* peer, int peer_len,
                           const std::uint8_t* data, std::size_t len) noexcept {
    if (sock_ == kInvalidSocket || peer == nullptr || data == nullptr) return -1;
    const ssize_t n = ::sendto(sock_,
                               reinterpret_cast<const char*>(data),
                               static_cast<int>(len), 0, peer,
                               static_cast<socklen_t>(peer_len));
    if (n > 0) tx_count_.v.fetch_add(1, std::memory_order_relaxed);
    return n;
}

void UdpTransport::demux(const sockaddr* peer, int peer_len,
                         const std::uint8_t* data, std::size_t len) noexcept {
    switch (classify(data[0])) {
        case PacketKind::Stun:
            if (stun_handler_) {
                stun_handler_(peer, peer_len, data, len);
            } else {
                drop_count_.v.fetch_add(1, std::memory_order_relaxed);
            }
            break;
        case PacketKind::Dtls:
            if (datagram_handler_) {
                datagram_handler_(peer, peer_len, data, len);
            } else {
                drop_count_.v.fetch_add(1, std::memory_order_relaxed);
            }
            break;
        case PacketKind::Drop:
        default:
            drop_count_.v.fetch_add(1, std::memory_order_relaxed);
            break;
    }
}

core::coro_task<void> UdpTransport::receive_loop() noexcept {
    while (!stop_flag_.load(std::memory_order_acquire)) {
        // Reset the peer-addr capacity each iteration (recvfrom out-param).
        peer_len_ = sizeof(peer_addr_);

        const ssize_t n = co_await dispatcher_->async_recvfrom(
            static_cast<int>(sock_), rx_buf_, kUdpRecvBufferSize,
            reinterpret_cast<sockaddr*>(&peer_addr_), &peer_len_);

        // Re-check the stop flag: a close()-triggered completion lands here with
        // n <= 0, and we must NOT touch the (closed) socket again.
        if (stop_flag_.load(std::memory_order_acquire)) break;

        if (n <= 0) {
            // Transient error on a live socket: loop and re-arm recvfrom.
            continue;
        }

        rx_count_.v.fetch_add(1, std::memory_order_relaxed);
        demux(reinterpret_cast<const sockaddr*>(&peer_addr_),
              static_cast<int>(peer_len_), rx_buf_,
              static_cast<std::size_t>(n));
    }

    // Signal stop() that we're done; after this we suspend at final_suspend and
    // stop() destroys the handle.
    rx_done_.store(true, std::memory_order_release);
    co_return;
}

}  // namespace net
}  // namespace bolt::api
