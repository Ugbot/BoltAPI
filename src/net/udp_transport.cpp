// src/net/udp_transport.cpp — implementation of the standalone UDP transport.
//
// DESIGN (correctness-first, isolation): the engine's IODispatcher has no UDP
// path and async_io must not be touched, so UdpTransport owns its OWN UDP socket
// and a dedicated receive thread. The thread runs a NON-BLOCKING socket + a
// short select() poll loop with an atomic stop flag — this gives a clean,
// portable, hang-free shutdown on both winsock and POSIX (a blocking recvfrom
// would otherwise need a self-pipe / socket-shutdown wakeup; the poll loop is
// simpler and provably terminates within one poll interval).
//
// Compiled UNCONDITIONALLY into boltapi (no engine deps).

#include "boltapi/net/udp_transport.h"

#include <cstring>

namespace bolt::api {
namespace net {

namespace {

// Poll timeout for the receive loop: short enough that stop() returns quickly,
// long enough not to spin. 50ms is imperceptible at shutdown and idle-cheap.
inline constexpr long kPollTimeoutMicros = 50 * 1000;  // 50 ms

// RFC 7983 first-byte classification.
enum class PacketKind : std::uint8_t { Stun, Dtls, Drop };

inline PacketKind classify(std::uint8_t first_byte) noexcept {
    if (first_byte <= 3) return PacketKind::Stun;             // 0..3   => STUN
    if (first_byte >= 20 && first_byte <= 63) return PacketKind::Dtls;  // 20..63 => DTLS
    return PacketKind::Drop;                                  // else   => drop
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

    // Non-blocking so the receive loop can poll + check the stop flag.
    if (sys::set_nonblocking(s) != 0) {
        sys::close_socket(s);
        sock_       = kInvalidSocket;
        bound_port_ = 0;
        return false;
    }

    sock_ = s;
    return true;
}

bool UdpTransport::start() noexcept {
    if (sock_ == kInvalidSocket) return false;
    if (running_.load(std::memory_order_acquire)) return false;
    stop_flag_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);
    rx_thread_ = std::thread([this]() noexcept { receive_loop(); });
    return true;
}

void UdpTransport::stop() noexcept {
    // Signal the loop to exit and join it before closing the socket so the rx
    // thread never touches a closed handle. Idempotent.
    stop_flag_.store(true, std::memory_order_release);
    if (rx_thread_.joinable()) {
        rx_thread_.join();
    }
    running_.store(false, std::memory_order_release);
    if (sock_ != kInvalidSocket) {
        sys::close_socket(sock_);
        sock_       = kInvalidSocket;
        bound_port_ = 0;
    }
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

void UdpTransport::receive_loop() noexcept {
    while (!stop_flag_.load(std::memory_order_acquire)) {
        // select() with a short timeout so we re-check the stop flag promptly.
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_, &rfds);
        timeval tv{};
        tv.tv_sec  = 0;
        tv.tv_usec = kPollTimeoutMicros;

        // On POSIX nfds must be the highest fd + 1; winsock ignores it.
#ifdef _WIN32
        const int nfds = 0;
#else
        const int nfds = static_cast<int>(sock_) + 1;
#endif
        const int ready = ::select(nfds, &rfds, nullptr, nullptr, &tv);
        if (ready <= 0) continue;  // timeout (0) or error (<0); re-check stop

        // Drain everything currently readable (a single select wake may carry
        // multiple datagrams). Non-blocking recvfrom returns EWOULDBLOCK when
        // empty, which ends the inner loop.
        for (;;) {
            sockaddr_storage src{};
            socklen_t        src_len = sizeof(src);
            const ssize_t n = ::recvfrom(
                sock_, reinterpret_cast<char*>(rx_buf_),
                static_cast<int>(kUdpRecvBufferSize), 0,
                reinterpret_cast<sockaddr*>(&src), &src_len);
            if (n <= 0) break;  // would-block / error -> back to select

            rx_count_.v.fetch_add(1, std::memory_order_relaxed);

            const auto* peer = reinterpret_cast<const sockaddr*>(&src);
            const int   plen = static_cast<int>(src_len);
            const std::size_t len = static_cast<std::size_t>(n);

            switch (classify(rx_buf_[0])) {
                case PacketKind::Stun:
                    if (stun_handler_) {
                        stun_handler_(peer, plen, rx_buf_, len);
                    } else {
                        drop_count_.v.fetch_add(1, std::memory_order_relaxed);
                    }
                    break;
                case PacketKind::Dtls:
                    if (datagram_handler_) {
                        datagram_handler_(peer, plen, rx_buf_, len);
                    } else {
                        // No DTLS path yet (next wave) — drop with a counter.
                        drop_count_.v.fetch_add(1, std::memory_order_relaxed);
                    }
                    break;
                case PacketKind::Drop:
                default:
                    drop_count_.v.fetch_add(1, std::memory_order_relaxed);
                    break;
            }
        }
    }
}

}  // namespace net
}  // namespace bolt::api
