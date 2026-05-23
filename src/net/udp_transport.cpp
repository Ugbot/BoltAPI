// src/net/udp_transport.cpp — UDP transport on the unified async event loop.
//
// DESIGN: the receive path uses the RAW async_io callback model directly. We
// submit recvfrom_async(fd, slot.buf, &slot.peer_addr, &slot.peer_len, cb,
// &slot); the callback `cb` runs INLINE on the I/O thread inside poll(). It
// demuxes the datagram, handles STUN/control inline (compute + sendto), then
// re-arms another recvfrom_async on the same slot. There is NO coroutine and NO
// per-packet worker handoff. UDP shares the same async I/O loop as TCP/HTTP.
//
// PIPELINING: on a completion backend (IOCP) we keep kUdpRecvInFlight ops
// posted at once so the kernel can deliver the next datagram while we demux the
// previous; each op has its own slot. On a readiness backend (epoll/kqueue) the
// callback drains the socket in a loop per wakeup (batching) and a single armed
// op suffices, but the accounting is uniform across backends.
//
// CLEAN SHUTDOWN: stop() sets an atomic stop flag and closes the socket. The
// close completes every in-flight recvfrom (with an error result); each
// completion runs the callback, which observes the stop flag, does NOT re-arm,
// and decrements in_flight_. stop() waits for in_flight_ to reach zero before
// returning, so the per-slot buffers + peer-addr out-params (which the kernel
// may write) always outlive every in-flight op. No hang, no leak, no
// use-after-free.
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
    io_ = dispatcher_->io_engine();
    if (io_ == nullptr) return false;

    stop_flag_.store(false, std::memory_order_release);
    in_flight_.store(0, std::memory_order_release);
    running_.store(true, std::memory_order_release);

    // Arm the receive path. On a completion backend (IOCP) we post
    // kUdpRecvInFlight concurrent recvfrom ops to pipeline completions; on a
    // readiness backend (epoll/kqueue) the callback drains per wakeup, so a
    // single armed op is enough. The initial arm here may run on a thread other
    // than the I/O thread — recvfrom_async is safe to submit from any thread.
#ifdef _WIN32
    const std::size_t to_arm = kUdpRecvInFlight;
#else
    const std::size_t to_arm = 1;
#endif
    bool any = false;
    for (std::size_t i = 0; i < to_arm; ++i) {
        slots_[i].owner = this;
        if (arm_recv(slots_[i])) any = true;
    }
    if (!any) {
        // Nothing armed (submit failure): unwind cleanly.
        running_.store(false, std::memory_order_release);
        return false;
    }
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

    // Signal the callback to stop re-arming, then close the socket to complete
    // any in-flight recvfrom (each completion runs the callback, which observes
    // the flag and does NOT re-arm). We leave sock_ set until every op has
    // drained so a racing submit targets a (now-invalid) handle that errors out
    // rather than a recycled fd.
    stop_flag_.store(true, std::memory_order_release);
    if (sock_ != kInvalidSocket) {
        // Close THROUGH the engine so any backend per-socket state (e.g. the
        // IOCP association cache) is dropped along with the handle — otherwise a
        // recycled SOCKET value could skip (re-)association. close_async closes
        // the handle, which completes every in-flight recvfrom and unblocks the
        // drain below.
        if (io_ != nullptr) {
            io_->close_async(static_cast<int>(sock_));
        } else {
            sys::close_socket(sock_);
        }
    }

    // Wait for every in-flight recvfrom op to complete and run its callback.
    // The closed socket completes pending ops promptly; bounded spin with a
    // yield so we never busy-burn. After this the per-slot buffers are no longer
    // referenced by any kernel/backend op.
    while (in_flight_.load(std::memory_order_acquire) != 0) {
        std::this_thread::yield();
    }

    sock_       = kInvalidSocket;
    bound_port_ = 0;
}

bool UdpTransport::arm_recv(RecvSlot& slot) noexcept {
    if (io_ == nullptr || sock_ == kInvalidSocket) return false;
    if (stop_flag_.load(std::memory_order_acquire)) return false;

    // Reset the peer-addr capacity for this op (recvfrom out-param).
    slot.peer_len = sizeof(slot.peer_addr);

    // Count the op as in-flight BEFORE submitting so a synchronous-inline
    // completion (which decrements) cannot underflow.
    in_flight_.fetch_add(1, std::memory_order_acq_rel);

    const int rc = io_->recvfrom_async(
        static_cast<int>(sock_), slot.buf, kUdpRecvBufferSize,
        reinterpret_cast<sockaddr*>(&slot.peer_addr), &slot.peer_len,
        [](const core::io_event& ev) noexcept {
            auto* s = static_cast<RecvSlot*>(ev.user_data);
            s->owner->on_recv(*s, ev.result);
        },
        &slot);

    if (rc != 0) {
        // Submit failed outright: this op never reaches a completion, so undo
        // the in-flight bump here.
        in_flight_.fetch_sub(1, std::memory_order_acq_rel);
        return false;
    }
    return true;
}

void UdpTransport::on_recv(RecvSlot& slot, ssize_t n) noexcept {
    // This runs INLINE on the I/O thread inside poll(). On stop, the socket
    // close completes the op with n <= 0; we must NOT touch the (closed) socket
    // and must NOT re-arm — just retire the op.
    if (stop_flag_.load(std::memory_order_acquire)) {
        in_flight_.fetch_sub(1, std::memory_order_acq_rel);
        return;
    }

    if (n > 0) {
        rx_count_.v.fetch_add(1, std::memory_order_relaxed);
        demux(reinterpret_cast<const sockaddr*>(&slot.peer_addr),
              static_cast<int>(slot.peer_len), slot.buf,
              static_cast<std::size_t>(n));
    }

#ifndef _WIN32
    // POSIX readiness backend: the socket is non-blocking and was just readable.
    // Drain it — keep recvfrom'ing until EWOULDBLOCK/EAGAIN — to amortize the
    // epoll/kqueue wakeup over every queued datagram (batching).
    if (n > 0) {
        for (;;) {
            if (stop_flag_.load(std::memory_order_acquire)) {
                in_flight_.fetch_sub(1, std::memory_order_acq_rel);
                return;
            }
            slot.peer_len = sizeof(slot.peer_addr);
            const ssize_t m = ::recvfrom(
                static_cast<int>(sock_),
                reinterpret_cast<char*>(slot.buf), kUdpRecvBufferSize, 0,
                reinterpret_cast<sockaddr*>(&slot.peer_addr), &slot.peer_len);
            if (m <= 0) break;  // EWOULDBLOCK/EAGAIN (or error) -> re-arm below
            rx_count_.v.fetch_add(1, std::memory_order_relaxed);
            demux(reinterpret_cast<const sockaddr*>(&slot.peer_addr),
                  static_cast<int>(slot.peer_len), slot.buf,
                  static_cast<std::size_t>(m));
        }
    }
#endif

    // Re-arm another recvfrom on this slot. CRITICAL ordering for clean stop:
    // arm the NEW op first (it bumps in_flight_), THEN drop THIS op's reference.
    // This keeps in_flight_ from transiently hitting zero while we still touch
    // `this` — otherwise stop() could observe zero and return, racing the very
    // code re-arming on the (about-to-be-destroyed) transport. If the re-arm
    // fails or stop was requested, we simply drop our reference and let stop()
    // proceed once the count settles to zero.
    if (!stop_flag_.load(std::memory_order_acquire)) {
        arm_recv(slot);  // bumps in_flight_ on success
    }
    in_flight_.fetch_sub(1, std::memory_order_acq_rel);  // retire THIS op last
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

}  // namespace net
}  // namespace bolt::api
