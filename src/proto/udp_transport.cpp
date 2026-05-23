// src/proto/udp_transport.cpp — UdpTransport STUB implementation.
//
// Compiled ONLY under BOLTAPI_WITH_HTTP3 || BOLTAPI_WITH_WEBRTC (see root
// CMakeLists). In the default build this TU is not added to the library, so the
// datagram transport simply does not exist in the linked artifact — the live
// HTTP/1.1+HTTP/2 engine is untouched and byte-for-byte unchanged.
//
// This is a STUB: start() returns NotImplemented and no UDP socket is created.
// It does NOT pull in any FasterAPI quic/ or webrtc/ source.
//
// REAL-IMPL PLAN (future dev — does not touch the H1/H2 core):
//   1. Open a UDP socket and register it with the existing async I/O backend
//      (net::IODispatcher over IOCP/epoll/kqueue) so QUIC/WebRTC packet I/O
//      shares the SAME event loop + worker pool the TCP listener uses.
//   2. Batched datagram receive (recvmmsg / IOCP overlapped) into a
//      PREALLOCATED buffer pool — TigerStyle, no per-packet malloc.
//   3. Hand each datagram to the owning IProtocol. Earmarked Bolt pieces:
//        - bolt SPSC channel (extern/bolt: bolt_channel.h / bolt_disruptor.h)
//          for the lock-free I/O-thread -> protocol-worker handoff.
//        - bolt::wire (extern/bolt/wire/bolt_wire.h) for zero-copy packet
//          header framing.

#include "boltapi/transport.h"

#if defined(BOLTAPI_WITH_HTTP3) || defined(BOLTAPI_WITH_WEBRTC)

namespace bolt::api {
namespace transport {

UdpTransport::UdpTransport(Endpoint bind) noexcept : bind_(std::move(bind)) {}

UdpTransport::~UdpTransport() { stop(); }

Status UdpTransport::start() {
    // SCAFFOLD: no socket yet. Real impl binds UDP + joins the IODispatcher.
    return not_implemented();
}

void UdpTransport::stop() noexcept {
    running_ = false;
}

}  // namespace transport
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_HTTP3 || BOLTAPI_WITH_WEBRTC
