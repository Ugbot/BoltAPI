// boltapi/transport.h — the ITransport seam.
//
// ============================================================================
// WHAT THIS IS (and what it is NOT)
// ============================================================================
// ITransport is the *byte/datagram source* a protocol runs over. It is the
// lower half of the M3 extensibility seam:
//
//     ITransport   (this file)  — where bytes/datagrams come from
//     IProtocol    (protocol.h) — how a protocol drives a connection over them
//     ProtocolReg. (protocol.h) — the extension-point registry for new protocols
//
// This is ADDITIVE, ARCHITECTURE-ONLY scaffolding for milestone M3. It does NOT
// touch — and is not wired into — the live HTTP/1.1 + HTTP/2 + TLS + WebSocket +
// SSE engine (`server/coro_unified_server.*`, `App`). The default build (both
// BOLTAPI_WITH_HTTP3 and BOLTAPI_WITH_WEBRTC OFF) is byte-for-byte unchanged in
// behavior: nothing here is compiled into a TU the default `boltapi` library
// links, and even when ON these are inert stubs returning NotImplemented.
//
// ============================================================================
// HOW THE LIVE ENGINE MAPS ONTO THIS SEAM (documentation only — do NOT refactor)
// ============================================================================
// The existing stream stack already *conceptually* satisfies the stream form of
// ITransport. We document the mapping so a future H3/WebRTC dev sees the shape
// the seam was modelled on, WITHOUT us retrofitting the live listener:
//
//   ITransport (stream form)        live engine equivalent
//   ------------------------        -----------------------------------------
//   start()/stop()                  CoroTcpListener::start()/stop()
//   "accept a connection"           CoroTcpListener accept loop -> client fd,
//                                   handed to a CoroConnectionHandler coroutine
//   transport kind = Stream         a connected TCP byte stream
//   TLS wrapping                    net::TlsContext (ALPN h2/http1.1) wraps the
//                                   accepted fd into a TLS byte stream; ALPN is
//                                   exactly the "which IProtocol?" decision for
//                                   the stream family today (h2 vs http/1.1),
//                                   made inline by the engine.
//
// HTTP/1.1 and HTTP/2 keep their current DIRECT dispatch inside the engine.
// They are the BUILT-IN protocols; they are not retrofitted onto IProtocol.
// The seam exists so the NEW datagram protocols (HTTP/3, WebRTC) can be added
// over a NEW datagram transport (UdpTransport) without editing that core.
//
// TigerStyle: bounded, no exceptions, no hidden allocation in the interface.

#pragma once

#include "boltapi/core/result.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace bolt::api {
namespace transport {

// ----------------------------------------------------------------------------
// Status: the seam's NotImplemented-aware result type.
//
// Reuses core::error_code so seam code interops with the rest of the codebase.
// `not_implemented` is mapped onto core::error_code::not_ready (the closest
// existing semantic: "the mechanism exists but cannot serve yet"). We expose a
// named helpers so call sites read intent-fully rather than leaning on the
// generic enum value.
// ----------------------------------------------------------------------------
using Status = core::result<void>;

// The canonical "scaffold present, real impl pending" status. Stubs return this.
inline Status not_implemented() noexcept {
    return Status(core::error_code::not_ready);
}

inline Status ok_status() noexcept { return Status(); }

// True iff `s` is the seam's NotImplemented sentinel.
inline bool is_not_implemented(const Status& s) noexcept {
    return s.is_err() && s.error() == core::error_code::not_ready;
}

// ----------------------------------------------------------------------------
// TransportKind — does a transport deliver a continuous byte stream or discrete
// datagrams? This is the single most load-bearing property a protocol needs:
//   * Stream   : TCP (+TLS). HTTP/1.1, HTTP/2 run here (built-in).
//   * Datagram : UDP. HTTP/3 (QUIC) and WebRTC (ICE/DTLS/SCTP) run here.
// ----------------------------------------------------------------------------
enum class TransportKind : std::uint8_t {
    Stream   = 0,  // ordered, reliable byte stream (TCP/TLS)
    Datagram = 1,  // unordered, unreliable messages (UDP)
};

// ----------------------------------------------------------------------------
// Endpoint — a bind/peer address. Kept tiny and owning-string-free in the hot
// path is a later concern; for the scaffold a small owned host + port is fine
// (transports are created once, not per packet).
// ----------------------------------------------------------------------------
struct Endpoint {
    std::string host = "0.0.0.0";
    std::uint16_t port = 0;
};

// ----------------------------------------------------------------------------
// ITransport — the abstract byte/datagram source.
//
// Lifecycle:    start() -> (accept/receive activity) -> stop().
// Family query: kind() tells a protocol whether to expect streams or datagrams.
//
// The accept/receive notion is intentionally MINIMAL and family-agnostic at the
// interface level; concrete transports expose the family-appropriate primitive
// (a stream transport yields accepted connections; a datagram transport yields
// received datagrams). The seam keeps the *contract* small so the live stream
// listener can be described by it without being rewritten, and so the future
// UdpTransport has a clear shape to implement.
//
// No exceptions (the project builds -fno-exceptions / EHsc-minimal); all
// fallible operations return Status.
// ----------------------------------------------------------------------------
class ITransport {
public:
    virtual ~ITransport() = default;

    // Begin listening / binding. Returns ok_status() on success. Stubs return
    // not_implemented().
    virtual Status start() = 0;

    // Stop and release resources. Idempotent. noexcept: teardown must not throw.
    virtual void stop() noexcept = 0;

    // Stream vs datagram. Drives which receive primitive a protocol uses.
    virtual TransportKind kind() const noexcept = 0;

    // Where this transport is bound. Valid after a successful start().
    virtual const Endpoint& local_endpoint() const noexcept = 0;

    // Is the transport currently active (post-start, pre-stop)?
    virtual bool is_running() const noexcept = 0;

protected:
    ITransport() = default;
    ITransport(const ITransport&) = default;
    ITransport& operator=(const ITransport&) = default;
};

// ----------------------------------------------------------------------------
// UdpTransport — the datagram transport for HTTP/3 and WebRTC.
//
// DECLARED ALWAYS (so headers/registry/tests can name the type and the build
// surface is stable), but its IMPLEMENTATION is compiled ONLY under
// BOLTAPI_WITH_HTTP3 || BOLTAPI_WITH_WEBRTC (see src/proto/udp_transport.cpp).
// In the default build the methods are unavailable to link (no datagram TU is
// added to the library), and even when compiled they are STUBS returning
// not_implemented() — there is no real UDP socket loop here yet.
//
// REAL-IMPL PLAN (future dev — does NOT touch the H1/H2 core):
//   * Bind a UDP socket via the existing IODispatcher/async_io backend
//     (IOCP on Windows, epoll/kqueue elsewhere) — the SAME event loop the TCP
//     listener uses, so QUIC/WebRTC packet I/O shares the worker pool.
//   * recvmmsg-style batched datagram receive into a preallocated buffer pool
//     (TigerStyle: no per-packet malloc).
//   * Hand received datagrams to the owning IProtocol. A bolt SPSC channel
//     (extern/bolt: bolt_channel.h / bolt_disruptor.h) is the earmarked
//     lock-free handoff from the I/O thread to the protocol worker.
//   * bolt::wire (extern/bolt/wire/bolt_wire.h) is earmarked for zero-copy
//     packet header framing/parsing.
// ----------------------------------------------------------------------------
class UdpTransport final : public ITransport {
public:
    explicit UdpTransport(Endpoint bind) noexcept;
    ~UdpTransport() override;

    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    Status start() override;
    void stop() noexcept override;
    TransportKind kind() const noexcept override { return TransportKind::Datagram; }
    const Endpoint& local_endpoint() const noexcept override { return bind_; }
    bool is_running() const noexcept override { return running_; }

private:
    Endpoint bind_;
    bool running_ = false;
};

}  // namespace transport
}  // namespace bolt::api
