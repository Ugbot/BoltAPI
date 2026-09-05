// boltapi/protocol.h — the IProtocol seam + ProtocolRegistry extension point.
//
// ============================================================================
// THE SEAM (upper half; the lower half is transport.h's ITransport)
// ============================================================================
// This defines HOW a protocol drives a connection over an ITransport, and the
// REGISTRY through which new protocols (HTTP/3, WebRTC) are plugged in WITHOUT
// editing the live HTTP/1.1 + HTTP/2 core.
//
// BUILT-IN vs EXTENSION:
//   * HTTP/1.1 and HTTP/2 are the BUILT-IN protocols. They keep their current
//     DIRECT dispatch inside the engine (CoroUnifiedServer over a TCP+TLS
//     stream, ALPN choosing h2 vs http/1.1). They are deliberately NOT
//     retrofitted onto IProtocol — doing so would mean touching the working
//     core, which M3 forbids. We register *placeholder* identities for them in
//     the registry only so ProtocolId is total and introspection is honest;
//     `has(Http11)`/`has(Http2)` report "built-in" rather than a usable factory.
//   * HTTP/3 and WebRTC are EXTENSION protocols. They are added purely by
//     registering a factory here. Filling them in later is "write a real
//     IProtocol + register its factory" — no core edits.
//
// All of this is ADDITIVE M3 scaffold. Default build (flags OFF) does not link
// any stub TU; the registry itself is header-only and inert until something
// registers a factory. When the flags are ON the H3/WebRTC factories register
// stubs that return NotImplemented.
//
// TigerStyle: bounded fixed-capacity registry (NO std::map / no hashing / no
// per-entry heap node), no exceptions, asserts on the bounds.

#pragma once

#include "boltapi/core/result.h"
#include "boltapi/transport.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace bolt::api {
namespace proto {

// Reuse the transport seam's Status / NotImplemented vocabulary so the whole
// seam speaks one result language.
using Status = transport::Status;
using transport::is_not_implemented;
using transport::not_implemented;
using transport::ok_status;

// ----------------------------------------------------------------------------
// ProtocolId — the closed set of protocols the seam knows about.
//
// Http11/Http2 are BUILT-IN (engine direct dispatch). Http3/WebRtc are the
// EXTENSION points this seam exists to enable.
// ----------------------------------------------------------------------------
enum class ProtocolId : std::uint8_t {
    Http11 = 0,
    Http2  = 1,
    Http3  = 2,
    WebRtc = 3,
    // Neo4j's CLIENT WIRE PROTOCOL (raw TCP, its own handshake + chunk framing
    // + PackStream). Unrelated to extern/bolt, our columnar core -- the two
    // just share a word. An EXTENSION protocol like Http3/WebRtc: gated by
    // BOLTAPI_WITH_NEO4J_BOLT, registered via a factory, no core dispatch edit.
    Neo4jBolt = 4,
};

// Number of distinct ProtocolId values — sizes the bounded registry. Update
// alongside the enum (TigerStyle: the bound is explicit, asserted below).
inline constexpr std::size_t kProtocolIdCount = 5;

inline constexpr const char* protocol_name(ProtocolId id) noexcept {
    switch (id) {
        case ProtocolId::Http11: return "HTTP/1.1";
        case ProtocolId::Http2:  return "HTTP/2";
        case ProtocolId::Http3:  return "HTTP/3";
        case ProtocolId::WebRtc: return "WebRTC";
        case ProtocolId::Neo4jBolt: return "Neo4j-Bolt";
    }
    return "?";
}

// ----------------------------------------------------------------------------
// IProtocol — drive one protocol's connection handling over an ITransport.
//
// The virtual surface is intentionally MINIMAL — just enough that a future H3
// or WebRTC implementation has a clear contract, while the built-in H1/H2 are
// NOT forced through it:
//
//   id()                     which protocol this is.
//   transport_kind()         what transport family it requires (Stream/Datagram)
//                            — H3/WebRTC require Datagram (UdpTransport).
//   serve(ITransport&)       bind this protocol to a started transport and run
//                            its connection handling. Stubs return
//                            not_implemented(); a real impl drives accept/recv
//                            -> per-connection state machine -> the SAME App
//                            request handler the H1/H2 path uses.
//   stop()                   stop serving; idempotent, noexcept.
//
// `serve` is synchronous-shaped in the scaffold (returns Status). The real
// implementation will spawn coroutines on the shared worker pool exactly like
// the TCP listener does; the seam does not prescribe that here to avoid pulling
// engine internals into the contract.
// ----------------------------------------------------------------------------
class IProtocol {
public:
    virtual ~IProtocol() = default;

    virtual ProtocolId id() const noexcept = 0;
    virtual transport::TransportKind transport_kind() const noexcept = 0;

    // Bind to a (started) transport and run. Stub => not_implemented().
    virtual Status serve(transport::ITransport& source) = 0;

    // Stop serving. Idempotent. Must not throw.
    virtual void stop() noexcept = 0;

protected:
    IProtocol() = default;
    IProtocol(const IProtocol&) = default;
    IProtocol& operator=(const IProtocol&) = default;
};

// Factory: produce a fresh IProtocol instance. Owned by the caller (the App /
// server wiring), so a unique_ptr. std::function is fine here — factories are
// registered once at startup, never in a hot path.
using ProtocolFactory = std::function<std::unique_ptr<IProtocol>()>;

// ----------------------------------------------------------------------------
// ProtocolRegistry — the extension point.
//
// A REAL, usable registry: register a factory for a ProtocolId, then create()
// an instance later. Filling in HTTP/3 is "register a real factory" — nothing
// else in this file changes.
//
// Bounded fixed-capacity storage (TigerStyle): an array indexed by
// ProtocolId, NOT a std::map. O(1) lookup, zero hashing, zero heap nodes. The
// only allocation is whatever the user's stored std::function/unique_ptr does,
// and only at register/create time.
//
// Built-in note: Http11/Http2 are served by the engine directly and normally
// have NO factory registered. has()/create() therefore report them absent here;
// that is correct — the registry tracks EXTENSION protocols, and the built-ins
// are reported via is_builtin().
// ----------------------------------------------------------------------------
class ProtocolRegistry {
public:
    ProtocolRegistry() = default;

    ProtocolRegistry(const ProtocolRegistry&) = delete;
    ProtocolRegistry& operator=(const ProtocolRegistry&) = delete;

    // Is this protocol served by the built-in engine (direct dispatch)?
    static constexpr bool is_builtin(ProtocolId id) noexcept {
        return id == ProtocolId::Http11 || id == ProtocolId::Http2;
    }

    // Register (or replace) the factory for `id`. Returns ok on success.
    // Asserts the index is in bounds and the factory is non-null (TigerStyle).
    Status register_protocol(ProtocolId id, ProtocolFactory factory) {
        const std::size_t i = index_of(id);
        assert(i < kProtocolIdCount);
        assert(static_cast<bool>(factory));
        if (i >= kProtocolIdCount || !factory) {
            return Status(core::error_code::invalid_state);
        }
        factories_[i] = std::move(factory);
        present_[i] = true;
        ++count_;
        return ok_status();
    }

    // Is there a usable factory registered for `id`?
    bool has(ProtocolId id) const noexcept {
        const std::size_t i = index_of(id);
        return i < kProtocolIdCount && present_[i];
    }

    // Create an instance, or nullptr if no factory is registered for `id`.
    std::unique_ptr<IProtocol> create(ProtocolId id) const {
        const std::size_t i = index_of(id);
        assert(i < kProtocolIdCount);
        if (i >= kProtocolIdCount || !present_[i]) {
            return nullptr;
        }
        assert(static_cast<bool>(factories_[i]));
        return factories_[i]();
    }

    // How many factories are registered.
    std::size_t size() const noexcept { return count_; }

private:
    static constexpr std::size_t index_of(ProtocolId id) noexcept {
        return static_cast<std::size_t>(id);
    }

    ProtocolFactory factories_[kProtocolIdCount]{};
    bool            present_[kProtocolIdCount]{};
    std::size_t     count_ = 0;
};

// ----------------------------------------------------------------------------
// WebRTC interface SKETCHES (declarations only — M3 scaffold).
//
// WebRTC needs more than a byte/datagram pump: it needs out-of-band signaling
// (SDP offer/answer exchange, usually over the existing HTTP/WebSocket path)
// and, once the peer connection is up, data channels (SCTP-over-DTLS-over-UDP).
// These are declared so the contract is visible; no implementation exists.
//
// REAL-IMPL PLAN (future dev):
//   * ISignaling rides the EXISTING H1/H2/WebSocket App routes (e.g. a POST
//     /webrtc/offer handler) — so signaling needs NO new core, it's just an
//     App handler that calls into the WebRtcProtocol.
//   * The media/data path uses UdpTransport (datagram) + ICE + DTLS + SCTP.
//   * IDataChannel messages can be framed with bolt::wire and handed across the
//     I/O<->worker boundary with a bolt SPSC channel (same earmark as H3).
// ----------------------------------------------------------------------------

// Out-of-band signaling channel (SDP/ICE exchange). Rides existing transports.
class ISignaling {
public:
    virtual ~ISignaling() = default;

    // Handle a received SDP offer; produce an answer into `out_answer`.
    // Stub => not_implemented().
    virtual Status on_offer(const char* sdp_offer, std::size_t len,
                            std::string& out_answer) = 0;

    // Handle a trickled ICE candidate. Stub => not_implemented().
    virtual Status on_ice_candidate(const char* candidate, std::size_t len) = 0;

protected:
    ISignaling() = default;
};

// An established WebRTC data channel (SCTP-over-DTLS). Send/receive messages.
class IDataChannel {
public:
    virtual ~IDataChannel() = default;

    virtual const char* label() const noexcept = 0;

    // Send a (possibly binary) message. Stub => not_implemented().
    virtual Status send(const void* data, std::size_t len) = 0;

    // Close the channel. Idempotent, noexcept.
    virtual void close() noexcept = 0;

protected:
    IDataChannel() = default;
};

// ----------------------------------------------------------------------------
// Factory registration entry points for the extension protocols.
//
// DECLARED ALWAYS so the App hook / tests can name them. DEFINED only under
// the matching compile flag (src/proto/http3_stub.cpp, webrtc_stub.cpp). When
// the flag is OFF the symbol is absent — the App hook is compiled out under the
// same flag, and the seam test only calls these inside #if guards.
// ----------------------------------------------------------------------------
#if defined(BOLTAPI_WITH_HTTP3)
// Registers a stub Http3Protocol factory into `reg`. Returns ok on success.
Status register_http3(ProtocolRegistry& reg);
#endif

#if defined(BOLTAPI_WITH_WEBRTC)
// Registers a stub WebRtcProtocol factory into `reg`. Returns ok on success.
Status register_webrtc(ProtocolRegistry& reg);
#endif

// The Neo4j-Bolt registration entry point lives in proto/neo4j_bolt.h because,
// unlike the H3/WebRTC stubs, it needs the caller's executor + config. Include
// that header under BOLTAPI_WITH_NEO4J_BOLT to reach it.

}  // namespace proto
}  // namespace bolt::api
