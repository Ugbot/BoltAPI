// src/proto/http3_stub.cpp — HTTP/3 protocol STUB.
//
// Compiled ONLY under BOLTAPI_WITH_HTTP3 (see root CMakeLists). Not present in
// the default build; the live HTTP/1.1+HTTP/2 engine is untouched.
//
// Http3Protocol implements IProtocol and returns NotImplemented. register_http3
// installs a factory for it into a ProtocolRegistry. This file does NOT pull in
// any FasterAPI quic/ source — it is a clean seam stub.
//
// ============================================================================
// REAL HTTP/3 IMPLEMENTATION PLAN (future dev — NO H1/H2 core edits required)
// ============================================================================
//   1. Transport: run over transport::UdpTransport (Datagram). The UDP socket
//      joins the existing net::IODispatcher (IOCP/epoll/kqueue) so QUIC packet
//      I/O shares the engine's worker pool — no new threading model.
//   2. QUIC: terminate QUIC (connection IDs, streams, loss recovery, 1-RTT/
//      0-RTT handshake via the existing OpenSSL TLS 1.3 stack — TlsContext
//      already speaks TLS 1.3; QUIC needs the TLS handshake bytes, not a TLS
//      record layer). Map each QUIC bidi stream to one HTTP/3 request/response.
//   3. QPACK: header compression (HTTP/3's HPACK analogue). A new qpack codec
//      sits beside the existing hpack.* — they do not share state.
//   4. Dispatch: decode the request, then call THE SAME App request handler the
//      H1/H2 path uses (CoroHttpRequest -> set_handler coroutine -> CoroHttp
//      Response). HTTP/3 reuses the App/Router/middleware unchanged; only the
//      framing differs. This is why the seam exists.
//   Earmarked Bolt pieces (comments only):
//     - bolt::wire (extern/bolt/wire/bolt_wire.h)  : QUIC/HTTP3 packet framing.
//     - bolt SPSC  (bolt_channel.h / bolt_disruptor.h) : I/O->worker packet handoff.

#include "boltapi/protocol.h"

#if defined(BOLTAPI_WITH_HTTP3)

namespace bolt::api {
namespace proto {

namespace {

class Http3Protocol final : public IProtocol {
public:
    ProtocolId id() const noexcept override { return ProtocolId::Http3; }

    transport::TransportKind transport_kind() const noexcept override {
        return transport::TransportKind::Datagram;  // QUIC over UDP
    }

    Status serve(transport::ITransport& /*source*/) override {
        // SCAFFOLD: no QUIC/QPACK yet. Real impl drives the UdpTransport and
        // bridges decoded requests to the App handler. See plan above.
        return not_implemented();
    }

    void stop() noexcept override { /* nothing running yet */ }
};

}  // namespace

Status register_http3(ProtocolRegistry& reg) {
    return reg.register_protocol(
        ProtocolId::Http3,
        []() -> std::unique_ptr<IProtocol> {
            return std::make_unique<Http3Protocol>();
        });
}

}  // namespace proto
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_HTTP3
