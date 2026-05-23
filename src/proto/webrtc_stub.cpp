// src/proto/webrtc_stub.cpp — WebRTC protocol STUB.
//
// Compiled ONLY under BOLTAPI_WITH_WEBRTC (see root CMakeLists). Not present in
// the default build; the live HTTP/1.1+HTTP/2 engine is untouched.
//
// WebRtcProtocol implements IProtocol and returns NotImplemented.
// register_webrtc installs a factory for it into a ProtocolRegistry. This file
// does NOT pull in any FasterAPI webrtc/ source — clean seam stub.
//
// ============================================================================
// REAL WebRTC IMPLEMENTATION PLAN (future dev — NO H1/H2 core edits required)
// ============================================================================
//   1. Signaling (ISignaling): SDP offer/answer + trickle ICE are exchanged
//      out-of-band over the EXISTING H1/H2/WebSocket App routes (e.g. POST
//      /webrtc/offer, or a WebSocket signaling channel). So signaling adds NO
//      new core — it's an App handler that forwards into WebRtcProtocol.
//   2. Transport: media/data path runs over transport::UdpTransport (Datagram),
//      its UDP socket joining the existing net::IODispatcher.
//   3. Connectivity: ICE (candidate gathering + checks) -> DTLS handshake
//      (reuse OpenSSL) -> SCTP association for data channels.
//   4. Data channels (IDataChannel): SCTP-over-DTLS-over-UDP. Each channel is a
//      labelled bidirectional message stream surfaced to the App.
//   Earmarked Bolt pieces (comments only):
//     - bolt::wire (extern/bolt/wire/bolt_wire.h)  : DTLS/SCTP/data-channel framing.
//     - bolt SPSC  (bolt_channel.h / bolt_disruptor.h) : I/O->worker datagram handoff.

#include "boltapi/protocol.h"

#if defined(BOLTAPI_WITH_WEBRTC)

namespace bolt::api {
namespace proto {

namespace {

class WebRtcProtocol final : public IProtocol {
public:
    ProtocolId id() const noexcept override { return ProtocolId::WebRtc; }

    transport::TransportKind transport_kind() const noexcept override {
        return transport::TransportKind::Datagram;  // ICE/DTLS/SCTP over UDP
    }

    Status serve(transport::ITransport& /*source*/) override {
        // SCAFFOLD: no ICE/DTLS/SCTP yet. Real impl wires signaling -> peer
        // connection -> data channels. See plan above.
        return not_implemented();
    }

    void stop() noexcept override { /* nothing running yet */ }
};

}  // namespace

Status register_webrtc(ProtocolRegistry& reg) {
    return reg.register_protocol(
        ProtocolId::WebRtc,
        []() -> std::unique_ptr<IProtocol> {
            return std::make_unique<WebRtcProtocol>();
        });
}

}  // namespace proto
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_WEBRTC
