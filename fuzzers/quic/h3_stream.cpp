// h3_stream — HTTP/3 server over an established QUIC connection.
//
// After a real handshake, the server gets an H3Connection exactly as App wires
// it (attach + request handler + send_settings). The fuzz input is a list of
// stream writes (stream selector, FIN, bytes) and DATAGRAM payloads that the
// real client seals as 1-RTT STREAM/DATAGRAM frames. That reaches the uni-stream
// classifier, QPACK encoder-stream + field-section decoding, H3 frame parsing,
// request assembly and the WebTransport detection paths.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "boltapi/http3/h3_connection.h"
#include "fuzz_input.h"
#include "quic_pair.h"

namespace q = bolt::api::quic;
namespace h3 = bolt::api::http3;
using boltapi_fuzz::Input;

namespace {

constexpr std::size_t kMaxOps = 64;
constexpr std::size_t kStreamSlots = 12;

struct Harness {
    boltapi_fuzz::Pair pair;
    h3::H3Connection h3;
    std::uint64_t offset[kStreamSlots] = {};
    bool finned[kStreamSlots] = {};
};

// Slots 0..7: client bidi (0,4,..28); 8..11: client uni (2,6,10,14).
std::uint64_t stream_id(std::size_t slot) {
    assert(slot < kStreamSlots && "stream slot out of range");
    return slot < 8 ? slot * 4 : 2 + (slot - 8) * 4;
}

void send_stream(Harness& h, Input& in) {
    const std::uint8_t sel = in.u8();
    const std::size_t slot = sel % kStreamSlots;
    const bool fin = (sel & 0x80) != 0;
    std::size_t n = 0;
    const std::uint8_t* d = in.chunk(1000, n);
    if (h.finned[slot]) return;
    std::uint8_t frame[q::kMaxPayloadSize];
    q::StreamFrame sf;
    sf.stream_id = stream_id(slot);
    sf.offset = h.offset[slot];
    sf.length = n;
    sf.fin = fin;
    sf.data = d;
    const std::size_t w = sf.serialize(frame);
    assert(w <= sizeof(frame) && "STREAM frame over payload budget");
    if (q::QuicConnectionTestAccess::send_frames(h.pair.client, q::TlsLevel::kApplication,
                                                 frame, w)) {
        h.offset[slot] += n;
        h.finned[slot] = fin;
    }
}

void send_datagram(Harness& h, Input& in) {
    std::size_t n = 0;
    const std::uint8_t* d = in.chunk(1000, n);
    std::uint8_t frame[q::kMaxPayloadSize];
    std::size_t w = 0;
    frame[w++] = 0x31;  // DATAGRAM with length
    w += q::varint_encode(n, frame + w);
    if (n > 0) std::memcpy(frame + w, d, n);
    w += n;
    (void)q::QuicConnectionTestAccess::send_frames(h.pair.client, q::TlsLevel::kApplication,
                                                   frame, w);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    Input in(data, size);
    auto h = std::make_unique<Harness>();
    if (!h->pair.init() || !h->pair.handshake()) return 0;
    h->h3.attach(h->pair.server, /*is_server=*/true);
    h3::H3Connection* conn = &h->h3;
    h->h3.set_request_handler([conn](const h3::H3Request& r) {
        static const h3::H3ResponseHeader hdr[1] = {{"content-type", "text/plain"}};
        (void)conn->send_response(r.stream_id, 200, hdr, 1, r.body, r.body_len);
    });
    h->h3.send_settings();
    h->pair.pump(1);
    for (std::size_t i = 0; i < kMaxOps && !in.empty(); ++i) {
        const std::uint8_t op = in.u8();
        if (op % 8 == 7) send_datagram(*h, in);
        else if (op % 8 == 6) h->pair.pump(1);
        else send_stream(*h, in);
        h->pair.pump(1);
    }
    h->pair.pump(2);
    return 0;
}
