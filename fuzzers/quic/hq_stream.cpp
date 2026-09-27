// hq_stream — hq-interop (HTTP/0.9 over QUIC) server over an established
// connection, wired as App wires it (HqConnection gets the server's stream
// data; the handler answers with a held body of input-chosen size, or resets).
//
// The input is a list of client stream writes (stream selector, FIN, bytes)
// and pump steps. Covers request-line assembly, stream credit (MAX_STREAMS,
// closed-id window), slot recycling, the send ring + held-body refill as
// ACKs arrive, and RESET_STREAM.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "boltapi/http3/hq_connection.h"
#include "fuzz_input.h"
#include "quic_pair.h"

namespace q = bolt::api::quic;
namespace h3 = bolt::api::http3;
using boltapi_fuzz::Input;

namespace {

constexpr std::size_t kMaxOps = 64;
constexpr std::size_t kStreamSlots = 24;  // client bidi 0,4,..,92 (past the credit)
constexpr std::size_t kMaxBody = 600 * 1024;  // > one send ring

struct Harness {
    boltapi_fuzz::Pair pair;
    h3::HqConnection hq;
    std::uint64_t offset[kStreamSlots] = {};
    bool finned[kStreamSlots] = {};
};

void send_stream(Harness& h, Input& in) {
    const std::uint8_t sel = in.u8();
    const std::size_t slot = sel % kStreamSlots;
    const bool fin = (sel & 0x80) != 0;
    std::size_t n = 0;
    const std::uint8_t* d = in.chunk(1000, n);
    if (h.finned[slot]) return;
    std::uint8_t frame[q::kMaxPayloadSize];
    q::StreamFrame sf;
    sf.stream_id = slot * 4;
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

// Response size from the path: every byte of it scales the body.
std::size_t body_size(std::string_view path) {
    std::size_t v = 0;
    for (const char c : path) v = v * 31u + static_cast<unsigned char>(c);
    return v % kMaxBody;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    Input in(data, size);
    auto h = std::make_unique<Harness>();
    if (!h->pair.init() || !h->pair.handshake()) return 0;
    q::QuicConnection* qc = &h->pair.server;
    h->hq.attach(*qc);
    h->hq.set_request_handler([qc](const h3::HqRequest& r) {
        const std::size_t n = body_size(r.path);
        if (n % 7 == 3) { (void)qc->reset_stream(r.stream_id, h3::kHqRequestRejected); return; }
        if (!qc->stream_write_owned(r.stream_id, std::string(n, 'b'), /*fin=*/true))
            (void)qc->reset_stream(r.stream_id, h3::kHqRequestRejected);
    });
    h3::HqConnection* hq = &h->hq;
    qc->set_stream_data_handler(
        [hq](std::uint64_t id, const std::uint8_t* d, std::size_t n, bool fin) {
            hq->on_stream_data(id, d, n, fin);
        });
    for (std::size_t i = 0; i < kMaxOps && !in.empty(); ++i) {
        const std::uint8_t op = in.u8();
        if (op % 8 == 6) {
            h->pair.pump(4);
            h->pair.client.tick();
            h->pair.server.tick();
        } else {
            send_stream(*h, in);
        }
        h->pair.pump(1);
    }
    h->pair.pump(4);
    assert(h->pair.server.live_streams() <= q::kMaxStreams && "stream pool overflow");
    return 0;
}
