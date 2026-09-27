// quic_conn — QuicConnection inbound path under adversarial peers.
//
// Input: [flags][op...]. flags bit0 runs a real TLS handshake first. Each op
// either sends fuzzed plaintext frames sealed at Initial/Handshake/1-RTT by
// the real peer (so they pass AEAD and reach frame dispatch), feeds a raw
// datagram (header parsing, header protection, AEAD failure paths), or pumps.
// Both roles are targets: ops aim frames at the server or at the client.

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "fuzz_input.h"
#include "quic_pair.h"

namespace q = bolt::api::quic;
using boltapi_fuzz::Input;

namespace {

constexpr std::size_t kMaxOps = 48;

q::TlsLevel level_of(std::uint8_t b) {
    switch (b % 3) {
        case 0: return q::TlsLevel::kInitial;
        case 1: return q::TlsLevel::kHandshake;
        default: return q::TlsLevel::kApplication;
    }
}

void run_op(boltapi_fuzz::Pair& p, Input& in) {
    const std::uint8_t op = in.u8();
    std::size_t n = 0;
    switch (op % 6) {
        case 0: {  // client -> server frames
            const q::TlsLevel lvl = level_of(in.u8());
            const std::uint8_t* d = in.chunk(q::kMaxPayloadSize, n);
            (void)q::QuicConnectionTestAccess::send_frames(p.client, lvl, d, n);
            p.pump(1);
            break;
        }
        case 1: {  // server -> client frames
            const q::TlsLevel lvl = level_of(in.u8());
            const std::uint8_t* d = in.chunk(q::kMaxPayloadSize, n);
            (void)q::QuicConnectionTestAccess::send_frames(p.server, lvl, d, n);
            p.pump(1);
            break;
        }
        case 2: {  // raw datagram -> server
            const std::uint8_t* d = in.chunk(q::kMaxDatagramSize, n);
            if (n > 0) p.server.feed_datagram(d, n);
            break;
        }
        case 3: {  // raw datagram -> client
            const std::uint8_t* d = in.chunk(q::kMaxDatagramSize, n);
            if (n > 0) p.client.feed_datagram(d, n);
            break;
        }
        case 4:
            p.client.tick();
            p.server.tick();
            p.pump(1);
            break;
        default:
            p.pump(2);
            break;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    Input in(data, size);
    const std::uint8_t flags = in.u8();
    auto p = boltapi_fuzz::make_pair();
    if (!p) return 0;
    if ((flags & 1) != 0) {
        if (!p->handshake()) return 0;
    } else {
        (void)p->client.start();  // ClientHello queued; server keyed on first feed
        if ((flags & 2) != 0) p->pump(1);
    }
    for (std::size_t i = 0; i < kMaxOps && !in.empty(); ++i) run_op(*p, in);
    p->pump(2);
    return 0;
}
