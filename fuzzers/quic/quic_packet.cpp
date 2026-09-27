// quic_packet — QUIC wire codecs the connection uses on every datagram:
// varints, long/short headers, STREAM/CRYPTO/ACK/CONNECTION_CLOSE frames,
// transport parameters, Version Negotiation, stateless reset, PN decode.
// Round-trips assert encode(decode(x)) re-decodes to the same value.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "boltapi/quic/frames.h"
#include "boltapi/quic/packet.h"
#include "boltapi/quic/pn_space.h"
#include "boltapi/quic/robustness.h"
#include "boltapi/quic/transport_params.h"
#include "boltapi/quic/varint.h"

namespace q = bolt::api::quic;

namespace {

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "quic_packet invariant failed: %s\n", what);
        std::abort();
    }
}

void fuzz_varint(const std::uint8_t* d, std::size_t n) {
    std::uint64_t v = 0;
    const int c = q::varint_decode(d, n, v);
    if (c < 0) return;
    check(static_cast<std::size_t>(c) <= n, "varint consumed past input");
    check(v <= q::kVarIntMax, "varint value above 2^62-1");
    std::uint8_t out[8];
    const std::size_t w = q::varint_encode(v, out);
    std::uint64_t back = 0;
    check(q::varint_decode(out, w, back) == static_cast<int>(w) && back == v,
          "varint round trip");
}

void fuzz_headers(const std::uint8_t* d, std::size_t n) {
    q::PacketForm form{};
    (void)q::parse_form(d, n, form);
    q::LongHeader lh;
    std::size_t used = 0;
    if (q::parse_long_header(d, n, lh, used) == q::kParseOk) {
        check(used <= n, "long header consumed past input");
        check(lh.dest_cid.length <= q::kMaxConnectionIdLen, "dcid len");
        check(lh.source_cid.length <= q::kMaxConnectionIdLen, "scid len");
        std::uint32_t vers[q::kMaxVnVersions];
        const std::size_t cnt =
            q::parse_version_negotiation_versions(d, n, used, vers, q::kMaxVnVersions);
        check(cnt <= q::kMaxVnVersions, "vn count");
        (void)q::verify_retry_integrity(lh.dest_cid, d, n);
    }
    for (std::uint8_t cid_len = 0; cid_len <= q::kMaxConnectionIdLen; cid_len += 4) {
        q::ShortHeader sh;
        if (q::parse_short_header(d, n, cid_len, sh, used) == q::kParseOk)
            check(used <= n, "short header consumed past input");
    }
    static const std::uint8_t token[16] = {};
    (void)q::is_stateless_reset(d, n, token);
}

void fuzz_frames(const std::uint8_t* d, std::size_t n) {
    if (n < 1) return;
    const std::uint8_t type = d[0];
    const std::uint8_t* b = d + 1;
    const std::size_t len = n - 1;
    std::size_t used = 0;
    std::uint8_t out[1 << 16];
    if (q::is_stream_frame_type(type)) {
        q::StreamFrame sf;
        if (sf.parse(type, b, len, used) == q::kFrameOk) {
            check(used <= len, "STREAM overran");
            if (sf.length < 4096) (void)sf.serialize(out);
        }
    }
    q::CryptoFrame cf;
    if (cf.parse(b, len, used) == q::kFrameOk) {
        check(used <= len, "CRYPTO overran");
        if (cf.length < 4096) (void)cf.serialize(out);
    }
    q::AckFrame af;
    if (af.parse(b, len, (type & 1) != 0, used) == q::kFrameOk) {
        check(used <= len && af.range_count <= q::kMaxAckRanges, "ACK bounds");
        const std::size_t w = af.serialize(out);
        q::AckFrame back;
        std::size_t bu = 0;
        check(back.parse(out + 1, w - 1, af.has_ecn, bu) == q::kFrameOk &&
                  back.largest_acked == af.largest_acked &&
                  back.range_count == af.range_count,
              "ACK round trip");
    }
    q::ConnectionCloseFrame cc;
    if (cc.parse(b, len, (type & 1) != 0, used) == q::kFrameOk)
        check(used <= len, "CLOSE overran");
}

void fuzz_tp(const std::uint8_t* d, std::size_t n) {
    q::TransportParameters tp;
    if (!q::decode_transport_params(d, n, &tp)) return;
    std::uint8_t out[4096];
    std::size_t w = 0;
    if (!q::encode_transport_params(tp, out, sizeof(out), &w)) return;
    q::TransportParameters back;
    check(q::decode_transport_params(out, w, &back), "tp re-decode");
    check(back.initial_max_data == tp.initial_max_data &&
              back.max_idle_timeout == tp.max_idle_timeout,
          "tp round trip");
}

void fuzz_pn(const std::uint8_t* d, std::size_t n) {
    if (n < 9) return;
    std::uint64_t trunc = 0, largest = 0;
    std::memcpy(&trunc, d, 4);
    std::memcpy(&largest, d + 4, 4);
    largest &= q::kPacketNumberMax;
    const std::uint8_t bits = static_cast<std::uint8_t>(8 * (1 + (d[8] & 3)));
    trunc &= (bits == 32) ? 0xFFFFFFFFull : ((1ull << bits) - 1);
    (void)q::pn_decode(trunc, largest, bits);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    const std::uint8_t sel = data[0];
    const std::uint8_t* d = data + 1;
    const std::size_t n = size - 1;
    switch (sel % 5) {
        case 0: fuzz_varint(d, n); break;
        case 1: fuzz_headers(d, n); break;
        case 2: fuzz_frames(d, n); break;
        case 3: fuzz_tp(d, n); break;
        default: fuzz_pn(d, n); break;
    }
    return 0;
}
