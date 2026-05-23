// quic_primitives_test.cpp — RFC-vector unit tests for the dependency-free QUIC
// primitives ported from FasterAPI (boltapi/quic/{varint,packet,frames,pn_space,
// ack}.h). NO network, NO crypto, NO OpenSSL — these compile into the default
// suite so the pure wire codecs are always covered.
//
// Vectors:
//   * varint:   RFC 9000 Appendix A.1 worked examples + boundary sizes + random.
//   * packet:   RFC 9001 Appendix A.1 client Initial public header fields;
//               short-header parse.
//   * frames:   ACK with multiple ranges round-trip; PADDING/PING/CRYPTO/STREAM
//               framing offsets; CONNECTION_CLOSE (transport + app).
//   * pn_space: RFC 9000 Appendix A.2/A.3 truncated PN encode/decode; sequencing.
//   * ack:      received-PN -> ACK range building round-trips through AckFrame.

#include "boltapi/quic/ack.h"
#include "boltapi/quic/frames.h"
#include "boltapi/quic/packet.h"
#include "boltapi/quic/pn_space.h"
#include "boltapi/quic/varint.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <vector>

namespace q = bolt::api::quic;

// ===========================================================================
// VARINT — RFC 9000 Appendix A.1
// ===========================================================================

TEST(QuicVarInt, Rfc9000A1Samples) {
    // value, expected encoded length (RFC 9000 §A.1).
    // These are the DECODED values of the RFC §A.1 wire-byte examples, paired
    // with the minimal encoded length each requires:
    //   wire 0x25               -> 37                  (1 byte)
    //   wire 0x7bbd             -> 15293               (2 bytes)
    //   wire 0x9d7f3e7d         -> 494878333           (4 bytes)
    //   wire 0xc2197c5eff14e88c -> 151288809941952652  (8 bytes)
    struct Sample { std::uint64_t value; std::size_t len; };
    const Sample samples[] = {
        {37ULL, 1},
        {15293ULL, 2},
        {494878333ULL, 4},
        {151288809941952652ULL, 8},
    };
    for (const auto& s : samples) {
        std::uint8_t buf[8] = {};
        const std::size_t n = q::varint_encode(s.value, buf);
        EXPECT_EQ(n, s.len) << "value=" << s.value;
        EXPECT_EQ(q::varint_encoded_size(s.value), s.len);

        std::uint64_t decoded = 0;
        const int c = q::varint_decode(buf, n, decoded);
        ASSERT_EQ(static_cast<std::size_t>(c), n);
        EXPECT_EQ(decoded, s.value);
    }
}

TEST(QuicVarInt, ExactRfcEightByteVector) {
    // RFC 9000 §A.1: the 8-byte example decodes 0xc2197c5eff14e88c to 151288809941952652.
    const std::uint8_t wire[8] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    std::uint64_t v = 0;
    const int c = q::varint_decode(wire, sizeof(wire), v);
    EXPECT_EQ(c, 8);
    EXPECT_EQ(v, 151288809941952652ULL);

    // Re-encode the decoded value -> identical 8 bytes.
    std::uint8_t out[8] = {};
    EXPECT_EQ(q::varint_encode(v, out), 8u);
    for (std::size_t i = 0; i < 8; ++i) EXPECT_EQ(out[i], wire[i]);
}

TEST(QuicVarInt, TwoByteRfcVector) {
    // RFC 9000 §A.1: 0x7bbd encodes as 0x7b 0xbd (with prefix 01 -> 0x40|0x3b).
    const std::uint8_t wire[2] = {0x7b, 0xbd};
    std::uint64_t v = 0;
    EXPECT_EQ(q::varint_decode(wire, 2, v), 2);
    EXPECT_EQ(v, 15293u);
    std::uint8_t out[8] = {};
    EXPECT_EQ(q::varint_encode(15293u, out), 2u);
    EXPECT_EQ(out[0], 0x7b);
    EXPECT_EQ(out[1], 0xbd);
}

TEST(QuicVarInt, BoundarySizes) {
    EXPECT_EQ(q::varint_encoded_size(q::kVarInt1Max), 1u);
    EXPECT_EQ(q::varint_encoded_size(q::kVarInt1Max + 1), 2u);
    EXPECT_EQ(q::varint_encoded_size(q::kVarInt2Max), 2u);
    EXPECT_EQ(q::varint_encoded_size(q::kVarInt2Max + 1), 4u);
    EXPECT_EQ(q::varint_encoded_size(q::kVarInt4Max), 4u);
    EXPECT_EQ(q::varint_encoded_size(q::kVarInt4Max + 1), 8u);
    EXPECT_EQ(q::varint_encoded_size(q::kVarIntMax), 8u);
}

TEST(QuicVarInt, NeedMoreOnShortBuffer) {
    std::uint8_t buf[8] = {};
    q::varint_encode(q::kVarInt2Max, buf);  // 2-byte form
    std::uint64_t v = 0;
    EXPECT_EQ(q::varint_decode(buf, 0, v), q::kVarIntNeedMore);
    EXPECT_EQ(q::varint_decode(buf, 1, v), q::kVarIntNeedMore);  // needs 2
    EXPECT_EQ(q::varint_decode(buf, 2, v), 2);
}

TEST(QuicVarInt, RandomRoundTrip) {
    std::mt19937_64 rng{0xC0FFEEULL};
    for (int i = 0; i < 100000; ++i) {
        const std::uint64_t v = rng() & ((1ULL << 62) - 1);
        std::uint8_t buf[8] = {};
        const std::size_t n = q::varint_encode(v, buf);
        std::uint64_t out = 0;
        ASSERT_EQ(static_cast<std::size_t>(q::varint_decode(buf, n, out)), n);
        ASSERT_EQ(out, v);
        ASSERT_EQ(q::varint_encoded_size(v), n);
    }
}

// ===========================================================================
// PACKET — RFC 9001 Appendix A.1 client Initial public header
// ===========================================================================

TEST(QuicPacket, Rfc9001ClientInitialPublicHeader) {
    // RFC 9001 §A.1: the client Initial unprotected header is
    //   c3 00000001 08 8394c8f03e515708 00 00 449e ...
    //   c3 = long header, fixed bit, Initial type, PN-len bits (protected);
    //   00000001 = version 1; 08 = DCID len; 8394c8f03e515708 = DCID;
    //   00 = SCID len (empty); 00 = token length 0; 449e = length varint (1182).
    const std::uint8_t hdr[] = {
        0xc3,
        0x00, 0x00, 0x00, 0x01,
        0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x00,
        0x00,
        0x44, 0x9e,
        // (protected packet number + payload would follow; not needed for header)
        0x00, 0x00, 0x00, 0x00
    };

    q::PacketForm form{};
    ASSERT_EQ(q::parse_form(hdr, sizeof(hdr), form), q::kParseOk);
    EXPECT_EQ(form, q::PacketForm::kLongInitial);

    q::LongHeader lh{};
    std::size_t consumed = 0;
    ASSERT_EQ(q::parse_long_header(hdr, sizeof(hdr), lh, consumed), q::kParseOk);

    EXPECT_EQ(lh.type, q::LongPacketType::kInitial);
    EXPECT_EQ(lh.version, q::kQuicVersion1);
    ASSERT_EQ(lh.dest_cid.length, 8);
    const std::uint8_t expect_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    for (int i = 0; i < 8; ++i) EXPECT_EQ(lh.dest_cid.data[i], expect_dcid[i]);
    EXPECT_EQ(lh.source_cid.length, 0);
    EXPECT_EQ(lh.token_length, 0u);
    EXPECT_EQ(lh.token, nullptr);
    EXPECT_TRUE(lh.has_length);
    EXPECT_EQ(lh.length, 1182u);          // 0x449e varint == 1182
    // consumed points at the first protected byte (the packet number).
    EXPECT_EQ(consumed, 18u);
}

TEST(QuicPacket, ShortHeaderParse) {
    // 1-RTT: 0|1|S|R|R|K|PP  -> 0x40 base. Set spin (0x20) + key phase (0x04).
    std::uint8_t dcid[4] = {0xde, 0xad, 0xbe, 0xef};
    std::uint8_t buf[16] = {};
    buf[0] = 0x40 | 0x20 | 0x04;  // short header, spin=1, key_phase=1
    for (int i = 0; i < 4; ++i) buf[1 + i] = dcid[i];

    q::PacketForm form{};
    ASSERT_EQ(q::parse_form(buf, sizeof(buf), form), q::kParseOk);
    EXPECT_EQ(form, q::PacketForm::kShort);

    q::ShortHeader sh{};
    std::size_t consumed = 0;
    ASSERT_EQ(q::parse_short_header(buf, sizeof(buf), 4, sh, consumed), q::kParseOk);
    EXPECT_TRUE(sh.spin_bit);
    EXPECT_TRUE(sh.key_phase);
    ASSERT_EQ(sh.dest_cid.length, 4);
    for (int i = 0; i < 4; ++i) EXPECT_EQ(sh.dest_cid.data[i], dcid[i]);
    EXPECT_EQ(consumed, 5u);  // 1 first byte + 4 DCID
}

TEST(QuicPacket, VersionNegotiationDiscrimination) {
    // Long header with version 0 == Version Negotiation (RFC 9000 §17.2.1).
    std::uint8_t buf[16] = {};
    buf[0] = 0x80;  // long header (fixed bit and type are unused / random in VN)
    // version = 0
    buf[5] = 0x00;  // DCID len 0
    buf[6] = 0x00;  // SCID len 0

    q::PacketForm form{};
    ASSERT_EQ(q::parse_form(buf, sizeof(buf), form), q::kParseOk);
    EXPECT_EQ(form, q::PacketForm::kVersionNegotiation);

    q::LongHeader lh{};
    std::size_t consumed = 0;
    ASSERT_EQ(q::parse_long_header(buf, sizeof(buf), lh, consumed), q::kParseOk);
    EXPECT_EQ(lh.version, 0u);
    EXPECT_FALSE(lh.has_length);  // VN has no Length field
}

TEST(QuicPacket, RetryHasNoLengthField) {
    std::uint8_t buf[16] = {};
    buf[0] = 0x80 | (static_cast<std::uint8_t>(q::LongPacketType::kRetry) << 4) | 0x40;
    buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x01;  // version 1
    buf[5] = 0x02; buf[6] = 0xaa; buf[7] = 0xbb;  // DCID len 2
    buf[8] = 0x00;  // SCID len 0

    q::LongHeader lh{};
    std::size_t consumed = 0;
    ASSERT_EQ(q::parse_long_header(buf, sizeof(buf), lh, consumed), q::kParseOk);
    EXPECT_EQ(lh.type, q::LongPacketType::kRetry);
    EXPECT_FALSE(lh.has_length);
    EXPECT_EQ(consumed, 9u);  // stops right after the CIDs
}

TEST(QuicPacket, NeedMoreOnTruncatedLongHeader) {
    const std::uint8_t hdr[] = {0xc3, 0x00, 0x00, 0x00};  // missing last version byte
    q::LongHeader lh{};
    std::size_t consumed = 0;
    EXPECT_EQ(q::parse_long_header(hdr, sizeof(hdr), lh, consumed), q::kParseNeedMore);
}

TEST(QuicPacket, RejectsOverlongConnectionId) {
    std::uint8_t buf[40] = {};
    buf[0] = 0xc0; buf[4] = 0x01;  // long, version 1
    buf[5] = 21;                   // DCID len 21 > 20 -> error
    q::LongHeader lh{};
    std::size_t consumed = 0;
    EXPECT_EQ(q::parse_long_header(buf, sizeof(buf), lh, consumed), q::kParseError);
}

// ===========================================================================
// FRAMES — ACK ranges, PADDING/PING/CRYPTO/STREAM, CONNECTION_CLOSE
// ===========================================================================

TEST(QuicFrames, AckMultiRangeRoundTrip) {
    q::AckFrame in{};
    in.largest_acked = 100;
    in.ack_delay = 1234;
    in.first_ack_range = 5;       // acks 95..100
    in.range_count = 2;
    in.ranges[0].gap = 1;         // skip 93,94 (gap=1 -> 2 missing)
    in.ranges[0].length = 3;      // acks 89..92
    in.ranges[1].gap = 0;
    in.ranges[1].length = 0;      // acks 87..87

    std::uint8_t buf[128] = {};
    const std::size_t n = in.serialize(buf);
    ASSERT_GT(n, 0u);
    EXPECT_EQ(buf[0], static_cast<std::uint8_t>(q::FrameType::kAck));

    q::AckFrame out{};
    std::size_t consumed = 0;
    // Caller consumes the type byte; pass the body.
    ASSERT_EQ(out.parse(buf + 1, n - 1, /*with_ecn=*/false, consumed), q::kFrameOk);
    EXPECT_EQ(consumed, n - 1);
    EXPECT_EQ(out.largest_acked, 100u);
    EXPECT_EQ(out.ack_delay, 1234u);
    EXPECT_EQ(out.first_ack_range, 5u);
    ASSERT_EQ(out.range_count, 2u);
    EXPECT_EQ(out.ranges[0].gap, 1u);
    EXPECT_EQ(out.ranges[0].length, 3u);
    EXPECT_EQ(out.ranges[1].gap, 0u);
    EXPECT_EQ(out.ranges[1].length, 0u);
}

TEST(QuicFrames, AckEcnRoundTrip) {
    q::AckFrame in{};
    in.largest_acked = 42;
    in.ack_delay = 7;
    in.first_ack_range = 42;  // acks 0..42
    in.range_count = 0;
    in.has_ecn = true;
    in.ect0 = 10; in.ect1 = 20; in.ecn_ce = 3;

    std::uint8_t buf[64] = {};
    const std::size_t n = in.serialize(buf);
    EXPECT_EQ(buf[0], static_cast<std::uint8_t>(q::FrameType::kAckEcn));

    q::AckFrame out{};
    std::size_t consumed = 0;
    ASSERT_EQ(out.parse(buf + 1, n - 1, /*with_ecn=*/true, consumed), q::kFrameOk);
    EXPECT_TRUE(out.has_ecn);
    EXPECT_EQ(out.ect0, 10u);
    EXPECT_EQ(out.ect1, 20u);
    EXPECT_EQ(out.ecn_ce, 3u);
}

TEST(QuicFrames, StreamFrameOffsets) {
    const std::uint8_t payload[5] = {'h', 'e', 'l', 'l', 'o'};
    q::StreamFrame in{};
    in.stream_id = 4;
    in.offset = 16384;   // forces a 4-byte varint offset
    in.length = 5;
    in.fin = true;
    in.data = payload;

    std::uint8_t buf[64] = {};
    const std::size_t n = in.serialize(buf);
    ASSERT_GT(n, 0u);
    // Type byte must carry OFF|LEN|FIN.
    EXPECT_EQ(buf[0] & 0x07,
              q::kStreamFlagOff | q::kStreamFlagLen | q::kStreamFlagFin);
    EXPECT_TRUE(q::is_stream_frame_type(buf[0]));

    q::StreamFrame out{};
    std::size_t consumed = 0;
    ASSERT_EQ(out.parse(buf[0], buf + 1, n - 1, consumed), q::kFrameOk);
    EXPECT_EQ(out.stream_id, 4u);
    EXPECT_EQ(out.offset, 16384u);
    EXPECT_EQ(out.length, 5u);
    EXPECT_TRUE(out.fin);
    ASSERT_NE(out.data, nullptr);
    for (int i = 0; i < 5; ++i) EXPECT_EQ(out.data[i], payload[i]);
}

TEST(QuicFrames, StreamFrameNoLengthExtendsToEnd) {
    // Type with OFF set, LEN clear -> length runs to end of buffer.
    std::uint8_t buf[16] = {};
    const std::uint8_t type = q::kStreamTypeBase | q::kStreamFlagOff;  // 0x0c
    // body: stream_id=1 (1B varint), offset=2 (1B varint), then 3 data bytes.
    buf[0] = 1;   // stream id
    buf[1] = 2;   // offset
    buf[2] = 0xAA; buf[3] = 0xBB; buf[4] = 0xCC;

    q::StreamFrame out{};
    std::size_t consumed = 0;
    ASSERT_EQ(out.parse(type, buf, 5, consumed), q::kFrameOk);
    EXPECT_EQ(out.stream_id, 1u);
    EXPECT_EQ(out.offset, 2u);
    EXPECT_EQ(out.length, 3u);
    EXPECT_FALSE(out.fin);
    EXPECT_EQ(consumed, 5u);
}

TEST(QuicFrames, CryptoFrameOffsets) {
    const std::uint8_t tls_bytes[4] = {0x01, 0x00, 0x00, 0xfc};
    q::CryptoFrame in{};
    in.offset = 0;
    in.length = 4;
    in.data = tls_bytes;

    std::uint8_t buf[32] = {};
    const std::size_t n = in.serialize(buf);
    EXPECT_EQ(buf[0], static_cast<std::uint8_t>(q::FrameType::kCrypto));

    q::CryptoFrame out{};
    std::size_t consumed = 0;
    ASSERT_EQ(out.parse(buf + 1, n - 1, consumed), q::kFrameOk);
    EXPECT_EQ(out.offset, 0u);
    EXPECT_EQ(out.length, 4u);
    ASSERT_NE(out.data, nullptr);
    for (int i = 0; i < 4; ++i) EXPECT_EQ(out.data[i], tls_bytes[i]);
}

TEST(QuicFrames, ConnectionCloseTransportAndApp) {
    // Transport close (0x1c) — has a frame_type field.
    {
        q::ConnectionCloseFrame in{};
        in.is_application = false;
        in.error_code = 0x0a;       // PROTOCOL_VIOLATION
        in.frame_type = 0x06;       // CRYPTO
        const char reason[] = "bad crypto";
        in.reason_length = sizeof(reason) - 1;
        in.reason_phrase = reason;

        std::uint8_t buf[64] = {};
        const std::size_t n = in.serialize(buf);
        EXPECT_EQ(buf[0], static_cast<std::uint8_t>(q::FrameType::kConnectionClose));

        q::ConnectionCloseFrame out{};
        std::size_t consumed = 0;
        ASSERT_EQ(out.parse(buf + 1, n - 1, /*is_app=*/false, consumed), q::kFrameOk);
        EXPECT_EQ(out.error_code, 0x0au);
        EXPECT_EQ(out.frame_type, 0x06u);
        ASSERT_EQ(out.reason_length, sizeof(reason) - 1);
        EXPECT_EQ(std::string(out.reason_phrase, out.reason_length), "bad crypto");
    }
    // Application close (0x1d) — no frame_type field.
    {
        q::ConnectionCloseFrame in{};
        in.is_application = true;
        in.error_code = 0x0101;
        in.reason_length = 0;
        in.reason_phrase = nullptr;

        std::uint8_t buf[32] = {};
        const std::size_t n = in.serialize(buf);
        EXPECT_EQ(buf[0], static_cast<std::uint8_t>(q::FrameType::kConnectionCloseApp));

        q::ConnectionCloseFrame out{};
        std::size_t consumed = 0;
        ASSERT_EQ(out.parse(buf + 1, n - 1, /*is_app=*/true, consumed), q::kFrameOk);
        EXPECT_EQ(out.error_code, 0x0101u);
        EXPECT_EQ(out.reason_length, 0u);
    }
}

TEST(QuicFrames, PaddingRun) {
    std::uint8_t buf[10] = {0, 0, 0, 0, 0x01 /*PING*/, 0, 0, 0, 0, 0};
    const std::size_t run = q::parse_padding_run(buf, sizeof(buf));
    EXPECT_EQ(run, 4u);  // 4 PADDING bytes, then PING
    EXPECT_EQ(buf[run], static_cast<std::uint8_t>(q::FrameType::kPing));
}

// ===========================================================================
// PN SPACE — RFC 9000 Appendix A.2 / A.3 truncated PN
// ===========================================================================

TEST(QuicPnSpace, Rfc9000A2EncodeLength) {
    // RFC 9000 §A.2 worked example: full_pn = 0xac5c02, largest_acked = 0xabe8b3.
    // num_unacked = 0xac5c02 - 0xabe8b3 = 0x7374f (472911); min_bits = 19;
    // ceil(19/8) = 3 bytes. The on-wire truncated PN is the low 3 bytes of the
    // full PN (0xac5c02), which round-trips back via pn_decode (checked below).
    const std::uint64_t full = 0xac5c02ULL;
    const std::uint64_t acked = 0xabe8b3ULL;
    const std::uint8_t nbytes = q::pn_encode_length_truncated(full, acked);
    EXPECT_EQ(nbytes, 3);
    const std::uint32_t truncated = static_cast<std::uint32_t>(full & 0xFFFFFF);
    EXPECT_EQ(truncated, 0xac5c02u);
    EXPECT_EQ(q::pn_decode(truncated, acked, /*pn_nbits=*/24), full);
}

TEST(QuicPnSpace, Rfc9000A3Decode) {
    // RFC 9000 §A.3 worked example: largest_pn = 0xa82f30ea, truncated = 0x9b32,
    // 16-bit field -> reconstructed full PN = 0xa82f9b32.
    const std::uint64_t reconstructed =
        q::pn_decode(0x9b32ULL, 0xa82f30eaULL, /*pn_nbits=*/16);
    EXPECT_EQ(reconstructed, 0xa82f9b32ULL);
}

TEST(QuicPnSpace, TruncateThenDecodeRoundTrip) {
    // For a window of recently-sent PNs, truncate to the chosen width and confirm
    // pn_decode reconstructs the full value.
    const std::uint64_t acked = 1000000;
    for (std::uint64_t full = acked + 1; full < acked + 5000; ++full) {
        const std::uint8_t nbytes = q::pn_encode_length_truncated(full, acked);
        const std::uint8_t nbits = static_cast<std::uint8_t>(nbytes * 8);
        const std::uint64_t mask = (nbits == 64) ? ~0ULL : ((1ULL << nbits) - 1);
        const std::uint64_t truncated = full & mask;
        const std::uint64_t got = q::pn_decode(truncated, acked, nbits);
        ASSERT_EQ(got, full) << "full=" << full << " nbits=" << int(nbits);
    }
}

TEST(QuicPnSpace, SequencingAndManager) {
    q::PacketNumberSpaceManager mgr;
    auto& app = mgr[q::PacketNumberSpace::kApplication];
    EXPECT_EQ(app.space(), q::PacketNumberSpace::kApplication);
    EXPECT_EQ(app.peek_next_packet_number(), 0u);
    EXPECT_EQ(app.next_packet_number(), 0u);
    EXPECT_EQ(app.next_packet_number(), 1u);
    EXPECT_EQ(app.peek_next_packet_number(), 2u);

    EXPECT_EQ(app.largest_received(), -1);
    app.on_packet_received(7);
    app.on_packet_received(3);
    EXPECT_EQ(app.largest_received(), 7);

    EXPECT_EQ(app.largest_acked(), -1);
    app.on_largest_acked(1);
    EXPECT_EQ(app.largest_acked(), 1);

    // Spaces are independent.
    EXPECT_EQ(mgr[q::PacketNumberSpace::kInitial].next_packet_number(), 0u);
    EXPECT_EQ(mgr[q::PacketNumberSpace::kHandshake].peek_next_packet_number(), 0u);
}

TEST(QuicPnSpace, EncodeLengthPlain) {
    EXPECT_EQ(q::pn_encode_length(0), 1);
    EXPECT_EQ(q::pn_encode_length(0xFF), 1);
    EXPECT_EQ(q::pn_encode_length(0x100), 2);
    EXPECT_EQ(q::pn_encode_length(0xFFFF), 2);
    EXPECT_EQ(q::pn_encode_length(0x10000), 3);
    EXPECT_EQ(q::pn_encode_length(0xFFFFFF), 3);
    EXPECT_EQ(q::pn_encode_length(0x1000000), 4);
}

// ===========================================================================
// ACK TRACKER — received PNs -> ranges -> AckFrame
// ===========================================================================

TEST(QuicAckTracker, ContiguousRange) {
    q::AckRangeTracker t;
    EXPECT_TRUE(t.empty());
    for (std::uint64_t pn = 0; pn <= 9; ++pn) t.record(pn);
    EXPECT_EQ(t.range_count(), 1u);
    std::uint64_t largest = 0;
    ASSERT_TRUE(t.largest(largest));
    EXPECT_EQ(largest, 9u);

    q::AckFrame ack{};
    ASSERT_TRUE(t.build_ack_frame(ack, /*ack_delay=*/0));
    EXPECT_EQ(ack.largest_acked, 9u);
    EXPECT_EQ(ack.first_ack_range, 9u);  // 0..9 inclusive
    EXPECT_EQ(ack.range_count, 0u);
}

TEST(QuicAckTracker, GappedRangesBuildAndReparse) {
    q::AckRangeTracker t;
    // Receive 0,1,2 ; 5,6 ; 9  -> three ranges.
    for (std::uint64_t pn : {0u, 1u, 2u, 5u, 6u, 9u}) t.record(pn);
    EXPECT_EQ(t.range_count(), 3u);

    q::AckFrame ack{};
    ASSERT_TRUE(t.build_ack_frame(ack, 0));
    EXPECT_EQ(ack.largest_acked, 9u);
    EXPECT_EQ(ack.first_ack_range, 0u);   // range {9}
    ASSERT_EQ(ack.range_count, 2u);
    // gap between {9} and {5,6}: missing 7,8 -> gap = 9 - 6 - 2 = 1.
    EXPECT_EQ(ack.ranges[0].gap, 1u);
    EXPECT_EQ(ack.ranges[0].length, 1u);  // {5,6} -> length 1
    // gap between {5,6} and {0,1,2}: missing 3,4 -> gap = 5 - 2 - 2 = 1.
    EXPECT_EQ(ack.ranges[1].gap, 1u);
    EXPECT_EQ(ack.ranges[1].length, 2u);  // {0,1,2} -> length 2

    // Round-trip through the AckFrame wire codec.
    std::uint8_t buf[128] = {};
    const std::size_t n = ack.serialize(buf);
    q::AckFrame out{};
    std::size_t consumed = 0;
    ASSERT_EQ(out.parse(buf + 1, n - 1, false, consumed), q::kFrameOk);
    EXPECT_EQ(out.largest_acked, 9u);
    EXPECT_EQ(out.first_ack_range, 0u);
    ASSERT_EQ(out.range_count, 2u);
    EXPECT_EQ(out.ranges[0].gap, 1u);
    EXPECT_EQ(out.ranges[1].length, 2u);
}

TEST(QuicAckTracker, OutOfOrderAndDuplicatesCoalesce) {
    q::AckRangeTracker t;
    // Insert 3 then 4 then 2 -> should coalesce to a single {2,3,4} range.
    t.record(3);
    t.record(4);
    t.record(2);
    t.record(3);  // duplicate, ignored
    EXPECT_EQ(t.range_count(), 1u);
    q::AckFrame ack{};
    ASSERT_TRUE(t.build_ack_frame(ack, 0));
    EXPECT_EQ(ack.largest_acked, 4u);
    EXPECT_EQ(ack.first_ack_range, 2u);  // 2..4 inclusive
    EXPECT_EQ(ack.range_count, 0u);
}

TEST(QuicAckTracker, RandomizedSetMatchesReference) {
    // Cross-check the tracker's ranges against a brute-force membership set.
    std::mt19937_64 rng{0xBEEFFACEULL};
    for (int trial = 0; trial < 200; ++trial) {
        q::AckRangeTracker t;
        std::array<bool, 256> present{};
        present.fill(false);
        const int draws = 1 + static_cast<int>(rng() % 120);
        for (int d = 0; d < draws; ++d) {
            const std::uint64_t pn = rng() % 256;
            t.record(pn);
            present[pn] = true;
        }
        std::uint64_t largest = 0;
        const bool any = t.largest(largest);
        // Reference largest.
        int ref_largest = -1;
        int ref_ranges = 0;
        bool prev = false;
        for (int i = 0; i < 256; ++i) {
            if (present[i]) { ref_largest = i; if (!prev) ++ref_ranges; }
            prev = present[i];
        }
        ASSERT_EQ(any, ref_largest >= 0);
        if (any) {
            ASSERT_EQ(static_cast<int>(largest), ref_largest);
            ASSERT_EQ(static_cast<int>(t.range_count()), ref_ranges);
        }
    }
}
