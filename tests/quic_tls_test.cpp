// quic_tls_test.cpp — wave 3 GATE: in-process TLS 1.3 QUIC handshake over the
// OpenSSL 3.6 QUIC-TLS callback API (boltapi/quic/tls.h) + the transport-params
// codec (boltapi/quic/transport_params.h). No UDP, no sockets: a client QuicTls
// and a server QuicTls are stepped in lockstep, shuttling each side's pulled
// CRYPTO bytes (per encryption level) into the other's feed_crypto until both
// report is_complete().
//
// Asserts (the shared-secret proof tying wave 2 + wave 3 together):
//   * both sides complete within a bounded iteration budget;
//   * client write_secret(level) == server read_secret(level), and vice-versa,
//     at Handshake and 1-RTT (Application) levels;
//   * transport parameters round-trip across the handshake (each side decoded
//     the OTHER's params correctly);
//   * a PacketProtection derived from those secrets lets one side SEAL a packet
//     the other OPENS (cross seal/open with wave-2 packet_protection.h).
//
// Plus standalone transport-params codec round-trip + skip-unknown + truncation
// tests. OpenSSL is always linked into boltapi, so this runs in the default
// suite.

#include "boltapi/quic/tls.h"
#include "boltapi/quic/transport_params.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace q = bolt::api::quic;

namespace {

// ALPN wire list: a single "h3" protocol.
constexpr std::uint8_t kAlpnH3[] = {2, 'h', '3'};

// Reasonable client/server transport parameters for the self-test.
q::TransportParameters make_client_params() {
    q::TransportParameters tp;
    tp.initial_max_data = 1u << 20;
    tp.initial_max_data_present = true;
    tp.initial_max_stream_data_bidi_local = 256u * 1024;
    tp.initial_max_stream_data_bidi_local_present = true;
    tp.initial_max_stream_data_bidi_remote = 256u * 1024;
    tp.initial_max_stream_data_bidi_remote_present = true;
    tp.initial_max_stream_data_uni = 128u * 1024;
    tp.initial_max_stream_data_uni_present = true;
    tp.initial_max_streams_bidi = 100;
    tp.initial_max_streams_bidi_present = true;
    tp.initial_max_streams_uni = 3;
    tp.initial_max_streams_uni_present = true;
    tp.max_idle_timeout = 30000;
    tp.max_idle_timeout_present = true;
    tp.max_udp_payload_size = 1452;
    tp.max_udp_payload_size_present = true;
    tp.ack_delay_exponent = 3;
    tp.ack_delay_exponent_present = true;
    tp.active_connection_id_limit = 4;
    tp.active_connection_id_limit_present = true;
    tp.disable_active_migration = true;
    // initial_source_connection_id (RFC 9000 §7.3): a client CID.
    const std::uint8_t cid[] = {0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8};
    std::memcpy(tp.initial_source_connection_id, cid, sizeof(cid));
    tp.initial_source_connection_id_len = sizeof(cid);
    tp.initial_source_connection_id_present = true;
    return tp;
}

q::TransportParameters make_server_params() {
    q::TransportParameters tp;
    tp.initial_max_data = 3u << 20;
    tp.initial_max_data_present = true;
    tp.initial_max_stream_data_bidi_local = 512u * 1024;
    tp.initial_max_stream_data_bidi_local_present = true;
    tp.initial_max_stream_data_bidi_remote = 512u * 1024;
    tp.initial_max_stream_data_bidi_remote_present = true;
    tp.initial_max_streams_bidi = 200;
    tp.initial_max_streams_bidi_present = true;
    tp.initial_max_streams_uni = 5;
    tp.initial_max_streams_uni_present = true;
    tp.max_ack_delay = 20;
    tp.max_ack_delay_present = true;
    tp.active_connection_id_limit = 8;
    tp.active_connection_id_limit_present = true;
    // Server echoes original_destination_connection_id (RFC 9000 §7.3).
    const std::uint8_t odcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    std::memcpy(tp.original_destination_connection_id, odcid, sizeof(odcid));
    tp.original_destination_connection_id_len = sizeof(odcid);
    tp.original_destination_connection_id_present = true;
    const std::uint8_t scid[] = {0x53, 0x52, 0x56, 0x49, 0x44};  // "SRVID"
    std::memcpy(tp.initial_source_connection_id, scid, sizeof(scid));
    tp.initial_source_connection_id_len = sizeof(scid);
    tp.initial_source_connection_id_present = true;
    return tp;
}

// Move every level's pending CRYPTO from `from` to `to->feed_crypto`. Returns
// total bytes shuttled this pass.
std::size_t shuttle(q::QuicTls& from, q::QuicTls& to) {
    std::size_t moved = 0;
    for (std::uint8_t i = 0; i < q::kNumTlsLevels; ++i) {
        const auto lvl = static_cast<q::TlsLevel>(i);
        std::vector<std::uint8_t> buf;
        const std::size_t n = from.pull_crypto(lvl, buf);
        if (n > 0) {
            EXPECT_TRUE(to.feed_crypto(lvl, buf.data(), buf.size()));
            moved += n;
        }
    }
    return moved;
}

bool secrets_equal(const std::uint8_t* a, std::size_t alen, const std::uint8_t* b,
                   std::size_t blen) {
    if (a == nullptr || b == nullptr) return false;
    if (alen == 0 || alen != blen) return false;
    return std::memcmp(a, b, alen) == 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// Transport-params codec — standalone round-trips (the codec GATE).
// ---------------------------------------------------------------------------
TEST(QuicTransportParams, RoundTripClientAndServer) {
    for (const auto& tp : {make_client_params(), make_server_params()}) {
        std::uint8_t buf[q::kMaxTransportParamsBytes];
        std::size_t n = 0;
        ASSERT_TRUE(q::encode_transport_params(tp, buf, sizeof(buf), &n));
        ASSERT_GT(n, 0u);

        q::TransportParameters dec;
        ASSERT_TRUE(q::decode_transport_params(buf, n, &dec));

        EXPECT_EQ(dec.initial_max_data, tp.initial_max_data);
        EXPECT_EQ(dec.initial_max_data_present, tp.initial_max_data_present);
        EXPECT_EQ(dec.initial_max_stream_data_bidi_local,
                  tp.initial_max_stream_data_bidi_local);
        EXPECT_EQ(dec.initial_max_streams_bidi, tp.initial_max_streams_bidi);
        EXPECT_EQ(dec.initial_max_streams_uni, tp.initial_max_streams_uni);
        EXPECT_EQ(dec.disable_active_migration, tp.disable_active_migration);
        EXPECT_EQ(dec.active_connection_id_limit, tp.active_connection_id_limit);
        EXPECT_EQ(dec.initial_source_connection_id_present,
                  tp.initial_source_connection_id_present);
        EXPECT_EQ(dec.initial_source_connection_id_len,
                  tp.initial_source_connection_id_len);
        EXPECT_EQ(0, std::memcmp(dec.initial_source_connection_id,
                                 tp.initial_source_connection_id,
                                 tp.initial_source_connection_id_len));
        EXPECT_EQ(dec.original_destination_connection_id_present,
                  tp.original_destination_connection_id_present);
        EXPECT_EQ(dec.original_destination_connection_id_len,
                  tp.original_destination_connection_id_len);
    }
}

TEST(QuicTransportParams, SkipsUnknownParameterId) {
    // Hand-built block: an unknown id (0x4000, 2-byte varint) with a 3-byte
    // value, followed by a known initial_max_data=12345.
    std::uint8_t buf[64];
    std::size_t n = 0;
    // unknown id 0x4000 -> varint 2 bytes; len 3; value bytes.
    n += q::varint_encode(0x4000, buf + n);
    n += q::varint_encode(3, buf + n);
    buf[n++] = 0xaa;
    buf[n++] = 0xbb;
    buf[n++] = 0xcc;
    // initial_max_data (id 0x04), value 12345 (2-byte varint).
    n += q::varint_encode(
        static_cast<std::uint64_t>(q::TransportParamId::kInitialMaxData),
        buf + n);
    n += q::varint_encode(q::varint_encoded_size(12345), buf + n);
    n += q::varint_encode(12345, buf + n);

    q::TransportParameters dec;
    ASSERT_TRUE(q::decode_transport_params(buf, n, &dec));
    EXPECT_TRUE(dec.initial_max_data_present);
    EXPECT_EQ(dec.initial_max_data, 12345u);
}

TEST(QuicTransportParams, RejectsTruncatedValue) {
    std::uint8_t buf[16];
    std::size_t n = 0;
    n += q::varint_encode(
        static_cast<std::uint64_t>(q::TransportParamId::kInitialMaxData),
        buf + n);
    n += q::varint_encode(8, buf + n);  // claim 8-byte value...
    buf[n++] = 0x01;                    // ...but only provide 1 byte
    q::TransportParameters dec;
    EXPECT_FALSE(q::decode_transport_params(buf, n, &dec));
}

TEST(QuicTransportParams, RejectsOverlongConnectionId) {
    // initial_source_connection_id with a 21-byte value (> kMaxConnectionIdLength).
    std::uint8_t buf[64];
    std::size_t n = 0;
    n += q::varint_encode(
        static_cast<std::uint64_t>(
            q::TransportParamId::kInitialSourceConnectionId),
        buf + n);
    n += q::varint_encode(21, buf + n);
    for (int i = 0; i < 21; ++i) buf[n++] = static_cast<std::uint8_t>(i);
    q::TransportParameters dec;
    EXPECT_FALSE(q::decode_transport_params(buf, n, &dec));
}

// ---------------------------------------------------------------------------
// The handshake GATE: full in-process client<->server TLS 1.3 QUIC handshake.
// ---------------------------------------------------------------------------
TEST(QuicTls, InProcessHandshakeSharedSecretsAndTransportParams) {
    q::QuicTls client;
    q::QuicTls server;
    ASSERT_TRUE(client.init_client());
    ASSERT_TRUE(server.init_server());

    ASSERT_TRUE(client.set_alpn(kAlpnH3, sizeof(kAlpnH3)));
    ASSERT_TRUE(server.set_alpn(kAlpnH3, sizeof(kAlpnH3)));

    const q::TransportParameters cli_tp = make_client_params();
    const q::TransportParameters srv_tp = make_server_params();
    ASSERT_TRUE(client.set_transport_params(cli_tp));
    ASSERT_TRUE(server.set_transport_params(srv_tp));

    // Lockstep pump with a bounded iteration budget (no infinite loop).
    constexpr int kMaxIters = 64;
    int iters = 0;
    for (; iters < kMaxIters; ++iters) {
        ASSERT_TRUE(client.advance()) << "client failed at iter " << iters;
        ASSERT_TRUE(server.advance()) << "server failed at iter " << iters;
        const std::size_t a = shuttle(client, server);
        const std::size_t b = shuttle(server, client);
        if (client.is_complete() && server.is_complete() && a == 0 && b == 0) {
            // One more drain pass to flush post-handshake (server may emit
            // 1-RTT CRYPTO / session tickets the client should consume).
            client.advance();
            server.advance();
            shuttle(client, server);
            shuttle(server, client);
            client.advance();
            server.advance();
            break;
        }
    }

    EXPECT_LT(iters, kMaxIters) << "handshake did not converge";
    ASSERT_TRUE(client.is_complete());
    ASSERT_TRUE(server.is_complete());
    ASSERT_FALSE(client.failed());
    ASSERT_FALSE(server.failed());

    // Shared-secret proof at Handshake and 1-RTT (Application) levels.
    for (const auto level : {q::TlsLevel::kHandshake, q::TlsLevel::kApplication}) {
        std::size_t cw = 0, sr = 0, sw = 0, cr = 0;
        const std::uint8_t* client_write = client.write_secret(level, &cw);
        const std::uint8_t* server_read = server.read_secret(level, &sr);
        const std::uint8_t* server_write = server.write_secret(level, &sw);
        const std::uint8_t* client_read = client.read_secret(level, &cr);

        EXPECT_TRUE(secrets_equal(client_write, cw, server_read, sr))
            << "client write != server read at level "
            << static_cast<int>(level);
        EXPECT_TRUE(secrets_equal(server_write, sw, client_read, cr))
            << "server write != client read at level "
            << static_cast<int>(level);
        EXPECT_EQ(cw, q::kSecretLength);
        EXPECT_EQ(sw, q::kSecretLength);
    }

    // Transport params exchanged correctly (each side decoded the OTHER's).
    ASSERT_TRUE(client.have_peer_transport_params());
    ASSERT_TRUE(server.have_peer_transport_params());
    const q::TransportParameters& cli_sees = client.peer_transport_params();
    const q::TransportParameters& srv_sees = server.peer_transport_params();
    EXPECT_EQ(cli_sees.initial_max_data, srv_tp.initial_max_data);
    EXPECT_EQ(cli_sees.initial_max_streams_bidi, srv_tp.initial_max_streams_bidi);
    EXPECT_EQ(cli_sees.original_destination_connection_id_len,
              srv_tp.original_destination_connection_id_len);
    EXPECT_EQ(srv_sees.initial_max_data, cli_tp.initial_max_data);
    EXPECT_EQ(srv_sees.initial_max_streams_uni, cli_tp.initial_max_streams_uni);
    EXPECT_EQ(srv_sees.disable_active_migration, cli_tp.disable_active_migration);
    EXPECT_EQ(srv_sees.initial_source_connection_id_len,
              cli_tp.initial_source_connection_id_len);

    // ALPN negotiated to h3 on both ends.
    const std::uint8_t* alpn = nullptr;
    std::size_t alpn_len = 0;
    server.negotiated_alpn(&alpn, &alpn_len);
    ASSERT_EQ(alpn_len, 2u);
    EXPECT_EQ(0, std::memcmp(alpn, "h3", 2));

    // Cross seal/open (wave 2 + wave 3 together) at the 1-RTT level: the client
    // seals a packet with its WRITE protection; the server opens it with its
    // READ protection (same secret). Then the reverse direction.
    auto cross_seal_open = [](q::QuicTls& sealer, q::QuicTls& opener,
                              q::TlsLevel level) {
        q::PacketProtection& seal = sealer.write_protection(level);
        q::PacketProtection& open = opener.read_protection(level);
        ASSERT_TRUE(seal.is_initialized());
        ASSERT_TRUE(open.is_initialized());

        // A minimal 1-RTT-ish header (header is just AAD here) + payload.
        const std::uint8_t header[] = {0x40, 0xde, 0xad, 0xbe, 0xef};
        std::mt19937 rng(0xC0FFEE);
        std::vector<std::uint8_t> plain(97);
        for (auto& b : plain) b = static_cast<std::uint8_t>(rng() & 0xFF);
        const std::uint64_t pn = 424242;

        std::vector<std::uint8_t> sealed(plain.size() + q::kAeadTagLength);
        std::size_t sealed_len = 0;
        ASSERT_TRUE(seal.encrypt(pn, header, sizeof(header), plain.data(),
                                 plain.size(), sealed.data(), &sealed_len));
        ASSERT_EQ(sealed_len, plain.size() + q::kAeadTagLength);

        std::vector<std::uint8_t> opened(plain.size());
        std::size_t opened_len = 0;
        ASSERT_TRUE(open.decrypt(pn, header, sizeof(header), sealed.data(),
                                 sealed_len, opened.data(), &opened_len));
        ASSERT_EQ(opened_len, plain.size());
        EXPECT_EQ(0, std::memcmp(opened.data(), plain.data(), plain.size()));

        // Tampering the tag must fail to open (AEAD integrity).
        std::vector<std::uint8_t> bad = sealed;
        bad.back() ^= 0x01;
        std::size_t junk = 0;
        EXPECT_FALSE(open.decrypt(pn, header, sizeof(header), bad.data(),
                                  bad.size(), opened.data(), &junk));
    };
    cross_seal_open(client, server, q::TlsLevel::kApplication);
    cross_seal_open(server, client, q::TlsLevel::kApplication);
    cross_seal_open(client, server, q::TlsLevel::kHandshake);
}
