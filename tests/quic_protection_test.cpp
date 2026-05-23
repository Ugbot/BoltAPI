// quic_protection_test.cpp — RFC 9001 Appendix A worked-example GATE for the
// QUIC packet-protection port (boltapi/quic/packet_protection.h).
//
// This is the correctness gate for wave 2 (packet protection; NO TLS handshake).
// Every expected value below is copied BYTE-EXACT from RFC 9001 Appendix A — if
// any assertion fails the port is wrong, not the vector.
//
//   §A.1  derive_initial_secret(DCID=8394c8f03e515708) and the derived client +
//         server quic key / iv / hp.
//   §A.2  client Initial (AES-128-GCM): seal the RFC plaintext under the client
//         keys, apply header protection, and compare the full protected packet
//         against the RFC bytes; then round-trip unprotect + open back.
//   §A.3  server Initial (AES-128-GCM): same for the server direction.
//   §A.5  ChaCha20-Poly1305 short-header worked example (key/iv/hp + protected
//         packet) + round-trip — exercises the corrected ChaCha20 HP mask.
//   negative: tampered tag / ciphertext / wrong key / wrong AAD all fail to open.
//   randomized: AEAD round-trip across all three suites with varied lengths/PNs.
//
// OpenSSL is always linked into boltapi, so this runs in the default suite.

#include "boltapi/quic/packet_protection.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace q = bolt::api::quic;

// ---------------------------------------------------------------------------
// hex helpers (test-only; correctness over speed).
// ---------------------------------------------------------------------------
namespace {

std::vector<std::uint8_t> from_hex(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (char c : hex) {
        const int v = nib(c);
        if (v < 0) continue;  // skip spaces / formatting
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(k[p[i] >> 4]);
        s.push_back(k[p[i] & 0x0F]);
    }
    return s;
}

std::string to_hex(const std::vector<std::uint8_t>& v) {
    return to_hex(v.data(), v.size());
}

// RFC 9001 §A.2 / §A.3 share this DCID.
const std::string kDcidHex = "8394c8f03e515708";

}  // namespace

// ===========================================================================
// §A.1 — Initial secret + client/server key / iv / hp.
// ===========================================================================
TEST(QuicProtection, Rfc9001A1InitialSecretsAndClientKeys) {
    const auto dcid = from_hex(kDcidHex);

    std::uint8_t initial_secret[32];
    ASSERT_TRUE(q::derive_initial_secret(dcid.data(), dcid.size(), initial_secret));
    EXPECT_EQ(to_hex(initial_secret, 32),
              "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");

    std::uint8_t client_secret[32];
    std::uint8_t server_secret[32];
    ASSERT_TRUE(q::derive_initial_secrets(initial_secret, client_secret, server_secret));
    EXPECT_EQ(to_hex(client_secret, 32),
              "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    EXPECT_EQ(to_hex(server_secret, 32),
              "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");

    // Client direction quic key / iv / hp (RFC 9001 §A.1).
    q::PacketProtectionKeys ck;
    ASSERT_TRUE(q::derive_packet_keys(client_secret, 32, q::AeadAlgorithm::kAes128Gcm, ck));
    EXPECT_EQ(to_hex(ck.key.data(), ck.key_len), "1f369613dd76d5467730efcbe3b1a22d");
    EXPECT_EQ(to_hex(ck.iv.data(), 12), "fa044b2f42a3fd3b46fb255c");
    EXPECT_EQ(to_hex(ck.hp_key.data(), ck.hp_len), "9f50449e04a0e810283a1e9933adedd2");

    // Server direction quic key / iv / hp (RFC 9001 §A.1).
    q::PacketProtectionKeys sk;
    ASSERT_TRUE(q::derive_packet_keys(server_secret, 32, q::AeadAlgorithm::kAes128Gcm, sk));
    EXPECT_EQ(to_hex(sk.key.data(), sk.key_len), "cf3a5331653c364c88f0f379b6067e37");
    EXPECT_EQ(to_hex(sk.iv.data(), 12), "0ac1493ca1905853b0bba03e");
    EXPECT_EQ(to_hex(sk.hp_key.data(), sk.hp_len), "c206b8d9b9f0f37644430b490eeaa314");
}

// ===========================================================================
// §A.2 — client Initial packet protection (AES-128-GCM), full protected packet.
// ===========================================================================
TEST(QuicProtection, Rfc9001A2ClientInitialProtect) {
    const auto dcid = from_hex(kDcidHex);

    q::PacketProtection client;
    ASSERT_TRUE(q::derive_initial(dcid.data(), dcid.size(), /*is_server=*/false, client));

    // RFC 9001 §A.2 unprotected header (through the 4-byte packet number):
    //   c3 00000001 08 8394c8f03e515708 00 00 449e 00000002
    //   pn = 2, pn_length = 4, pn_offset = 18, Length field 0x449e = 1182.
    const auto header = from_hex("c300000001088394c8f03e5157080000449e00000002");
    const std::size_t pn_offset = 18;
    const std::size_t pn_length = 4;
    const std::uint64_t pn = 2;
    ASSERT_EQ(header.size(), pn_offset + pn_length);

    // RFC 9001 §A.2: CRYPTO frame (verbatim) + PADDING to a 1162-byte payload.
    const std::string crypto_frame_hex =
        "060040f1010000ed0303ebf8fa56f129"
        "39b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c000004130113"
        "02010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a"
        "00080006001d00170018001000070005"
        "04616c706e0005000501000000000033"
        "00260024001d00209370b2c9caa47fba"
        "baf4559fedba753de171fa71f50f1ce1"
        "5d43e994ec74d748002b000302030400"
        "0d0010000e0403050306030203080408"
        "050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff050480"
        "00ffff07048000ffff08011001048000"
        "75300901100f088394c8f03e51570806"
        "048000ffff";
    auto payload = from_hex(crypto_frame_hex);
    ASSERT_LE(payload.size(), 1162u);
    payload.resize(1162, 0x00);  // PADDING frames are 0x00

    // Seal (AEAD).
    std::vector<std::uint8_t> ct(payload.size() + q::kAeadTagLength);
    std::size_t ct_len = 0;
    ASSERT_TRUE(client.encrypt(pn, header.data(), header.size(),
                               payload.data(), payload.size(), ct.data(), &ct_len));
    ASSERT_EQ(ct_len, payload.size() + q::kAeadTagLength);

    // RFC 9001 §A.2 published protected-payload sample + tag.
    EXPECT_EQ(to_hex(ct.data(), 16), "d1b1c98dd7689fb8ec11d242b123dc9b");
    EXPECT_EQ(to_hex(ct.data() + ct_len - 16, 16), "e221af44860018ab0856972e194cd934");

    // Header protection: sample at sample_offset(pn_offset) within the packet.
    std::vector<std::uint8_t> prot_header(header);
    const std::size_t sample_off = q::PacketProtection::sample_offset(pn_offset);
    const std::uint8_t* sample = ct.data() + (sample_off - header.size());
    EXPECT_EQ(to_hex(sample, q::kHpSampleLength), "d1b1c98dd7689fb8ec11d242b123dc9b");
    ASSERT_TRUE(client.protect_header(prot_header.data(), pn_offset, pn_length, sample));

    // RFC 9001 §A.2 protected header (mask 437b9aec36 -> first byte c0, pn 7b9aec34).
    EXPECT_EQ(to_hex(prot_header), "c000000001088394c8f03e5157080000449e7b9aec34");

    // The full protected packet = protected header || protected payload(+tag).
    // Spot-check the published full-packet first 32 bytes.
    std::vector<std::uint8_t> packet(prot_header);
    packet.insert(packet.end(), ct.begin(), ct.begin() + ct_len);
    EXPECT_EQ(to_hex(packet.data(), 32),
              "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11");

    // ---- Round-trip: unprotect header, open AEAD ----
    std::vector<std::uint8_t> rt_header(prot_header);
    std::size_t got_pn_len = 0;
    ASSERT_TRUE(client.unprotect_header(rt_header.data(), pn_offset, sample, &got_pn_len));
    EXPECT_EQ(got_pn_len, pn_length);
    EXPECT_EQ(to_hex(rt_header), to_hex(header));

    std::vector<std::uint8_t> pt(ct_len);
    std::size_t pt_len = 0;
    ASSERT_TRUE(client.decrypt(pn, rt_header.data(), rt_header.size(),
                               ct.data(), ct_len, pt.data(), &pt_len));
    ASSERT_EQ(pt_len, payload.size());
    EXPECT_EQ(to_hex(pt.data(), pt_len), to_hex(payload));
}

// ===========================================================================
// §A.3 — server Initial packet protection (AES-128-GCM), full protected packet.
// ===========================================================================
TEST(QuicProtection, Rfc9001A3ServerInitialProtect) {
    const auto dcid = from_hex(kDcidHex);

    q::PacketProtection server;
    ASSERT_TRUE(q::derive_initial(dcid.data(), dcid.size(), /*is_server=*/true, server));

    // RFC 9001 §A.3 unprotected header:
    //   c1 00000001 00 08 f067a5502a4262b5 4075 0001
    //   DCID len 00, SCID len 08 (f067a5502a4262b5), Length 0x4075, pn 0001.
    //   header is 20 bytes; pn_offset = 18, pn_length = 2, pn = 1.
    const auto header = from_hex("c1000000010008f067a5502a4262b50040750001");
    const std::size_t pn_offset = 18;
    const std::size_t pn_length = 2;
    const std::uint64_t pn = 1;
    ASSERT_EQ(header.size(), pn_offset + pn_length);

    // RFC 9001 §A.3 unprotected payload (ACK + CRYPTO, no PADDING).
    const std::string payload_hex =
        "02000000000600405a020000560303ee"
        "fce7f7b37ba1d1632e96677825ddf739"
        "88cfc79825df566dc5430b9a045a1200"
        "130100002e00330024001d00209d3c94"
        "0d89690b84d08a60993c144eca684d10"
        "81287c834d5311bcf32bb9da1a002b00"
        "020304";
    const auto payload = from_hex(payload_hex);

    std::vector<std::uint8_t> ct(payload.size() + q::kAeadTagLength);
    std::size_t ct_len = 0;
    ASSERT_TRUE(server.encrypt(pn, header.data(), header.size(),
                               payload.data(), payload.size(), ct.data(), &ct_len));

    // Header protection. RFC 9001 §A.3 sample = 2cd0991cd25b0aac406a5816b6394100.
    std::vector<std::uint8_t> prot_header(header);
    const std::size_t sample_off = q::PacketProtection::sample_offset(pn_offset);
    const std::uint8_t* sample = ct.data() + (sample_off - header.size());
    EXPECT_EQ(to_hex(sample, q::kHpSampleLength), "2cd0991cd25b0aac406a5816b6394100");
    ASSERT_TRUE(server.protect_header(prot_header.data(), pn_offset, pn_length, sample));

    // RFC 9001 §A.3 protected header: cf...4075c0d9 (mask 2ec0d8356a).
    EXPECT_EQ(to_hex(prot_header), "cf000000010008f067a5502a4262b5004075c0d9");

    // RFC 9001 §A.3 final protected packet, first 32 bytes.
    std::vector<std::uint8_t> packet(prot_header);
    packet.insert(packet.end(), ct.begin(), ct.begin() + ct_len);
    EXPECT_EQ(to_hex(packet.data(), 32),
              "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a");

    // Round-trip.
    std::vector<std::uint8_t> rt_header(prot_header);
    std::size_t got_pn_len = 0;
    ASSERT_TRUE(server.unprotect_header(rt_header.data(), pn_offset, sample, &got_pn_len));
    EXPECT_EQ(got_pn_len, pn_length);
    EXPECT_EQ(to_hex(rt_header), to_hex(header));

    std::vector<std::uint8_t> pt(ct_len);
    std::size_t pt_len = 0;
    ASSERT_TRUE(server.decrypt(pn, rt_header.data(), rt_header.size(),
                               ct.data(), ct_len, pt.data(), &pt_len));
    ASSERT_EQ(pt_len, payload.size());
    EXPECT_EQ(to_hex(pt.data(), pt_len), to_hex(payload));
}

// ===========================================================================
// §A.5 — ChaCha20-Poly1305 short-header worked example.
// ===========================================================================
TEST(QuicProtection, Rfc9001A5ChaCha20ShortHeader) {
    const auto secret = from_hex(
        "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");

    q::PacketProtectionKeys keys;
    ASSERT_TRUE(q::derive_packet_keys(secret.data(), secret.size(),
                                      q::AeadAlgorithm::kChaCha20Poly1305, keys));
    EXPECT_EQ(to_hex(keys.key.data(), keys.key_len),
              "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
    EXPECT_EQ(to_hex(keys.iv.data(), 12), "e0459b3474bdd0e44a41c144");
    EXPECT_EQ(to_hex(keys.hp_key.data(), keys.hp_len),
              "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");

    q::PacketProtection pp;
    ASSERT_TRUE(pp.initialize(keys));

    // RFC 9001 §A.5: pn = 654360564 (3-byte 00bff4), header byte 0x42, PING (0x01).
    const std::uint64_t pn = 654360564;
    const auto header = from_hex("4200bff4");
    const std::size_t pn_offset = 1;
    const std::size_t pn_length = 3;
    const auto payload = from_hex("01");

    std::vector<std::uint8_t> ct(payload.size() + q::kAeadTagLength);
    std::size_t ct_len = 0;
    ASSERT_TRUE(pp.encrypt(pn, header.data(), header.size(),
                           payload.data(), payload.size(), ct.data(), &ct_len));
    // RFC 9001 §A.5 payload ciphertext.
    EXPECT_EQ(to_hex(ct), "655e5cd55c41f69080575d7999c25a5bfb");

    // Header protection. RFC §A.5 sample = 5e5cd55c41f69080575d7999c25a5bfb,
    // mask = aefefe7d03, protected header = 4cfe4189.
    std::vector<std::uint8_t> prot_header(header);
    const std::size_t sample_off = q::PacketProtection::sample_offset(pn_offset);
    const std::uint8_t* sample = ct.data() + (sample_off - header.size());
    EXPECT_EQ(to_hex(sample, q::kHpSampleLength), "5e5cd55c41f69080575d7999c25a5bfb");
    ASSERT_TRUE(pp.protect_header(prot_header.data(), pn_offset, pn_length, sample));
    EXPECT_EQ(to_hex(prot_header), "4cfe4189");

    // Full protected packet (RFC §A.5): 4cfe4189655e5cd55c41f69080575d7999c25a5bfb.
    std::vector<std::uint8_t> packet(prot_header);
    packet.insert(packet.end(), ct.begin(), ct.begin() + ct_len);
    EXPECT_EQ(to_hex(packet), "4cfe4189655e5cd55c41f69080575d7999c25a5bfb");

    // Round-trip.
    std::vector<std::uint8_t> rt_header(prot_header);
    std::size_t got_pn_len = 0;
    ASSERT_TRUE(pp.unprotect_header(rt_header.data(), pn_offset, sample, &got_pn_len));
    EXPECT_EQ(got_pn_len, pn_length);
    EXPECT_EQ(to_hex(rt_header), to_hex(header));

    std::vector<std::uint8_t> pt(ct_len);
    std::size_t pt_len = 0;
    ASSERT_TRUE(pp.decrypt(pn, rt_header.data(), rt_header.size(),
                           ct.data(), ct_len, pt.data(), &pt_len));
    EXPECT_EQ(to_hex(pt.data(), pt_len), to_hex(payload));
}

// ===========================================================================
// Negative — tampered tag / ciphertext / wrong key / wrong AAD must NOT open.
// ===========================================================================
TEST(QuicProtection, NegativeAuthFailures) {
    const auto dcid = from_hex(kDcidHex);
    q::PacketProtection client;
    ASSERT_TRUE(q::derive_initial(dcid.data(), dcid.size(), /*is_server=*/false, client));

    const auto header = from_hex("c300000001088394c8f03e5157080000449e00000002");
    std::vector<std::uint8_t> payload(64, 0xAB);
    payload[0] = 0x06;

    std::vector<std::uint8_t> ct(payload.size() + q::kAeadTagLength);
    std::size_t ct_len = 0;
    ASSERT_TRUE(client.encrypt(2, header.data(), header.size(),
                               payload.data(), payload.size(), ct.data(), &ct_len));

    std::vector<std::uint8_t> pt(ct_len);
    std::size_t n = 0;
    ASSERT_TRUE(client.decrypt(2, header.data(), header.size(),
                               ct.data(), ct_len, pt.data(), &n));
    EXPECT_EQ(n, payload.size());

    { auto bad = ct; bad[ct_len - 1] ^= 0x01;  // tag
      EXPECT_FALSE(client.decrypt(2, header.data(), header.size(),
                                  bad.data(), ct_len, pt.data(), &n)); }
    { auto bad = ct; bad[0] ^= 0x80;           // ciphertext body
      EXPECT_FALSE(client.decrypt(2, header.data(), header.size(),
                                  bad.data(), ct_len, pt.data(), &n)); }
    { q::PacketProtection server;              // wrong direction key
      ASSERT_TRUE(q::derive_initial(dcid.data(), dcid.size(), true, server));
      EXPECT_FALSE(server.decrypt(2, header.data(), header.size(),
                                  ct.data(), ct_len, pt.data(), &n)); }
    { auto bad = header; bad[0] ^= 0x01;       // wrong AAD
      EXPECT_FALSE(client.decrypt(2, bad.data(), bad.size(),
                                  ct.data(), ct_len, pt.data(), &n)); }
}

// ===========================================================================
// Randomized AEAD round-trip across all three suites (varied lengths/PNs/keys).
// ===========================================================================
TEST(QuicProtection, RandomizedRoundTripAllSuites) {
    const q::AeadAlgorithm algos[] = {q::AeadAlgorithm::kAes128Gcm,
                                      q::AeadAlgorithm::kAes256Gcm,
                                      q::AeadAlgorithm::kChaCha20Poly1305};
    std::mt19937_64 rng(0xC0FFEEull);
    for (auto algo : algos) {
        std::array<std::uint8_t, 32> secret{};
        for (auto& b : secret) b = static_cast<std::uint8_t>(rng());
        q::PacketProtectionKeys keys;
        ASSERT_TRUE(q::derive_packet_keys(secret.data(), secret.size(), algo, keys));
        q::PacketProtection pp;
        ASSERT_TRUE(pp.initialize(keys));

        for (int trial = 0; trial < 200; ++trial) {
            const std::size_t hlen = 1 + (rng() % 30);
            const std::size_t plen = rng() % 1500;
            const std::uint64_t pn = rng() & ((1ULL << 62) - 1);
            std::vector<std::uint8_t> header(hlen), payload(plen);
            for (auto& b : header) b = static_cast<std::uint8_t>(rng());
            for (auto& b : payload) b = static_cast<std::uint8_t>(rng());

            std::vector<std::uint8_t> ct(plen + q::kAeadTagLength);
            std::size_t ct_len = 0;
            ASSERT_TRUE(pp.encrypt(pn, header.data(), hlen, payload.data(), plen,
                                   ct.data(), &ct_len));
            ASSERT_EQ(ct_len, plen + q::kAeadTagLength);

            std::vector<std::uint8_t> pt(ct_len);
            std::size_t pt_len = 0;
            ASSERT_TRUE(pp.decrypt(pn, header.data(), hlen, ct.data(), ct_len,
                                   pt.data(), &pt_len));
            ASSERT_EQ(pt_len, plen);
            ASSERT_EQ(to_hex(pt.data(), pt_len), to_hex(payload));

            std::size_t n = 0;  // wrong PN -> nonce differs -> fail
            EXPECT_FALSE(pp.decrypt(pn ^ 1, header.data(), hlen, ct.data(), ct_len,
                                    pt.data(), &n));
        }
    }
}
