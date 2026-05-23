// srtp_test.cpp — SRTP / SRTCP (RFC 3711, RFC 7714) correctness GATE for
// boltapi/webrtc/srtp.h.
//
// This is the correctness gate for the SRTP module. The KDF expected values are
// copied BYTE-EXACT from RFC 3711 Appendix B.3 — if those assertions fail the
// implementation is wrong, not the vector.
//
//   KDF (B.3): master key E1F97A0D3E018BE0D64FA32C06DE4139, master salt
//     0EC675AD498AFEEBB6960B3AABE6 -> session cipher key, salt, auth key.
//   SRTP protect->unprotect round-trip (AES-CM and AES-GCM), multiple SSRCs.
//   SRTCP protect->unprotect round-trip (both profiles).
//   Negative: tag tamper -> kAuthFail; replay -> kReplay.
//   ROC rollover across the 16-bit sequence wrap.
//
// OpenSSL is always linked into boltapi, so this runs in the default suite.

#include "boltapi/webrtc/srtp.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace s = bolt::api::webrtc::srtp;

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
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    }
    return out;
}

std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(d[p[i] >> 4]);
        out.push_back(d[p[i] & 0x0F]);
    }
    return out;
}

// Build a minimal valid RTP packet: 12-byte header + payload.
std::vector<std::uint8_t> make_rtp(std::uint16_t seq, std::uint32_t ssrc,
                                   std::uint32_t ts, const std::uint8_t* pl,
                                   std::size_t pl_len, std::uint8_t pt = 96) {
    std::vector<std::uint8_t> p(12 + pl_len);
    p[0] = 0x80;            // V=2, P=0, X=0, CC=0
    p[1] = pt & 0x7F;       // M=0, PT
    p[2] = static_cast<std::uint8_t>(seq >> 8);
    p[3] = static_cast<std::uint8_t>(seq);
    p[4] = static_cast<std::uint8_t>(ts >> 24);
    p[5] = static_cast<std::uint8_t>(ts >> 16);
    p[6] = static_cast<std::uint8_t>(ts >> 8);
    p[7] = static_cast<std::uint8_t>(ts);
    p[8] = static_cast<std::uint8_t>(ssrc >> 24);
    p[9] = static_cast<std::uint8_t>(ssrc >> 16);
    p[10] = static_cast<std::uint8_t>(ssrc >> 8);
    p[11] = static_cast<std::uint8_t>(ssrc);
    if (pl_len) std::memcpy(p.data() + 12, pl, pl_len);
    return p;
}

// Build a minimal RTCP sender report: 8-byte header (incl SSRC) + body.
std::vector<std::uint8_t> make_rtcp(std::uint32_t ssrc, const std::uint8_t* body,
                                    std::size_t body_len) {
    std::vector<std::uint8_t> p(8 + body_len);
    p[0] = 0x80;  // V=2, P=0, RC=0
    p[1] = 200;   // PT=SR
    const std::uint16_t words = static_cast<std::uint16_t>((p.size() / 4) - 1);
    p[2] = static_cast<std::uint8_t>(words >> 8);
    p[3] = static_cast<std::uint8_t>(words);
    p[4] = static_cast<std::uint8_t>(ssrc >> 24);
    p[5] = static_cast<std::uint8_t>(ssrc >> 16);
    p[6] = static_cast<std::uint8_t>(ssrc >> 8);
    p[7] = static_cast<std::uint8_t>(ssrc);
    if (body_len) std::memcpy(p.data() + 8, body, body_len);
    return p;
}

const auto kMasterKey  = from_hex("E1F97A0D3E018BE0D64FA32C06DE4139");
const auto kMasterSalt = from_hex("0EC675AD498AFEEBB6960B3AABE6");

}  // namespace

// ---------------------------------------------------------------------------
// RFC 3711 Appendix B.3 — KDF test vectors (BYTE-EXACT gate).
// ---------------------------------------------------------------------------
TEST(SrtpKdf, Rfc3711AppendixB3) {
    ASSERT_EQ(kMasterKey.size(), s::kMasterKeyLen);
    ASSERT_EQ(kMasterSalt.size(), s::kMasterSaltLen);

    s::SessionKeys k;
    ASSERT_EQ(s::derive_session_keys(kMasterKey.data(), kMasterKey.size(),
                                     kMasterSalt.data(), kMasterSalt.size(),
                                     /*is_rtcp=*/false, k),
              s::Error::kOk);

    // RFC 3711 B.3: cipher (encr) key = C61E7A93744F39EE10734AFE3FF7A087.
    EXPECT_EQ(to_hex(k.cipher.data(), k.cipher.size()),
              "c61e7a93744f39ee10734afe3ff7a087");

    // RFC 3711 B.3: session salt (14 bytes) = 30CBBC08863D8C85D49DB34A9AE1.
    EXPECT_EQ(to_hex(k.salt.data(), k.salt.size()),
              "30cbbc08863d8c85d49db34a9ae1");

    // RFC 3711 B.3: auth key (160-bit) = CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4.
    EXPECT_EQ(to_hex(k.auth.data(), k.auth.size()),
              "cebe321f6ff7716b6fd4ab49af256a156d38baa4");
}

// ---------------------------------------------------------------------------
// SRTP round-trip — AES-CM-128-HMAC-SHA1-80.
// ---------------------------------------------------------------------------
TEST(SrtpRtp, RoundTripCm) {
    s::SrtpSession enc, dec;
    ASSERT_EQ(enc.init(s::Profile::kAesCm128HmacSha1_80, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);
    ASSERT_EQ(dec.init(s::Profile::kAesCm128HmacSha1_80, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);

    std::mt19937 rng(1234);
    // Two SSRCs, varied seq + random payload lengths and bytes.
    const std::uint32_t ssrcs[2] = {0xCAFEBABEu, 0x12345678u};
    for (int round = 0; round < 50; ++round) {
        const std::uint32_t ssrc = ssrcs[round & 1];
        const std::uint16_t seq = static_cast<std::uint16_t>(1000 + round);
        const std::size_t pl_len = (rng() % 200) + 1;
        std::vector<std::uint8_t> pl(pl_len);
        for (auto& b : pl) b = static_cast<std::uint8_t>(rng());
        auto rtp = make_rtp(seq, ssrc, round * 160u, pl.data(), pl_len);

        std::vector<std::uint8_t> prot(rtp.size() + 16);
        std::size_t prot_len = 0;
        ASSERT_EQ(enc.protect_rtp(rtp.data(), rtp.size(), prot.data(), prot.size(),
                                  &prot_len),
                  s::Error::kOk);
        EXPECT_EQ(prot_len, rtp.size() + s::kSrtpTagLenCm);
        // Payload must actually be encrypted (differs from plaintext).
        EXPECT_NE(0, std::memcmp(prot.data() + 12, rtp.data() + 12, pl_len));

        std::vector<std::uint8_t> back(prot_len);
        std::size_t back_len = 0;
        ASSERT_EQ(dec.unprotect_rtp(prot.data(), prot_len, back.data(), back.size(),
                                    &back_len),
                  s::Error::kOk);
        ASSERT_EQ(back_len, rtp.size());
        EXPECT_EQ(0, std::memcmp(back.data(), rtp.data(), rtp.size()));
    }
}

// ---------------------------------------------------------------------------
// SRTP round-trip — AEAD_AES_128_GCM (RFC 7714).
// ---------------------------------------------------------------------------
TEST(SrtpRtp, RoundTripGcm) {
    s::SrtpSession enc, dec;
    ASSERT_EQ(enc.init(s::Profile::kAeadAes128Gcm, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);
    ASSERT_EQ(dec.init(s::Profile::kAeadAes128Gcm, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);

    std::mt19937 rng(99);
    for (int round = 0; round < 50; ++round) {
        const std::uint16_t seq = static_cast<std::uint16_t>(200 + round);
        const std::size_t pl_len = (rng() % 300) + 1;
        std::vector<std::uint8_t> pl(pl_len);
        for (auto& b : pl) b = static_cast<std::uint8_t>(rng());
        auto rtp = make_rtp(seq, 0xABCDEF01u, round * 90u, pl.data(), pl_len);

        std::vector<std::uint8_t> prot(rtp.size() + 16);
        std::size_t prot_len = 0;
        ASSERT_EQ(enc.protect_rtp(rtp.data(), rtp.size(), prot.data(), prot.size(),
                                  &prot_len),
                  s::Error::kOk);
        EXPECT_EQ(prot_len, rtp.size() + s::kGcmTagLen);

        std::vector<std::uint8_t> back(prot_len);
        std::size_t back_len = 0;
        ASSERT_EQ(dec.unprotect_rtp(prot.data(), prot_len, back.data(), back.size(),
                                    &back_len),
                  s::Error::kOk);
        ASSERT_EQ(back_len, rtp.size());
        EXPECT_EQ(0, std::memcmp(back.data(), rtp.data(), rtp.size()));
    }
}

// ---------------------------------------------------------------------------
// Negative: auth-tag tamper must be rejected (both profiles).
// ---------------------------------------------------------------------------
TEST(SrtpRtp, TamperRejected) {
    for (auto prof : {s::Profile::kAesCm128HmacSha1_80, s::Profile::kAeadAes128Gcm}) {
        s::SrtpSession enc, dec;
        ASSERT_EQ(enc.init(prof, kMasterKey.data(), kMasterKey.size(),
                           kMasterSalt.data(), kMasterSalt.size()),
                  s::Error::kOk);
        ASSERT_EQ(dec.init(prof, kMasterKey.data(), kMasterKey.size(),
                           kMasterSalt.data(), kMasterSalt.size()),
                  s::Error::kOk);
        const std::uint8_t pl[] = {1, 2, 3, 4, 5, 6, 7, 8};
        auto rtp = make_rtp(7, 0x99u, 0, pl, sizeof(pl));
        std::vector<std::uint8_t> prot(rtp.size() + 16);
        std::size_t prot_len = 0;
        ASSERT_EQ(enc.protect_rtp(rtp.data(), rtp.size(), prot.data(), prot.size(),
                                  &prot_len),
                  s::Error::kOk);

        // Flip a bit in the last (tag) byte.
        std::vector<std::uint8_t> bad(prot.begin(), prot.begin() + prot_len);
        bad[prot_len - 1] ^= 0x01;
        std::vector<std::uint8_t> back(prot_len);
        std::size_t back_len = 0;
        EXPECT_EQ(dec.unprotect_rtp(bad.data(), prot_len, back.data(), back.size(),
                                    &back_len),
                  s::Error::kAuthFail);

        // Flip a ciphertext byte (CM has no integrity over... it does via HMAC).
        std::vector<std::uint8_t> bad2(prot.begin(), prot.begin() + prot_len);
        bad2[12] ^= 0xFF;
        EXPECT_EQ(dec.unprotect_rtp(bad2.data(), prot_len, back.data(), back.size(),
                                    &back_len),
                  s::Error::kAuthFail);
    }
}

// ---------------------------------------------------------------------------
// Negative: replay must be rejected.
// ---------------------------------------------------------------------------
TEST(SrtpRtp, ReplayRejected) {
    s::SrtpSession enc, dec;
    ASSERT_EQ(enc.init(s::Profile::kAesCm128HmacSha1_80, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);
    ASSERT_EQ(dec.init(s::Profile::kAesCm128HmacSha1_80, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);
    const std::uint8_t pl[] = {9, 8, 7, 6, 5};
    auto rtp = make_rtp(42, 0x55u, 0, pl, sizeof(pl));
    std::vector<std::uint8_t> prot(rtp.size() + 16);
    std::size_t prot_len = 0;
    ASSERT_EQ(enc.protect_rtp(rtp.data(), rtp.size(), prot.data(), prot.size(),
                              &prot_len),
              s::Error::kOk);
    std::vector<std::uint8_t> back(prot_len);
    std::size_t back_len = 0;
    EXPECT_EQ(dec.unprotect_rtp(prot.data(), prot_len, back.data(), back.size(),
                                &back_len),
              s::Error::kOk);
    // Same packet again -> replay.
    EXPECT_EQ(dec.unprotect_rtp(prot.data(), prot_len, back.data(), back.size(),
                                &back_len),
              s::Error::kReplay);
}

// ---------------------------------------------------------------------------
// ROC rollover across the 16-bit sequence wrap.
// ---------------------------------------------------------------------------
TEST(SrtpRtp, RocRollover) {
    s::SrtpSession enc, dec;
    ASSERT_EQ(enc.init(s::Profile::kAeadAes128Gcm, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);
    ASSERT_EQ(dec.init(s::Profile::kAeadAes128Gcm, kMasterKey.data(),
                       kMasterKey.size(), kMasterSalt.data(), kMasterSalt.size()),
              s::Error::kOk);

    // Sequence numbers around the wrap: 65534, 65535, 0, 1, 2. The decryptor
    // must guess ROC=1 for seq 0..2 even though SEQ went backwards numerically.
    const std::uint16_t seqs[] = {65534, 65535, 0, 1, 2};
    std::uint32_t prev_index_hi = 0;
    for (std::size_t i = 0; i < std::size(seqs); ++i) {
        const std::uint8_t pl[] = {static_cast<std::uint8_t>(i), 0xAA, 0xBB};
        auto rtp = make_rtp(seqs[i], 0x77u, static_cast<std::uint32_t>(i), pl,
                            sizeof(pl));
        std::vector<std::uint8_t> prot(rtp.size() + 16);
        std::size_t prot_len = 0;
        ASSERT_EQ(enc.protect_rtp(rtp.data(), rtp.size(), prot.data(), prot.size(),
                                  &prot_len),
                  s::Error::kOk);
        std::vector<std::uint8_t> back(prot_len);
        std::size_t back_len = 0;
        ASSERT_EQ(dec.unprotect_rtp(prot.data(), prot_len, back.data(), back.size(),
                                    &back_len),
                  s::Error::kOk)
            << "failed at seq " << seqs[i];
        ASSERT_EQ(back_len, rtp.size());
        EXPECT_EQ(0, std::memcmp(back.data(), rtp.data(), rtp.size()));
        (void)prev_index_hi;
    }
}

// ---------------------------------------------------------------------------
// SRTCP round-trip (both profiles) + tamper reject.
// ---------------------------------------------------------------------------
TEST(Srtcp, RoundTripBothProfiles) {
    for (auto prof : {s::Profile::kAesCm128HmacSha1_80, s::Profile::kAeadAes128Gcm}) {
        s::SrtpSession enc, dec;
        ASSERT_EQ(enc.init(prof, kMasterKey.data(), kMasterKey.size(),
                           kMasterSalt.data(), kMasterSalt.size()),
                  s::Error::kOk);
        ASSERT_EQ(dec.init(prof, kMasterKey.data(), kMasterKey.size(),
                           kMasterSalt.data(), kMasterSalt.size()),
                  s::Error::kOk);
        std::mt19937 rng(7);
        for (int round = 0; round < 20; ++round) {
            const std::size_t body_len = ((rng() % 16) + 1) * 4;  // word-aligned
            std::vector<std::uint8_t> body(body_len);
            for (auto& b : body) b = static_cast<std::uint8_t>(rng());
            auto rtcp = make_rtcp(0xDEADBEEFu, body.data(), body_len);

            std::vector<std::uint8_t> prot(rtcp.size() + 4 + 16);
            std::size_t prot_len = 0;
            ASSERT_EQ(enc.protect_rtcp(rtcp.data(), rtcp.size(), prot.data(),
                                       prot.size(), &prot_len),
                      s::Error::kOk);
            // Body after the 8-byte header must be encrypted.
            EXPECT_NE(0, std::memcmp(prot.data() + 8, rtcp.data() + 8, body_len));

            std::vector<std::uint8_t> back(prot_len);
            std::size_t back_len = 0;
            ASSERT_EQ(dec.unprotect_rtcp(prot.data(), prot_len, back.data(),
                                         back.size(), &back_len),
                      s::Error::kOk);
            ASSERT_EQ(back_len, rtcp.size());
            EXPECT_EQ(0, std::memcmp(back.data(), rtcp.data(), rtcp.size()));

            // Tamper the tag.
            std::vector<std::uint8_t> bad(prot.begin(), prot.begin() + prot_len);
            bad[prot_len - 1] ^= 0x01;
            EXPECT_EQ(dec.unprotect_rtcp(bad.data(), prot_len, back.data(),
                                         back.size(), &back_len),
                      s::Error::kAuthFail);
        }
    }
}

#ifdef SRTP_STANDALONE_MAIN
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
