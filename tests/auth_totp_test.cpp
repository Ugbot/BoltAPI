// boltapi/auth/totp gtest — RFC 4226 + RFC 6238 reference vectors + recovery codes.

#include <gtest/gtest.h>

#include <cstring>

#include "boltapi/auth/totp.h"

using namespace bolt::api::auth::totp;

TEST(Base32, RoundTripRandomBytes) {
    uint8_t secret[kSecretBytes] = {};
    ASSERT_TRUE(generate_secret(secret));
    char enc[kBase32SecretChars + 1];
    const size_t n = base32_encode(secret, sizeof(secret), enc, sizeof(enc));
    EXPECT_EQ(n, kBase32SecretChars);
    uint8_t back[kSecretBytes] = {};
    const size_t m = base32_decode(enc, back, sizeof(back));
    EXPECT_EQ(m, kSecretBytes);
    EXPECT_EQ(0, std::memcmp(secret, back, kSecretBytes));
}

TEST(Base32, AcceptsLowerAndPaddingAndSpaces) {
    // "Hello!" -> JBSWY3DPEE====== in RFC 4648 base32. We accept padding and spaces.
    const uint8_t want[] = {'H', 'e', 'l', 'l', 'o', '!'};
    uint8_t out[16] = {};
    const size_t n = base32_decode("jbswy 3dp ee======", out, sizeof(out));
    ASSERT_EQ(n, sizeof(want));
    EXPECT_EQ(0, std::memcmp(out, want, sizeof(want)));
}

// RFC 4226 Appendix D — HOTP test vectors. Key = ASCII "12345678901234567890".
TEST(Hotp, Rfc4226AppendixDVectors) {
    const uint8_t key[] = "12345678901234567890";
    const size_t klen = sizeof(key) - 1;
    const uint32_t expected[10] = {
        755224, 287082, 359152, 969429, 338314,
        254676, 287922, 162583, 399871, 520489,
    };
    for (uint64_t i = 0; i < 10; ++i) {
        EXPECT_EQ(expected[i], hotp_code(key, klen, i, 6))
            << "counter=" << i;
    }
}

// RFC 6238 Appendix B — TOTP SHA-1 test vectors (the HMAC-SHA1 row, 8-digit).
TEST(Totp, Rfc6238AppendixBSha1) {
    const uint8_t key[] = "12345678901234567890";
    const size_t klen = sizeof(key) - 1;
    struct V { uint64_t t; uint32_t code; };
    const V vs[] = {
        {59ULL,          94287082u},
        {1111111109ULL,   7081804u},
        {1111111111ULL,  14050471u},
        {1234567890ULL,  89005924u},
        {2000000000ULL,  69279037u},
    };
    for (const auto& v : vs) {
        EXPECT_EQ(v.code, totp_code_at(key, klen, v.t, 30, 8)) << "t=" << v.t;
    }
}

TEST(Totp, VerifyExactAndWindow) {
    uint8_t secret[kSecretBytes];
    ASSERT_TRUE(generate_secret(secret));
    const uint64_t now = 1700000000ULL;
    const uint32_t code_now    = totp_code_at(secret, sizeof(secret), now);
    const uint32_t code_prev   = totp_code_at(secret, sizeof(secret), now - 30);
    const uint32_t code_next   = totp_code_at(secret, sizeof(secret), now + 30);
    const uint32_t code_way    = totp_code_at(secret, sizeof(secret), now + 600);

    EXPECT_TRUE (totp_verify(secret, sizeof(secret), code_now,  now, 1));
    EXPECT_TRUE (totp_verify(secret, sizeof(secret), code_prev, now, 1));
    EXPECT_TRUE (totp_verify(secret, sizeof(secret), code_next, now, 1));
    EXPECT_FALSE(totp_verify(secret, sizeof(secret), code_way,  now, 1));
    EXPECT_FALSE(totp_verify(secret, sizeof(secret), 0,         now, 1));
}

TEST(Totp, VerifyWindowZeroOnlyMatchesCurrent) {
    uint8_t secret[kSecretBytes];
    ASSERT_TRUE(generate_secret(secret));
    const uint64_t now = 1700000000ULL;
    const uint32_t code_prev = totp_code_at(secret, sizeof(secret), now - 30);
    const uint32_t code_now  = totp_code_at(secret, sizeof(secret), now);
    EXPECT_FALSE(totp_verify(secret, sizeof(secret), code_prev, now, 0));
    EXPECT_TRUE (totp_verify(secret, sizeof(secret), code_now,  now, 0));
}

TEST(ProvisioningUri, ShapeIsOtpAuth) {
    uint8_t secret[kSecretBytes];
    ASSERT_TRUE(generate_secret(secret));
    char uri[320] = {};
    const size_t n = provisioning_uri(uri, sizeof(uri),
                                      "Gestalt", "alice@example.com",
                                      secret, sizeof(secret));
    ASSERT_GT(n, 0u);
    EXPECT_NE(nullptr, std::strstr(uri, "otpauth://totp/Gestalt:alice@example.com?"));
    EXPECT_NE(nullptr, std::strstr(uri, "secret="));
    EXPECT_NE(nullptr, std::strstr(uri, "issuer=Gestalt"));
    EXPECT_NE(nullptr, std::strstr(uri, "digits=6"));
    EXPECT_NE(nullptr, std::strstr(uri, "period=30"));
}

TEST(RecoveryCodes, MintsDistinctReadableCodes) {
    char codes[kRecoveryCodeCount][kRecoveryCodeChars + 1] = {};
    ASSERT_TRUE(mint_recovery_codes(codes, kRecoveryCodeCount));
    // Each must be exactly 8 chars, NUL-terminated, alphabet-only.
    for (size_t i = 0; i < kRecoveryCodeCount; ++i) {
        EXPECT_EQ(std::strlen(codes[i]), kRecoveryCodeChars);
        for (size_t j = 0; j < kRecoveryCodeChars; ++j) {
            char c = codes[i][j];
            EXPECT_TRUE((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '9'));
            EXPECT_NE(c, '0'); EXPECT_NE(c, '1');
            EXPECT_NE(c, 'I'); EXPECT_NE(c, 'O');
        }
    }
    // Practically all distinct (collision prob ≈ C(10,2)/28^8 ≈ 1e-10).
    for (size_t i = 0; i < kRecoveryCodeCount; ++i)
        for (size_t j = i + 1; j < kRecoveryCodeCount; ++j)
            EXPECT_NE(0, std::strcmp(codes[i], codes[j]));
}

TEST(RecoveryCodes, HashIsDeterministicAndCtEqualWorks) {
    uint8_t h1[kHashBytes], h2[kHashBytes], h3[kHashBytes];
    hash_recovery_code("ABCDEFGH", h1);
    hash_recovery_code("ABCDEFGH", h2);
    hash_recovery_code("ABCDEFGI", h3);
    EXPECT_TRUE (ct_equal(h1, h2, kHashBytes));
    EXPECT_FALSE(ct_equal(h1, h3, kHashBytes));
}
