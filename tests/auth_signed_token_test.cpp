// boltapi/auth/signed_token gtest.

#include <gtest/gtest.h>
#include <cstring>

#include "boltapi/auth/signed_token.h"

using namespace bolt::api::auth::signed_token;

namespace {
constexpr uint8_t kSecret[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
};
}

TEST(SignedToken, RoundTripPasswordReset) {
    char tok[kEncodedMax];
    const size_t n = mint(kSecret, sizeof(kSecret),
                          "reset", "user=42", 2000000000ULL,
                          tok, sizeof(tok));
    ASSERT_GT(n, 0u);
    uint8_t scratch[kPayloadMax + kPurposeMax];
    Parsed p = verify(kSecret, sizeof(kSecret), {tok, n},
                      "reset", 1700000000ULL, scratch, sizeof(scratch));
    ASSERT_TRUE(p.ok) << "reason=" << p.reason;
    EXPECT_EQ("reset",   p.purpose);
    EXPECT_EQ("user=42", p.payload);
    EXPECT_EQ(2000000000ULL, p.exp_unix);
}

TEST(SignedToken, RejectsWrongPurpose) {
    char tok[kEncodedMax];
    const size_t n = mint(kSecret, sizeof(kSecret),
                          "reset", "x", 2000000000ULL, tok, sizeof(tok));
    ASSERT_GT(n, 0u);
    uint8_t scratch[kPayloadMax + kPurposeMax];
    Parsed p = verify(kSecret, sizeof(kSecret), {tok, n},
                      "invite", 1700000000ULL, scratch, sizeof(scratch));
    EXPECT_FALSE(p.ok);
    EXPECT_EQ(p.reason, "purpose_mismatch");
}

TEST(SignedToken, RejectsExpired) {
    char tok[kEncodedMax];
    const size_t n = mint(kSecret, sizeof(kSecret),
                          "verify", "user=7", 1000ULL, tok, sizeof(tok));
    ASSERT_GT(n, 0u);
    uint8_t scratch[kPayloadMax + kPurposeMax];
    Parsed p = verify(kSecret, sizeof(kSecret), {tok, n},
                      "verify", 2000ULL, scratch, sizeof(scratch));
    EXPECT_FALSE(p.ok);
    EXPECT_EQ(p.reason, "expired");
}

TEST(SignedToken, RejectsTamperedSignature) {
    char tok[kEncodedMax];
    const size_t n = mint(kSecret, sizeof(kSecret),
                          "invite", "user=99", 2000000000ULL, tok, sizeof(tok));
    ASSERT_GT(n, 0u);
    // Flip a bit at the end (in the signature) without invalidating base64.
    tok[n - 1] = (tok[n - 1] == 'A') ? 'B' : 'A';
    uint8_t scratch[kPayloadMax + kPurposeMax];
    Parsed p = verify(kSecret, sizeof(kSecret), {tok, n},
                      "invite", 1700000000ULL, scratch, sizeof(scratch));
    EXPECT_FALSE(p.ok);
    EXPECT_EQ(p.reason, "bad_signature");
}

TEST(SignedToken, RejectsDifferentSecret) {
    char tok[kEncodedMax];
    const size_t n = mint(kSecret, sizeof(kSecret),
                          "reset", "u=1", 2000000000ULL, tok, sizeof(tok));
    ASSERT_GT(n, 0u);
    uint8_t other[32]; std::memcpy(other, kSecret, 32); other[0] ^= 1;
    uint8_t scratch[kPayloadMax + kPurposeMax];
    Parsed p = verify(other, sizeof(other), {tok, n},
                      "reset", 1700000000ULL, scratch, sizeof(scratch));
    EXPECT_FALSE(p.ok);
    EXPECT_EQ(p.reason, "bad_signature");
}

TEST(SignedToken, MalformedTokenRejected) {
    uint8_t scratch[kPayloadMax + kPurposeMax];
    Parsed p = verify(kSecret, sizeof(kSecret), "not-a-token",
                      "reset", 1700000000ULL, scratch, sizeof(scratch));
    EXPECT_FALSE(p.ok);
    EXPECT_EQ(p.reason, "malformed");
}

TEST(SignedToken, HashIsDeterministic) {
    uint8_t a[32], b[32];
    hash_token("abc", a);
    hash_token("abc", b);
    EXPECT_EQ(0, std::memcmp(a, b, 32));
    hash_token("abd", b);
    EXPECT_NE(0, std::memcmp(a, b, 32));
}
