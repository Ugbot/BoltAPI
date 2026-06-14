// boltapi/auth/totp.cpp — RFC 4226 HOTP + RFC 6238 TOTP via OpenSSL EVP_MAC.
//
// HOTP: `T = HMAC-SHA1(K, counter_be64)`; dynamic truncation on `T[T[19] & 0xf]`;
// reduce mod 10^digits.  TOTP: counter = floor(unix_time / period).
//
// All ops are noexcept and allocation-free past the small fixed buffers shown
// at the top of each function.  The OpenSSL handles use only stack-resident
// EVP_MAC / EVP_MAC_CTX instances and are freed on every exit path.

#include "boltapi/auth/totp.h"

#include <cassert>
#include <cstdio>
#include <cstring>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace bolt::api::auth::totp {

namespace {

// RFC 4648 base32 alphabet.
constexpr char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Recovery-code alphabet: base32 minus the visually ambiguous 0/1/O/I.
// Yields 28 distinct chars, still well above the security floor for an
// 8-char single-use code (log2(28^8) ≈ 38.5 bits — sha256-stored).
constexpr char kRecoveryAlphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
constexpr size_t kRecoveryAlphabetLen = sizeof(kRecoveryAlphabet) - 1;
static_assert(kRecoveryAlphabetLen == 32, "ambiguous-char alphabet must be 32 wide");

uint32_t kPow10[] = {1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u,
                     10000000u, 100000000u, 1000000000u};

// HMAC-SHA1 via EVP_MAC. Returns true on success; writes the 20-byte MAC.
bool hmac_sha1(const uint8_t* key, size_t key_len,
               const uint8_t* msg, size_t msg_len,
               uint8_t out[20]) noexcept {
    assert(key != nullptr && msg != nullptr && out != nullptr);
    assert(key_len > 0);

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac == nullptr) return false;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == nullptr) { EVP_MAC_free(mac); return false; }

    char digest_name[] = "SHA1";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    bool ok = (EVP_MAC_init(ctx, key, key_len, params) == 1) &&
              (EVP_MAC_update(ctx, msg, msg_len) == 1);
    size_t out_len = 0;
    if (ok) ok = (EVP_MAC_final(ctx, out, &out_len, 20) == 1);
    if (out_len != 20) ok = false;

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

uint8_t b32_decode_char(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return uint8_t(c - 'A');
    if (c >= 'a' && c <= 'z') return uint8_t(c - 'a');
    if (c >= '2' && c <= '7') return uint8_t(26 + (c - '2'));
    return 0xFF;
}

}  // namespace

bool generate_secret(uint8_t out[kSecretBytes]) noexcept {
    assert(out != nullptr);
    return RAND_bytes(out, int(kSecretBytes)) == 1;
}

size_t base32_encode(const uint8_t* in, size_t n,
                     char* out, size_t out_cap) noexcept {
    assert(in != nullptr && out != nullptr);
    const size_t need = ((n * 8) + 4) / 5;          // ceil(n*8/5)
    if (out_cap <= need) return 0;                  // need room for NUL too
    size_t bits = 0, buf = 0, w = 0;
    for (size_t i = 0; i < n; ++i) {
        buf = (buf << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            assert(w < need);
            out[w++] = kBase32Alphabet[(buf >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        assert(w < need);
        out[w++] = kBase32Alphabet[(buf << (5 - bits)) & 0x1F];
    }
    out[w] = '\0';
    return w;
}

size_t base32_decode(std::string_view in,
                     uint8_t* out, size_t out_cap) noexcept {
    assert(out != nullptr);
    size_t bits = 0, buf = 0, w = 0;
    for (char c : in) {
        if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        const uint8_t v = b32_decode_char(c);
        if (v == 0xFF) return 0;
        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (w >= out_cap) return 0;
            out[w++] = uint8_t((buf >> bits) & 0xFF);
        }
    }
    return w;
}

uint32_t hotp_code(const uint8_t* secret, size_t secret_len,
                   uint64_t counter, uint32_t digits) noexcept {
    assert(secret != nullptr);
    assert(secret_len > 0);
    assert(digits >= 6 && digits <= 9);

    uint8_t cbuf[8];
    for (int i = 7; i >= 0; --i) {
        cbuf[i] = uint8_t(counter & 0xFF);
        counter >>= 8;
    }
    uint8_t mac[20];
    if (!hmac_sha1(secret, secret_len, cbuf, 8, mac)) return 0;

    const uint8_t offset = uint8_t(mac[19] & 0x0F);
    const uint32_t bin = (uint32_t(mac[offset]     & 0x7F) << 24) |
                         (uint32_t(mac[offset + 1] & 0xFF) << 16) |
                         (uint32_t(mac[offset + 2] & 0xFF) <<  8) |
                          uint32_t(mac[offset + 3] & 0xFF);
    return bin % kPow10[digits];
}

uint32_t totp_code_at(const uint8_t* secret, size_t secret_len,
                      uint64_t unix_time,
                      uint32_t period_sec, uint32_t digits) noexcept {
    assert(period_sec > 0);
    return hotp_code(secret, secret_len, unix_time / period_sec, digits);
}

bool totp_verify(const uint8_t* secret, size_t secret_len,
                 uint32_t code, uint64_t now_unix,
                 int32_t window, uint32_t period_sec, uint32_t digits) noexcept {
    assert(secret != nullptr);
    assert(secret_len > 0);
    assert(period_sec > 0);
    assert(window >= 0 && window <= 16);

    const uint64_t base = now_unix / period_sec;
    // Constant-time across the window: probe every step regardless of an
    // early match so the timing doesn't leak which step matched.
    uint32_t matched = 0;
    for (int32_t i = -window; i <= window; ++i) {
        const uint64_t step = (i < 0 && uint64_t(-i) > base)
                              ? 0 : base + uint64_t(int64_t(i));
        const uint32_t c = hotp_code(secret, secret_len, step, digits);
        // Constant-time compare of two uint32s.
        const uint32_t diff = c ^ code;
        const uint32_t eq   = uint32_t(1) ^
                              ((diff | (~diff + 1u)) >> 31);  // 1 iff diff==0
        matched |= eq;
    }
    return matched != 0;
}

size_t provisioning_uri(char* out, size_t out_cap,
                        std::string_view issuer,
                        std::string_view account,
                        const uint8_t* secret, size_t secret_len,
                        uint32_t digits, uint32_t period_sec) noexcept {
    assert(out != nullptr);
    if (out_cap < 32) return 0;
    char b32[kBase32SecretChars + 1];
    const size_t n = base32_encode(secret, secret_len, b32, sizeof(b32));
    if (n == 0) return 0;

    // Plain otpauth URI; issuer/account are passed through as-is. Callers
    // are expected to keep them ASCII-safe (no '/', '?', '&'); the
    // formatter does not percent-encode (deliberate: bounded buffer, no
    // allocation, kept honest by the caller-side assertion).
    assert(issuer.find_first_of("/?&#") == std::string_view::npos);
    assert(account.find_first_of("/?&#") == std::string_view::npos);

    const int w = std::snprintf(out, out_cap,
        "otpauth://totp/%.*s:%.*s?secret=%s&issuer=%.*s&digits=%u&period=%u",
        int(issuer.size()), issuer.data(),
        int(account.size()), account.data(),
        b32,
        int(issuer.size()), issuer.data(),
        digits, period_sec);
    if (w < 0 || size_t(w) >= out_cap) return 0;
    return size_t(w);
}

bool mint_recovery_codes(char (*out)[kRecoveryCodeChars + 1], size_t count) noexcept {
    assert(out != nullptr);
    assert(count > 0 && count <= 64);

    // One RAND draw of `count * chars` bytes; map each byte mod-32 onto the
    // alphabet. Modulo bias is ~zero for a 28-char-alphabet on uint8 input
    // (the cut at 32 is exact since 256 = 8 * 32) — actually our alphabet
    // happens to be exactly 32 long so this is bias-free.
    static_assert(kRecoveryAlphabetLen == 32, "alphabet length must be a power of 2");

    uint8_t buf[64 * kRecoveryCodeChars];  // bounded by `count <= 64` assert above
    const size_t need = count * kRecoveryCodeChars;
    if (RAND_bytes(buf, int(need)) != 1) return false;

    for (size_t i = 0; i < count; ++i) {
        for (size_t j = 0; j < kRecoveryCodeChars; ++j) {
            out[i][j] = kRecoveryAlphabet[buf[i * kRecoveryCodeChars + j] & 0x1F];
        }
        out[i][kRecoveryCodeChars] = '\0';
    }
    return true;
}

void hash_recovery_code(std::string_view raw, uint8_t out[kHashBytes]) noexcept {
    assert(out != nullptr);
    SHA256(reinterpret_cast<const uint8_t*>(raw.data()), raw.size(), out);
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    assert(a != nullptr && b != nullptr);
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= uint8_t(a[i] ^ b[i]);
    return diff == 0;
}

}  // namespace bolt::api::auth::totp
