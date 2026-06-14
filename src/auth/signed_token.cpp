// boltapi/auth/signed_token.cpp — HMAC-SHA256 signed-token impl.

#include "boltapi/auth/signed_token.h"

#include <cassert>
#include <cstdio>
#include <cstring>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace bolt::api::auth::signed_token {

namespace {

constexpr char kB64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

uint8_t b64url_decode_char(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return uint8_t(c - 'A');
    if (c >= 'a' && c <= 'z') return uint8_t(c - 'a' + 26);
    if (c >= '0' && c <= '9') return uint8_t(c - '0' + 52);
    if (c == '-') return 62;
    if (c == '_') return 63;
    return 0xFF;
}

size_t b64url_encode(const uint8_t* in, size_t n, char* out, size_t cap) noexcept {
    const size_t need = ((n + 2) / 3) * 4;
    if (cap < need + 1) return 0;
    size_t w = 0, i = 0;
    while (i + 3 <= n) {
        const uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8) | in[i + 2];
        out[w++] = kB64UrlAlphabet[(v >> 18) & 63];
        out[w++] = kB64UrlAlphabet[(v >> 12) & 63];
        out[w++] = kB64UrlAlphabet[(v >>  6) & 63];
        out[w++] = kB64UrlAlphabet[ v        & 63];
        i += 3;
    }
    if (i < n) {
        const size_t rem = n - i;
        uint32_t v = uint32_t(in[i]) << 16;
        if (rem > 1) v |= uint32_t(in[i + 1]) << 8;
        out[w++] = kB64UrlAlphabet[(v >> 18) & 63];
        out[w++] = kB64UrlAlphabet[(v >> 12) & 63];
        if (rem > 1) out[w++] = kB64UrlAlphabet[(v >> 6) & 63];
    }
    // No '=' padding (URL-safe convention).
    out[w] = '\0';
    return w;
}

size_t b64url_decode(std::string_view s, uint8_t* out, size_t cap) noexcept {
    size_t w = 0;
    uint32_t buf = 0; int bits = 0;
    for (char c : s) {
        const uint8_t v = b64url_decode_char(c);
        if (v == 0xFF) return 0;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (w >= cap) return 0;
            out[w++] = uint8_t((buf >> bits) & 0xFF);
        }
    }
    return w;
}

// HMAC-SHA256 via EVP_MAC. Writes 32 bytes to `out`.
bool hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[32]) noexcept {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac == nullptr) return false;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == nullptr) { EVP_MAC_free(mac); return false; }
    char digest[] = "SHA256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_end();
    bool ok = (EVP_MAC_init(ctx, key, key_len, params) == 1) &&
              (EVP_MAC_update(ctx, msg, msg_len) == 1);
    size_t outlen = 0;
    if (ok) ok = (EVP_MAC_final(ctx, out, &outlen, 32) == 1);
    if (outlen != 32) ok = false;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= uint8_t(a[i] ^ b[i]);
    return diff == 0;
}

}  // namespace

size_t mint(const uint8_t* secret, size_t secret_len,
            std::string_view purpose,
            std::string_view payload,
            uint64_t exp_unix,
            char* out, size_t out_cap) noexcept {
    assert(secret != nullptr && out != nullptr);
    if (secret_len < kSecretMin) return 0;
    if (purpose.empty() || purpose.size() > kPurposeMax) return 0;
    if (payload.size() > kPayloadMax) return 0;
    if (out_cap < kEncodedMax) return 0;

    // 1) Encode parts.
    char p_enc[kPurposeMax * 2 + 1] = {};
    char d_enc[kPayloadMax * 2 + 1] = {};
    const size_t pn = b64url_encode(reinterpret_cast<const uint8_t*>(purpose.data()),
                                    purpose.size(), p_enc, sizeof(p_enc));
    const size_t dn = b64url_encode(reinterpret_cast<const uint8_t*>(payload.data()),
                                    payload.size(), d_enc, sizeof(d_enc));
    if (pn == 0 || (payload.size() > 0 && dn == 0)) return 0;

    // 2) Compose signing input = purpose_b64 "." payload_b64 "." exp_dec.
    char signed_buf[kEncodedMax];
    const int sn = std::snprintf(signed_buf, sizeof(signed_buf),
                                 "%s.%s.%llu",
                                 p_enc, d_enc, static_cast<unsigned long long>(exp_unix));
    if (sn <= 0 || size_t(sn) >= sizeof(signed_buf)) return 0;

    // 3) MAC.
    uint8_t mac[32];
    if (!hmac_sha256(secret, secret_len,
                     reinterpret_cast<const uint8_t*>(signed_buf), size_t(sn), mac)) return 0;
    char mac_enc[64];
    const size_t mn = b64url_encode(mac, 32, mac_enc, sizeof(mac_enc));
    if (mn == 0) return 0;

    // 4) Final token = signed_buf "." mac_b64.
    const int w = std::snprintf(out, out_cap, "%s.%s", signed_buf, mac_enc);
    if (w <= 0 || size_t(w) >= out_cap) return 0;
    return size_t(w);
}

Parsed verify(const uint8_t* secret, size_t secret_len,
              std::string_view token,
              std::string_view expected_purpose,
              uint64_t now_unix,
              uint8_t* scratch, size_t scratch_cap) noexcept {
    assert(secret != nullptr && scratch != nullptr);
    Parsed r;
    if (secret_len < kSecretMin || token.empty() || expected_purpose.empty()) {
        r.reason = "malformed"; return r;
    }
    // Split on '.' (3 separators → 4 parts).
    size_t dot1 = token.find('.');
    if (dot1 == std::string_view::npos) { r.reason = "malformed"; return r; }
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string_view::npos) { r.reason = "malformed"; return r; }
    size_t dot3 = token.find('.', dot2 + 1);
    if (dot3 == std::string_view::npos) { r.reason = "malformed"; return r; }

    const auto p_b64   = token.substr(0,        dot1);
    const auto d_b64   = token.substr(dot1 + 1, dot2 - dot1 - 1);
    const auto exp_dec = token.substr(dot2 + 1, dot3 - dot2 - 1);
    const auto m_b64   = token.substr(dot3 + 1);

    // Recompute MAC over signed_buf = "<p_b64>.<d_b64>.<exp_dec>" (subtree of token).
    const std::string_view signed_part = token.substr(0, dot3);
    uint8_t mac_expect[32];
    if (!hmac_sha256(secret, secret_len,
                     reinterpret_cast<const uint8_t*>(signed_part.data()),
                     signed_part.size(), mac_expect)) {
        r.reason = "malformed"; return r;
    }
    uint8_t mac_got[32];
    if (b64url_decode(m_b64, mac_got, sizeof(mac_got)) != 32) {
        r.reason = "bad_signature"; return r;
    }
    if (!ct_equal(mac_got, mac_expect, 32)) {
        r.reason = "bad_signature"; return r;
    }

    // Decode purpose into a temp small buffer that lives inside scratch
    // (the caller's scratch holds payload; we tail-allocate purpose at the end).
    if (scratch_cap < kPayloadMax + kPurposeMax) { r.reason = "malformed"; return r; }
    uint8_t* purpose_scratch = scratch + kPayloadMax;
    const size_t pn = b64url_decode(p_b64, purpose_scratch, kPurposeMax);
    if (pn == 0) { r.reason = "malformed"; return r; }
    const std::string_view purpose_sv(reinterpret_cast<const char*>(purpose_scratch), pn);
    if (purpose_sv != expected_purpose) { r.reason = "purpose_mismatch"; return r; }

    // Decode payload.
    const size_t dn = b64url_decode(d_b64, scratch, kPayloadMax);
    // Payload of size 0 is legal (encoded as empty string between two dots);
    // b64url_decode returns 0 in both "empty" and "error" cases, but we already
    // verified the MAC so this is safe: a zero-length payload means the
    // original input was empty.
    const std::string_view payload_sv(reinterpret_cast<const char*>(scratch), dn);

    // Parse exp.
    uint64_t exp = 0;
    for (char c : exp_dec) {
        if (c < '0' || c > '9') { r.reason = "malformed"; return r; }
        exp = exp * 10 + uint64_t(c - '0');
    }
    if (now_unix >= exp) { r.reason = "expired"; return r; }

    r.ok       = true;
    r.purpose  = purpose_sv;
    r.payload  = payload_sv;
    r.exp_unix = exp;
    return r;
}

void hash_token(std::string_view token, uint8_t out[32]) noexcept {
    assert(out != nullptr);
    SHA256(reinterpret_cast<const uint8_t*>(token.data()), token.size(), out);
}

}  // namespace bolt::api::auth::signed_token
