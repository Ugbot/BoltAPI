// boltapi/quic/robustness.h — QUIC/HTTP3 protocol ROBUSTNESS primitives (W5d).
//
// PURE, dependency-light wire builders/parsers for the RFC 9000 §8/§10/§17 +
// RFC 9001 §5.8/§6 robustness mechanisms that sit AROUND the established
// connection path (connection.h wires these in):
//   * Version Negotiation packets (RFC 9000 §6, §17.2.1);
//   * Retry packets + Retry integrity tag (RFC 9000 §17.2.5, RFC 9001 §5.8);
//   * Address-validation token mint/verify (RFC 9000 §8.1);
//   * stateless-reset token derivation + tail detection (RFC 9000 §10.3);
//   * the 3x anti-amplification budget (RFC 9000 §8.1);
//   * a previous-keys window helper used by key update (RFC 9001 §6).
//
// Tiger Style: namespace bolt::api::quic, >=2 asserts/fn, named bounds, bounded
// fixed buffers (NO unbounded std::vector on hot paths), noexcept, no exceptions,
// explicit bool/size returns. The Retry integrity tag + token MAC use OpenSSL
// (AES-128-GCM / HMAC-SHA256), which is always linked into boltapi, so this
// header compiles UNCONDITIONALLY and the default ctest suite covers it. No
// BOLTAPI_WITH_HTTP3 gate.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "boltapi/quic/packet.h"
#include "boltapi/quic/packet_protection.h"
#include "boltapi/quic/varint.h"

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (RFC 9000 §17.2 / §10.3, RFC 9001 §5.8).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kMaxVnVersions = 16;       // versions we list in VN
inline constexpr std::size_t kRetryIntegrityTagLen = 16;  // RFC 9001 §5.8
inline constexpr std::size_t kStatelessResetTokenLen = 16;  // RFC 9000 §10.3
inline constexpr std::size_t kMinStatelessResetLen = 21;  // §10.3: 5 + 16 min
inline constexpr std::size_t kMaxRetryToken = 256;       // our minted token cap
inline constexpr std::size_t kRetryTokenMacLen = 16;     // HMAC-SHA256 truncated
inline constexpr std::size_t kMaxVnPacketLen = 256;      // header + version list
inline constexpr std::size_t kMaxRetryPacketLen = 512;   // header + token + tag

// RFC 9001 §5.8 Retry integrity protection — fixed key + nonce for QUIC v1.
inline constexpr std::uint8_t kRetryIntegrityKey[16] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
inline constexpr std::uint8_t kRetryIntegrityNonce[12] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

// ----------------------------------------------------------------------------
// build_version_negotiation — RFC 9000 §17.2.1. A VN packet echoes the client's
// DCID/SCID (swapped: our SCID becomes the dest), version field = 0, then the
// list of versions WE support. `versions` are host-order 32-bit ids. Returns the
// number of bytes written to `out` (0 on overflow).
// ----------------------------------------------------------------------------
inline std::size_t build_version_negotiation(
    const ConnectionId& client_dcid, const ConnectionId& client_scid,
    const std::uint32_t* versions, std::size_t version_count,
    std::uint8_t* out, std::size_t cap) noexcept {
    assert(out != nullptr && "build_vn: null out");
    assert(versions != nullptr && version_count > 0 && "build_vn: no versions");
    assert(version_count <= kMaxVnVersions && "build_vn: too many versions");
    // 1 (first) + 4 (version=0) + 1+dcid + 1+scid + 4*N.
    const std::size_t need = 1 + 4 + 1 + client_scid.length + 1 +
                             client_dcid.length + 4 * version_count;
    if (need > cap) return 0;
    std::size_t pos = 0;
    // First byte: long-header form bit set + arbitrary unpredictable bits.
    out[pos++] = static_cast<std::uint8_t>(0x80 | 0x40);
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 0;  // version 0
    // Echo: client's SCID is our DCID; client's DCID is our SCID (RFC §17.2.1).
    out[pos++] = client_scid.length;
    std::memcpy(out + pos, client_scid.data, client_scid.length);
    pos += client_scid.length;
    out[pos++] = client_dcid.length;
    std::memcpy(out + pos, client_dcid.data, client_dcid.length);
    pos += client_dcid.length;
    for (std::size_t i = 0; i < version_count; ++i) {
        out[pos++] = static_cast<std::uint8_t>((versions[i] >> 24) & 0xFF);
        out[pos++] = static_cast<std::uint8_t>((versions[i] >> 16) & 0xFF);
        out[pos++] = static_cast<std::uint8_t>((versions[i] >> 8) & 0xFF);
        out[pos++] = static_cast<std::uint8_t>(versions[i] & 0xFF);
    }
    assert(pos == need && "build_vn: size mismatch");
    assert(pos <= cap && "build_vn overran");
    return pos;
}

// ----------------------------------------------------------------------------
// parse_version_negotiation_versions — read the supported-version list from a VN
// packet, starting at `body_off` (the offset returned by parse_long_header as
// out_consumed for a VN). Fills `out_versions` (host order), returns the count
// (bounded by cap_versions); writes 0 on malformed input.
// ----------------------------------------------------------------------------
inline std::size_t parse_version_negotiation_versions(
    const std::uint8_t* data, std::size_t len, std::size_t body_off,
    std::uint32_t* out_versions, std::size_t cap_versions) noexcept {
    assert(data != nullptr && "parse_vn: null data");
    assert(out_versions != nullptr && cap_versions > 0 && "parse_vn: null out");
    if (body_off > len) return 0;
    const std::size_t avail = len - body_off;
    if (avail < 4 || (avail % 4) != 0) return 0;  // must be whole 32-bit words
    std::size_t count = avail / 4;
    if (count > cap_versions) count = cap_versions;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t o = body_off + i * 4;
        out_versions[i] = (static_cast<std::uint32_t>(data[o]) << 24) |
                          (static_cast<std::uint32_t>(data[o + 1]) << 16) |
                          (static_cast<std::uint32_t>(data[o + 2]) << 8) |
                          static_cast<std::uint32_t>(data[o + 3]);
    }
    assert(count <= cap_versions && "parse_vn: count overflow");
    return count;
}

// is_supported_version — true if `v` is QUIC v1 (the only version we handshake).
inline bool is_supported_version(std::uint32_t v) noexcept {
    return v == kQuicVersion1;
}

// ----------------------------------------------------------------------------
// retry_integrity_tag — RFC 9001 §5.8. The tag is AES-128-GCM over EMPTY
// plaintext with AAD = Retry pseudo-packet:
//   ODCID-len(1) || ODCID || Retry-packet-without-tag.
// Writes the 16-byte tag to `out_tag`. Returns true on success.
// ----------------------------------------------------------------------------
inline bool retry_integrity_tag(const ConnectionId& odcid,
                                const std::uint8_t* retry_wo_tag,
                                std::size_t retry_wo_tag_len,
                                std::uint8_t* out_tag) noexcept {
    assert(retry_wo_tag != nullptr && "retry_tag: null retry");
    assert(out_tag != nullptr && "retry_tag: null out");
    assert(retry_wo_tag_len <= kMaxRetryPacketLen && "retry_tag: oversize");

    std::uint8_t aad[1 + kMaxConnectionIdLen + kMaxRetryPacketLen];
    std::size_t alen = 0;
    aad[alen++] = odcid.length;
    std::memcpy(aad + alen, odcid.data, odcid.length);
    alen += odcid.length;
    std::memcpy(aad + alen, retry_wo_tag, retry_wo_tag_len);
    alen += retry_wo_tag_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr,
                                 kRetryIntegrityKey, kRetryIntegrityNonce) == 1;
    int outl = 0;
    if (ok)
        ok = EVP_EncryptUpdate(ctx, nullptr, &outl, aad,
                               static_cast<int>(alen)) == 1;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, nullptr, &outl) == 1;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                 static_cast<int>(kRetryIntegrityTagLen),
                                 out_tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    assert(alen <= sizeof(aad) && "retry_tag: aad overran");
    return ok;
}

// ----------------------------------------------------------------------------
// build_retry — RFC 9000 §17.2.5. Server -> client: a Retry carrying our new
// SCID + an address-validation `token`, integrity-protected over the ORIGINAL
// DCID the client sent (`odcid`). Returns bytes written (0 on overflow/failure).
// ----------------------------------------------------------------------------
inline std::size_t build_retry(const ConnectionId& odcid,
                               const ConnectionId& client_scid,
                               const ConnectionId& server_scid,
                               const std::uint8_t* token, std::size_t token_len,
                               std::uint8_t* out, std::size_t cap) noexcept {
    assert(out != nullptr && "build_retry: null out");
    assert((token != nullptr || token_len == 0) && "build_retry: null token");
    assert(token_len <= kMaxRetryToken && "build_retry: token too big");
    const std::size_t need = 1 + 4 + 1 + client_scid.length + 1 +
                             server_scid.length + token_len +
                             kRetryIntegrityTagLen;
    if (need > cap || need > kMaxRetryPacketLen) return 0;
    std::size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(
        0xC0 | (static_cast<std::uint8_t>(LongPacketType::kRetry) << 4));
    out[pos++] = (kQuicVersion1 >> 24) & 0xFF;
    out[pos++] = (kQuicVersion1 >> 16) & 0xFF;
    out[pos++] = (kQuicVersion1 >> 8) & 0xFF;
    out[pos++] = kQuicVersion1 & 0xFF;
    out[pos++] = client_scid.length;  // Retry DCID = client's SCID
    std::memcpy(out + pos, client_scid.data, client_scid.length);
    pos += client_scid.length;
    out[pos++] = server_scid.length;  // Retry SCID = our fresh SCID
    std::memcpy(out + pos, server_scid.data, server_scid.length);
    pos += server_scid.length;
    if (token_len > 0) std::memcpy(out + pos, token, token_len);
    pos += token_len;
    if (!retry_integrity_tag(odcid, out, pos, out + pos)) return 0;
    pos += kRetryIntegrityTagLen;
    assert(pos == need && "build_retry: size mismatch");
    return pos;
}

// verify_retry_integrity — recompute the tag over a received Retry and compare
// in constant time. `retry` is the full received Retry packet (incl. trailing
// 16-byte tag); `odcid` is the DCID the client used in its first Initial.
inline bool verify_retry_integrity(const ConnectionId& odcid,
                                   const std::uint8_t* retry,
                                   std::size_t retry_len) noexcept {
    assert(retry != nullptr && "verify_retry: null");
    if (retry_len < kRetryIntegrityTagLen + 1) return false;
    const std::size_t body = retry_len - kRetryIntegrityTagLen;
    std::uint8_t tag[kRetryIntegrityTagLen];
    if (!retry_integrity_tag(odcid, retry, body, tag)) return false;
    return CRYPTO_memcmp(tag, retry + body, kRetryIntegrityTagLen) == 0;
}

// ============================================================================
// AddressValidator — mints + verifies Retry tokens (RFC 9000 §8.1). A token is
// MAC(secret, odcid) || odcid, so the server can re-derive the original DCID
// (needed to key the retried Initial's Initial secrets per RFC 9001 §5.2). The
// secret is per-server-instance random (no persistence at this scope).
// ============================================================================
class AddressValidator {
public:
    AddressValidator() noexcept {
        RAND_bytes(secret_, sizeof(secret_));
        assert(sizeof(secret_) == 32 && "validator: bad secret size");
    }

    // mint_token — token := HMAC-SHA256(secret, odcid)[0..15] || odcid.
    // Returns the token length (0 on overflow).
    std::size_t mint_token(const ConnectionId& odcid, std::uint8_t* out,
                           std::size_t cap) noexcept {
        assert(out != nullptr && "mint_token: null out");
        assert(odcid.length <= kMaxConnectionIdLen && "mint_token: bad odcid");
        const std::size_t need = kRetryTokenMacLen + odcid.length;
        if (need > cap || need > kMaxRetryToken) return 0;
        std::uint8_t mac[kRetryTokenMacLen];
        if (!compute_mac(odcid, mac)) return 0;
        std::memcpy(out, mac, kRetryTokenMacLen);
        std::memcpy(out + kRetryTokenMacLen, odcid.data, odcid.length);
        assert(need <= kMaxRetryToken && "mint_token: overran");
        return need;
    }

    // verify_token — recompute the MAC over the embedded odcid and compare. On
    // success writes the recovered original DCID to *out_odcid.
    bool verify_token(const std::uint8_t* token, std::size_t token_len,
                      ConnectionId* out_odcid) noexcept {
        assert(out_odcid != nullptr && "verify_token: null out");
        if (token == nullptr || token_len < kRetryTokenMacLen) return false;
        const std::size_t cid_len = token_len - kRetryTokenMacLen;
        if (cid_len > kMaxConnectionIdLen) return false;
        ConnectionId odcid(token + kRetryTokenMacLen,
                           static_cast<std::uint8_t>(cid_len));
        std::uint8_t mac[kRetryTokenMacLen];
        if (!compute_mac(odcid, mac)) return false;
        if (CRYPTO_memcmp(mac, token, kRetryTokenMacLen) != 0) return false;
        *out_odcid = odcid;
        return true;
    }

private:
    bool compute_mac(const ConnectionId& odcid,
                     std::uint8_t* out_mac /*[16]*/) noexcept {
        assert(out_mac != nullptr && "compute_mac: null out");
        unsigned int mlen = 0;
        std::uint8_t full[32];
        const std::uint8_t* r =
            HMAC(EVP_sha256(), secret_, sizeof(secret_), odcid.data,
                 odcid.length, full, &mlen);
        if (r == nullptr || mlen < kRetryTokenMacLen) return false;
        std::memcpy(out_mac, full, kRetryTokenMacLen);
        return true;
    }

    std::uint8_t secret_[32]{};
};

// ----------------------------------------------------------------------------
// AntiAmplification — RFC 9000 §8.1: before address validation the server MUST
// NOT send more than 3x the bytes it has received. Tracks received/sent byte
// counts; can_send() gates outbound until validated().
// ----------------------------------------------------------------------------
class AntiAmplification {
public:
    static constexpr std::uint64_t kFactor = 3;

    void on_received(std::size_t n) noexcept {
        received_ += n;
        assert(received_ >= n && "amp: received overflow");
    }
    void on_sent(std::size_t n) noexcept {
        sent_ += n;
        assert(sent_ >= n && "amp: sent overflow");
    }
    void validate() noexcept { validated_ = true; }
    bool validated() const noexcept { return validated_; }

    // Bytes still permitted to send right now (UINT64_MAX once validated).
    std::uint64_t budget() const noexcept {
        if (validated_) return UINT64_MAX;
        const std::uint64_t cap = received_ * kFactor;
        return (sent_ >= cap) ? 0 : cap - sent_;
    }
    bool can_send(std::size_t n) const noexcept {
        return validated_ || static_cast<std::uint64_t>(n) <= budget();
    }

private:
    std::uint64_t received_ = 0;
    std::uint64_t sent_ = 0;
    bool validated_ = false;
};

// ----------------------------------------------------------------------------
// derive_stateless_reset_token — RFC 9000 §10.3: token := HMAC(reset_secret,
// CID)[0..15]. Deterministic per (secret, CID) so an endpoint that lost state
// can still emit a recognizable reset. Returns true on success.
// ----------------------------------------------------------------------------
inline bool derive_stateless_reset_token(const std::uint8_t* reset_secret,
                                         std::size_t secret_len,
                                         const ConnectionId& cid,
                                         std::uint8_t* out_token /*[16]*/) noexcept {
    assert(reset_secret != nullptr && secret_len > 0 && "srt: null secret");
    assert(out_token != nullptr && "srt: null out");
    unsigned int mlen = 0;
    std::uint8_t full[32];
    const std::uint8_t* r = HMAC(EVP_sha256(), reset_secret, static_cast<int>(secret_len),
                                 cid.data, cid.length, full, &mlen);
    if (r == nullptr || mlen < kStatelessResetTokenLen) return false;
    std::memcpy(out_token, full, kStatelessResetTokenLen);
    return true;
}

// build_stateless_reset — RFC 9000 §10.3: a short-header-shaped packet of
// `pad_len` unpredictable bytes followed by the 16-byte reset token. `pad_len`
// must be >= 5 so it is >= kMinStatelessResetLen total. Returns bytes written.
inline std::size_t build_stateless_reset(const std::uint8_t* token /*[16]*/,
                                         std::size_t pad_len, std::uint8_t* out,
                                         std::size_t cap) noexcept {
    assert(token != nullptr && out != nullptr && "build_sr: null");
    if (pad_len < 5) pad_len = 5;
    const std::size_t total = pad_len + kStatelessResetTokenLen;
    if (total > cap || total < kMinStatelessResetLen) return 0;
    RAND_bytes(out, static_cast<int>(pad_len));
    out[0] = static_cast<std::uint8_t>((out[0] & 0x3F) | 0x40);  // short-header shape
    std::memcpy(out + pad_len, token, kStatelessResetTokenLen);
    assert(total >= kMinStatelessResetLen && "build_sr: too short");
    return total;
}

// is_stateless_reset — RFC 9000 §10.3.1: a datagram is a stateless reset if its
// last 16 bytes equal our expected token. Constant-time compare.
inline bool is_stateless_reset(const std::uint8_t* dgram, std::size_t len,
                               const std::uint8_t* expected_token /*[16]*/) noexcept {
    assert((dgram != nullptr || len == 0) && "is_sr: null dgram");
    assert(expected_token != nullptr && "is_sr: null token");
    if (len < kMinStatelessResetLen) return false;
    return CRYPTO_memcmp(dgram + len - kStatelessResetTokenLen, expected_token,
                         kStatelessResetTokenLen) == 0;
}

// ----------------------------------------------------------------------------
// next_generation_secret — RFC 9001 §6.1 key update: the next 1-RTT secret is
//   HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length).
// Returns true on success.
// ----------------------------------------------------------------------------
// `secret_len` is one hash output (32B SHA-256 / 48B SHA-384) and `hash` is the
// negotiated suite's key-schedule hash; both default to SHA-256 for callers that
// only ever use SHA-256 suites.
inline bool next_generation_secret(
    const std::uint8_t* current, std::uint8_t* next,
    std::size_t secret_len = kSecretLength,
    HashAlgorithm hash = HashAlgorithm::kSha256) noexcept {
    assert(current != nullptr && next != nullptr && "ku: null");
    assert(secret_len == hash_length(hash) && "ku: secret length vs hash");
    return hkdf_expand_label(current, secret_len, "quic ku", 7, next, secret_len,
                             hash);
}

}  // namespace bolt::api::quic
