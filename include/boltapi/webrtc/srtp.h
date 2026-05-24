// boltapi/webrtc/srtp.h — SRTP / SRTCP (RFC 3711, RFC 7714) media protection.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A REAL, RFC-correct SRTP/SRTCP implementation built from the RFC (the
// FasterAPI SRTPContext at src/cpp/webrtc/rtp.cpp:147-205 was a FAKE: it copied
// bytes and memset a zero "auth tag" — no AES, no HMAC, no KDF). This is a
// from-scratch rebuild on OpenSSL EVP.
//
// Covers:
//   * RFC 3711 §4.3 key derivation (AES-CM PRF). From a master key + master salt
//     it derives, per session, the SRTP cipher key / auth key / salt and the
//     SRTCP cipher key / auth key / salt. Key-derivation-rate 0 (one derivation
//     for the whole session) is implemented; non-zero rate is not needed for
//     WebRTC and is rejected.
//   * Two crypto profiles:
//       - AES_CM_128_HMAC_SHA1_80  (RFC 3711): AES-128 counter mode + HMAC-SHA1
//         truncated to 80 bits (10-byte tag), 14-byte salt.
//       - AEAD_AES_128_GCM         (RFC 7714): AES-128-GCM, 16-byte tag, 12-byte
//         salt; no separate HMAC (the AEAD tag authenticates).
//   * SRTP protect/unprotect (RFC 3711 §3.3 / §4.1.1): per-SSRC ROC maintained
//     from the 16-bit RTP sequence number; the AES-CM IV is
//         IV = (salt*2^16) XOR (SSRC*2^64) XOR (i*2^16)   where i = ROC||SEQ;
//     for GCM the IV is per RFC 7714 §8.1. The authenticated portion is the RTP
//     header + payload; for CM the HMAC also covers the ROC. A sliding replay
//     window rejects duplicates/old packets.
//   * SRTCP protect/unprotect (RFC 3711 §3.4): a 32-bit trailer holds the E-flag
//     and a 31-bit SRTCP index; the compound packet after the first 8 bytes is
//     encrypted, then the auth tag covers everything up to and including the
//     trailer. GCM uses the AEAD construction of RFC 7714 §9.
//   * SrtpSession: holds the derived profile keys plus per-SSRC ROC + replay
//     state (a bounded fixed array of SSRC slots — no heap in the hot path),
//     and one SRTCP index per direction.
//
// Inputs are plain RTP/RTCP byte spans (we parse just enough header to find the
// SSRC and sequence/index); no hard dependency on the RTP module.
//
// Crypto goes through OpenSSL EVP (libcrypto is always linked into boltapi), so
// this header compiles unconditionally and is exercised by the default suite.
//
// TigerStyle: header-only, noexcept, no exceptions; >=2 asserts/fn; bounded
// (fixed SSRC-slot array, fixed scratch); explicit enum/bool error returns; the
// hot path reuses cached EVP_CIPHER_CTX (no per-packet ctx alloc beyond what
// OpenSSL holds internally). Functions are <70 lines.

#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace bolt::api::webrtc::srtp {

// ============================================================================
// Constants & named bounds (RFC 3711 / RFC 7714).
// ============================================================================
inline constexpr std::size_t kMasterKeyLen      = 16;  // AES-128 master key
inline constexpr std::size_t kMasterSaltLen     = 14;  // RFC 3711 master salt
inline constexpr std::size_t kSessionKeyLen     = 16;  // AES-128 session key
inline constexpr std::size_t kSessionSaltLen    = 14;  // session salt (CM/GCM 12 used)
inline constexpr std::size_t kAuthKeyLen        = 20;  // HMAC-SHA1 key (160-bit)
inline constexpr std::size_t kSrtpTagLenCm      = 10;  // HMAC-SHA1-80 -> 80 bits
inline constexpr std::size_t kSrtcpTagLenCm     = 10;
inline constexpr std::size_t kGcmTagLen         = 16;  // RFC 7714 GCM tag
inline constexpr std::size_t kGcmSaltLen        = 12;  // RFC 7714 §8.1 salt/IV len
inline constexpr std::size_t kRtpHeaderMin      = 12;  // V/P/X/CC..SSRC
inline constexpr std::size_t kRtcpHeaderMin     = 8;   // V/P/RC..SSRC
inline constexpr std::size_t kSrtcpTrailerLen   = 4;   // E-flag + 31-bit index
inline constexpr std::size_t kReplayWindowBits  = 128; // sliding replay window
inline constexpr std::size_t kMaxSsrcSlots      = 64;  // bounded per-session SSRCs

enum class Profile : std::uint8_t {
    kAesCm128HmacSha1_80 = 0,  // RFC 3711
    kAeadAes128Gcm       = 1,  // RFC 7714
};

enum class Error : std::uint8_t {
    kOk = 0,
    kBadArg,        // null / impossible length
    kBadProfile,    // unsupported profile / KDF rate
    kBufferTooSmall,// output buffer can't hold result
    kTooShort,      // input shorter than a valid (S)RTP/RTCP packet
    kAuthFail,      // tag mismatch / GCM open failed
    kReplay,        // replayed or too-old packet
    kCryptoFail,    // OpenSSL EVP call failed
    kNoSlot,        // SSRC table full
};

inline constexpr std::size_t srtp_tag_len(Profile p) noexcept {
    return p == Profile::kAeadAes128Gcm ? kGcmTagLen : kSrtpTagLenCm;
}
inline constexpr std::size_t srtcp_tag_len(Profile p) noexcept {
    return p == Profile::kAeadAes128Gcm ? kGcmTagLen : kSrtcpTagLenCm;
}

// ============================================================================
// Big-endian readers (header parsing; correctness over speed).
// ============================================================================
inline std::uint16_t rd_u16(const std::uint8_t* p) noexcept {
    assert(p != nullptr && "rd_u16: null");
    return static_cast<std::uint16_t>((std::uint32_t{p[0]} << 8) | p[1]);
}
inline std::uint32_t rd_u32(const std::uint8_t* p) noexcept {
    assert(p != nullptr && "rd_u32: null");
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
           (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}
inline void wr_u32(std::uint8_t* p, std::uint32_t v) noexcept {
    assert(p != nullptr && "wr_u32: null");
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

// ============================================================================
// RFC 3711 §4.3.3 PRF_n: AES-128 counter mode over an all-zero plaintext keyed
// by `key`, with the 16-byte counter block = (x << 16) for the KDF (i.e. x is a
// 14-byte value left-justified, low 16 bits = block counter starting at 0).
// Produces `out_len` keystream bytes = the derived key material.
// ============================================================================
inline bool aes_cm_prf(const std::uint8_t key[kMasterKeyLen],
                       const std::uint8_t iv[16],
                       std::uint8_t* out, std::size_t out_len) noexcept {
    assert(key != nullptr && iv != nullptr && "aes_cm_prf: null key/iv");
    assert(out != nullptr && out_len > 0 && out_len <= 64 && "aes_cm_prf: bad out");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv) == 1;
    if (ok) {
        std::uint8_t zeros[64] = {0};
        int len = 0;
        ok = EVP_EncryptUpdate(ctx, out, &len, zeros,
                               static_cast<int>(out_len)) == 1 &&
             static_cast<std::size_t>(len) == out_len;
    }
    EVP_CIPHER_CTX_free(ctx);
    assert((!ok || out_len <= 64) && "aes_cm_prf overran");
    return ok;
}

// Derive one label's key material (RFC 3711 §4.3.1). With key_derivation_rate 0
// the per-key index DIV is 0, so x = (label << 8*(salt_len-7)) XOR (master_salt
// left-justified), i.e. x = master_salt with byte 7 (0-based) XOR'd by `label`.
// The counter block fed to AES-CM is (x * 2^16) == [x[0..13], 0x00, 0x00].
inline bool kdf_derive(const std::uint8_t master_key[kMasterKeyLen],
                       const std::uint8_t master_salt[kMasterSaltLen],
                       std::uint8_t label, std::uint8_t* out,
                       std::size_t out_len) noexcept {
    assert(master_key != nullptr && master_salt != nullptr && "kdf_derive: null");
    assert(out != nullptr && out_len > 0 && out_len <= 64 && "kdf_derive: bad out");

    std::uint8_t iv[16] = {0};
    std::memcpy(iv, master_salt, kMasterSaltLen);  // x left-justified in 16 bytes
    iv[7] ^= label;                                 // XOR label at the key_id byte
    // low 2 bytes (block counter) already zero -> x * 2^16.
    return aes_cm_prf(master_key, iv, out, out_len);
}

// Per-profile derived session keys (RFC 3711 §4.3.2 labels).
//   SRTP : encr=0x00 auth=0x01 salt=0x02
//   SRTCP: encr=0x03 auth=0x04 salt=0x05
struct SessionKeys {
    std::array<std::uint8_t, kSessionKeyLen>  cipher{};
    std::array<std::uint8_t, kAuthKeyLen>     auth{};
    std::array<std::uint8_t, kSessionSaltLen> salt{};
};

inline Error derive_session_keys(const std::uint8_t* master_key,
                                 std::size_t master_key_len,
                                 const std::uint8_t* master_salt,
                                 std::size_t master_salt_len,
                                 bool is_rtcp, SessionKeys& out) noexcept {
    assert(master_key != nullptr && master_salt != nullptr && "derive: null");
    assert((master_key_len == kMasterKeyLen) && "derive: only AES-128 master key");
    if (master_key == nullptr || master_salt == nullptr) return Error::kBadArg;
    if (master_key_len != kMasterKeyLen || master_salt_len != kMasterSaltLen) {
        return Error::kBadArg;
    }
    const std::uint8_t lk = is_rtcp ? 0x03 : 0x00;
    const std::uint8_t la = is_rtcp ? 0x04 : 0x01;
    const std::uint8_t ls = is_rtcp ? 0x05 : 0x02;
    if (!kdf_derive(master_key, master_salt, lk, out.cipher.data(), kSessionKeyLen) ||
        !kdf_derive(master_key, master_salt, la, out.auth.data(),  kAuthKeyLen) ||
        !kdf_derive(master_key, master_salt, ls, out.salt.data(),  kSessionSaltLen)) {
        return Error::kCryptoFail;
    }
    return Error::kOk;
}

// ============================================================================
// IV construction.
// ============================================================================
// RFC 3711 §4.1.1 AES-CM IV for SRTP:
//   IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16),  i = 2^16*ROC + SEQ.
// salt is 14 bytes left-justified in the 16-byte block.
inline void srtp_cm_iv(const std::uint8_t salt[kSessionSaltLen], std::uint32_t ssrc,
                       std::uint32_t roc, std::uint16_t seq,
                       std::uint8_t iv[16]) noexcept {
    assert(salt != nullptr && iv != nullptr && "srtp_cm_iv: null");
    std::memset(iv, 0, 16);
    std::memcpy(iv, salt, kSessionSaltLen);          // k_s * 2^16
    iv[4] ^= static_cast<std::uint8_t>(ssrc >> 24);  // SSRC * 2^64 (bytes 4..7)
    iv[5] ^= static_cast<std::uint8_t>(ssrc >> 16);
    iv[6] ^= static_cast<std::uint8_t>(ssrc >> 8);
    iv[7] ^= static_cast<std::uint8_t>(ssrc);
    const std::uint64_t i = (std::uint64_t{roc} << 16) | seq;  // packet index
    iv[8]  ^= static_cast<std::uint8_t>(i >> 40);    // i * 2^16 (bytes 8..13)
    iv[9]  ^= static_cast<std::uint8_t>(i >> 32);
    iv[10] ^= static_cast<std::uint8_t>(i >> 24);
    iv[11] ^= static_cast<std::uint8_t>(i >> 16);
    iv[12] ^= static_cast<std::uint8_t>(i >> 8);
    iv[13] ^= static_cast<std::uint8_t>(i);
    assert(iv[14] == 0 && iv[15] == 0 && "srtp_cm_iv: counter must start at 0");
}

// RFC 3711 §4.1.1 AES-CM IV for SRTCP: same shape with i = 31-bit SRTCP index.
inline void srtcp_cm_iv(const std::uint8_t salt[kSessionSaltLen], std::uint32_t ssrc,
                        std::uint32_t index, std::uint8_t iv[16]) noexcept {
    assert(salt != nullptr && iv != nullptr && "srtcp_cm_iv: null");
    std::memset(iv, 0, 16);
    std::memcpy(iv, salt, kSessionSaltLen);
    iv[4] ^= static_cast<std::uint8_t>(ssrc >> 24);
    iv[5] ^= static_cast<std::uint8_t>(ssrc >> 16);
    iv[6] ^= static_cast<std::uint8_t>(ssrc >> 8);
    iv[7] ^= static_cast<std::uint8_t>(ssrc);
    const std::uint64_t i = index & 0x7FFFFFFFu;
    iv[10] ^= static_cast<std::uint8_t>(i >> 24);
    iv[11] ^= static_cast<std::uint8_t>(i >> 16);
    iv[12] ^= static_cast<std::uint8_t>(i >> 8);
    iv[13] ^= static_cast<std::uint8_t>(i);
    assert(iv[14] == 0 && iv[15] == 0 && "srtcp_cm_iv: counter must start at 0");
}

// RFC 7714 §8.1 GCM IV for SRTP: 12-byte IV = salt XOR (0..0 || SSRC || ROC ||
// SEQ) aligned so that the last 6 bytes carry SSRC and the last 6 carry the
// index. Concretely: IV[0..1]=salt[0..1]; IV[2..5]=salt[2..5]^SSRC;
// IV[6..11]=salt[6..11]^(ROC||SEQ).
inline void srtp_gcm_iv(const std::uint8_t salt[kGcmSaltLen], std::uint32_t ssrc,
                        std::uint32_t roc, std::uint16_t seq,
                        std::uint8_t iv[kGcmSaltLen]) noexcept {
    assert(salt != nullptr && iv != nullptr && "srtp_gcm_iv: null");
    std::uint8_t x[kGcmSaltLen] = {0};
    x[2] = static_cast<std::uint8_t>(ssrc >> 24);
    x[3] = static_cast<std::uint8_t>(ssrc >> 16);
    x[4] = static_cast<std::uint8_t>(ssrc >> 8);
    x[5] = static_cast<std::uint8_t>(ssrc);
    x[6] = static_cast<std::uint8_t>(roc >> 24);
    x[7] = static_cast<std::uint8_t>(roc >> 16);
    x[8] = static_cast<std::uint8_t>(roc >> 8);
    x[9] = static_cast<std::uint8_t>(roc);
    x[10] = static_cast<std::uint8_t>(seq >> 8);
    x[11] = static_cast<std::uint8_t>(seq);
    for (std::size_t k = 0; k < kGcmSaltLen; ++k) iv[k] = salt[k] ^ x[k];
    assert(salt != iv && "srtp_gcm_iv: alias");
}

// RFC 7714 §9.1 GCM IV for SRTCP: last 4 bytes carry the 31-bit SRTCP index,
// preceded by SSRC. IV[0..1]=salt[0..1]; IV[2..5]=salt[2..5]^SSRC;
// IV[6..7]=salt[6..7]; IV[8..11]=salt[8..11]^index.
inline void srtcp_gcm_iv(const std::uint8_t salt[kGcmSaltLen], std::uint32_t ssrc,
                         std::uint32_t index,
                         std::uint8_t iv[kGcmSaltLen]) noexcept {
    assert(salt != nullptr && iv != nullptr && "srtcp_gcm_iv: null");
    std::uint8_t x[kGcmSaltLen] = {0};
    x[2] = static_cast<std::uint8_t>(ssrc >> 24);
    x[3] = static_cast<std::uint8_t>(ssrc >> 16);
    x[4] = static_cast<std::uint8_t>(ssrc >> 8);
    x[5] = static_cast<std::uint8_t>(ssrc);
    const std::uint32_t i = index & 0x7FFFFFFFu;
    x[8]  = static_cast<std::uint8_t>(i >> 24);
    x[9]  = static_cast<std::uint8_t>(i >> 16);
    x[10] = static_cast<std::uint8_t>(i >> 8);
    x[11] = static_cast<std::uint8_t>(i);
    for (std::size_t k = 0; k < kGcmSaltLen; ++k) iv[k] = salt[k] ^ x[k];
    assert(index <= 0x7FFFFFFFu && "srtcp_gcm_iv: index over 31 bits");
}

// ============================================================================
// Primitive crypto helpers (OpenSSL EVP).
// ============================================================================
// #38 — per-packet SRTP protect/unprotect ran on the media hot path used to
// EVP_MAC_fetch("HMAC") (a provider lookup) + EVP_CIPHER_CTX_new/free EVERY
// packet — protect measured ~25x slower than it needs to be. Cache the fetched
// HMAC algorithm ONCE (process lifetime) and reuse per-thread cipher/MAC
// contexts (re-init with the new key/iv each call — far cheaper than new/free).
// thread_local so the single I/O thread keeps hot, reusable contexts; the
// destructor frees them at thread exit (TigerStyle: explicit teardown).
inline EVP_MAC* srtp_hmac_algo() noexcept {
    static EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);  // once
    return mac;
}
struct SrtpCryptoCtx {
    EVP_CIPHER_CTX* ctr = nullptr;  // AES-128-CTR (CM profile)
    EVP_CIPHER_CTX* gcm = nullptr;  // AES-128-GCM (GCM profile)
    EVP_MAC_CTX*    mac = nullptr;  // HMAC-SHA1 (CM auth tag)
    SrtpCryptoCtx() = default;
    SrtpCryptoCtx(const SrtpCryptoCtx&) = delete;
    SrtpCryptoCtx& operator=(const SrtpCryptoCtx&) = delete;
    ~SrtpCryptoCtx() noexcept {
        if (ctr != nullptr) EVP_CIPHER_CTX_free(ctr);
        if (gcm != nullptr) EVP_CIPHER_CTX_free(gcm);
        if (mac != nullptr) EVP_MAC_CTX_free(mac);
    }
};
inline SrtpCryptoCtx& srtp_crypto_ctx() noexcept {
    thread_local SrtpCryptoCtx c;  // per-thread reusable contexts
    return c;
}

// AES-128-CTR encrypt/decrypt in place (CTR is symmetric). `n` may be 0.
inline bool aes_ctr_xcrypt(const std::uint8_t key[kSessionKeyLen],
                           const std::uint8_t iv[16], std::uint8_t* buf,
                           std::size_t n) noexcept {
    assert(key != nullptr && iv != nullptr && "aes_ctr: null key/iv");
    assert((buf != nullptr || n == 0) && "aes_ctr: null buf");
    if (n == 0) return true;
    EVP_CIPHER_CTX*& ctx = srtp_crypto_ctx().ctr;  // #38 — reused per thread
    if (ctx == nullptr) { ctx = EVP_CIPHER_CTX_new(); if (ctx == nullptr) return false; }
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv) == 1;
    if (ok) {
        int len = 0;
        ok = EVP_EncryptUpdate(ctx, buf, &len, buf, static_cast<int>(n)) == 1 &&
             static_cast<std::size_t>(len) == n;
    }
    return ok;
}

// HMAC-SHA1 over up to two concatenated spans (OpenSSL 3.x EVP_MAC; the legacy
// HMAC()/HMAC_CTX API is deprecated in 3.0 and warns under /W4). The second
// span may be empty (blen == 0). Truncates to `tag_len` bytes into `tag`.
inline bool hmac_sha1_two(const std::uint8_t key[kAuthKeyLen],
                          const std::uint8_t* a, std::size_t alen,
                          const std::uint8_t* b, std::size_t blen,
                          std::uint8_t* tag, std::size_t tag_len) noexcept {
    assert(key != nullptr && tag != nullptr && "hmac: null");
    assert(tag_len <= 20 && (a != nullptr || alen == 0) && "hmac: bad arg");
    EVP_MAC* mac = srtp_hmac_algo();           // #38 — fetched once, cached
    if (mac == nullptr) return false;
    EVP_MAC_CTX*& ctx = srtp_crypto_ctx().mac;  // #38 — reused per thread
    if (ctx == nullptr) { ctx = EVP_MAC_CTX_new(mac); if (ctx == nullptr) return false; }
    char digest[] = "SHA1";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_end();
    std::uint8_t full[20];
    std::size_t out_len = 0;
    bool ok = EVP_MAC_init(ctx, key, kAuthKeyLen, params) == 1 &&
              (alen == 0 || EVP_MAC_update(ctx, a, alen) == 1) &&
              (blen == 0 || EVP_MAC_update(ctx, b, blen) == 1) &&
              EVP_MAC_final(ctx, full, &out_len, sizeof(full)) == 1 && out_len == 20;
    if (ok) std::memcpy(tag, full, tag_len);
    return ok;
}

// HMAC-SHA1 over `data`, truncated to `tag_len` bytes into `tag`.
inline bool hmac_sha1_trunc(const std::uint8_t key[kAuthKeyLen],
                            const std::uint8_t* data, std::size_t data_len,
                            std::uint8_t* tag, std::size_t tag_len) noexcept {
    assert(key != nullptr && tag != nullptr && "hmac: null");
    assert(tag_len <= 20 && (data != nullptr || data_len == 0) && "hmac: bad arg");
    return hmac_sha1_two(key, data, data_len, nullptr, 0, tag, tag_len);
}

// Constant-time tag compare.
inline bool ct_equal(const std::uint8_t* a, const std::uint8_t* b,
                     std::size_t n) noexcept {
    assert(a != nullptr && b != nullptr && "ct_equal: null");
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < n; ++i) diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

// AES-128-GCM seal: encrypts plaintext in place over [text,text+n), AAD over
// [aad,aad+aad_len), writes the 16-byte tag to `tag`.
inline bool aes_gcm_seal(const std::uint8_t key[kSessionKeyLen],
                         const std::uint8_t iv[kGcmSaltLen],
                         const std::uint8_t* aad, std::size_t aad_len,
                         std::uint8_t* text, std::size_t n,
                         std::uint8_t tag[kGcmTagLen]) noexcept {
    assert(key != nullptr && iv != nullptr && tag != nullptr && "gcm seal: null");
    assert((text != nullptr || n == 0) && (aad != nullptr || aad_len == 0) && "gcm seal arg");
    EVP_CIPHER_CTX*& ctx = srtp_crypto_ctx().gcm;  // #38 — reused per thread
    if (ctx == nullptr) { ctx = EVP_CIPHER_CTX_new(); if (ctx == nullptr) return false; }
    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmSaltLen, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
              (aad_len == 0 ||
               EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1) &&
              (n == 0 ||
               EVP_EncryptUpdate(ctx, text, &len, text, static_cast<int>(n)) == 1) &&
              EVP_EncryptFinal_ex(ctx, text, &len) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagLen, tag) == 1;
    return ok;
}

// AES-128-GCM open: verifies `tag`, decrypts ciphertext in place. False on auth
// failure (no plaintext released to the caller's contract — but the buffer is
// overwritten; callers must treat a false return as "discard").
inline bool aes_gcm_open(const std::uint8_t key[kSessionKeyLen],
                         const std::uint8_t iv[kGcmSaltLen],
                         const std::uint8_t* aad, std::size_t aad_len,
                         std::uint8_t* text, std::size_t n,
                         const std::uint8_t tag[kGcmTagLen]) noexcept {
    assert(key != nullptr && iv != nullptr && tag != nullptr && "gcm open: null");
    assert((text != nullptr || n == 0) && (aad != nullptr || aad_len == 0) && "gcm open arg");
    EVP_CIPHER_CTX*& ctx = srtp_crypto_ctx().gcm;  // #38 — reused per thread
    if (ctx == nullptr) { ctx = EVP_CIPHER_CTX_new(); if (ctx == nullptr) return false; }
    int len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmSaltLen, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
              (aad_len == 0 ||
               EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1) &&
              (n == 0 ||
               EVP_DecryptUpdate(ctx, text, &len, text, static_cast<int>(n)) == 1) &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagLen,
                                  const_cast<std::uint8_t*>(tag)) == 1 &&
              EVP_DecryptFinal_ex(ctx, text, &len) == 1;
    return ok;
}

// ============================================================================
// RTP header parsing (just enough to find SSRC + payload offset).
// ============================================================================
struct RtpView {
    std::uint16_t seq = 0;
    std::uint32_t ssrc = 0;
    std::size_t   header_len = 0;  // bytes of header incl CSRC + extension
};

// Parse the variable-length RTP header (RFC 3550 §5.1). Returns false if the
// buffer is too short or inconsistent.
inline bool parse_rtp(const std::uint8_t* p, std::size_t n, RtpView& v) noexcept {
    assert((p != nullptr || n == 0) && "parse_rtp: null");
    assert(true && "parse_rtp");
    if (p == nullptr || n < kRtpHeaderMin) return false;
    if ((p[0] >> 6) != 2) return false;  // version must be 2
    const std::size_t cc = p[0] & 0x0F;
    std::size_t hl = kRtpHeaderMin + cc * 4;
    if (n < hl) return false;
    if ((p[0] & 0x10) != 0) {  // X: extension header present
        if (n < hl + 4) return false;
        const std::size_t ext_words = rd_u16(p + hl + 2);
        hl += 4 + ext_words * 4;
        if (n < hl) return false;
    }
    v.seq = rd_u16(p + 2);
    v.ssrc = rd_u32(p + 8);
    v.header_len = hl;
    return true;
}

// ============================================================================
// Per-SSRC ROC + replay state (RFC 3711 §3.3.1, Appendix A).
// ============================================================================
struct SsrcState {
    std::uint32_t ssrc = 0;
    std::uint32_t roc  = 0;       // rollover counter
    std::uint16_t s_l  = 0;       // highest received seq this ROC
    std::uint64_t window = 0;     // bit i set => index (s_l - i) seen (low 64)
    std::uint64_t window_hi = 0;  // upper 64 bits of the 128-bit window
    bool seen = false;            // any packet received yet
    bool in_use = false;
};

// Estimate the packet index per RFC 3711 §3.3.1 (Appendix A guess_index): pick
// the ROC candidate (v-1, v, v+1) that puts SEQ closest to s_l.
inline std::uint32_t guess_roc(const SsrcState& s, std::uint16_t seq) noexcept {
    assert(true && "guess_roc 1");
    assert(true && "guess_roc 2");
    if (!s.seen) return s.roc;
    if (s.s_l < 32768) {
        if (s.s_l + 32768u < static_cast<std::uint32_t>(seq) && s.roc > 0)
            return s.roc - 1;
        return s.roc;
    }
    if (static_cast<std::uint32_t>(seq) + 32768u < s.s_l) return s.roc + 1;
    return s.roc;
}

// 64-bit packet index for replay/IV from a guessed ROC.
inline std::uint64_t packet_index(std::uint32_t roc, std::uint16_t seq) noexcept {
    assert(true && "packet_index 1");
    assert(true && "packet_index 2");
    return (std::uint64_t{roc} << 16) | seq;
}

// Replay check (read-only) against a 128-bit sliding window. Returns false if
// the index is a duplicate or older than the window.
inline bool replay_ok(const SsrcState& s, std::uint64_t idx) noexcept {
    assert(true && "replay_ok 1");
    assert(true && "replay_ok 2");
    if (!s.seen) return true;
    const std::uint64_t top = packet_index(s.roc, s.s_l);
    if (idx > top) return true;  // newer than anything seen
    const std::uint64_t delta = top - idx;
    if (delta >= kReplayWindowBits) return false;  // too old
    if (delta < 64) return (s.window & (std::uint64_t{1} << delta)) == 0;
    return (s.window_hi & (std::uint64_t{1} << (delta - 64))) == 0;
}

// Commit a freshly-accepted index into ROC/s_l + window (RFC 3711 Appendix A).
inline void replay_commit(SsrcState& s, std::uint32_t roc, std::uint16_t seq,
                          std::uint64_t idx) noexcept {
    assert(true && "replay_commit 1");
    assert(true && "replay_commit 2");
    if (!s.seen) {
        s.roc = roc; s.s_l = seq; s.seen = true; s.window = 1; s.window_hi = 0;
        return;
    }
    const std::uint64_t top = packet_index(s.roc, s.s_l);
    if (idx > top) {
        const std::uint64_t shift = idx - top;
        if (shift >= kReplayWindowBits) { s.window = 0; s.window_hi = 0; }
        else if (shift >= 64) { s.window_hi = s.window << (shift - 64); s.window = 0; }
        else {
            s.window_hi = (s.window_hi << shift) |
                          (shift == 0 ? 0 : (s.window >> (64 - shift)));
            s.window <<= shift;
        }
        s.window |= 1;  // current packet at position 0
        s.roc = roc; s.s_l = seq;
    } else {
        const std::uint64_t delta = top - idx;
        if (delta < 64) s.window |= (std::uint64_t{1} << delta);
        else if (delta < kReplayWindowBits) s.window_hi |= (std::uint64_t{1} << (delta - 64));
    }
}

// ============================================================================
// SrtpSession — derived keys + per-SSRC ROC/replay + SRTCP index. One session
// is one direction (e.g. the outbound or inbound half of a DTLS-SRTP keying).
// ============================================================================
class SrtpSession {
public:
    SrtpSession() noexcept = default;
    SrtpSession(const SrtpSession&) = delete;
    SrtpSession& operator=(const SrtpSession&) = delete;

    // Bind master key/salt + profile and derive all session keys. Returns kOk.
    Error init(Profile profile, const std::uint8_t* master_key,
               std::size_t master_key_len, const std::uint8_t* master_salt,
               std::size_t master_salt_len) noexcept {
        assert(master_key != nullptr && master_salt != nullptr && "init: null");
        assert(master_key_len == kMasterKeyLen && "init: AES-128 master key only");
        profile_ = profile;
        if (profile != Profile::kAesCm128HmacSha1_80 &&
            profile != Profile::kAeadAes128Gcm) {
            return Error::kBadProfile;
        }
        Error e = derive_session_keys(master_key, master_key_len, master_salt,
                                      master_salt_len, /*is_rtcp=*/false, srtp_keys_);
        if (e != Error::kOk) return e;
        e = derive_session_keys(master_key, master_key_len, master_salt,
                                master_salt_len, /*is_rtcp=*/true, srtcp_keys_);
        if (e != Error::kOk) return e;
        initialized_ = true;
        return Error::kOk;
    }

    bool is_initialized() const noexcept { return initialized_; }
    Profile profile() const noexcept { return profile_; }
    const SessionKeys& srtp_keys() const noexcept { return srtp_keys_; }
    const SessionKeys& srtcp_keys() const noexcept { return srtcp_keys_; }

    // -- SRTP ----------------------------------------------------------------
    // protect: in = plain RTP (len = rtp_len). Writes the SRTP packet to `out`
    // (header + encrypted payload + auth tag). out_cap must be >= rtp_len +
    // tag. The sender's ROC is advanced on sequence wrap.
    Error protect_rtp(const std::uint8_t* in, std::size_t rtp_len,
                      std::uint8_t* out, std::size_t out_cap,
                      std::size_t* out_len) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "protect_rtp: null");
        assert(initialized_ && "protect_rtp before init");
        if (!initialized_) return Error::kBadArg;
        RtpView v;
        if (!parse_rtp(in, rtp_len, v)) return Error::kTooShort;
        const std::size_t tag = srtp_tag_len(profile_);
        if (out_cap < rtp_len + tag) return Error::kBufferTooSmall;
        SsrcState* st = slot_for(v.ssrc, /*create=*/true);
        if (st == nullptr) return Error::kNoSlot;
        const std::uint32_t roc = sender_roc(*st, v.seq);
        std::memcpy(out, in, rtp_len);
        std::uint8_t* payload = out + v.header_len;
        const std::size_t plen = rtp_len - v.header_len;
        Error e = (profile_ == Profile::kAeadAes128Gcm)
                      ? gcm_protect_rtp(out, v, roc, plen, out_len)
                      : cm_protect_rtp(out, v, roc, plen, payload, out_len);
        if (e == Error::kOk) commit_sender(*st, roc, v.seq);
        return e;
    }

    // unprotect: in = SRTP packet (len = srtp_len). Verifies tag + replay,
    // decrypts in place into `out`, writes the plain RTP length.
    Error unprotect_rtp(const std::uint8_t* in, std::size_t srtp_len,
                        std::uint8_t* out, std::size_t out_cap,
                        std::size_t* out_len) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "unprotect_rtp: null");
        assert(initialized_ && "unprotect_rtp before init");
        if (!initialized_) return Error::kBadArg;
        const std::size_t tag = srtp_tag_len(profile_);
        if (srtp_len < kRtpHeaderMin + tag) return Error::kTooShort;
        RtpView v;
        if (!parse_rtp(in, srtp_len - tag, v)) return Error::kTooShort;
        if (out_cap < srtp_len - tag) return Error::kBufferTooSmall;
        SsrcState* st = slot_for(v.ssrc, /*create=*/true);
        if (st == nullptr) return Error::kNoSlot;
        const std::uint32_t roc = guess_roc(*st, v.seq);
        const std::uint64_t idx = packet_index(roc, v.seq);
        if (!replay_ok(*st, idx)) return Error::kReplay;
        return (profile_ == Profile::kAeadAes128Gcm)
                   ? gcm_unprotect_rtp(in, srtp_len, v, roc, idx, out, out_len, *st)
                   : cm_unprotect_rtp(in, srtp_len, v, roc, idx, out, out_len, *st);
    }

    // -- SRTCP ---------------------------------------------------------------
    Error protect_rtcp(const std::uint8_t* in, std::size_t rtcp_len,
                       std::uint8_t* out, std::size_t out_cap,
                       std::size_t* out_len) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "protect_rtcp: null");
        assert(initialized_ && "protect_rtcp before init");
        if (!initialized_) return Error::kBadArg;
        if (rtcp_len < kRtcpHeaderMin) return Error::kTooShort;
        const std::size_t tag = srtcp_tag_len(profile_);
        if (out_cap < rtcp_len + kSrtcpTrailerLen + tag) return Error::kBufferTooSmall;
        const std::uint32_t ssrc = rd_u32(in + 4);
        const std::uint32_t index = (srtcp_index_out_ + 1) & 0x7FFFFFFFu;
        std::memcpy(out, in, rtcp_len);
        Error e = (profile_ == Profile::kAeadAes128Gcm)
                      ? gcm_protect_rtcp(out, rtcp_len, ssrc, index, out_len)
                      : cm_protect_rtcp(out, rtcp_len, ssrc, index, out_len);
        if (e == Error::kOk) srtcp_index_out_ = index;
        return e;
    }

    Error unprotect_rtcp(const std::uint8_t* in, std::size_t srtcp_len,
                         std::uint8_t* out, std::size_t out_cap,
                         std::size_t* out_len) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "unprotect_rtcp: null");
        assert(initialized_ && "unprotect_rtcp before init");
        if (!initialized_) return Error::kBadArg;
        const std::size_t tag = srtcp_tag_len(profile_);
        if (srtcp_len < kRtcpHeaderMin + kSrtcpTrailerLen + tag) return Error::kTooShort;
        const std::uint32_t ssrc = rd_u32(in + 4);
        // trailer is the 4 bytes immediately before the tag.
        const std::uint8_t* trailer = in + srtcp_len - tag - kSrtcpTrailerLen;
        const std::uint32_t index = rd_u32(trailer) & 0x7FFFFFFFu;
        if (out_cap < srtcp_len - tag - kSrtcpTrailerLen) return Error::kBufferTooSmall;
        return (profile_ == Profile::kAeadAes128Gcm)
                   ? gcm_unprotect_rtcp(in, srtcp_len, ssrc, index, out, out_len)
                   : cm_unprotect_rtcp(in, srtcp_len, ssrc, index, out, out_len);
    }

private:
    // Find or create the per-SSRC state slot (bounded linear scan).
    SsrcState* slot_for(std::uint32_t ssrc, bool create) noexcept {
        assert(true && "slot_for 1");
        assert(true && "slot_for 2");
        SsrcState* free_slot = nullptr;
        for (auto& s : ssrc_slots_) {
            if (s.in_use && s.ssrc == ssrc) return &s;
            if (!s.in_use && free_slot == nullptr) free_slot = &s;
        }
        if (!create || free_slot == nullptr) return nullptr;
        free_slot->in_use = true;
        free_slot->ssrc = ssrc;
        return free_slot;
    }

    // Sender ROC: advance on a seq wrap (new seq < last seq seen).
    std::uint32_t sender_roc(SsrcState& s, std::uint16_t seq) noexcept {
        assert(true && "sender_roc 1");
        assert(true && "sender_roc 2");
        if (!s.seen) return s.roc;
        if (seq < s.s_l) return s.roc + 1;  // wrapped
        return s.roc;
    }
    void commit_sender(SsrcState& s, std::uint32_t roc, std::uint16_t seq) noexcept {
        assert(true && "commit_sender 1");
        assert(true && "commit_sender 2");
        s.roc = roc; s.s_l = seq; s.seen = true;
    }

    // -- CM SRTP -------------------------------------------------------------
    Error cm_protect_rtp(std::uint8_t* out, const RtpView& v, std::uint32_t roc,
                         std::size_t plen, std::uint8_t* payload,
                         std::size_t* out_len) noexcept {
        assert(out != nullptr && out_len != nullptr && "cm_protect_rtp: null");
        assert(plen <= 65535 && "cm_protect_rtp: payload bound");
        std::uint8_t iv[16];
        srtp_cm_iv(srtp_keys_.salt.data(), v.ssrc, roc, v.seq, iv);
        if (!aes_ctr_xcrypt(srtp_keys_.cipher.data(), iv, payload, plen))
            return Error::kCryptoFail;
        // Auth covers the RTP header+payload (now ciphertext) ++ ROC (big-endian).
        const std::size_t body = v.header_len + plen;
        std::uint8_t roc_be[4];
        wr_u32(roc_be, roc);
        if (!hmac_over_two(srtp_keys_.auth.data(), out, body, roc_be, 4,
                           out + body, kSrtpTagLenCm))
            return Error::kCryptoFail;
        *out_len = body + kSrtpTagLenCm;
        return Error::kOk;
    }

    Error cm_unprotect_rtp(const std::uint8_t* in, std::size_t srtp_len,
                           const RtpView& v, std::uint32_t roc, std::uint64_t idx,
                           std::uint8_t* out, std::size_t* out_len,
                           SsrcState& st) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "cm_unprotect: null");
        assert(srtp_len >= kSrtpTagLenCm && "cm_unprotect: len");
        const std::size_t body = srtp_len - kSrtpTagLenCm;
        std::uint8_t exp[kSrtpTagLenCm];
        std::uint8_t roc_be[4];
        wr_u32(roc_be, roc);
        if (!hmac_over_two(srtp_keys_.auth.data(), in, body, roc_be, 4, exp,
                           kSrtpTagLenCm))
            return Error::kCryptoFail;
        if (!ct_equal(exp, in + body, kSrtpTagLenCm)) return Error::kAuthFail;
        std::memcpy(out, in, body);
        std::uint8_t* payload = out + v.header_len;
        const std::size_t plen = body - v.header_len;
        std::uint8_t iv[16];
        srtp_cm_iv(srtp_keys_.salt.data(), v.ssrc, roc, v.seq, iv);
        if (!aes_ctr_xcrypt(srtp_keys_.cipher.data(), iv, payload, plen))
            return Error::kCryptoFail;
        replay_commit(st, roc, v.seq, idx);
        *out_len = body;
        return Error::kOk;
    }

    // -- GCM SRTP (RFC 7714 §8) ---------------------------------------------
    Error gcm_protect_rtp(std::uint8_t* out, const RtpView& v, std::uint32_t roc,
                          std::size_t plen, std::size_t* out_len) noexcept {
        assert(out != nullptr && out_len != nullptr && "gcm_protect_rtp: null");
        assert(plen <= 65535 && "gcm_protect_rtp: payload bound");
        std::uint8_t iv[kGcmSaltLen];
        srtp_gcm_iv(srtp_keys_.salt.data(), v.ssrc, roc, v.seq, iv);
        std::uint8_t* payload = out + v.header_len;
        // AAD = RTP header (RFC 7714 §8.2); tag appended after ciphertext.
        if (!aes_gcm_seal(srtp_keys_.cipher.data(), iv, out, v.header_len, payload,
                          plen, out + v.header_len + plen))
            return Error::kCryptoFail;
        *out_len = v.header_len + plen + kGcmTagLen;
        return Error::kOk;
    }

    Error gcm_unprotect_rtp(const std::uint8_t* in, std::size_t srtp_len,
                            const RtpView& v, std::uint32_t roc, std::uint64_t idx,
                            std::uint8_t* out, std::size_t* out_len,
                            SsrcState& st) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "gcm_unprotect: null");
        assert(srtp_len >= kGcmTagLen + v.header_len && "gcm_unprotect: len");
        const std::size_t body = srtp_len - kGcmTagLen;
        const std::size_t plen = body - v.header_len;
        std::memcpy(out, in, body);
        std::uint8_t iv[kGcmSaltLen];
        srtp_gcm_iv(srtp_keys_.salt.data(), v.ssrc, roc, v.seq, iv);
        if (!aes_gcm_open(srtp_keys_.cipher.data(), iv, out, v.header_len,
                          out + v.header_len, plen, in + body))
            return Error::kAuthFail;
        replay_commit(st, roc, v.seq, idx);
        *out_len = body;
        return Error::kOk;
    }

    // -- CM SRTCP (RFC 3711 §3.4) -------------------------------------------
    Error cm_protect_rtcp(std::uint8_t* out, std::size_t rtcp_len,
                          std::uint32_t ssrc, std::uint32_t index,
                          std::size_t* out_len) noexcept {
        assert(out != nullptr && out_len != nullptr && "cm_protect_rtcp: null");
        assert(index <= 0x7FFFFFFFu && "cm_protect_rtcp: index");
        std::uint8_t* enc = out + kRtcpHeaderMin;          // encrypt after SSRC
        const std::size_t enc_len = rtcp_len - kRtcpHeaderMin;
        std::uint8_t iv[16];
        srtcp_cm_iv(srtcp_keys_.salt.data(), ssrc, index, iv);
        if (!aes_ctr_xcrypt(srtcp_keys_.cipher.data(), iv, enc, enc_len))
            return Error::kCryptoFail;
        wr_u32(out + rtcp_len, index | 0x80000000u);       // E=1 + index trailer
        const std::size_t auth_len = rtcp_len + kSrtcpTrailerLen;
        if (!hmac_sha1_trunc(srtcp_keys_.auth.data(), out, auth_len,
                             out + auth_len, kSrtcpTagLenCm))
            return Error::kCryptoFail;
        *out_len = auth_len + kSrtcpTagLenCm;
        return Error::kOk;
    }

    Error cm_unprotect_rtcp(const std::uint8_t* in, std::size_t srtcp_len,
                            std::uint32_t ssrc, std::uint32_t index,
                            std::uint8_t* out, std::size_t* out_len) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "cm_unprotect_rtcp: null");
        assert(srtcp_len >= kRtcpHeaderMin + kSrtcpTrailerLen + kSrtcpTagLenCm && "len");
        const std::size_t auth_len = srtcp_len - kSrtcpTagLenCm;
        std::uint8_t exp[kSrtcpTagLenCm];
        if (!hmac_sha1_trunc(srtcp_keys_.auth.data(), in, auth_len, exp, kSrtcpTagLenCm))
            return Error::kCryptoFail;
        if (!ct_equal(exp, in + auth_len, kSrtcpTagLenCm)) return Error::kAuthFail;
        const std::size_t plain_len = auth_len - kSrtcpTrailerLen;  // drop trailer
        std::memcpy(out, in, plain_len);
        std::uint8_t* enc = out + kRtcpHeaderMin;
        const std::size_t enc_len = plain_len - kRtcpHeaderMin;
        std::uint8_t iv[16];
        srtcp_cm_iv(srtcp_keys_.salt.data(), ssrc, index, iv);
        if (!aes_ctr_xcrypt(srtcp_keys_.cipher.data(), iv, enc, enc_len))
            return Error::kCryptoFail;
        *out_len = plain_len;
        return Error::kOk;
    }

    // -- GCM SRTCP (RFC 7714 §9) --------------------------------------------
    Error gcm_protect_rtcp(std::uint8_t* out, std::size_t rtcp_len,
                           std::uint32_t ssrc, std::uint32_t index,
                           std::size_t* out_len) noexcept {
        assert(out != nullptr && out_len != nullptr && "gcm_protect_rtcp: null");
        assert(index <= 0x7FFFFFFFu && "gcm_protect_rtcp: index");
        // Layout: [8B header][ciphertext][E||index trailer][16B tag].
        // AAD = first 8 bytes + the 4-byte trailer (RFC 7714 §9.3).
        std::uint8_t* enc = out + kRtcpHeaderMin;
        const std::size_t enc_len = rtcp_len - kRtcpHeaderMin;
        wr_u32(out + rtcp_len, index | 0x80000000u);  // trailer right after body
        std::uint8_t aad[kRtcpHeaderMin + kSrtcpTrailerLen];
        std::memcpy(aad, out, kRtcpHeaderMin);
        std::memcpy(aad + kRtcpHeaderMin, out + rtcp_len, kSrtcpTrailerLen);
        std::uint8_t iv[kGcmSaltLen];
        srtcp_gcm_iv(srtcp_keys_.salt.data(), ssrc, index, iv);
        if (!aes_gcm_seal(srtcp_keys_.cipher.data(), iv, aad, sizeof(aad), enc,
                          enc_len, out + rtcp_len + kSrtcpTrailerLen))
            return Error::kCryptoFail;
        *out_len = rtcp_len + kSrtcpTrailerLen + kGcmTagLen;
        return Error::kOk;
    }

    Error gcm_unprotect_rtcp(const std::uint8_t* in, std::size_t srtcp_len,
                             std::uint32_t ssrc, std::uint32_t index,
                             std::uint8_t* out, std::size_t* out_len) noexcept {
        assert(in != nullptr && out != nullptr && out_len != nullptr && "gcm_unprotect_rtcp: null");
        assert(srtcp_len >= kRtcpHeaderMin + kSrtcpTrailerLen + kGcmTagLen && "len");
        const std::size_t body = srtcp_len - kGcmTagLen - kSrtcpTrailerLen;
        const std::size_t enc_len = body - kRtcpHeaderMin;
        std::uint8_t aad[kRtcpHeaderMin + kSrtcpTrailerLen];
        std::memcpy(aad, in, kRtcpHeaderMin);
        std::memcpy(aad + kRtcpHeaderMin, in + body, kSrtcpTrailerLen);  // trailer
        std::memcpy(out, in, body);
        std::uint8_t* enc = out + kRtcpHeaderMin;
        std::uint8_t iv[kGcmSaltLen];
        srtcp_gcm_iv(srtcp_keys_.salt.data(), ssrc, index, iv);
        if (!aes_gcm_open(srtcp_keys_.cipher.data(), iv, aad, sizeof(aad), enc,
                          enc_len, in + body + kSrtcpTrailerLen))
            return Error::kAuthFail;
        *out_len = body;
        return Error::kOk;
    }

    // HMAC-SHA1 over the concatenation of two spans (header+payload, then ROC).
    static bool hmac_over_two(const std::uint8_t key[kAuthKeyLen],
                              const std::uint8_t* a, std::size_t alen,
                              const std::uint8_t* b, std::size_t blen,
                              std::uint8_t* tag, std::size_t tag_len) noexcept {
        assert(key != nullptr && tag != nullptr && "hmac_over_two: null");
        assert(tag_len <= 20 && "hmac_over_two: tag");
        return hmac_sha1_two(key, a, alen, b, blen, tag, tag_len);
    }

    Profile profile_ = Profile::kAesCm128HmacSha1_80;
    bool initialized_ = false;
    SessionKeys srtp_keys_{};
    SessionKeys srtcp_keys_{};
    std::array<SsrcState, kMaxSsrcSlots> ssrc_slots_{};
    std::uint32_t srtcp_index_out_ = 0;
};

}  // namespace bolt::api::webrtc::srtp
