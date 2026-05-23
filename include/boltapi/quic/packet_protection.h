// boltapi/quic/packet_protection.h — QUIC packet protection (RFC 9001 §5).
//
// PORTED from FasterAPI src/cpp/http/quic/quic_packet_protection.h — the audit
// confirmed that file is GENUINE OpenSSL EVP crypto (HKDF / AES-GCM / ChaCha20 /
// header protection). Reshaped to Bolt Tiger Style:
//   * namespace bolt::api::quic (was fasterapi::quic);
//   * >=2 asserts per function, bounded fixed buffers, noexcept, no exceptions;
//   * explicit bool/enum error returns (no magic ints leaking to callers);
//   * the AEAD/HP hot path reuses cached EVP_CIPHER_CTX (no per-op alloc beyond
//     what OpenSSL holds internally);
//   * RESHAPED FIX: the FasterAPI ChaCha20 header-protection mask was wrong
//     (it ignored the counter and used the sample's first 4 bytes as part of a
//     12-byte nonce). Per RFC 9001 §5.4.4 the mask is
//       ChaCha20(hp_key, counter = sample[0..3] little-endian, nonce = sample[4..15])
//     applied to five zero bytes. OpenSSL's EVP_chacha20 takes a 16-byte IV =
//     [counter:4 LE][nonce:12], so we feed the 16-byte sample DIRECTLY as the IV.
//
// AEAD/HKDF/HP go through OpenSSL EVP and are API-agnostic (RFC 9001 §5 is
// identical for the BoringSSL and OpenSSL-3.5 QUIC-TLS surfaces — see HTTP3_PLAN
// DECISION LOG D0), so this header compiles UNCONDITIONALLY: OpenSSL is always
// linked into boltapi, so the default ctest suite covers it.
//
// SCOPE (wave 2): packet protection only. NO TLS handshake (wave 3).

#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// AEAD algorithm selection (the three QUIC v1 cipher suites, RFC 9001 §5.3).
// ----------------------------------------------------------------------------
enum class AeadAlgorithm : std::uint8_t {
    kAes128Gcm = 0,        // TLS_AES_128_GCM_SHA256 (Initial uses this)
    kAes256Gcm = 1,        // TLS_AES_256_GCM_SHA384
    kChaCha20Poly1305 = 2, // TLS_CHACHA20_POLY1305_SHA256
};

// ----------------------------------------------------------------------------
// Named bounds (RFC 9001 §5).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kAeadTagLength = 16;     // §5.3 all suites
inline constexpr std::size_t kAeadIvLength = 12;      // §5.3 all suites
inline constexpr std::size_t kAeadMaxKeyLength = 32;  // AES-256 / ChaCha20
inline constexpr std::size_t kHpKeyLength = 16;       // §5.4.3 AES uses 16; ChaCha 32
inline constexpr std::size_t kHpMaxKeyLength = 32;
inline constexpr std::size_t kHpSampleLength = 16;    // §5.4.2
inline constexpr std::size_t kHpMaskLength = 5;       // 1 flag byte + 4 PN bytes
inline constexpr std::size_t kMaxPacketNumberLength = 4;
inline constexpr std::size_t kSecretLength = 32;      // SHA-256 PRK / secrets

// Initial salt for QUIC v1 (RFC 9001 §5.2): 0x38762cf7...ccbb7f0a.
inline constexpr std::uint8_t kQuicV1InitialSalt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a};
inline constexpr std::size_t kQuicV1InitialSaltLength = sizeof(kQuicV1InitialSalt);

// Initial salt for QUIC v2 (RFC 9369).
inline constexpr std::uint8_t kQuicV2InitialSalt[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9};
inline constexpr std::size_t kQuicV2InitialSaltLength = sizeof(kQuicV2InitialSalt);

inline constexpr std::size_t aead_key_length(AeadAlgorithm algo) noexcept {
    switch (algo) {
        case AeadAlgorithm::kAes128Gcm:        return 16;
        case AeadAlgorithm::kAes256Gcm:        return 32;
        case AeadAlgorithm::kChaCha20Poly1305: return 32;
    }
    return 0;
}

inline constexpr std::size_t hp_key_length(AeadAlgorithm algo) noexcept {
    switch (algo) {
        case AeadAlgorithm::kAes128Gcm:        return 16;
        case AeadAlgorithm::kAes256Gcm:        return 32;  // AES-256-ECB key
        case AeadAlgorithm::kChaCha20Poly1305: return 32;
    }
    return 0;
}

// ============================================================================
// HKDF (RFC 8446 §7.1 / RFC 9001 §5) via OpenSSL 3.x EVP_KDF.
// ============================================================================

// HKDF-Extract(salt, ikm) -> PRK (32 bytes for SHA-256). Returns true on success.
inline bool hkdf_extract(std::uint8_t* out, std::size_t out_cap,
                         const std::uint8_t* ikm, std::size_t ikm_len,
                         const std::uint8_t* salt, std::size_t salt_len) noexcept {
    assert(out != nullptr && "hkdf_extract: null out");
    assert(out_cap >= kSecretLength && "hkdf_extract: out too small for SHA-256 PRK");
    (void)out_cap;  // referenced only by the assert (compiled out under NDEBUG)

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) return false;
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) return false;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(ikm), ikm_len);
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt), salt_len);
    params[4] = OSSL_PARAM_construct_end();

    const int ret = EVP_KDF_derive(ctx, out, kSecretLength, params);
    EVP_KDF_CTX_free(ctx);
    assert((ret <= 0 || out_cap >= kSecretLength) && "hkdf_extract overran");
    return ret > 0;
}

// HKDF-Expand(prk, info, L) -> out[0..out_len). Returns true on success.
inline bool hkdf_expand(std::uint8_t* out, std::size_t out_len,
                        const std::uint8_t* prk, std::size_t prk_len,
                        const std::uint8_t* info, std::size_t info_len) noexcept {
    assert(out != nullptr && "hkdf_expand: null out");
    assert(out_len > 0 && out_len <= 255 * 32 && "hkdf_expand: L out of range");

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) return false;
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) return false;

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(prk), prk_len);
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, const_cast<std::uint8_t*>(info), info_len);
    params[4] = OSSL_PARAM_construct_end();

    const int ret = EVP_KDF_derive(ctx, out, out_len, params);
    EVP_KDF_CTX_free(ctx);
    return ret > 0;
}

// HKDF-Expand-Label (TLS 1.3, RFC 8446 §7.1; QUIC labels per RFC 9001 §5.1):
//   HkdfLabel = { uint16 length; opaque label<7..255> = "tls13 "+label;
//                 opaque context<0..255> = "" }
// Returns true on success.
inline bool hkdf_expand_label(const std::uint8_t* secret, std::size_t secret_len,
                              const char* label, std::size_t label_len,
                              std::uint8_t* out, std::size_t out_len) noexcept {
    assert(label != nullptr && "hkdf_expand_label: null label");
    assert(label_len <= 249 && "hkdf_expand_label: label too long for one byte");

    static constexpr char kTls13Prefix[] = "tls13 ";
    static constexpr std::size_t kTls13PrefixLen = 6;  // excludes NUL

    // 2 (length) + 1 (label len) + prefix + label + 1 (empty context len).
    std::uint8_t hkdf_label[2 + 1 + kTls13PrefixLen + 249 + 1];
    std::size_t n = 0;

    hkdf_label[n++] = static_cast<std::uint8_t>((out_len >> 8) & 0xFF);
    hkdf_label[n++] = static_cast<std::uint8_t>(out_len & 0xFF);

    const std::size_t full_label_len = kTls13PrefixLen + label_len;
    hkdf_label[n++] = static_cast<std::uint8_t>(full_label_len);
    std::memcpy(hkdf_label + n, kTls13Prefix, kTls13PrefixLen);
    n += kTls13PrefixLen;
    std::memcpy(hkdf_label + n, label, label_len);
    n += label_len;
    hkdf_label[n++] = 0;  // empty context

    assert(n <= sizeof(hkdf_label) && "hkdf_expand_label overran scratch");
    return hkdf_expand(out, out_len, secret, secret_len, hkdf_label, n);
}

// ============================================================================
// Initial secrets (RFC 9001 §5.2).
// ============================================================================

// initial_secret = HKDF-Extract(salt, DCID). Returns true on success.
inline bool derive_initial_secret(const std::uint8_t* dcid, std::size_t dcid_len,
                                  std::uint8_t* initial_secret /*[32]*/,
                                  std::uint32_t version = 1) noexcept {
    assert(initial_secret != nullptr && "derive_initial_secret: null out");
    assert((dcid != nullptr || dcid_len == 0) && "derive_initial_secret: null DCID");

    const std::uint8_t* salt = (version == 2) ? kQuicV2InitialSalt : kQuicV1InitialSalt;
    const std::size_t salt_len =
        (version == 2) ? kQuicV2InitialSaltLength : kQuicV1InitialSaltLength;
    return hkdf_extract(initial_secret, kSecretLength, dcid, dcid_len, salt, salt_len);
}

// client_initial_secret / server_initial_secret (RFC 9001 §5.2).
inline bool derive_initial_secrets(const std::uint8_t* initial_secret /*[32]*/,
                                   std::uint8_t* client_secret /*[32]*/,
                                   std::uint8_t* server_secret /*[32]*/) noexcept {
    assert(initial_secret != nullptr && "derive_initial_secrets: null PRK");
    assert(client_secret != nullptr && server_secret != nullptr &&
           "derive_initial_secrets: null out");
    if (!hkdf_expand_label(initial_secret, kSecretLength, "client in", 9,
                           client_secret, kSecretLength)) {
        return false;
    }
    return hkdf_expand_label(initial_secret, kSecretLength, "server in", 9,
                             server_secret, kSecretLength);
}

// ----------------------------------------------------------------------------
// Per-direction protection keys derived from a traffic secret (RFC 9001 §5.1).
// ----------------------------------------------------------------------------
struct PacketProtectionKeys {
    std::array<std::uint8_t, kAeadMaxKeyLength> key{};
    std::array<std::uint8_t, kAeadIvLength> iv{};
    std::array<std::uint8_t, kHpMaxKeyLength> hp_key{};
    std::size_t key_len = 0;
    std::size_t hp_len = 0;
    AeadAlgorithm algorithm = AeadAlgorithm::kAes128Gcm;
};

// quic key / quic iv / quic hp (RFC 9001 §5.1). Returns true on success.
inline bool derive_packet_keys(const std::uint8_t* secret, std::size_t secret_len,
                               AeadAlgorithm algo,
                               PacketProtectionKeys& keys) noexcept {
    assert(secret != nullptr && "derive_packet_keys: null secret");
    assert(secret_len == kSecretLength && "derive_packet_keys: secret must be 32B");

    keys.algorithm = algo;
    keys.key_len = aead_key_length(algo);
    keys.hp_len = hp_key_length(algo);
    if (keys.key_len == 0 || keys.hp_len == 0) return false;

    if (!hkdf_expand_label(secret, secret_len, "quic key", 8,
                           keys.key.data(), keys.key_len)) {
        return false;
    }
    if (!hkdf_expand_label(secret, secret_len, "quic iv", 7,
                           keys.iv.data(), kAeadIvLength)) {
        return false;
    }
    return hkdf_expand_label(secret, secret_len, "quic hp", 7,
                             keys.hp_key.data(), keys.hp_len);
}

// ============================================================================
// PacketProtection — holds derived key/iv/hp for one level+direction; performs
// AEAD seal/open (§5.3) and header protect/unprotect (§5.4). Reuses cached
// EVP_CIPHER_CTX across calls (no per-packet ctx alloc).
// ============================================================================
class PacketProtection {
public:
    PacketProtection() noexcept = default;

    ~PacketProtection() {
        if (encrypt_ctx_ != nullptr) EVP_CIPHER_CTX_free(encrypt_ctx_);
        if (decrypt_ctx_ != nullptr) EVP_CIPHER_CTX_free(decrypt_ctx_);
        if (hp_ctx_ != nullptr) EVP_CIPHER_CTX_free(hp_ctx_);
    }

    PacketProtection(const PacketProtection&) = delete;
    PacketProtection& operator=(const PacketProtection&) = delete;

    PacketProtection(PacketProtection&& o) noexcept
        : keys_(o.keys_),
          encrypt_ctx_(o.encrypt_ctx_),
          decrypt_ctx_(o.decrypt_ctx_),
          hp_ctx_(o.hp_ctx_),
          initialized_(o.initialized_) {
        o.encrypt_ctx_ = nullptr;
        o.decrypt_ctx_ = nullptr;
        o.hp_ctx_ = nullptr;
        o.initialized_ = false;
    }

    PacketProtection& operator=(PacketProtection&& o) noexcept {
        if (this != &o) {
            if (encrypt_ctx_ != nullptr) EVP_CIPHER_CTX_free(encrypt_ctx_);
            if (decrypt_ctx_ != nullptr) EVP_CIPHER_CTX_free(decrypt_ctx_);
            if (hp_ctx_ != nullptr) EVP_CIPHER_CTX_free(hp_ctx_);
            keys_ = o.keys_;
            encrypt_ctx_ = o.encrypt_ctx_;
            decrypt_ctx_ = o.decrypt_ctx_;
            hp_ctx_ = o.hp_ctx_;
            initialized_ = o.initialized_;
            o.encrypt_ctx_ = nullptr;
            o.decrypt_ctx_ = nullptr;
            o.hp_ctx_ = nullptr;
            o.initialized_ = false;
        }
        return *this;
    }

    // Bind the derived keys + select ciphers. Returns true on success.
    bool initialize(const PacketProtectionKeys& keys) noexcept {
        assert(keys.key_len == aead_key_length(keys.algorithm) && "key_len mismatch");
        assert(keys.hp_len == hp_key_length(keys.algorithm) && "hp_len mismatch");
        keys_ = keys;

        const EVP_CIPHER* cipher = nullptr;
        const EVP_CIPHER* hp_cipher = nullptr;
        switch (keys_.algorithm) {
            case AeadAlgorithm::kAes128Gcm:
                cipher = EVP_aes_128_gcm();
                hp_cipher = EVP_aes_128_ecb();
                break;
            case AeadAlgorithm::kAes256Gcm:
                cipher = EVP_aes_256_gcm();
                hp_cipher = EVP_aes_256_ecb();
                break;
            case AeadAlgorithm::kChaCha20Poly1305:
                cipher = EVP_chacha20_poly1305();
                hp_cipher = EVP_chacha20();
                break;
        }
        if (cipher == nullptr || hp_cipher == nullptr) return false;

        encrypt_ctx_ = EVP_CIPHER_CTX_new();
        decrypt_ctx_ = EVP_CIPHER_CTX_new();
        hp_ctx_ = EVP_CIPHER_CTX_new();
        if (encrypt_ctx_ == nullptr || decrypt_ctx_ == nullptr || hp_ctx_ == nullptr) {
            return false;
        }
        if (EVP_EncryptInit_ex(encrypt_ctx_, cipher, nullptr, keys_.key.data(),
                               nullptr) != 1) {
            return false;
        }
        if (EVP_DecryptInit_ex(decrypt_ctx_, cipher, nullptr, keys_.key.data(),
                               nullptr) != 1) {
            return false;
        }
        // ChaCha20 HP re-keys per-call (IV carries the sample), so only AES-ECB
        // is keyed once here.
        if (keys_.algorithm != AeadAlgorithm::kChaCha20Poly1305) {
            if (EVP_EncryptInit_ex(hp_ctx_, hp_cipher, nullptr, keys_.hp_key.data(),
                                   nullptr) != 1) {
                return false;
            }
            EVP_CIPHER_CTX_set_padding(hp_ctx_, 0);
        }
        initialized_ = true;
        return true;
    }

    bool is_initialized() const noexcept { return initialized_; }
    const PacketProtectionKeys& keys() const noexcept { return keys_; }

    // AEAD seal (RFC 9001 §5.3): out := AEAD(key, nonce=iv^pn, aad=header,
    // plaintext). Writes plaintext_len + 16 (tag) bytes. Returns true on success.
    bool encrypt(std::uint64_t pn, const std::uint8_t* header, std::size_t header_len,
                 const std::uint8_t* plaintext, std::size_t plaintext_len,
                 std::uint8_t* out, std::size_t* out_len) noexcept {
        assert(initialized_ && "encrypt before initialize");
        assert(out != nullptr && out_len != nullptr && "encrypt: null out");
        if (!initialized_) return false;

        std::uint8_t nonce[kAeadIvLength];
        construct_nonce(pn, nonce);
        if (EVP_EncryptInit_ex(encrypt_ctx_, nullptr, nullptr, nullptr, nonce) != 1) {
            return false;
        }
        int len = 0;
        if (EVP_EncryptUpdate(encrypt_ctx_, nullptr, &len, header,
                              static_cast<int>(header_len)) != 1) {
            return false;
        }
        if (EVP_EncryptUpdate(encrypt_ctx_, out, &len, plaintext,
                              static_cast<int>(plaintext_len)) != 1) {
            return false;
        }
        std::size_t produced = static_cast<std::size_t>(len);
        if (EVP_EncryptFinal_ex(encrypt_ctx_, out + produced, &len) != 1) {
            return false;
        }
        produced += static_cast<std::size_t>(len);
        if (EVP_CIPHER_CTX_ctrl(encrypt_ctx_, EVP_CTRL_AEAD_GET_TAG,
                                static_cast<int>(kAeadTagLength), out + produced) != 1) {
            return false;
        }
        produced += kAeadTagLength;
        *out_len = produced;
        assert(produced == plaintext_len + kAeadTagLength && "seal length wrong");
        return true;
    }

    // AEAD open (RFC 9001 §5.3): verifies tag; on success writes plaintext.
    // ciphertext_len INCLUDES the trailing 16-byte tag. Returns false on auth
    // failure (no plaintext released).
    bool decrypt(std::uint64_t pn, const std::uint8_t* header, std::size_t header_len,
                 const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                 std::uint8_t* out, std::size_t* out_len) noexcept {
        assert(initialized_ && "decrypt before initialize");
        assert(out != nullptr && out_len != nullptr && "decrypt: null out");
        if (!initialized_) return false;
        if (ciphertext_len < kAeadTagLength) return false;

        std::uint8_t nonce[kAeadIvLength];
        construct_nonce(pn, nonce);
        if (EVP_DecryptInit_ex(decrypt_ctx_, nullptr, nullptr, nullptr, nonce) != 1) {
            return false;
        }
        const std::size_t body_len = ciphertext_len - kAeadTagLength;
        if (EVP_CIPHER_CTX_ctrl(
                decrypt_ctx_, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagLength),
                const_cast<std::uint8_t*>(ciphertext + body_len)) != 1) {
            return false;
        }
        int len = 0;
        if (EVP_DecryptUpdate(decrypt_ctx_, nullptr, &len, header,
                              static_cast<int>(header_len)) != 1) {
            return false;
        }
        if (EVP_DecryptUpdate(decrypt_ctx_, out, &len, ciphertext,
                              static_cast<int>(body_len)) != 1) {
            return false;
        }
        std::size_t produced = static_cast<std::size_t>(len);
        if (EVP_DecryptFinal_ex(decrypt_ctx_, out + produced, &len) != 1) {
            return false;  // authentication failed
        }
        produced += static_cast<std::size_t>(len);
        *out_len = produced;
        assert(produced == body_len && "open length wrong");
        return true;
    }

    // Apply header protection in place (RFC 9001 §5.4): masks the low bits of
    // byte 0 and the pn_length packet-number bytes. Returns true on success.
    bool protect_header(std::uint8_t* header, std::size_t pn_offset,
                        std::size_t pn_length, const std::uint8_t* sample) noexcept {
        assert(initialized_ && "protect_header before initialize");
        assert(pn_length >= 1 && pn_length <= kMaxPacketNumberLength && "bad pn_length");
        if (!initialized_) return false;

        std::uint8_t mask[kHpSampleLength];
        if (!generate_hp_mask(sample, mask)) return false;

        if ((header[0] & 0x80) != 0) {
            header[0] ^= mask[0] & 0x0F;  // long header: low 4 bits
        } else {
            header[0] ^= mask[0] & 0x1F;  // short header: low 5 bits
        }
        for (std::size_t i = 0; i < pn_length; ++i) {
            header[pn_offset + i] ^= mask[1 + i];
        }
        return true;
    }

    // Remove header protection in place (RFC 9001 §5.4.1). Recovers pn_length
    // from the unmasked first byte. Returns true on success.
    bool unprotect_header(std::uint8_t* header, std::size_t pn_offset,
                          const std::uint8_t* sample,
                          std::size_t* out_pn_length) noexcept {
        assert(initialized_ && "unprotect_header before initialize");
        assert(out_pn_length != nullptr && "unprotect_header: null out");
        if (!initialized_) return false;

        std::uint8_t mask[kHpSampleLength];
        if (!generate_hp_mask(sample, mask)) return false;

        if ((header[0] & 0x80) != 0) {
            header[0] ^= mask[0] & 0x0F;
        } else {
            header[0] ^= mask[0] & 0x1F;
        }
        const std::size_t pn_length = static_cast<std::size_t>(header[0] & 0x03) + 1;
        assert(pn_length >= 1 && pn_length <= kMaxPacketNumberLength && "bad pn_length");
        for (std::size_t i = 0; i < pn_length; ++i) {
            header[pn_offset + i] ^= mask[1 + i];
        }
        *out_pn_length = pn_length;
        return true;
    }

    // The HP sample begins 4 bytes after the START of the packet-number field
    // (RFC 9001 §5.4.2), independent of the actual PN length.
    static constexpr std::size_t sample_offset(std::size_t pn_offset) noexcept {
        return pn_offset + 4;
    }

private:
    // nonce = iv XOR (pn right-aligned, big-endian) (RFC 9001 §5.3).
    void construct_nonce(std::uint64_t pn, std::uint8_t* nonce) const noexcept {
        assert(nonce != nullptr && "construct_nonce: null");
        assert(keys_.iv.size() == kAeadIvLength && "iv size");
        std::memcpy(nonce, keys_.iv.data(), kAeadIvLength);
        for (int i = 0; i < 8; ++i) {
            nonce[kAeadIvLength - 1 - i] ^=
                static_cast<std::uint8_t>((pn >> (8 * i)) & 0xFF);
        }
    }

    // mask[0..15] from the 16-byte sample (RFC 9001 §5.4.3 / §5.4.4). Only the
    // first 5 bytes are used by callers. Returns true on success.
    bool generate_hp_mask(const std::uint8_t* sample, std::uint8_t* mask) noexcept {
        assert(sample != nullptr && mask != nullptr && "generate_hp_mask: null");
        if (keys_.algorithm == AeadAlgorithm::kChaCha20Poly1305) {
            // RFC 9001 §5.4.4: mask = ChaCha20(hp_key,
            //   counter = sample[0..3] (little-endian), nonce = sample[4..15])
            //   applied to 5 zero bytes. OpenSSL EVP_chacha20 IV layout is
            //   [counter:4 LE][nonce:12] == the 16-byte sample verbatim.
            if (EVP_EncryptInit_ex(hp_ctx_, EVP_chacha20(), nullptr,
                                   keys_.hp_key.data(), sample) != 1) {
                return false;
            }
            const std::uint8_t zeros[kHpMaskLength] = {0, 0, 0, 0, 0};
            int len = 0;
            if (EVP_EncryptUpdate(hp_ctx_, mask, &len, zeros,
                                  static_cast<int>(kHpMaskLength)) != 1) {
                return false;
            }
            assert(len == static_cast<int>(kHpMaskLength) && "chacha hp short");
            return true;
        }
        // AES-ECB(hp_key, sample) -> 16-byte block; first 5 bytes are the mask.
        int len = 0;
        if (EVP_EncryptUpdate(hp_ctx_, mask, &len, sample,
                              static_cast<int>(kHpSampleLength)) != 1) {
            return false;
        }
        assert(len == static_cast<int>(kHpSampleLength) && "aes-ecb hp short");
        return true;
    }

    PacketProtectionKeys keys_{};
    EVP_CIPHER_CTX* encrypt_ctx_ = nullptr;
    EVP_CIPHER_CTX* decrypt_ctx_ = nullptr;
    EVP_CIPHER_CTX* hp_ctx_ = nullptr;
    bool initialized_ = false;
};

// ----------------------------------------------------------------------------
// derive_initial — convenience: full DCID -> Initial protection chain for one
// direction (RFC 9001 §5.2). is_server selects the server traffic secret.
// Initial packets always use AES-128-GCM (§5.2). Returns true on success.
// ----------------------------------------------------------------------------
inline bool derive_initial(const std::uint8_t* dcid, std::size_t dcid_len,
                           bool is_server, PacketProtection& out,
                           std::uint32_t version = 1) noexcept {
    assert((dcid != nullptr || dcid_len == 0) && "derive_initial: null DCID");
    assert(dcid_len <= 20 && "derive_initial: DCID too long");

    std::uint8_t initial_secret[kSecretLength];
    if (!derive_initial_secret(dcid, dcid_len, initial_secret, version)) return false;

    std::uint8_t client_secret[kSecretLength];
    std::uint8_t server_secret[kSecretLength];
    if (!derive_initial_secrets(initial_secret, client_secret, server_secret)) {
        return false;
    }
    const std::uint8_t* secret = is_server ? server_secret : client_secret;

    PacketProtectionKeys keys;
    bool ok = derive_packet_keys(secret, kSecretLength, AeadAlgorithm::kAes128Gcm, keys);
    if (ok) ok = out.initialize(keys);

    std::memset(initial_secret, 0, sizeof(initial_secret));
    std::memset(client_secret, 0, sizeof(client_secret));
    std::memset(server_secret, 0, sizeof(server_secret));
    return ok;
}

}  // namespace bolt::api::quic
