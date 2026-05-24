// boltapi/quic/tls.h — TLS 1.3 QUIC handshake driver over OpenSSL 3.6's native
// QUIC-TLS callback API (SSL_set_quic_tls_cbs + OSSL_DISPATCH), wave 3.
//
// DECISION LOG D0 (docs/HTTP3_PLAN.md): the installed OpenSSL is 3.6.1, which
// does NOT expose the BoringSSL/quictls SSL_QUIC_METHOD surface FasterAPI's
// quic_tls.h targets (SSL_provide_quic_data / SSL_set_quic_method are absent).
// Instead it ships the OpenSSL 3.5+ "QUIC-TLS" callback API: a regular TLS_method
// SSL object on which we install a dispatch table via
//     int SSL_set_quic_tls_cbs(SSL *s, const OSSL_DISPATCH *qtdis, void *arg);
// and the peer transport params via
//     int SSL_set_quic_tls_transport_params(SSL *s, const unsigned char *, size_t);
// The dispatch table carries six callbacks (core_dispatch.h ids 2001..2006):
//     OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND      (2001) — TLS hands us bytes to send
//     OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD  (2002) — TLS pulls received bytes
//     OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD (2003) — TLS frees consumed bytes
//     OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET     (2004) — TLS gives a per-level secret
//     OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS (2005) — peer's transport params
//     OSSL_FUNC_SSL_QUIC_TLS_ALERT            (2006) — TLS raises an alert
//
// This is the SAME conceptual flow as FasterAPI's quic_tls.h (provide handshake
// bytes, emit handshake bytes, install per-level secrets, exchange transport
// params) re-wired to the OpenSSL 3.5+ dispatch model. We reuse the WebRTC DTLS
// self-signed-cert pattern (src/webrtc/dtls.cpp) for the server identity.
//
// Each yielded secret is fed into a wave-2 PacketProtection (packet_protection.h)
// for that level+direction so wave 4 can seal/open Handshake and 1-RTT packets
// (Initial keys still come from the DCID per RFC 9001 §5.2).
//
// Tiger Style: namespace bolt::api::quic, >=2 asserts/fn, bounded buffers,
// noexcept on the hot path, no exceptions, explicit bool returns. Header-only:
// OpenSSL is always linked into boltapi (and the test links OpenSSL::SSL/Crypto),
// so it compiles UNCONDITIONALLY into the default suite — no BOLTAPI_WITH_HTTP3
// gate. SCOPE (wave 3): the handshake + secrets + transport params. NO QUIC
// packet/connection wiring (that is wave 4).

#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "boltapi/quic/packet_protection.h"
#include "boltapi/quic/transport_params.h"

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Encryption levels (RFC 9001 §4). Indexed 0..3; ordering matches OpenSSL's
// OSSL_RECORD_PROTECTION_LEVEL_* (NONE=Initial, EARLY=0-RTT, HANDSHAKE,
// APPLICATION=1-RTT) so the dispatch callbacks map straight through.
// ----------------------------------------------------------------------------
enum class TlsLevel : std::uint8_t {
    kInitial = 0,    // OSSL_RECORD_PROTECTION_LEVEL_NONE
    kEarlyData = 1,  // OSSL_RECORD_PROTECTION_LEVEL_EARLY (0-RTT)
    kHandshake = 2,  // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
    kApplication = 3,  // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION (1-RTT)
};
inline constexpr std::size_t kNumTlsLevels = 4;

// OpenSSL QUIC-TLS yield_secret direction: 0 = read (RX) secret, 1 = write (TX)
// secret. (The OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET callback's `direction` arg.)
inline constexpr int kQuicTlsDirRead = 0;
inline constexpr int kQuicTlsDirWrite = 1;

inline TlsLevel level_from_ossl(std::uint32_t prot_level) noexcept {
    switch (prot_level) {
        case OSSL_RECORD_PROTECTION_LEVEL_NONE: return TlsLevel::kInitial;
        case OSSL_RECORD_PROTECTION_LEVEL_EARLY: return TlsLevel::kEarlyData;
        case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE: return TlsLevel::kHandshake;
        case OSSL_RECORD_PROTECTION_LEVEL_APPLICATION:
            return TlsLevel::kApplication;
        default: return TlsLevel::kInitial;
    }
}

// ----------------------------------------------------------------------------
// generate_self_signed_p256 — ECDSA P-256 self-signed cert/key for the server
// identity (reuses the WebRTC DTLS approach in src/webrtc/dtls.cpp). Caller owns
// *out_cert / *out_key. Returns true on success.
// ----------------------------------------------------------------------------
inline bool generate_self_signed_p256(X509** out_cert, EVP_PKEY** out_key,
                                      const char* cn = "boltapi-quic") noexcept {
    assert(out_cert != nullptr && out_key != nullptr &&
           "generate_self_signed_p256: null out");
    assert(cn != nullptr && "generate_self_signed_p256: null cn");

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (kctx != nullptr) {
        if (EVP_PKEY_keygen_init(kctx) > 0 &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) >
                0) {
            EVP_PKEY_keygen(kctx, &pkey);
        }
        EVP_PKEY_CTX_free(kctx);
    }
    if (pkey == nullptr) return false;

    X509* x = X509_new();
    if (x == nullptr) {
        EVP_PKEY_free(pkey);
        return false;
    }
    X509_set_version(x, 2);  // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    // Validity well under 14 days so a WebTransport client may pin this cert via
    // serverCertificateHashes (Chrome rejects pinned certs whose validity period
    // exceeds the limit). Use ~7 days with a small (5 min) clock-skew backdate so
    // the TOTAL validity (notAfter - notBefore) stays comfortably under any limit
    // — a 13-day window left almost no margin and Chrome rejected with
    // certificate_unknown / CERTIFICATE_VERIFY_FAILED.
    X509_gmtime_adj(X509_get_notBefore(x), -300);
    X509_gmtime_adj(X509_get_notAfter(x), 7L * 24 * 3600);
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn), -1, -1,
                               0);
    X509_set_issuer_name(x, name);  // self-signed

    // Standard leaf-certificate extensions (added BEFORE signing). A bare cert
    // with NO extensions is accepted by aioquic but REJECTED by Chrome's
    // WebTransport verifier (certificate_unknown), which expects a well-formed TLS
    // leaf: not a CA, usable for digital signatures + server auth, with a SAN.
    {
        const auto add_ext = [&](int nid, const char* value) noexcept -> bool {
            X509_EXTENSION* ext =
                X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);
            if (ext == nullptr) return false;
            const int rc = X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
            return rc == 1;
        };
        if (!add_ext(NID_basic_constraints, "critical,CA:FALSE") ||
            !add_ext(NID_key_usage, "critical,digitalSignature") ||
            !add_ext(NID_ext_key_usage, "serverAuth") ||
            !add_ext(NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1")) {
            X509_free(x);
            EVP_PKEY_free(pkey);
            return false;
        }
    }

    if (X509_sign(x, pkey, EVP_sha256()) == 0) {
        X509_free(x);
        EVP_PKEY_free(pkey);
        return false;
    }
    *out_cert = x;
    *out_key = pkey;
    return true;
}

// ----------------------------------------------------------------------------
// shared_server_identity — a PROCESS-STABLE self-signed P-256 cert/key, generated
// ONCE (thread-safe static init) and reused by every server handshake so a
// WebTransport client can pin the cert via serverCertificateHashes. Returns
// BORROWED pointers (the statics own them for the process lifetime; do NOT free).
// ----------------------------------------------------------------------------
inline bool shared_server_identity(X509** out_cert, EVP_PKEY** out_key) noexcept {
    assert(out_cert != nullptr && out_key != nullptr &&
           "shared_server_identity: null out");
    static X509*      s_cert = nullptr;
    static EVP_PKEY*  s_key  = nullptr;
    static const bool s_ok   = generate_self_signed_p256(&s_cert, &s_key);
    if (!s_ok) return false;
    *out_cert = s_cert;
    *out_key  = s_key;
    return true;
}

// ----------------------------------------------------------------------------
// server_cert_sha256 — SHA-256 of the DER encoding of the shared server cert (32
// bytes): exactly the hash a browser passes in WebTransport serverCertificateHashes.
// Generates the shared identity on demand. noexcept; returns false on any failure.
// ----------------------------------------------------------------------------
inline bool server_cert_sha256(std::uint8_t out[32]) noexcept {
    assert(out != nullptr && "server_cert_sha256: null out");
    X509* cert = nullptr;
    EVP_PKEY* key = nullptr;
    if (!shared_server_identity(&cert, &key)) return false;
    assert(cert != nullptr && "server_cert_sha256: null cert");
    unsigned char* der = nullptr;
    const int n = i2d_X509(cert, &der);
    if (n <= 0 || der == nullptr) return false;
    unsigned int mdlen = 0;
    const int ok = EVP_Digest(der, static_cast<std::size_t>(n), out, &mdlen,
                              EVP_sha256(), nullptr);
    OPENSSL_free(der);
    return ok == 1 && mdlen == 32;
}

// Diagnostic: log the shared server cert's hash, validity window, and key type, so
// we can confirm it meets Chrome's serverCertificateHashes rules (ECDSA P-256,
// validity <= 14 days). Only meaningful with BOLTAPI_QUIC_TRACE; safe no-op without.
inline void trace_server_cert_info() noexcept {
#ifdef BOLTAPI_QUIC_TRACE
    X509* cert = nullptr;
    EVP_PKEY* key = nullptr;
    if (!shared_server_identity(&cert, &key)) {
        std::fprintf(stderr, "[quic-cert] no shared identity\n");
        return;
    }
    std::uint8_t h[32];
    const bool hok = server_cert_sha256(h);
    char hex[65];
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) { hex[2*i] = hx[(h[i]>>4)&0xF]; hex[2*i+1] = hx[h[i]&0xF]; }
    hex[64] = 0;
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, X509_get0_notBefore(cert), X509_get0_notAfter(cert));
    std::fprintf(stderr,
        "[quic-cert] sha256=%s hashok=%d validity_days=%d secs=%d keytype=%d (EC=%d)\n",
        hex, (int)hok, days, secs, EVP_PKEY_base_id(key), EVP_PKEY_EC);
#endif
}

// ============================================================================
// QuicTls — drives one side (client or server) of the TLS 1.3 QUIC handshake
// via the OpenSSL QUIC-TLS callbacks, buffering CRYPTO data per level and
// deriving a PacketProtection from each yielded secret.
// ============================================================================
class QuicTls {
public:
    QuicTls() noexcept = default;

    ~QuicTls() {
        if (ssl_ != nullptr) SSL_free(ssl_);
        if (owns_ctx_ && ctx_ != nullptr) SSL_CTX_free(ctx_);
    }

    QuicTls(const QuicTls&) = delete;
    QuicTls& operator=(const QuicTls&) = delete;

    // ------------------------------------------------------------------------
    // Per-level CRYPTO + secret state.
    // ------------------------------------------------------------------------
    struct LevelState {
        // Outbound CRYPTO bytes TLS asked us to send (crypto_send), to be drained
        // by pull_crypto() and framed into CRYPTO frames by the connection layer.
        std::vector<std::uint8_t> send_buf;
        // Inbound CRYPTO bytes we were fed (feed_crypto) for TLS to pull
        // (crypto_recv_rcd) and release (crypto_release_rcd).
        std::vector<std::uint8_t> recv_buf;
        std::size_t recv_consumed = 0;  // bytes released back to us by TLS

        // Sized for the largest TLS 1.3 hash (SHA-384, 48B) so AES-256-GCM
        // suites — which aioquic offers FIRST — are not truncated to 32B.
        std::array<std::uint8_t, kMaxSecretLength> read_secret{};
        std::array<std::uint8_t, kMaxSecretLength> write_secret{};
        std::size_t read_secret_len = 0;
        std::size_t write_secret_len = 0;

        PacketProtection read_protection;   // open() peer packets at this level
        PacketProtection write_protection;  // seal() our packets at this level
        bool read_keys_ready = false;
        bool write_keys_ready = false;
    };

    // ------------------------------------------------------------------------
    // init_server / init_client — build the SSL_CTX (TLS 1.3 only) + SSL and
    // install the QUIC-TLS dispatch callbacks. The server uses a self-signed
    // P-256 cert; the client installs a permissive verify callback for the
    // in-process self-test (real cert/SNI verification is wave 6). Returns true
    // on success.
    // ------------------------------------------------------------------------
    // Constrain the SSL_CTX to TLS 1.3 and a DETERMINISTIC cipher-suite order so
    // both roles (and external peers) converge on the same suite. We prefer
    // TLS_AES_128_GCM_SHA256 (32B SHA-256 secrets) but still OFFER AES-256-GCM /
    // ChaCha20 — the suite-aware key schedule (packet_protection.h) derives the
    // correct hash/length for whichever is negotiated. Returns true on success.
    bool configure_ctx_common() noexcept {
        assert(ctx_ != nullptr && "configure_ctx_common: null ctx");
        assert(owns_ctx_ && "configure_ctx_common: ctx not owned");
        SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
        // Honour OUR order (server preference) and put the SHA-256 suite first so
        // the negotiated suite is stable across OpenSSL default-order changes.
        SSL_CTX_set_options(ctx_, SSL_OP_CIPHER_SERVER_PREFERENCE);
        return SSL_CTX_set_ciphersuites(
                   ctx_,
                   "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                   "TLS_CHACHA20_POLY1305_SHA256") == 1;
    }

    bool init_server() noexcept {
        is_server_ = true;
        ctx_ = SSL_CTX_new(TLS_method());
        if (ctx_ == nullptr) return false;
        owns_ctx_ = true;
        if (!configure_ctx_common()) return false;

        // Use the PROCESS-STABLE identity so every connection presents the same
        // cert (a WebTransport client pins its hash via serverCertificateHashes).
        // Borrowed pointers — SSL_CTX_use_* take their own refs; do NOT free here.
        X509* cert = nullptr;
        EVP_PKEY* key = nullptr;
        if (!shared_server_identity(&cert, &key)) return false;
        const bool loaded = SSL_CTX_use_certificate(ctx_, cert) == 1 &&
                            SSL_CTX_use_PrivateKey(ctx_, key) == 1 &&
                            SSL_CTX_check_private_key(ctx_) == 1;
        if (!loaded) return false;

        SSL_CTX_set_alpn_select_cb(ctx_, &QuicTls::alpn_select_cb, this);
        return finish_init();
    }

    bool init_client() noexcept {
        is_server_ = false;
        ctx_ = SSL_CTX_new(TLS_method());
        if (ctx_ == nullptr) return false;
        owns_ctx_ = true;
        if (!configure_ctx_common()) return false;
        // Permissive: the self-test server presents a self-signed cert with no
        // CA chain. Real verification (CA store + SNI) lands in wave 6.
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        return finish_init();
    }

    // Set the wire-format ALPN list (length-prefixed), e.g. {2,'h','3'}. Must be
    // called before advance(). Returns true on success.
    bool set_alpn(const std::uint8_t* protos, std::size_t len) noexcept {
        assert(ssl_ != nullptr && "set_alpn before init");
        assert(protos != nullptr && len > 0 && "set_alpn: empty list");
        return SSL_set_alpn_protos(ssl_, protos,
                                   static_cast<unsigned int>(len)) == 0;
    }

    // Set OUR transport parameters (encoded per RFC 9000 §18) before the
    // handshake; OpenSSL carries them in the quic_transport_parameters
    // extension. Returns true on success.
    bool set_transport_params(const TransportParameters& tp) noexcept {
        assert(ssl_ != nullptr && "set_transport_params before init");
        std::size_t n = 0;
        if (!encode_transport_params(tp, local_tp_, sizeof(local_tp_), &n))
            return false;
        // OpenSSL retains the pointer (it does NOT copy), so the encoded block
        // MUST outlive the handshake — keep it in local_tp_ (a member).
        local_tp_len_ = n;
        return SSL_set_quic_tls_transport_params(ssl_, local_tp_, n) == 1;
    }

    // Set OUR transport parameters from an already-encoded block. The bytes are
    // copied into a member buffer so they outlive the call (OpenSSL retains the
    // pointer rather than copying).
    bool set_transport_params_raw(const std::uint8_t* data,
                                  std::size_t len) noexcept {
        assert(ssl_ != nullptr && "set_transport_params_raw before init");
        assert((data != nullptr || len == 0) && "set_transport_params_raw: null");
        if (len > sizeof(local_tp_)) return false;
        if (len > 0) std::memcpy(local_tp_, data, len);
        local_tp_len_ = len;
        return SSL_set_quic_tls_transport_params(ssl_, local_tp_, len) == 1;
    }

    // ------------------------------------------------------------------------
    // feed_crypto — hand received CRYPTO-frame bytes (at `level`) to TLS. They
    // are buffered until TLS pulls them via crypto_recv_rcd. Returns true on
    // success (buffering never fails barring OOM, which std::vector signals via
    // bad_alloc — but we are -fno-exceptions, so a failed reserve simply leaves
    // the buffer; the assert documents the contract).
    // ------------------------------------------------------------------------
    bool feed_crypto(TlsLevel level, const std::uint8_t* data,
                     std::size_t len) noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels &&
               "feed_crypto: bad level");
        assert((data != nullptr || len == 0) && "feed_crypto: null data");
        if (len == 0) return true;
        LevelState& ls = levels_[static_cast<std::size_t>(level)];
        ls.recv_buf.insert(ls.recv_buf.end(), data, data + len);
        return true;
    }

    // pull_crypto — move all pending outbound CRYPTO bytes for `level` into out
    // (clearing the level's send buffer). Returns the number of bytes appended.
    // The connection layer frames these into CRYPTO frames at the matching level.
    std::size_t pull_crypto(TlsLevel level,
                            std::vector<std::uint8_t>& out) noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels &&
               "pull_crypto: bad level");
        LevelState& ls = levels_[static_cast<std::size_t>(level)];
        const std::size_t n = ls.send_buf.size();
        if (n > 0) {
            out.insert(out.end(), ls.send_buf.begin(), ls.send_buf.end());
            ls.send_buf.clear();
        }
        return n;
    }

    bool has_pending_crypto(TlsLevel level) const noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels &&
               "has_pending_crypto: bad level");
        return !levels_[static_cast<std::size_t>(level)].send_buf.empty();
    }

    bool has_any_pending_crypto() const noexcept {
        for (std::size_t i = 0; i < kNumTlsLevels; ++i)
            if (!levels_[i].send_buf.empty()) return true;
        return false;
    }

    // ------------------------------------------------------------------------
    // advance — run SSL_do_handshake once, processing fed CRYPTO data and
    // producing outbound CRYPTO data + secrets via the callbacks. Returns true
    // unless a fatal error occurred (WANT_READ/WANT_WRITE are normal mid-
    // handshake and return true). Inspect is_complete()/failed() afterwards.
    // ------------------------------------------------------------------------
    bool advance() noexcept {
        assert(ssl_ != nullptr && "advance before init");
        if (failed_) return false;
        if (complete_) {
            // Drive post-handshake (NewSessionTicket etc.) so any late secrets
            // / transport params are processed; ignore WANT_READ.
            const int r = SSL_do_handshake(ssl_);
            (void)r;
            return true;
        }
        const int rc = SSL_do_handshake(ssl_);
        if (rc == 1) {
            complete_ = true;
            return true;
        }
        const int err = SSL_get_error(ssl_, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return true;  // need more peer CRYPTO; not an error
        }
        failed_ = true;
#ifdef BOLTAPI_QUIC_TRACE
        {
            unsigned long e;
            char ebuf[256];
            std::fprintf(stderr, "[quic-tls] SSL_do_handshake rc=%d err=%d\n",
                         rc, err);
            while ((e = ERR_get_error()) != 0) {
                ERR_error_string_n(e, ebuf, sizeof(ebuf));
                std::fprintf(stderr, "[quic-tls] handshake error: %s\n", ebuf);
            }
        }
#endif
        ERR_clear_error();
        return false;
    }

    bool is_complete() const noexcept { return complete_; }
    bool failed() const noexcept { return failed_; }
    bool is_server() const noexcept { return is_server_; }

    // ------------------------------------------------------------------------
    // Secrets + protection accessors (valid once yielded for the level).
    // ------------------------------------------------------------------------
    const std::uint8_t* read_secret(TlsLevel level,
                                    std::size_t* out_len) const noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        assert(out_len != nullptr && "read_secret: null out_len");
        const LevelState& ls = levels_[static_cast<std::size_t>(level)];
        *out_len = ls.read_secret_len;
        return ls.read_secret_len > 0 ? ls.read_secret.data() : nullptr;
    }

    const std::uint8_t* write_secret(TlsLevel level,
                                     std::size_t* out_len) const noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        assert(out_len != nullptr && "write_secret: null out_len");
        const LevelState& ls = levels_[static_cast<std::size_t>(level)];
        *out_len = ls.write_secret_len;
        return ls.write_secret_len > 0 ? ls.write_secret.data() : nullptr;
    }

    bool have_read_secret(TlsLevel level) const noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        return levels_[static_cast<std::size_t>(level)].read_secret_len > 0;
    }
    bool have_write_secret(TlsLevel level) const noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        return levels_[static_cast<std::size_t>(level)].write_secret_len > 0;
    }

    // PacketProtection derived from the yielded secrets (RFC 9001 §5.1). The
    // read side opens peer packets; the write side seals ours.
    PacketProtection& read_protection(TlsLevel level) noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        return levels_[static_cast<std::size_t>(level)].read_protection;
    }
    PacketProtection& write_protection(TlsLevel level) noexcept {
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        return levels_[static_cast<std::size_t>(level)].write_protection;
    }

    // ------------------------------------------------------------------------
    // Peer transport params (decoded once the peer's extension arrives via the
    // got_transport_params callback).
    // ------------------------------------------------------------------------
    bool have_peer_transport_params() const noexcept {
        return peer_tp_present_;
    }
    const TransportParameters& peer_transport_params() const noexcept {
        assert(peer_tp_present_ && "peer_transport_params before received");
        return peer_tp_;
    }

    // Negotiated ALPN protocol (empty if none).
    void negotiated_alpn(const std::uint8_t** out, std::size_t* out_len) const
        noexcept {
        assert(out != nullptr && out_len != nullptr && "negotiated_alpn: null");
        const unsigned char* p = nullptr;
        unsigned int l = 0;
        if (ssl_ != nullptr) SSL_get0_alpn_selected(ssl_, &p, &l);
        *out = p;
        *out_len = l;
    }

    // Detected AEAD suite from the negotiated TLS 1.3 cipher (RFC 8446). Used to
    // pick the right PacketProtection cipher for Handshake/1-RTT levels.
    AeadAlgorithm aead_algorithm() const noexcept {
        if (ssl_ == nullptr) return AeadAlgorithm::kAes128Gcm;
        const SSL_CIPHER* c = SSL_get_current_cipher(ssl_);
        if (c == nullptr) return AeadAlgorithm::kAes128Gcm;
        switch (SSL_CIPHER_get_id(c) & 0xFFFF) {
            case 0x1302: return AeadAlgorithm::kAes256Gcm;
            case 0x1303: return AeadAlgorithm::kChaCha20Poly1305;
            case 0x1301:
            default: return AeadAlgorithm::kAes128Gcm;
        }
    }

    SSL* ssl() const noexcept { return ssl_; }

private:
    // Common SSL creation + callback install for both roles.
    bool finish_init() noexcept {
        ssl_ = SSL_new(ctx_);
        if (ssl_ == nullptr) return false;
        if (is_server_) {
            SSL_set_accept_state(ssl_);
        } else {
            SSL_set_connect_state(ssl_);
        }
        if (SSL_set_quic_tls_cbs(ssl_, quic_tls_dispatch(), this) != 1) {
            return false;
        }
        return true;
    }

    LevelState& level_state(std::uint32_t prot_level) noexcept {
        return levels_[static_cast<std::size_t>(level_from_ossl(prot_level))];
    }

    // Pick the AEAD suite for a secret-bearing level. Initial always AES-128-GCM
    // (RFC 9001 §5.2); other levels follow the negotiated cipher.
    AeadAlgorithm aead_for_level(TlsLevel level) const noexcept {
        if (level == TlsLevel::kInitial) return AeadAlgorithm::kAes128Gcm;
        return aead_algorithm();
    }

    // Derive + initialize a PacketProtection from a freshly yielded secret.
    bool install_protection(LevelState& ls, TlsLevel level, bool is_read,
                            const std::uint8_t* secret,
                            std::size_t secret_len) noexcept {
        assert(secret != nullptr && "install_protection: null secret");
        assert(static_cast<std::size_t>(level) < kNumTlsLevels && "bad level");
        const AeadAlgorithm algo = aead_for_level(level);
        // The yielded secret MUST be exactly one hash output long for the suite
        // (32B SHA-256 / 48B SHA-384). A mismatch means we mis-detected the
        // cipher; refuse rather than derive keys the peer cannot match.
        if (secret_len != hash_length(hash_for_aead(algo))) return false;
        PacketProtectionKeys keys;
        if (!derive_packet_keys(secret, secret_len, algo, keys))
            return false;
        PacketProtection& pp = is_read ? ls.read_protection : ls.write_protection;
        if (!pp.initialize(keys)) return false;
        if (is_read) {
            ls.read_keys_ready = true;
        } else {
            ls.write_keys_ready = true;
        }
        return true;
    }

    // ===================================================================
    // OpenSSL QUIC-TLS dispatch callbacks (core_dispatch.h ids 2001..2006).
    // Each recovers the QuicTls* from the `arg` we passed to
    // SSL_set_quic_tls_cbs. They are extern "C"-compatible static functions.
    // ===================================================================

    // 2001: TLS hands us `buf_len` bytes to transmit; we buffer them at the
    // current write level and report all consumed.
    static int cb_crypto_send(SSL* /*s*/, const unsigned char* buf,
                              size_t buf_len, size_t* consumed,
                              void* arg) noexcept {
        auto* self = static_cast<QuicTls*>(arg);
        assert(self != nullptr && "cb_crypto_send: null arg");
        assert(consumed != nullptr && "cb_crypto_send: null consumed");
        LevelState& ls = self->levels_[self->write_level_idx_];
        if (buf_len > 0 && buf != nullptr) {
            ls.send_buf.insert(ls.send_buf.end(), buf, buf + buf_len);
        }
        *consumed = buf_len;
        return 1;
    }

    // 2002: TLS pulls received CRYPTO bytes. We hand it a contiguous view of the
    // unconsumed tail of the current read level's recv buffer.
    static int cb_crypto_recv_rcd(SSL* /*s*/, const unsigned char** buf,
                                  size_t* bytes_read, void* arg) noexcept {
        auto* self = static_cast<QuicTls*>(arg);
        assert(self != nullptr && "cb_crypto_recv_rcd: null arg");
        assert(buf != nullptr && bytes_read != nullptr &&
               "cb_crypto_recv_rcd: null out");
        LevelState& ls = self->levels_[self->read_level_idx_];
        const std::size_t avail = ls.recv_buf.size() - ls.recv_consumed;
        *buf = avail > 0 ? ls.recv_buf.data() + ls.recv_consumed : nullptr;
        *bytes_read = avail;
        return 1;
    }

    // 2003: TLS releases `bytes_read` it finished with. Advance the consumed
    // mark; compact when the whole buffer is drained.
    static int cb_crypto_release_rcd(SSL* /*s*/, size_t bytes_read,
                                     void* arg) noexcept {
        auto* self = static_cast<QuicTls*>(arg);
        assert(self != nullptr && "cb_crypto_release_rcd: null arg");
        LevelState& ls = self->levels_[self->read_level_idx_];
        ls.recv_consumed += bytes_read;
        assert(ls.recv_consumed <= ls.recv_buf.size() &&
               "cb_crypto_release_rcd: over-release");
        if (ls.recv_consumed >= ls.recv_buf.size()) {
            ls.recv_buf.clear();
            ls.recv_consumed = 0;
        }
        return 1;
    }

    // 2004: TLS yields a per-level secret for one direction. Store it, track the
    // current read/write level (so crypto_send / crypto_recv use the right
    // buffer), and derive the matching PacketProtection.
    static int cb_yield_secret(SSL* /*s*/, uint32_t prot_level, int direction,
                               const unsigned char* secret, size_t secret_len,
                               void* arg) noexcept {
        auto* self = static_cast<QuicTls*>(arg);
        assert(self != nullptr && "cb_yield_secret: null arg");
        assert(secret != nullptr && "cb_yield_secret: null secret");
        const TlsLevel level = level_from_ossl(prot_level);
        const std::size_t idx = static_cast<std::size_t>(level);
        LevelState& ls = self->levels_[idx];
        const std::size_t copy =
            secret_len <= kMaxSecretLength ? secret_len : kMaxSecretLength;
        const bool is_read = (direction == kQuicTlsDirRead);
        if (is_read) {
            std::memcpy(ls.read_secret.data(), secret, copy);
            ls.read_secret_len = copy;
            self->read_level_idx_ = idx;  // we now read at this level
        } else {
            std::memcpy(ls.write_secret.data(), secret, copy);
            ls.write_secret_len = copy;
            self->write_level_idx_ = idx;  // we now write at this level
        }
        // Drive wave-2 packet protection from the secret. Both SHA-256 (32B)
        // and SHA-384 (48B, TLS_AES_256_GCM_SHA384) suites are wired — the hash
        // and secret length follow the negotiated cipher (RFC 9001 §5.1).
        self->install_protection(ls, level, is_read, secret, copy);
        return 1;
    }

    // 2005: the peer's transport parameters arrived; decode them (RFC 9000 §18).
    static int cb_got_transport_params(SSL* /*s*/, const unsigned char* params,
                                       size_t params_len, void* arg) noexcept {
        auto* self = static_cast<QuicTls*>(arg);
        assert(self != nullptr && "cb_got_transport_params: null arg");
        TransportParameters tp;
        if (decode_transport_params(params, params_len, &tp)) {
            self->peer_tp_ = tp;
            self->peer_tp_present_ = true;
        }
        return 1;
    }

    // 2006: TLS raised an alert; record it (the connection layer maps it to a
    // QUIC CRYPTO_ERROR per RFC 9001 §4.8).
    static int cb_alert(SSL* /*s*/, unsigned char alert_code,
                        void* arg) noexcept {
        auto* self = static_cast<QuicTls*>(arg);
        assert(self != nullptr && "cb_alert: null arg");
        self->alert_code_ = alert_code;
        self->got_alert_ = true;
        return 1;
    }

    // Server-side ALPN selection: prefer "h3".
    static int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out,
                              unsigned char* outlen, const unsigned char* in,
                              unsigned int inlen, void* /*arg*/) noexcept {
        static const unsigned char kH3[] = {'h', '3'};
        const unsigned char* p = in;
        const unsigned char* end = in + inlen;
        while (p < end) {
            const unsigned int l = *p++;
            if (p + l > end) break;
            if (l == sizeof(kH3) && std::memcmp(p, kH3, sizeof(kH3)) == 0) {
                *out = p;
                *outlen = static_cast<unsigned char>(l);
                return SSL_TLSEXT_ERR_OK;
            }
            p += l;
        }
        return SSL_TLSEXT_ERR_NOACK;  // tolerate no-ALPN in the self-test
    }

    // The dispatch table (static, shared). function_id ordering is irrelevant;
    // OpenSSL keys on the id. Terminated by OSSL_DISPATCH_END.
    static const OSSL_DISPATCH* quic_tls_dispatch() noexcept {
        static const OSSL_DISPATCH table[] = {
            {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
             reinterpret_cast<void (*)(void)>(cb_crypto_send)},
            {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
             reinterpret_cast<void (*)(void)>(cb_crypto_recv_rcd)},
            {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
             reinterpret_cast<void (*)(void)>(cb_crypto_release_rcd)},
            {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
             reinterpret_cast<void (*)(void)>(cb_yield_secret)},
            {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
             reinterpret_cast<void (*)(void)>(cb_got_transport_params)},
            {OSSL_FUNC_SSL_QUIC_TLS_ALERT,
             reinterpret_cast<void (*)(void)>(cb_alert)},
            OSSL_DISPATCH_END};
        return table;
    }

    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    bool owns_ctx_ = false;
    bool is_server_ = false;
    bool complete_ = false;
    bool failed_ = false;
    bool got_alert_ = false;
    unsigned char alert_code_ = 0;

    // The level whose buffer crypto_send / crypto_recv currently target. Updated
    // when a write/read secret for a higher level is yielded.
    std::size_t write_level_idx_ = static_cast<std::size_t>(TlsLevel::kInitial);
    std::size_t read_level_idx_ = static_cast<std::size_t>(TlsLevel::kInitial);

    std::array<LevelState, kNumTlsLevels> levels_{};

    TransportParameters peer_tp_{};
    bool peer_tp_present_ = false;

    // Our encoded transport params, kept alive for the SSL object's lifetime
    // (OpenSSL retains, not copies, the pointer passed to
    // SSL_set_quic_tls_transport_params).
    std::uint8_t local_tp_[kMaxTransportParamsBytes] = {};
    std::size_t local_tp_len_ = 0;
};

}  // namespace bolt::api::quic
