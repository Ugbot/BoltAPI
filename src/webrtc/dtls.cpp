// src/webrtc/dtls.cpp — WebRTC DTLS server (answerer) over UDP via memory BIOs.
//
// See include/boltapi/webrtc/dtls.h for the architecture. OpenSSL drives the
// DTLS record layer + handshake; we own the framing/demux/transport around it.

#include "boltapi/webrtc/dtls.h"
#include "boltapi/net/udp_transport.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cctype>
#include <cstring>

namespace bolt::api {
namespace webrtc {

namespace {

// Permissive verify callback: WebRTC presents a self-signed cert with no CA
// chain, so chain verification ALWAYS "passes" here. The real identity check is
// the SHA-256 fingerprint comparison done after the handshake (verify_peer()).
// We still set SSL_VERIFY_PEER so OpenSSL REQUESTS + retains the client cert.
int permissive_verify(int /*preverify_ok*/, X509_STORE_CTX* /*ctx*/) {
    return 1;
}

// Format a raw byte buffer as uppercase "AA:BB:..".
void hex_colon(const unsigned char* buf, std::size_t n, std::string& out) {
    static const char* kHex = "0123456789ABCDEF";
    out.clear();
    out.reserve(n * 3);
    for (std::size_t i = 0; i < n; ++i) {
        if (i) out.push_back(':');
        out.push_back(kHex[(buf[i] >> 4) & 0xF]);
        out.push_back(kHex[buf[i] & 0xF]);
    }
}

// Generate a self-signed cert/key. Prefers ECDSA P-256 (the WebRTC norm); falls
// back to RSA-2048 if EC keygen is unavailable. Returns true and fills *out_pkey
// / *out_x509 (caller owns both) on success.
bool make_self_signed(EVP_PKEY** out_pkey, X509** out_x509) {
    EVP_PKEY* pkey = nullptr;

    // --- ECDSA P-256 first ---
    {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (kctx) {
            if (EVP_PKEY_keygen_init(kctx) > 0 &&
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) > 0) {
                EVP_PKEY_keygen(kctx, &pkey);
            }
            EVP_PKEY_CTX_free(kctx);
        }
    }
    // --- RSA-2048 fallback ---
    if (!pkey) {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (kctx) {
            if (EVP_PKEY_keygen_init(kctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) > 0) {
                EVP_PKEY_keygen(kctx, &pkey);
            }
            EVP_PKEY_CTX_free(kctx);
        }
    }
    if (!pkey) return false;

    X509* x = X509_new();
    if (!x) { EVP_PKEY_free(pkey); return false; }

    X509_set_version(x, 2);  // X509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 365L * 24 * 3600);  // 1 year
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("BoltAPI-WebRTC"),
                               -1, -1, 0);
    X509_set_issuer_name(x, name);  // self-signed

    if (!X509_sign(x, pkey, EVP_sha256())) {
        X509_free(x);
        EVP_PKEY_free(pkey);
        return false;
    }

    *out_pkey = pkey;
    *out_x509 = x;
    return true;
}

// Compare two sockaddr peers (IPv4 / IPv6) for equality.
bool same_peer(const sockaddr* a, int alen, const sockaddr_storage& b, int blen) {
    if (alen != blen) return false;
    if (a->sa_family != b.ss_family) return false;
    if (a->sa_family == AF_INET) {
        const auto* x = reinterpret_cast<const sockaddr_in*>(a);
        const auto* y = reinterpret_cast<const sockaddr_in*>(&b);
        return x->sin_port == y->sin_port &&
               x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        const auto* x = reinterpret_cast<const sockaddr_in6*>(a);
        const auto* y = reinterpret_cast<const sockaddr_in6*>(&b);
        return x->sin6_port == y->sin6_port &&
               std::memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return std::memcmp(a, &b, static_cast<std::size_t>(alen)) == 0;
}

}  // namespace

// ===========================================================================
// Free helpers
// ===========================================================================
bool x509_sha256_fingerprint(X509* cert, std::string& out) noexcept {
    out.clear();
    if (!cert) return false;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;
    if (X509_digest(cert, EVP_sha256(), md, &mdlen) != 1) return false;
    hex_colon(md, mdlen, out);
    return true;
}

bool fingerprints_equal(std::string_view a, std::string_view b) noexcept {
    auto strip = [](std::string_view s) -> std::string_view {
        // Drop a leading "sha-256" (or any algo token) + following spaces.
        // Trim leading/trailing whitespace too.
        auto is_space = [](char c) { return c == ' ' || c == '\t' ||
                                            c == '\r' || c == '\n'; };
        while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
        // If the first token has no ':' it's an algorithm prefix; skip it.
        std::size_t sp = s.find(' ');
        if (sp != std::string_view::npos) {
            std::string_view first = s.substr(0, sp);
            if (first.find(':') == std::string_view::npos) {
                s.remove_prefix(sp);
                while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
            }
        }
        while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
        return s;
    };
    std::string_view sa = strip(a);
    std::string_view sb = strip(b);
    if (sa.size() != sb.size()) return false;
    for (std::size_t i = 0; i < sa.size(); ++i) {
        if (std::toupper(static_cast<unsigned char>(sa[i])) !=
            std::toupper(static_cast<unsigned char>(sb[i])))
            return false;
    }
    return !sa.empty();
}

// ===========================================================================
// DtlsContext
// ===========================================================================
DtlsContext::~DtlsContext() {
    if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
}

std::unique_ptr<DtlsContext> DtlsContext::create() {
    auto self = std::unique_ptr<DtlsContext>(new DtlsContext());

    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) return nullptr;

    // DTLS 1.2 floor (RFC 8261 / browser interop). 1.3 over DTLS is negotiated
    // up automatically when both peers support it.
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);

    // WebRTC identity is bound by fingerprint, not by a CA chain: request the
    // peer cert (SSL_VERIFY_PEER) but accept any chain (permissive callback);
    // the real check is verify_peer() comparing the SHA-256 fingerprint.
    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       permissive_verify);

    // Self-signed cert + key.
    EVP_PKEY* pkey = nullptr;
    X509*     cert = nullptr;
    if (!make_self_signed(&pkey, &cert)) {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Compute our fingerprint for the SDP a=fingerprint line.
    if (!x509_sha256_fingerprint(cert, self->fingerprint_)) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // SSL_CTX_use_* duplicated/up-ref'd what it needs; free our handles.
    X509_free(cert);
    EVP_PKEY_free(pkey);

    self->ctx_ = ctx;
    return self;
}

SSL* DtlsContext::new_ssl() const noexcept {
    if (!ctx_) return nullptr;
    SSL* ssl = SSL_new(ctx_);
    if (!ssl) return nullptr;
    SSL_set_accept_state(ssl);  // server role
    return ssl;
}

// ===========================================================================
// DtlsSession
// ===========================================================================
DtlsSession::DtlsSession(const DtlsContext& ctx, net::UdpTransport& transport,
                         const sockaddr* addr, int addr_len) noexcept
    : transport_(&transport) {
    if (addr && addr_len > 0 &&
        static_cast<std::size_t>(addr_len) <= sizeof(sockaddr_storage)) {
        std::memcpy(&peer_, addr, static_cast<std::size_t>(addr_len));
        peer_len_ = addr_len;
    }

    ssl_ = ctx.new_ssl();
    if (!ssl_) { state_ = State::Failed; return; }

    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());
    if (!rbio_ || !wbio_) {
        if (rbio_) BIO_free(rbio_);
        if (wbio_) BIO_free(wbio_);
        rbio_ = wbio_ = nullptr;
        SSL_free(ssl_);
        ssl_ = nullptr;
        state_ = State::Failed;
        return;
    }
    // Memory BIOs return retry-want-read on empty rather than EOF, so the DTLS
    // state machine drives off WANT_READ cleanly between datagrams.
    BIO_set_mem_eof_return(rbio_, -1);
    BIO_set_mem_eof_return(wbio_, -1);

    // SSL takes ownership of both BIOs (we must NOT free them ourselves).
    SSL_set_bio(ssl_, rbio_, wbio_);
}

DtlsSession::~DtlsSession() {
    // SSL_free releases the attached rbio_/wbio_ too.
    if (ssl_) { SSL_free(ssl_); ssl_ = nullptr; }
    rbio_ = wbio_ = nullptr;
}

void DtlsSession::set_expected_fingerprint(std::string_view fp) {
    expected_fingerprint_ = std::string(fp);
}

void DtlsSession::flush_wbio() noexcept {
    if (!wbio_ || !transport_) return;
    std::uint8_t buf[kDtlsDrainBuf];
    for (;;) {
        const int n = BIO_read(wbio_, buf, static_cast<int>(sizeof(buf)));
        if (n <= 0) break;
        transport_->send(reinterpret_cast<const sockaddr*>(&peer_), peer_len_,
                         buf, static_cast<std::size_t>(n));
        ++records_out_;
    }
}

void DtlsSession::verify_peer() noexcept {
    X509* peer = SSL_get1_peer_certificate(ssl_);
    if (!peer) {
        // No peer cert: WebRTC mandates one. Reject.
        state_ = State::Failed;
        return;
    }
    const bool ok = x509_sha256_fingerprint(peer, peer_fingerprint_);
    X509_free(peer);
    if (!ok) { state_ = State::Failed; return; }

    if (!expected_fingerprint_.empty()) {
        if (!fingerprints_equal(peer_fingerprint_, expected_fingerprint_)) {
            // Identity binding failed — this is the actual WebRTC security check.
            state_ = State::Failed;
            return;
        }
    }
    state_ = State::Established;
}

void DtlsSession::pump_handshake() noexcept {
    if (!ssl_) { state_ = State::Failed; return; }
    if (state_ == State::New) state_ = State::Handshaking;

    const int rc = SSL_do_handshake(ssl_);
    // Always flush whatever OpenSSL produced (ServerHello flight, retransmits).
    flush_wbio();

    if (rc == 1) {
        verify_peer();  // -> Established or Failed
        return;
    }
    const int err = SSL_get_error(ssl_, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Mid-handshake: wait for the next datagram. Stay Handshaking.
        return;
    }
    // Fatal handshake error.
    state_ = State::Failed;
    ERR_clear_error();
}

bool DtlsSession::feed(const std::uint8_t* data, std::size_t len) noexcept {
    if (!ssl_ || !rbio_) { return false; }
    if (state_ == State::Failed) return false;
    if (data && len > 0) {
        BIO_write(rbio_, data, static_cast<int>(len));
        ++records_in_;
    }

    if (state_ != State::Established) {
        pump_handshake();
    } else {
        // Established: a fed record may be app data; nothing to do here — the
        // App/SCTP layer pulls it via read_app(). But still flush in case a
        // post-handshake message (e.g. a renegotiation alert) produced output.
        flush_wbio();
    }
    return state_ != State::Failed;
}

int DtlsSession::send_app(const std::uint8_t* data, std::size_t len) noexcept {
    if (!ssl_ || state_ != State::Established) return -1;
    if (len == 0) return 0;
    const int n = SSL_write(ssl_, data, static_cast<int>(len));
    flush_wbio();
    if (n <= 0) {
        const int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    return n;
}

int DtlsSession::read_app(std::uint8_t* out, std::size_t cap) noexcept {
    if (!ssl_ || state_ != State::Established) return -1;
    if (cap == 0) return 0;
    const int n = SSL_read(ssl_, out, static_cast<int>(cap));
    if (n <= 0) {
        const int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        if (err == SSL_ERROR_ZERO_RETURN) return 0;  // peer closed cleanly
        return -1;
    }
    // A read can advance internal state and produce output (e.g. acks); flush.
    flush_wbio();
    return n;
}

// ===========================================================================
// DtlsSessionManager
// ===========================================================================
DtlsSessionManager::Entry*
DtlsSessionManager::lookup(const sockaddr* peer, int peer_len) noexcept {
    if (!peer || peer_len <= 0) return nullptr;
    for (std::size_t i = 0; i < kMaxPeers; ++i) {
        Entry& e = entries_[i];
        if (e.used && same_peer(peer, peer_len, e.addr, e.addr_len)) return &e;
    }
    return nullptr;
}

DtlsSession*
DtlsSessionManager::find(const sockaddr* peer, int peer_len) noexcept {
    Entry* e = lookup(peer, peer_len);
    return e ? e->session.get() : nullptr;
}

void DtlsSessionManager::feed(const sockaddr* peer, int peer_len,
                              const std::uint8_t* data, std::size_t len) noexcept {
    if (!ctx_ || !transport_ || !peer || peer_len <= 0) return;
    if (static_cast<std::size_t>(peer_len) > sizeof(sockaddr_storage)) return;

    Entry* e = lookup(peer, peer_len);
    if (!e) {
        // First DTLS record from this peer: create a session (the ClientHello).
        if (count_ >= kMaxPeers) return;  // bounded; drop overflow peers
        for (std::size_t i = 0; i < kMaxPeers; ++i) {
            if (!entries_[i].used) { e = &entries_[i]; break; }
        }
        if (!e) return;
        e->used = true;
        std::memcpy(&e->addr, peer, static_cast<std::size_t>(peer_len));
        e->addr_len = peer_len;
        e->session = std::make_unique<DtlsSession>(*ctx_, *transport_, peer,
                                                   peer_len);
        if (!offer_fingerprint_.empty()) {
            e->session->set_expected_fingerprint(offer_fingerprint_);
        }
        ++count_;
    }
    if (e->session) {
        e->session->feed(data, len);
    }
}

}  // namespace webrtc
}  // namespace bolt::api
