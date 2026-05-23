// boltapi/webrtc/dtls.h — WebRTC DTLS (server / answerer role) over the shared
// UDP datagram transport, driven by OpenSSL memory BIOs.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// Bolt is the WebRTC ANSWERER, so it is the DTLS SERVER (a=setup:passive). The
// browser (offerer) is the DTLS client. We do NOT let OpenSSL own a socket: the
// single UDP socket is owned by net::UdpTransport and shared with ICE/STUN, so
// DTLS runs over OpenSSL MEMORY BIOs:
//
//   feed(datagram) -> BIO_write(rbio)         (incoming records into OpenSSL)
//                  -> SSL_do_handshake()/SSL_read()  (drive the state machine)
//                  -> drain wbio with BIO_read -> UdpTransport::send(peer, ...)
//                     (outgoing records back over the ICE-selected 4-tuple)
//
// Two objects:
//   * DtlsContext (shared, one per App): an SSL_CTX with DTLS_server_method(),
//     a self-signed ECDSA P-256 (RSA fallback) cert + key generated once at
//     startup, and SSL_VERIFY_PEER with a PERMISSIVE verify callback (WebRTC
//     accepts any cert and binds identity by FINGERPRINT, not by a CA chain).
//     It exposes our cert's SHA-256 fingerprint as "AA:BB:.." for the SDP
//     a=fingerprint line.
//   * DtlsSession (per peer): an SSL object wired to a read BIO + write BIO.
//     State machine New -> Handshaking -> Established / Failed. On established,
//     the peer cert's SHA-256 fingerprint is compared to the fingerprint from
//     the SDP offer (the WebRTC identity binding) — mismatch => Failed.
//
// A DtlsSessionManager keys sessions by peer sockaddr (bolt::SwissTable) and is
// what UdpTransport's datagram handler (first byte 20..63) dispatches to. The
// manager creates a session on the first DTLS record from a peer (the
// ClientHello), so the server side is purely reactive (it never speaks first).
//
// After the handshake, application data flows through send_app()/read_app()
// (SSL_write/SSL_read over the BIOs). That is the byte channel SCTP will run on
// in the next wave. (DTLS-SRTP keying-material export is media/later — TODO.)
//
// CRYPTO STOPGAP: per docs/WEBRTC_PLAN.md §6, OpenSSL is the justified crypto
// provider for DTLS (reimplementing X.509/ECDHE/AEAD is out of scope and a
// security footgun). The transport, demux and framing around it stay Bolt-native.
//
// Compiled UNCONDITIONALLY into boltapi (OpenSSL is always linked); only the App
// wiring that starts a DtlsContext/manager is gated behind BOLTAPI_WITH_WEBRTC.
//
// TigerStyle: bounded scratch, no exceptions, explicit teardown (free SSL / BIO
// / CTX), noexcept on the hot paths.

#pragma once

#include "boltapi/net/sys_compat.h"
#include "boltapi/webrtc/srtp.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace bolt::api {
namespace net { class UdpTransport; }
namespace webrtc {

// ----------------------------------------------------------------------------
// DTLS-SRTP keying (RFC 5764). After the DTLS handshake completes, the peers
// agree on an SRTP protection profile (via the use_srtp extension) and derive
// SRTP master key+salt material with SSL_export_keying_material. The 60-byte
// (CM) / 56-byte (GCM) keying block carries, in order:
//   client_write_master_key | server_write_master_key |
//   client_write_master_salt | server_write_master_salt
// As the DTLS SERVER (answerer), our OUTBOUND SRTP uses the server-write keys
// and our INBOUND SRTP uses the client-write keys (reversed for a client role).
// ----------------------------------------------------------------------------

// The two profiles Bolt advertises (RFC 5764 §4.1.2 profile IDs). Mirrors the
// SRTP crypto Profile so a SrtpKeying can build a srtp::SrtpSession directly.
enum class SrtpProfileId : std::uint8_t {
    kNone                = 0,
    kAesCm128HmacSha1_80 = 1,  // SRTP_AES128_CM_SHA1_80  (0x0001)
    kAeadAes128Gcm       = 2,  // SRTP_AEAD_AES_128_GCM   (0x0007)
};

// Per-profile master key + salt lengths (RFC 3711 / RFC 7714). CM uses a 16-byte
// key + 14-byte salt; GCM uses a 16-byte key + 12-byte salt.
inline constexpr std::size_t kSrtpMasterKeyLen = 16;     // both profiles
inline constexpr std::size_t kSrtpSaltLenCm    = 14;     // RFC 3711
inline constexpr std::size_t kSrtpSaltLenGcm   = 12;     // RFC 7714 §8.1
// Bound on the exported keying block = 2 keys + 2 (CM) salts (the larger case).
inline constexpr std::size_t kSrtpKeyingMax =
    2 * kSrtpMasterKeyLen + 2 * kSrtpSaltLenCm;  // 60 bytes

inline constexpr std::size_t srtp_salt_len(SrtpProfileId p) noexcept {
    return p == SrtpProfileId::kAeadAes128Gcm ? kSrtpSaltLenGcm : kSrtpSaltLenCm;
}

// SrtpKeying — the negotiated profile + the two master key/salt pairs split out
// of the exported keying block. Fixed-size buffers (no heap). build_sessions()
// turns it into a ready inbound + outbound srtp::SrtpSession with the correct
// role mapping for the DTLS server.
struct SrtpKeying {
    SrtpProfileId profile   = SrtpProfileId::kNone;
    bool          is_server = true;  // our DTLS role (server = answerer)

    std::uint8_t client_key[kSrtpMasterKeyLen]{};
    std::uint8_t server_key[kSrtpMasterKeyLen]{};
    std::uint8_t client_salt[kSrtpSaltLenCm]{};  // up to 14 bytes used
    std::uint8_t server_salt[kSrtpSaltLenCm]{};

    bool valid() const noexcept { return profile != SrtpProfileId::kNone; }

    // Map the DTLS-SRTP profile to the SRTP crypto Profile.
    srtp::Profile crypto_profile() const noexcept {
        assert(profile != SrtpProfileId::kNone && "crypto_profile: no profile");
        assert(static_cast<int>(profile) <= 2 && "crypto_profile: bad id");
        return profile == SrtpProfileId::kAeadAes128Gcm
                   ? srtp::Profile::kAeadAes128Gcm
                   : srtp::Profile::kAesCm128HmacSha1_80;
    }

    // Build the inbound + outbound SRTP sessions with role-correct key mapping.
    // server (our role): outbound = server-write keys; inbound = client-write.
    // client role: reversed. Returns false if not valid or a session init fails.
    bool build_sessions(srtp::SrtpSession& inbound,
                        srtp::SrtpSession& outbound) const noexcept;
};

// ----------------------------------------------------------------------------
// Bounds (TigerStyle). A DTLS record is bounded by the UDP MTU; the wbio drain
// scratch generously covers a full flight. SHA-256 fingerprint text is fixed:
// 32 bytes -> "AA:" * 31 + "AA" = 95 chars.
// ----------------------------------------------------------------------------
inline constexpr std::size_t kDtlsDrainBuf       = 4096;  // wbio drain scratch
inline constexpr std::size_t kDtlsFingerprintLen = 95;    // "AA:..AA" SHA-256

// ----------------------------------------------------------------------------
// DtlsContext — the shared SSL_CTX (DTLS_server_method) + our self-signed cert.
//
// Build once at startup with create(). Holds the cert/key for the lifetime of
// the App; new_ssl() mints a per-peer SSL object that DtlsSession wraps. The
// SHA-256 fingerprint of our cert (DER) is computed once and exposed for the
// SDP a=fingerprint line.
// ----------------------------------------------------------------------------
class DtlsContext {
public:
    DtlsContext() = default;
    ~DtlsContext();

    DtlsContext(const DtlsContext&) = delete;
    DtlsContext& operator=(const DtlsContext&) = delete;

    // Build the SSL_CTX (DTLS_server_method) + a fresh self-signed ECDSA P-256
    // certificate (RSA-2048 fallback if EC keygen fails) and compute our SHA-256
    // fingerprint. Returns nullptr on any OpenSSL failure (no throw).
    static std::unique_ptr<DtlsContext> create();

    bool is_valid() const noexcept { return ctx_ != nullptr; }

    // Our cert's SHA-256 fingerprint as uppercase hex "AA:BB:..:ZZ" (no algo
    // prefix). Goes into the SDP "a=fingerprint:sha-256 <this>" line.
    const std::string& fingerprint() const noexcept { return fingerprint_; }

    SSL_CTX* native_ctx() const noexcept { return ctx_; }

    // Mint a server-role SSL object on this context (caller owns; DtlsSession
    // frees it). Returns nullptr on failure.
    SSL* new_ssl() const noexcept;

private:
    SSL_CTX*    ctx_ = nullptr;
    std::string fingerprint_;
};

// ----------------------------------------------------------------------------
// Compute the SHA-256 fingerprint of an X509 cert (DER) as "AA:BB:..". Used for
// both our cert (in DtlsContext::create) and the peer cert (verification).
// Writes into `out` (cleared first). Returns false on error.
// ----------------------------------------------------------------------------
bool x509_sha256_fingerprint(X509* cert, std::string& out) noexcept;

// Case-insensitive compare of two "AA:BB:.." fingerprint strings, tolerating an
// optional "sha-256 " algorithm prefix and surrounding whitespace on either side
// (the SDP a=fingerprint value carries the algorithm token).
bool fingerprints_equal(std::string_view a, std::string_view b) noexcept;

// ----------------------------------------------------------------------------
// DtlsSession — one peer's DTLS connection over memory BIOs.
// ----------------------------------------------------------------------------
class DtlsSession {
public:
    enum class State : std::uint8_t {
        New,          // created, no records fed yet
        Handshaking,  // SSL_do_handshake in progress (WANT_READ/WANT_WRITE)
        Established,   // handshake complete AND fingerprint verified
        Failed,       // handshake error or fingerprint mismatch
    };

    // Construct a server-role session on `ctx` for peer `addr`. `transport` is
    // borrowed (not owned) — used to send outgoing records back to the peer.
    DtlsSession(const DtlsContext& ctx, net::UdpTransport& transport,
                const sockaddr* addr, int addr_len) noexcept;
    ~DtlsSession();

    DtlsSession(const DtlsSession&) = delete;
    DtlsSession& operator=(const DtlsSession&) = delete;

    bool is_valid() const noexcept { return ssl_ != nullptr; }
    State state() const noexcept { return state_; }
    bool established() const noexcept { return state_ == State::Established; }

    // Set the expected peer fingerprint taken from the SDP offer's
    // a=fingerprint. When non-empty, the handshake is only promoted to
    // Established if the peer cert's SHA-256 matches. When empty, fingerprint
    // verification is SKIPPED (the handshake alone establishes the channel) —
    // tests that drive a raw OpenSSL client without an SDP exchange use this.
    void set_expected_fingerprint(std::string_view fp);

    // Feed one inbound DTLS datagram (a record or coalesced records). Writes it
    // into the read BIO, drives the handshake (if not yet established) or leaves
    // it for read_app(), then flushes any pending outgoing records to the peer
    // via the transport. Returns true unless the session has Failed. noexcept.
    bool feed(const std::uint8_t* data, std::size_t len) noexcept;

    // After Established: queue application bytes (SSL_write) and flush the
    // resulting record(s) to the peer. Returns bytes accepted, or -1 on error.
    int send_app(const std::uint8_t* data, std::size_t len) noexcept;

    // After Established: read decrypted application bytes already buffered from
    // prior feed() calls (SSL_read). Returns bytes read, 0 if none pending, -1
    // on error. Does not block.
    int read_app(std::uint8_t* out, std::size_t cap) noexcept;

    // The peer's cert SHA-256 fingerprint, valid once Established (empty before).
    const std::string& peer_fingerprint() const noexcept { return peer_fingerprint_; }

    // ---- DTLS-SRTP keying (RFC 5764) -------------------------------------
    // After Established: read the negotiated SRTP profile and export the keying
    // material (SSL_export_keying_material, label "EXTRACTOR-dtls_srtp", empty
    // context), splitting it into client/server master key+salt for `out`.
    // Returns false if not Established, no profile was negotiated, or the export
    // failed. `out` is fully overwritten on success. noexcept, bounded scratch.
    bool export_srtp_keying(SrtpKeying& out) const noexcept;

    // Convenience: export + build_sessions in one step. False on any failure.
    bool make_srtp_sessions(srtp::SrtpSession& inbound,
                            srtp::SrtpSession& outbound) const noexcept;

    // Counters (observability).
    std::uint64_t records_in()  const noexcept { return records_in_; }
    std::uint64_t records_out() const noexcept { return records_out_; }

private:
    // Push everything pending in the write BIO out to the peer as datagrams.
    void flush_wbio() noexcept;
    // Drive SSL_do_handshake one step; manage state transitions + fingerprint
    // verification on completion.
    void pump_handshake() noexcept;
    // On handshake completion: pull the peer cert, compute its fingerprint, and
    // (if an expected fingerprint was set) verify the binding.
    void verify_peer() noexcept;

    net::UdpTransport* transport_ = nullptr;  // borrowed
    SSL*               ssl_  = nullptr;       // owned
    BIO*               rbio_ = nullptr;       // read BIO (we BIO_write into it)
    BIO*               wbio_ = nullptr;       // write BIO (we BIO_read out of it)
    // NOTE: SSL_set_bio takes ownership of the BIOs; we do NOT free them.

    sockaddr_storage   peer_{};
    int                peer_len_ = 0;

    State              state_ = State::New;
    std::string        expected_fingerprint_;  // from the SDP offer (may be empty)
    std::string        peer_fingerprint_;      // computed at handshake completion

    std::uint64_t      records_in_  = 0;
    std::uint64_t      records_out_ = 0;
};

// ----------------------------------------------------------------------------
// DtlsSessionManager — per-peer session map keyed by sockaddr.
//
// UdpTransport's datagram handler (first byte 20..63 -> DTLS) calls feed(); the
// manager looks up (or, on the first record from a peer, creates) the session
// and feeds the datagram into it. The expected peer fingerprint (from the SDP
// offer) is applied to newly created sessions.
// ----------------------------------------------------------------------------
class DtlsSessionManager {
public:
    DtlsSessionManager(const DtlsContext& ctx,
                       net::UdpTransport& transport) noexcept
        : ctx_(&ctx), transport_(&transport) {}
    ~DtlsSessionManager() = default;

    DtlsSessionManager(const DtlsSessionManager&) = delete;
    DtlsSessionManager& operator=(const DtlsSessionManager&) = delete;

    // Set the fingerprint (from the SDP offer's a=fingerprint) that newly
    // created sessions must verify the peer cert against. Empty => no
    // verification (handshake alone establishes).
    void set_offer_fingerprint(std::string_view fp) { offer_fingerprint_ = std::string(fp); }

    // Dispatch one inbound DTLS datagram from `peer` to its session, creating
    // the session on first contact. noexcept; safe on malformed input.
    void feed(const sockaddr* peer, int peer_len, const std::uint8_t* data,
              std::size_t len) noexcept;

    // Look up an existing session for a peer (nullptr if none). For tests /
    // App introspection.
    DtlsSession* find(const sockaddr* peer, int peer_len) noexcept;

    std::size_t session_count() const noexcept { return count_; }

private:
    // Bounded peer table (TigerStyle). Data channels are 1:few peers per App in
    // v1; a small fixed table keyed by 4-tuple is cheap and avoids per-packet
    // hashing churn. SwissTable is the perf-phase upgrade (WEBRTC_PLAN §11).
    static constexpr std::size_t kMaxPeers = 64;

    struct Entry {
        sockaddr_storage             addr{};
        int                          addr_len = 0;
        bool                         used = false;
        std::unique_ptr<DtlsSession> session;
    };

    Entry* lookup(const sockaddr* peer, int peer_len) noexcept;

    const DtlsContext* ctx_       = nullptr;  // borrowed
    net::UdpTransport* transport_ = nullptr;  // borrowed
    std::string        offer_fingerprint_;

    Entry       entries_[kMaxPeers]{};
    std::size_t count_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
