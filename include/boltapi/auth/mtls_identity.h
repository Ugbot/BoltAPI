// boltapi/auth/mtls_identity.h — extract subject identity from a TLS peer cert.
//
// Given an `SSL*` that completed a handshake with client-cert auth, surface
// the peer's certificate subject CN plus any DNS / URI SANs in a small
// caller-owned struct.
//
// Exception-free, no heap. The strings point into a caller-provided scratch
// buffer (`out_buf`) so the result has a clear lifetime.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

// Forward-declare to avoid pulling all of openssl/ssl.h into every consumer.
typedef struct ssl_st SSL;

namespace bolt::api::auth::mtls_identity {

inline constexpr size_t kMaxSans = 16;

struct Identity {
    bool             present = false;        // true iff a peer cert exists
    std::string_view subject_cn;             // "CN=" RDN; empty if absent
    std::string_view subject_dn;             // full DN as one line (RFC 2253 shape)
    std::string_view sans[kMaxSans];         // DNS / URI SANs, in order
    size_t           n_sans = 0;
    bool             chain_verified = false; // SSL_get_verify_result() == X509_V_OK
};

// Extract the peer cert's identity into `out`, with strings pointing into
// `out_buf`. Returns true on success (regardless of whether a cert is
// present — check `out->present`). Returns false only on argument errors.
bool extract(SSL* ssl, Identity* out,
             char* out_buf, size_t out_buf_cap) noexcept;

}  // namespace bolt::api::auth::mtls_identity
