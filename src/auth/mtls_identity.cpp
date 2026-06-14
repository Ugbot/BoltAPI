// boltapi/auth/mtls_identity.cpp — peer-cert subject + SAN extraction.

#include "boltapi/auth/mtls_identity.h"

#include <cassert>
#include <cstring>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace bolt::api::auth::mtls_identity {

namespace {

// Append `s` (n bytes) into `out_buf` starting at `cursor`. Returns the
// view into out_buf or empty_view on overflow. Advances `cursor` past the
// stored bytes (does NOT write a NUL — the view's size is the source of truth).
std::string_view append(char* out_buf, size_t cap, size_t& cursor,
                        const char* s, size_t n) noexcept {
    if (cursor + n > cap) return {};
    std::memcpy(out_buf + cursor, s, n);
    const std::string_view v(out_buf + cursor, n);
    cursor += n;
    return v;
}

}  // namespace

bool extract(SSL* ssl, Identity* out,
             char* out_buf, size_t out_buf_cap) noexcept {
    if (ssl == nullptr || out == nullptr || out_buf == nullptr) return false;
    *out = Identity{};
    if (out_buf_cap < 256) return false;

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        // Not an error — just no client cert presented.
        out->present = false;
        return true;
    }
    out->present        = true;
    out->chain_verified = (SSL_get_verify_result(ssl) == X509_V_OK);

    size_t cursor = 0;

    // Subject DN (RFC 2253 one-line shape).
    X509_NAME* nm = X509_get_subject_name(cert);
    if (nm != nullptr) {
        char dn_buf[256] = {};
        const int dn_len = X509_NAME_get_text_by_NID(nm, NID_commonName, dn_buf, sizeof(dn_buf));
        if (dn_len > 0) {
            out->subject_cn = append(out_buf, out_buf_cap, cursor, dn_buf, size_t(dn_len));
        }
        // Full DN via X509_NAME_oneline (RFC 2253-ish; good enough for matching).
        char one_line[256] = {};
        char* p = X509_NAME_oneline(nm, one_line, sizeof(one_line));
        if (p != nullptr) {
            const size_t pl = std::strlen(p);
            out->subject_dn = append(out_buf, out_buf_cap, cursor, p, pl);
        }
    }

    // SANs: DNS + URI types.
    auto* sans = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans != nullptr) {
        const int n = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < n && out->n_sans < kMaxSans; ++i) {
            const GENERAL_NAME* gn = sk_GENERAL_NAME_value(sans, i);
            if (gn == nullptr) continue;
            const ASN1_STRING* s = nullptr;
            if (gn->type == GEN_DNS) s = gn->d.dNSName;
            else if (gn->type == GEN_URI) s = gn->d.uniformResourceIdentifier;
            if (s == nullptr) continue;
            const auto* data = ASN1_STRING_get0_data(s);
            const int   len  = ASN1_STRING_length(s);
            if (data == nullptr || len <= 0) continue;
            auto v = append(out_buf, out_buf_cap, cursor,
                            reinterpret_cast<const char*>(data), size_t(len));
            if (v.empty()) break;
            out->sans[out->n_sans++] = v;
        }
        GENERAL_NAMES_free(sans);
    }

    X509_free(cert);
    return true;
}

}  // namespace bolt::api::auth::mtls_identity
