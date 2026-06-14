// boltapi/auth/mtls_identity gtest.
//
// Generates a self-signed X.509 in-memory, builds an SSL* with that cert
// attached as the peer (via SSL_use_certificate, which sets the local
// cert; `SSL_get_peer_certificate` returns the same object for a
// not-yet-handshaken SSL but with a real handshake it would return the
// remote's cert). To exercise the extractor without standing up two
// sockets, we use the lower-level `SSL_set0_peer_certificate`-style
// trick: install the cert as the local cert, then call extract directly
// after manually installing it as the peer cert via the SSL session.
//
// For the live two-peer mTLS path see Phase E's integration test.

#include <gtest/gtest.h>
#include <cstring>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "boltapi/auth/mtls_identity.h"

using namespace bolt::api::auth::mtls_identity;

namespace {

// Make a self-signed cert with CN=test-user + DNS SAN "example.com".
X509* make_self_signed_cert(EVP_PKEY** out_key) noexcept {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048);
    if (pkey == nullptr) return nullptr;
    X509* x = X509_new();
    if (x == nullptr) { EVP_PKEY_free(pkey); return nullptr; }
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60 * 60);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("test-user"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    // Add a DNS SAN.
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_subject_alt_name, "DNS:example.com,URI:spiffe://td/sa");
    if (ext != nullptr) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    X509_sign(x, pkey, EVP_sha256());
    *out_key = pkey;
    return x;
}

}  // namespace

TEST(MtlsIdentity, NullArgsReturnFalse) {
    Identity id;
    char buf[256];
    EXPECT_FALSE(extract(nullptr, &id, buf, sizeof(buf)));
    EXPECT_FALSE(extract(reinterpret_cast<SSL*>(0x1), nullptr, buf, sizeof(buf)));
    EXPECT_FALSE(extract(reinterpret_cast<SSL*>(0x1), &id, nullptr, sizeof(buf)));
}

TEST(MtlsIdentity, SmallScratchBufferRejected) {
    Identity id;
    char buf[64];  // < 256
    EXPECT_FALSE(extract(reinterpret_cast<SSL*>(0x1), &id, buf, sizeof(buf)));
}

TEST(MtlsIdentity, NoPeerCertReportsAbsent) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    ASSERT_NE(ctx, nullptr);
    SSL* ssl = SSL_new(ctx);
    ASSERT_NE(ssl, nullptr);
    Identity id;
    char buf[512];
    EXPECT_TRUE(extract(ssl, &id, buf, sizeof(buf)));
    EXPECT_FALSE(id.present);
    EXPECT_EQ(id.n_sans, 0u);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

TEST(MtlsIdentity, ExtractsCnAndSans) {
    // Build an SSL with our self-signed cert installed as the "local" cert,
    // then use the OpenSSL test hook to also treat it as the peer. The
    // simplest portable trick: build two SSLs and let them MITM each other
    // via BIO_new_bio_pair until they both think the other is the peer.
    // (Standard self-test pattern; bounded.)
    EVP_PKEY* key = nullptr;
    X509* cert = make_self_signed_cert(&key);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(key, nullptr);

    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    ASSERT_NE(ctx, nullptr);
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, key);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_cert_store(ctx, X509_STORE_new());  // empty store -> chain not verified
    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert);  // trust the self-sign

    SSL* server = SSL_new(ctx); ASSERT_NE(server, nullptr);
    SSL* client = SSL_new(ctx); ASSERT_NE(client, nullptr);
    BIO* sb = nullptr; BIO* cb = nullptr;
    ASSERT_EQ(1, BIO_new_bio_pair(&sb, 0, &cb, 0));
    SSL_set_bio(server, sb, sb);
    SSL_set_bio(client, cb, cb);
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);

    // Drive the handshake to completion.
    for (int i = 0; i < 32 && (SSL_is_init_finished(client) == 0 ||
                                SSL_is_init_finished(server) == 0); ++i) {
        SSL_do_handshake(client);
        SSL_do_handshake(server);
    }
    ASSERT_TRUE(SSL_is_init_finished(server));
    ASSERT_TRUE(SSL_is_init_finished(client));

    // The server's `peer` is the client (who presented the same cert).
    Identity id;
    char buf[1024];
    ASSERT_TRUE(extract(server, &id, buf, sizeof(buf)));
    EXPECT_TRUE(id.present);
    EXPECT_EQ(id.subject_cn, "test-user");
    EXPECT_NE(id.subject_dn.find("CN=test-user"), std::string_view::npos);
    ASSERT_GE(id.n_sans, 1u);
    bool saw_dns = false, saw_uri = false;
    for (size_t i = 0; i < id.n_sans; ++i) {
        if (id.sans[i] == "example.com") saw_dns = true;
        if (id.sans[i] == "spiffe://td/sa") saw_uri = true;
    }
    EXPECT_TRUE(saw_dns);
    EXPECT_TRUE(saw_uri);

    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(key);
}
