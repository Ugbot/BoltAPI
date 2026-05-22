/**
 * TLS Certificate Generator Implementation
 */

#include "boltapi/net/tls_cert_generator.h"
#include "boltapi/core/logger.h"
#include <openssl/err.h>
#include <cstring>

namespace bolt::api {
namespace net {

GeneratedCertificate TlsCertGenerator::generate(const CertGeneratorConfig& config) {
    GeneratedCertificate result;

    // Create RSA key pair
    EVP_PKEY* pkey = create_rsa_key(config.key_bits);
    if (!pkey) {
        result.error = "Failed to create RSA key: " + get_openssl_error();
        LOG_ERROR("TLS", "Certificate generation failed: %s", result.error.c_str());
        return result;
    }

    // Create X.509 certificate
    X509* cert = create_certificate(pkey, config);
    if (!cert) {
        EVP_PKEY_free(pkey);
        result.error = "Failed to create certificate: " + get_openssl_error();
        LOG_ERROR("TLS", "Certificate generation failed: %s", result.error.c_str());
        return result;
    }

    // Convert to PEM format
    result.key_pem = pkey_to_pem(pkey);
    result.cert_pem = cert_to_pem(cert);

    // Cleanup
    X509_free(cert);
    EVP_PKEY_free(pkey);

    if (result.key_pem.empty() || result.cert_pem.empty()) {
        result.error = "Failed to convert to PEM format";
        LOG_ERROR("TLS", "Certificate generation failed: %s", result.error.c_str());
        return result;
    }

    result.success = true;
    LOG_INFO("TLS", "Generated self-signed certificate (CN=%s, %d days validity)",
             config.common_name.c_str(), config.validity_days);

    return result;
}

EVP_PKEY* TlsCertGenerator::create_rsa_key(int key_bits) {
    // Create EVP_PKEY context
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        return nullptr;
    }

    // Create RSA key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // Set key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    // Generate key
    EVP_PKEY* generated_key = nullptr;
    if (EVP_PKEY_keygen(ctx, &generated_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return generated_key;
}

X509* TlsCertGenerator::create_certificate(EVP_PKEY* pkey, const CertGeneratorConfig& config) {
    // Create X509 certificate
    X509* cert = X509_new();
    if (!cert) {
        return nullptr;
    }

    // Set version (X509 v3)
    X509_set_version(cert, 2);

    // Set serial number (random)
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), config.validity_days * 24 * 3600);

    // Set public key
    X509_set_pubkey(cert, pkey);

    // Set subject name
    X509_NAME* name = X509_get_subject_name(cert);

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                (unsigned char*)config.country.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                (unsigned char*)config.organization.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (unsigned char*)config.common_name.c_str(), -1, -1, 0);

    // Self-signed: issuer = subject
    X509_set_issuer_name(cert, name);

    // Sign the certificate
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        X509_free(cert);
        return nullptr;
    }

    return cert;
}

std::string TlsCertGenerator::pkey_to_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio);
        return "";
    }

    // Read PEM data
    char* pem_data = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    std::string result(pem_data, pem_len);

    BIO_free(bio);
    return result;
}

std::string TlsCertGenerator::cert_to_pem(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }

    if (!PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return "";
    }

    // Read PEM data
    char* pem_data = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    std::string result(pem_data, pem_len);

    BIO_free(bio);
    return result;
}

std::string TlsCertGenerator::get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

} // namespace net
} // namespace bolt::api
