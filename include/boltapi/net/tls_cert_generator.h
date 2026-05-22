/**
 * TLS Certificate Generator
 *
 * Generates self-signed certificates for development/testing
 *
 * Features:
 * - Auto-generate self-signed certificates using OpenSSL
 * - Returns certificates in PEM format (memory)
 * - Configurable common name, validity period
 * - No file I/O - purely in-memory
 *
 * Use for local development when proper certificates aren't available.
 * NOT for production use.
 */

#pragma once

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <string>
#include <memory>

namespace bolt::api {
namespace net {

/**
 * Certificate generator configuration
 */
struct CertGeneratorConfig {
    std::string common_name = "localhost";     // CN field
    std::string country = "US";                // C field
    std::string organization = "Bolt API";    // O field
    int validity_days = 365;                   // Certificate validity
    int key_bits = 2048;                       // RSA key size

    CertGeneratorConfig() = default;
};

/**
 * Generated certificate pair
 */
struct GeneratedCertificate {
    std::string cert_pem;    // Certificate in PEM format
    std::string key_pem;     // Private key in PEM format
    bool success = false;    // Generation succeeded
    std::string error;       // Error message if failed
};

/**
 * TLS Certificate Generator
 *
 * Generates self-signed X.509 certificates using OpenSSL.
 * Thread-safe (each call creates independent OpenSSL objects).
 */
class TlsCertGenerator {
public:
    /**
     * Generate self-signed certificate
     *
     * Creates RSA key pair and self-signed X.509 certificate.
     * Returns both in PEM format for use with TlsContext.
     *
     * @param config Certificate configuration
     * @return GeneratedCertificate with cert_pem and key_pem
     */
    static GeneratedCertificate generate(const CertGeneratorConfig& config = {});

private:
    /**
     * Create RSA key pair
     *
     * @param key_bits RSA key size
     * @return EVP_PKEY* or nullptr on error
     */
    static EVP_PKEY* create_rsa_key(int key_bits);

    /**
     * Create X.509 certificate
     *
     * @param pkey Private key
     * @param config Certificate configuration
     * @return X509* or nullptr on error
     */
    static X509* create_certificate(EVP_PKEY* pkey, const CertGeneratorConfig& config);

    /**
     * Convert EVP_PKEY to PEM string
     *
     * @param pkey Private key
     * @return PEM-encoded private key
     */
    static std::string pkey_to_pem(EVP_PKEY* pkey);

    /**
     * Convert X509 to PEM string
     *
     * @param cert Certificate
     * @return PEM-encoded certificate
     */
    static std::string cert_to_pem(X509* cert);

    /**
     * Get OpenSSL error string
     */
    static std::string get_openssl_error();
};

} // namespace net
} // namespace bolt::api
