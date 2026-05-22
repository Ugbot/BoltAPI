/**
 * TLS Context with ALPN Support
 *
 * Pure C++ OpenSSL wrapper for Bolt API
 *
 * Features:
 * - ALPN (Application-Layer Protocol Negotiation)
 * - File-based and memory-based certificates
 * - Thread-safe reference counting
 * - Server and client modes
 * - Protocol negotiation callback
 *
 * Used for HTTPS with automatic HTTP/2 vs HTTP/1.1 selection
 */

#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace bolt::api {
namespace net {

/**
 * TLS Context Configuration
 */
struct TlsContextConfig {
    // Certificate configuration
    std::string cert_file;           // Path to certificate file
    std::string key_file;            // Path to private key file
    std::string cert_data;           // In-memory certificate (PEM format)
    std::string key_data;            // In-memory private key (PEM format)

    // ALPN configuration
    std::vector<std::string> alpn_protocols;  // e.g., ["h2", "http/1.1"]

    // TLS version
    bool allow_tlsv12 = true;        // Allow TLS 1.2
    bool allow_tlsv13 = true;        // Allow TLS 1.3

    // Cipher suites (empty = OpenSSL defaults)
    std::string cipher_list;         // TLS 1.2 ciphers
    std::string cipher_suites;       // TLS 1.3 ciphersuites

    // Client verification (server mode)
    bool verify_client = false;      // Require client certificate
    std::string ca_file;             // CA certificate file for client verification

    TlsContextConfig() = default;
};

/**
 * TLS Context (wraps SSL_CTX*)
 *
 * Thread-safe wrapper around OpenSSL SSL_CTX with ALPN support.
 * Manages lifecycle and provides factory methods for server/client contexts.
 */
class TlsContext {
public:
    /**
     * Create server TLS context from configuration
     *
     * Supports both file-based and memory-based certificates.
     * ALPN protocols are configured automatically if provided.
     *
     * @param config TLS configuration
     * @return Shared pointer to TLS context, or nullptr on error
     */
    static std::shared_ptr<TlsContext> create_server(const TlsContextConfig& config);

    /**
     * Create client TLS context
     *
     * @param alpn_protocols Optional ALPN protocols to advertise
     * @return Shared pointer to TLS context, or nullptr on error
     */
    static std::shared_ptr<TlsContext> create_client(
        const std::vector<std::string>& alpn_protocols = {}
    );

    /**
     * Destructor - cleans up SSL_CTX
     */
    ~TlsContext();

    /**
     * Get raw SSL_CTX pointer (for OpenSSL API calls)
     */
    SSL_CTX* get_ssl_ctx() const noexcept {
        return ctx_;
    }

    /**
     * Get ALPN protocols configured
     */
    const std::vector<std::string>& get_alpn_protocols() const noexcept {
        return alpn_protocols_;
    }

    /**
     * Check if context is valid
     */
    bool is_valid() const noexcept {
        return ctx_ != nullptr;
    }

    /**
     * Get last error message
     */
    const std::string& get_error() const noexcept {
        return error_message_;
    }

private:
    /**
     * Private constructor - use factory methods
     */
    TlsContext() = default;

    /**
     * Initialize OpenSSL library (called once)
     */
    static void init_openssl();

    /**
     * Load certificate from file
     *
     * @param ctx SSL context
     * @param cert_file Certificate file path
     * @return true on success
     */
    bool load_cert_file(SSL_CTX* ctx, const std::string& cert_file);

    /**
     * Load private key from file
     *
     * @param ctx SSL context
     * @param key_file Private key file path
     * @return true on success
     */
    bool load_key_file(SSL_CTX* ctx, const std::string& key_file);

    /**
     * Load certificate from memory (PEM format)
     *
     * @param ctx SSL context
     * @param cert_data Certificate data (PEM)
     * @return true on success
     */
    bool load_cert_mem(SSL_CTX* ctx, const std::string& cert_data);

    /**
     * Load private key from memory (PEM format)
     *
     * @param ctx SSL context
     * @param key_data Private key data (PEM)
     * @return true on success
     */
    bool load_key_mem(SSL_CTX* ctx, const std::string& key_data);

    /**
     * Configure ALPN for server
     *
     * Sets up ALPN selection callback to negotiate protocol during handshake.
     *
     * @param ctx SSL context
     * @param protocols ALPN protocols to advertise
     * @return true on success
     */
    bool configure_alpn_server(SSL_CTX* ctx, const std::vector<std::string>& protocols);

    /**
     * Configure ALPN for client
     *
     * Sets up ALPN protocol list for client advertisement.
     *
     * @param ctx SSL context
     * @param protocols ALPN protocols to advertise
     * @return true on success
     */
    bool configure_alpn_client(SSL_CTX* ctx, const std::vector<std::string>& protocols);

    /**
     * ALPN selection callback (server side)
     *
     * Called during TLS handshake to select protocol from client's list.
     *
     * @param ssl SSL connection
     * @param out Selected protocol (output)
     * @param outlen Length of selected protocol (output)
     * @param in Client's protocol list
     * @param inlen Length of client's list
     * @param arg User data (TlsContext*)
     * @return SSL_TLSEXT_ERR_OK on success
     */
    static int alpn_select_callback(
        SSL* ssl,
        const unsigned char** out,
        unsigned char* outlen,
        const unsigned char* in,
        unsigned int inlen,
        void* arg
    );

    /**
     * Get OpenSSL error string
     */
    static std::string get_openssl_error();

    SSL_CTX* ctx_ = nullptr;
    std::vector<std::string> alpn_protocols_;
    std::string error_message_;

    // ALPN wire format (length-prefixed strings)
    // e.g., "\x02h2\x08http/1.1"
    std::vector<unsigned char> alpn_wire_format_;
};

} // namespace net
} // namespace bolt::api
