/**
 * TLS Context Implementation
 *
 * OpenSSL-based TLS with ALPN support for protocol negotiation
 */

#include "boltapi/net/tls_context.h"
#include <cstring>
#include <atomic>

namespace bolt::api {
namespace net {

// OpenSSL initialization (once per process)
static std::atomic<bool> openssl_initialized{false};

void TlsContext::init_openssl() {
    bool expected = false;
    if (openssl_initialized.compare_exchange_strong(expected, true)) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
}

std::string TlsContext::get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

std::shared_ptr<TlsContext> TlsContext::create_server(const TlsContextConfig& config) {
    init_openssl();

    auto ctx = std::shared_ptr<TlsContext>(new TlsContext());

    // Create SSL context for server
    ctx->ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx->ctx_) {
        ctx->error_message_ = "Failed to create SSL_CTX: " + get_openssl_error();
        return nullptr;
    }

    // Set TLS version options
    int options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    if (!config.allow_tlsv12) {
        options |= SSL_OP_NO_TLSv1_2;
    }
    // TLS 1.3 is always allowed unless explicitly disabled
    SSL_CTX_set_options(ctx->ctx_, options);

    // Set minimum TLS version
    if (!SSL_CTX_set_min_proto_version(ctx->ctx_, TLS1_2_VERSION)) {
        ctx->error_message_ = "Failed to set min TLS version";
        return nullptr;
    }

    // Load certificate (file or memory)
    if (!config.cert_file.empty()) {
        if (!ctx->load_cert_file(ctx->ctx_, config.cert_file)) {
            return nullptr;
        }
    } else if (!config.cert_data.empty()) {
        if (!ctx->load_cert_mem(ctx->ctx_, config.cert_data)) {
            return nullptr;
        }
    } else {
        ctx->error_message_ = "No certificate provided (cert_file or cert_data)";
        return nullptr;
    }

    // Load private key (file or memory)
    if (!config.key_file.empty()) {
        if (!ctx->load_key_file(ctx->ctx_, config.key_file)) {
            return nullptr;
        }
    } else if (!config.key_data.empty()) {
        if (!ctx->load_key_mem(ctx->ctx_, config.key_data)) {
            return nullptr;
        }
    } else {
        ctx->error_message_ = "No private key provided (key_file or key_data)";
        return nullptr;
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx->ctx_)) {
        ctx->error_message_ = "Private key does not match certificate: " + get_openssl_error();
        return nullptr;
    }

    // Configure cipher suites
    if (!config.cipher_list.empty()) {
        if (!SSL_CTX_set_cipher_list(ctx->ctx_, config.cipher_list.c_str())) {
            ctx->error_message_ = "Failed to set cipher list: " + get_openssl_error();
            return nullptr;
        }
    }

    if (!config.cipher_suites.empty()) {
        if (!SSL_CTX_set_ciphersuites(ctx->ctx_, config.cipher_suites.c_str())) {
            ctx->error_message_ = "Failed to set TLS 1.3 ciphersuites: " + get_openssl_error();
            return nullptr;
        }
    }

    // Configure client verification (optional)
    if (config.verify_client) {
        SSL_CTX_set_verify(ctx->ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

        if (!config.ca_file.empty()) {
            if (!SSL_CTX_load_verify_locations(ctx->ctx_, config.ca_file.c_str(), nullptr)) {
                ctx->error_message_ = "Failed to load CA file: " + get_openssl_error();
                return nullptr;
            }
        }
    }

    // Configure ALPN (if protocols specified)
    if (!config.alpn_protocols.empty()) {
        if (!ctx->configure_alpn_server(ctx->ctx_, config.alpn_protocols)) {
            return nullptr;
        }
        ctx->alpn_protocols_ = config.alpn_protocols;
    }

    return ctx;
}

std::shared_ptr<TlsContext> TlsContext::create_client(
    const std::vector<std::string>& alpn_protocols
) {
    init_openssl();

    auto ctx = std::shared_ptr<TlsContext>(new TlsContext());

    // Create SSL context for client
    ctx->ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx->ctx_) {
        ctx->error_message_ = "Failed to create SSL_CTX: " + get_openssl_error();
        return nullptr;
    }

    // Set TLS options
    SSL_CTX_set_options(ctx->ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Set default verify paths
    if (!SSL_CTX_set_default_verify_paths(ctx->ctx_)) {
        ctx->error_message_ = "Failed to set default verify paths: " + get_openssl_error();
        return nullptr;
    }

    // Configure ALPN (if protocols specified)
    if (!alpn_protocols.empty()) {
        if (!ctx->configure_alpn_client(ctx->ctx_, alpn_protocols)) {
            return nullptr;
        }
        ctx->alpn_protocols_ = alpn_protocols;
    }

    return ctx;
}

TlsContext::~TlsContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

bool TlsContext::load_cert_file(SSL_CTX* ctx, const std::string& cert_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        error_message_ = "Failed to load certificate file '" + cert_file + "': " + get_openssl_error();
        return false;
    }
    return true;
}

bool TlsContext::load_key_file(SSL_CTX* ctx, const std::string& key_file) {
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        error_message_ = "Failed to load private key file '" + key_file + "': " + get_openssl_error();
        return false;
    }
    return true;
}

bool TlsContext::load_cert_mem(SSL_CTX* ctx, const std::string& cert_data) {
    BIO* bio = BIO_new_mem_buf(cert_data.data(), cert_data.size());
    if (!bio) {
        error_message_ = "Failed to create BIO for certificate: " + get_openssl_error();
        return false;
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        error_message_ = "Failed to parse certificate from memory: " + get_openssl_error();
        return false;
    }

    int result = SSL_CTX_use_certificate(ctx, cert);
    X509_free(cert);

    if (result != 1) {
        error_message_ = "Failed to use certificate: " + get_openssl_error();
        return false;
    }

    return true;
}

bool TlsContext::load_key_mem(SSL_CTX* ctx, const std::string& key_data) {
    BIO* bio = BIO_new_mem_buf(key_data.data(), key_data.size());
    if (!bio) {
        error_message_ = "Failed to create BIO for private key: " + get_openssl_error();
        return false;
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!key) {
        error_message_ = "Failed to parse private key from memory: " + get_openssl_error();
        return false;
    }

    int result = SSL_CTX_use_PrivateKey(ctx, key);
    EVP_PKEY_free(key);

    if (result != 1) {
        error_message_ = "Failed to use private key: " + get_openssl_error();
        return false;
    }

    return true;
}

bool TlsContext::configure_alpn_server(SSL_CTX* ctx, const std::vector<std::string>& protocols) {
    // Build ALPN wire format (length-prefixed strings)
    // e.g., ["h2", "http/1.1"] -> "\x02h2\x08http/1.1"
    alpn_wire_format_.clear();

    for (const auto& protocol : protocols) {
        if (protocol.empty() || protocol.size() > 255) {
            error_message_ = "Invalid ALPN protocol: '" + protocol + "'";
            return false;
        }

        // Add length byte
        alpn_wire_format_.push_back(static_cast<unsigned char>(protocol.size()));

        // Add protocol string
        alpn_wire_format_.insert(
            alpn_wire_format_.end(),
            protocol.begin(),
            protocol.end()
        );
    }

    // Set ALPN selection callback
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, this);

    return true;
}

bool TlsContext::configure_alpn_client(SSL_CTX* ctx, const std::vector<std::string>& protocols) {
    // Build ALPN wire format (length-prefixed strings)
    alpn_wire_format_.clear();

    for (const auto& protocol : protocols) {
        if (protocol.empty() || protocol.size() > 255) {
            error_message_ = "Invalid ALPN protocol: '" + protocol + "'";
            return false;
        }

        alpn_wire_format_.push_back(static_cast<unsigned char>(protocol.size()));
        alpn_wire_format_.insert(
            alpn_wire_format_.end(),
            protocol.begin(),
            protocol.end()
        );
    }

    // Set ALPN protocols for client
    if (SSL_CTX_set_alpn_protos(ctx, alpn_wire_format_.data(), alpn_wire_format_.size()) != 0) {
        error_message_ = "Failed to set ALPN protocols: " + get_openssl_error();
        return false;
    }

    return true;
}

int TlsContext::alpn_select_callback(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg
) {
    TlsContext* ctx = static_cast<TlsContext*>(arg);

    // Use SSL_select_next_proto to find first matching protocol
    // This prefers server's protocol order
    int result = SSL_select_next_proto(
        (unsigned char**)out,
        outlen,
        ctx->alpn_wire_format_.data(),
        ctx->alpn_wire_format_.size(),
        in,
        inlen
    );

    if (result == OPENSSL_NPN_NEGOTIATED) {
        // Successfully negotiated a protocol
        return SSL_TLSEXT_ERR_OK;
    }

    // No match - fall back to first server protocol if available
    if (!ctx->alpn_wire_format_.empty()) {
        *outlen = ctx->alpn_wire_format_[0];
        *out = &ctx->alpn_wire_format_[1];
        return SSL_TLSEXT_ERR_OK;
    }

    // No protocols available
    return SSL_TLSEXT_ERR_NOACK;
}

} // namespace net
} // namespace bolt::api
