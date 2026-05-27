// boltapi/http/tls_client.h — synchronous TLS-capable outbound HTTP/1.1 client.
//
// This is the control-plane companion to bolt::api::http::Client (cleartext,
// async, coroutine). TlsClient is deliberately SYNCHRONOUS and runs on the
// caller's thread — it exists for low-rate outbound calls from gateway
// handlers (OIDC discovery / JWKS / token endpoint) where:
//   * the call shape is "one request, one response, then go home"
//   * we want hostname verification + system trust store + ALPN
//   * we don't want to thread async TLS state through the coroutine dispatcher
//
// Both http:// and https:// URLs are accepted. cleartext rides a plain socket;
// TLS rides OpenSSL on top.
//
// Tiger Style: bounded everything (10 s I/O timeout, 1 MiB response cap),
// noexcept on failure, no exceptions across the boundary.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api::http {

inline constexpr std::size_t kTlsClientMaxRespBytes  = 1u << 20;   // 1 MiB
inline constexpr int         kTlsClientTimeoutMs     = 10 * 1000;  // 10 s
inline constexpr std::size_t kTlsClientMaxExtraHdrs  = 16;

struct TlsExtraHeader {
    std::string_view name;
    std::string_view value;
};

struct TlsClientRequest {
    std::string_view url;                   // http(s)://host[:port]/path?...
    std::string_view method = "GET";
    std::string_view body   = {};
    std::string_view content_type = "application/x-www-form-urlencoded";
    const TlsExtraHeader* extra_headers = nullptr;
    std::size_t           extra_count   = 0;
};

struct TlsClientResponseHeader {
    std::string name;
    std::string value;
};

struct TlsClientResponse {
    bool        ok           = false;
    int         status       = 0;
    std::string body;
    std::vector<TlsClientResponseHeader> headers;
    std::string error;   // empty on success; human-readable on failure.

    // Case-insensitive header lookup; returns "" when absent.
    std::string_view header(std::string_view name) const noexcept;
};

class TlsClient {
public:
    struct Config {
        // Optional path to a CA bundle file (PEM); when empty, fall back to
        // the OpenSSL default verify paths (system trust store). On startup
        // we additionally honour GESTALT_CA_BUNDLE if it's set in the
        // environment.
        std::string ca_bundle_path;
        // When true, skip certificate verification. ONLY for local-dev /
        // tests against a self-signed mock IdP. NEVER in production.
        bool insecure_skip_verify = false;
        // I/O timeout in milliseconds, applied to connect/read/write.
        int timeout_ms = kTlsClientTimeoutMs;
    };

    TlsClient() noexcept;
    explicit TlsClient(Config cfg) noexcept;
    ~TlsClient() noexcept;

    TlsClient(const TlsClient&)            = delete;
    TlsClient& operator=(const TlsClient&) = delete;

    // Issue one request. Never throws; on failure `resp.ok == false` and
    // `resp.error` is set.
    TlsClientResponse send(const TlsClientRequest& req) noexcept;

private:
    Config cfg_;
    void*  tls_ctx_ = nullptr;   // SSL_CTX*; lazily built on first https://
    bool   inited_  = false;     // OpenSSL global init done

    void ensure_tls_ctx_() noexcept;
};

// URL parser (exposed for tests). Returns false on malformed input.
// Defaults: port = 80 (http) / 443 (https); path = "/".
struct ParsedUrl {
    bool        is_tls = false;
    std::string host;
    uint16_t    port = 0;
    std::string path_and_query;   // starts with '/'
};
bool parse_url(std::string_view url, ParsedUrl* out) noexcept;

}  // namespace bolt::api::http
