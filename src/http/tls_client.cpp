// boltapi/http/tls_client.cpp — synchronous TLS+HTTP/1.1 outbound client.
//
// See include/boltapi/http/tls_client.h for the surface.
//
// Design notes:
//   * Blocking sockets + SO_RCVTIMEO/SO_SNDTIMEO for bounded I/O. Much simpler
//     than non-blocking + select, and this client is called from the gateway
//     control plane on a worker thread, never from the inbound hot path.
//   * One SSL_CTX per TlsClient instance, reused across requests. Lazily
//     constructed on first https:// request.
//   * Hostname verification: SSL_set_tlsext_host_name (SNI) + X509_VERIFY_PARAM_set1_host.
//   * Trust roots: explicit CA bundle (cfg / env), else SSL_CTX_set_default_verify_paths.
//   * Response framing: Content-Length only (matches Client; chunked is a
//     follow-up). 1 MiB ceiling.

#include "boltapi/http/tls_client.h"
#include "boltapi/http/client.h"   // ResponseParser, serialize_request
#include "boltapi/net/sys_compat.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cassert>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace bolt::api::http {

namespace {

// One-shot OpenSSL init guard. Modern OpenSSL is auto-init on first use, but
// being explicit keeps the boot path predictable on tiny test binaries.
std::once_flag g_openssl_once;
void openssl_init_once() noexcept {
    std::call_once(g_openssl_once, []() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    });
}

bool iequals_(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

void apply_io_timeout_(int fd, int timeout_ms) noexcept {
    assert(fd >= 0);
    assert(timeout_ms > 0);
#ifdef _WIN32
    DWORD t = static_cast<DWORD>(timeout_ms);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&t), sizeof(t));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&t), sizeof(t));
#else
    struct timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// Resolve `host` → first IPv4 sockaddr. Returns false on failure.
bool resolve_v4_(const std::string& host, uint16_t port,
                 sockaddr_in* out) noexcept {
    assert(out != nullptr);
    std::memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port   = htons(port);

    // Numeric literal fast path.
    if (::inet_pton(AF_INET, host.c_str(), &out->sin_addr) == 1) return true;

    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || res == nullptr) return false;
    bool ok = false;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(sockaddr_in)) {
            const sockaddr_in* sa = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
            out->sin_addr = sa->sin_addr;
            ok = true;
            break;
        }
    }
    ::freeaddrinfo(res);
    return ok;
}

std::string read_ssl_error_() noexcept {
    char buf[256];
    const unsigned long e = ERR_get_error();
    if (e == 0) return std::string("ssl: unknown error");
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

// Read until ResponseParser is Complete or the connection ends.
bool read_response_(int fd, SSL* ssl, ResponseParser* parser,
                    std::string* err) noexcept {
    assert(parser != nullptr);
    char buf[16 * 1024];
    constexpr int kMaxIters = 4096;     // 64 MiB ceiling regardless of TLS framing
    for (int iter = 0; iter < kMaxIters; ++iter) {
        int n = 0;
        if (ssl != nullptr) {
            n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
        } else {
            n = static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
        }
        if (n <= 0) {
            // Treat clean EOF as "end of body" — if the parser already had a
            // complete message we'll catch it on the way out.
            if (n == 0) break;
            if (err) *err = ssl ? read_ssl_error_() : std::string("recv failed");
            return false;
        }
        const auto st = parser->consume(buf, static_cast<std::size_t>(n));
        if (st == ResponseParser::State::Complete) return true;
        if (st == ResponseParser::State::Error) {
            if (err) *err = "response parse error";
            return false;
        }
    }
    if (err) *err = "response read exceeded iteration cap";
    return false;
}

bool write_all_(int fd, SSL* ssl, const std::string& wbuf,
                std::string* err) noexcept {
    std::size_t sent = 0;
    while (sent < wbuf.size()) {
        const int chunk = static_cast<int>(wbuf.size() - sent);
        int n = 0;
        if (ssl != nullptr) {
            n = SSL_write(ssl, wbuf.data() + sent, chunk);
        } else {
            n = static_cast<int>(::send(fd, wbuf.data() + sent, chunk, 0));
        }
        if (n <= 0) {
            if (err) *err = ssl ? read_ssl_error_() : std::string("send failed");
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// URL parse
// ---------------------------------------------------------------------------
bool parse_url(std::string_view url, ParsedUrl* out) noexcept {
    assert(out != nullptr);
    out->is_tls = false;
    out->host.clear();
    out->port = 0;
    out->path_and_query.clear();

    constexpr std::string_view kHttps = "https://";
    constexpr std::string_view kHttp  = "http://";
    std::string_view rest;
    if (url.size() > kHttps.size() && url.substr(0, kHttps.size()) == kHttps) {
        out->is_tls = true;
        out->port = 443;
        rest = url.substr(kHttps.size());
    } else if (url.size() > kHttp.size() && url.substr(0, kHttp.size()) == kHttp) {
        out->is_tls = false;
        out->port = 80;
        rest = url.substr(kHttp.size());
    } else {
        return false;
    }
    if (rest.empty()) return false;

    // host[:port][/path...]
    const std::size_t slash = rest.find('/');
    std::string_view authority = (slash == std::string_view::npos)
                                     ? rest : rest.substr(0, slash);
    if (authority.empty()) return false;
    const std::size_t colon = authority.find(':');
    if (colon == std::string_view::npos) {
        out->host.assign(authority.data(), authority.size());
    } else {
        out->host.assign(authority.data(), colon);
        const std::string portstr(authority.data() + colon + 1,
                                  authority.size() - colon - 1);
        if (portstr.empty()) return false;
        char* endp = nullptr;
        const long p = std::strtol(portstr.c_str(), &endp, 10);
        if (endp == nullptr || *endp != '\0' || p <= 0 || p > 65535) return false;
        out->port = static_cast<uint16_t>(p);
    }
    if (slash == std::string_view::npos) {
        out->path_and_query = "/";
    } else {
        out->path_and_query.assign(rest.data() + slash, rest.size() - slash);
    }
    return true;
}

// ---------------------------------------------------------------------------
// TlsClientResponse
// ---------------------------------------------------------------------------
std::string_view TlsClientResponse::header(std::string_view name) const noexcept {
    for (const auto& h : headers) {
        if (iequals_(h.name, name)) return h.value;
    }
    return {};
}

// ---------------------------------------------------------------------------
// TlsClient
// ---------------------------------------------------------------------------
TlsClient::TlsClient() noexcept : TlsClient(Config{}) {}

TlsClient::TlsClient(Config cfg) noexcept : cfg_(std::move(cfg)) {
    if (cfg_.timeout_ms <= 0) cfg_.timeout_ms = kTlsClientTimeoutMs;
    // Pick up GESTALT_CA_BUNDLE if the field was left empty.
    if (cfg_.ca_bundle_path.empty()) {
        if (const char* env = std::getenv("GESTALT_CA_BUNDLE")) {
            if (env[0] != '\0') cfg_.ca_bundle_path.assign(env);
        }
    }
    openssl_init_once();
    bolt::api::net::sys::startup();
    inited_ = true;
}

TlsClient::~TlsClient() noexcept {
    if (tls_ctx_ != nullptr) {
        SSL_CTX_free(static_cast<SSL_CTX*>(tls_ctx_));
        tls_ctx_ = nullptr;
    }
}

void TlsClient::ensure_tls_ctx_() noexcept {
    if (tls_ctx_ != nullptr) return;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx != nullptr);
    if (ctx == nullptr) return;
    // Minimum TLS 1.2.
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (cfg_.insecure_skip_verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        if (!cfg_.ca_bundle_path.empty()) {
            SSL_CTX_load_verify_locations(ctx, cfg_.ca_bundle_path.c_str(), nullptr);
        } else {
            // System trust store: default verify paths covers /etc/ssl/certs
            // on Linux and the OpenSSL-bundled trust store on Windows.
            SSL_CTX_set_default_verify_paths(ctx);
        }
    }
    tls_ctx_ = ctx;
}

TlsClientResponse TlsClient::send(const TlsClientRequest& req) noexcept {
    assert(inited_);
    TlsClientResponse resp;
    if (req.url.empty()) { resp.error = "empty url"; return resp; }
    if (req.method.empty()) { resp.error = "empty method"; return resp; }
    if (req.extra_count > kTlsClientMaxExtraHdrs) {
        resp.error = "too many extra headers";
        return resp;
    }

    ParsedUrl pu{};
    if (!parse_url(req.url, &pu)) {
        resp.error = "malformed url";
        return resp;
    }

    sockaddr_in addr{};
    if (!resolve_v4_(pu.host, pu.port, &addr)) {
        resp.error = "dns resolution failed";
        return resp;
    }

    const int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) {
        resp.error = "socket() failed";
        return resp;
    }
    apply_io_timeout_(fd, cfg_.timeout_ms);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        resp.error = "connect failed";
        bolt::api::net::sys::close_socket(fd);
        return resp;
    }

    SSL* ssl = nullptr;
    if (pu.is_tls) {
        ensure_tls_ctx_();
        if (tls_ctx_ == nullptr) {
            resp.error = "ssl ctx alloc failed";
            bolt::api::net::sys::close_socket(fd);
            return resp;
        }
        ssl = SSL_new(static_cast<SSL_CTX*>(tls_ctx_));
        if (ssl == nullptr) {
            resp.error = "SSL_new failed";
            bolt::api::net::sys::close_socket(fd);
            return resp;
        }
        SSL_set_fd(ssl, fd);
        SSL_set_connect_state(ssl);
        // SNI.
        SSL_set_tlsext_host_name(ssl, pu.host.c_str());
        // Hostname verification (unless explicitly disabled).
        if (!cfg_.insecure_skip_verify) {
            X509_VERIFY_PARAM* p = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (X509_VERIFY_PARAM_set1_host(p, pu.host.c_str(), 0) != 1) {
                resp.error = "set1_host failed";
                SSL_free(ssl);
                bolt::api::net::sys::close_socket(fd);
                return resp;
            }
        }
        if (SSL_connect(ssl) != 1) {
            resp.error = std::string("tls handshake failed: ") + read_ssl_error_();
            SSL_free(ssl);
            bolt::api::net::sys::close_socket(fd);
            return resp;
        }
        if (!cfg_.insecure_skip_verify) {
            const long vr = SSL_get_verify_result(ssl);
            if (vr != X509_V_OK) {
                resp.error = std::string("tls verify failed: ")
                           + X509_verify_cert_error_string(vr);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                bolt::api::net::sys::close_socket(fd);
                return resp;
            }
        }
    }

    // Build the request line. We reuse boltapi http::serialize_request via a
    // ClientRequest with path/host/method/body. Connection: close so we don't
    // have to worry about keep-alive framing on the synchronous path.
    ClientRequest creq{};
    creq.method       = req.method;
    creq.path         = pu.path_and_query;
    creq.host         = pu.host;
    creq.body         = req.body;
    creq.content_type = req.content_type;

    // Augment with Connection: close + caller extras. serialize_request will
    // emit the headers in `extra_headers`.
    TlsExtraHeader hdrs[kTlsClientMaxExtraHdrs + 1];
    std::size_t nh = 0;
    hdrs[nh++] = TlsExtraHeader{"Connection", "close"};
    for (std::size_t i = 0; i < req.extra_count && nh < (kTlsClientMaxExtraHdrs + 1); ++i) {
        hdrs[nh++] = req.extra_headers[i];
    }
    // Build a ClientHeader[] adapter (same layout).
    ClientHeader chdrs[kTlsClientMaxExtraHdrs + 1];
    for (std::size_t i = 0; i < nh; ++i) {
        chdrs[i].name  = hdrs[i].name;
        chdrs[i].value = hdrs[i].value;
    }
    creq.extra_headers = chdrs;
    creq.extra_count   = nh;

    std::string wbuf;
    char host_hdr[320];
    std::snprintf(host_hdr, sizeof(host_hdr), "%s:%u",
                  pu.host.c_str(), static_cast<unsigned>(pu.port));
    serialize_request(creq, host_hdr, wbuf);

    if (!write_all_(fd, ssl, wbuf, &resp.error)) {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
        bolt::api::net::sys::close_socket(fd);
        return resp;
    }

    ResponseParser parser;
    const bool got = read_response_(fd, ssl, &parser, &resp.error);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    bolt::api::net::sys::close_socket(fd);

    if (!got) return resp;

    resp.ok     = true;
    resp.status = parser.status();
    const std::string_view b = parser.body();
    if (b.size() > kTlsClientMaxRespBytes) {
        resp.ok = false;
        resp.error = "response body exceeds 1 MiB cap";
        return resp;
    }
    resp.body.assign(b.data(), b.size());
    resp.headers.reserve(parser.header_count());
    for (std::size_t i = 0; i < parser.header_count(); ++i) {
        resp.headers.push_back(TlsClientResponseHeader{
            std::string(parser.header_name(i)),
            std::string(parser.header_value(i))});
    }
    return resp;
}

}  // namespace bolt::api::http
