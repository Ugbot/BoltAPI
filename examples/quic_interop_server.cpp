// quic_interop_server.cpp — quic-interop-runner server endpoint (HTTP/3).
//
// Serves regular files from a root directory over HTTP/3 (and HTTP/1.1) on one
// port. testing/quic-interop/ packages it per the runner's endpoint spec.
//
// Run:   boltapi_quic_interop_server [port] [www-root] [host]
//        (defaults 443 /www 0.0.0.0)

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

namespace api = bolt::api;

namespace {

constexpr std::size_t kMaxNameBytes = 255;
constexpr std::uint64_t kMaxFileBytes = 64ull << 20;

// A single path segment of safe characters; anything else is a 404.
bool safe_name(std::string_view n) {
    assert(n.size() <= 4096);
    if (n.empty() || n.size() > kMaxNameBytes || n == "." || n == "..") return false;
    for (const char c : n) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

bool read_file(const std::string& path, std::string* out) {
    assert(out != nullptr);
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const std::streamoff sz = in.tellg();
    if (sz < 0 || static_cast<std::uint64_t>(sz) > kMaxFileBytes) return false;
    out->resize(static_cast<std::size_t>(sz));
    in.seekg(0);
    if (sz > 0 && !in.read(out->data(), sz)) return false;
    assert(out->size() == static_cast<std::size_t>(sz));
    return true;
}

}  // namespace

// Options after the positional [port] [www-root] [host]:
//   --retry          Retry before every handshake (runner "retry")
//   --early-data     accept 0-RTT on resumed connections ("zerortt")
//   --hq             also offer ALPN hq-interop (HTTP/0.9, transport cases)
//   --cert F --key K present this chain/key instead of the self-signed one
int main(int argc, char** argv) {
    api::net::sys::startup();

    std::uint16_t port = 443;
    std::string root = "/www";
    const char* host = "0.0.0.0";
    api::App app;
    int positional = 0;
    std::string cert, key;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--retry") { app.http3_require_retry(); continue; }
        if (a == "--early-data") { app.http3_early_data(); continue; }
        if (a == "--hq") { app.http3_hq_interop(); continue; }
        if (a == "--cert" && i + 1 < argc) { cert = argv[++i]; continue; }
        if (a == "--key" && i + 1 < argc) { key = argv[++i]; continue; }
        if (positional == 0) {
            const long p = std::strtol(argv[i], nullptr, 10);
            if (p > 0 && p < 65536) port = static_cast<std::uint16_t>(p);
        } else if (positional == 1) {
            root = argv[i];
        } else if (positional == 2) {
            host = argv[i];
        }
        ++positional;
    }
    if (!cert.empty() && !key.empty()) app.http3_certificate(cert, key);

    app.enable_http3(port);
    app.get("/{name}", [root](api::Request& req, api::Response& res) {
        const std::string_view name = req.path_param_view("name");
        std::string body;
        if (!safe_name(name) || !read_file(root + "/" + std::string(name), &body)) {
            res.not_found();
            return;
        }
        res.ok().header("content-type", "application/octet-stream");
        res.send_owned(std::move(body));
    });

    std::printf("quic_interop_server: h3 on udp %s:%u, root %s\n", host,
                static_cast<unsigned>(port), root.c_str());
    std::fflush(stdout);
    return app.run(host, port);
}
