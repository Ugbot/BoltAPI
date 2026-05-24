// http3_server.cpp — HTTP/3 (QUIC) alongside HTTP/1.1 on one App.
//
// Build with HTTP/3 on:
//   cmake --preset msvc -DBOLTAPI_WITH_HTTP3=ON
//   cmake --build build/msvc --config Release --target boltapi_http3_server
// Run:   boltapi_http3_server [port]      (default 8080)
//
// Test with an independent HTTP/3 stack (no system curl-http3 needed):
//   uv run --no-project --with aioquic python tests/interop/aioquic_client.py 8080
//
// HTTP/3 runs over QUIC (UDP) on the SAME port number as the TCP listener.
// Requests bridge through the SAME router + middleware + handler path as H1/H2,
// so the routes below are reachable over both. We also advertise Alt-Svc on the
// H1 responses (RFC 7838) so a browser learns the H3 endpoint and upgrades.
//
// NOTE: built WITHOUT BOLTAPI_WITH_HTTP3, enable_http3() is a harmless no-op
// (logs + ignores) and this serves plain HTTP/1.1 — so the example always
// compiles. HTTP/2 additionally needs TLS (set Config.server.enable_tls + a
// cert); this example stays cleartext H1 + H3 to keep it runnable as-is.
#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

namespace api = bolt::api;

int main(int argc, char** argv) {
    api::net::sys::startup();

    std::uint16_t port = 8080;
    if (argc > 1) {
        const long p = std::strtol(argv[1], nullptr, 10);
        if (p > 0 && p < 65536) port = static_cast<std::uint16_t>(p);
    }

    api::App app;

    // Turn on HTTP/3 on the same port number over UDP (QUIC, ALPN h3).
    app.enable_http3(port);

    // Advertise the H3 endpoint to browsers via Alt-Svc on H1/H2 responses.
    {
        char alt_svc[64];
        std::snprintf(alt_svc, sizeof(alt_svc),
                      "h3=\":%u\"; ma=86400; persist=1",
                      static_cast<unsigned>(port));
        const std::string alt_svc_value = alt_svc;
        app.use([alt_svc_value](api::Request&, api::Response& res,
                                std::function<void()> next) {
            next();
            res.header("alt-svc", alt_svc_value);
        });
    }

    app.get("/ping", [](api::Request&, api::Response& res) {
        res.ok().text("pong");
    });
    app.post("/echo", [](api::Request& req, api::Response& res) {
        res.ok().send(req.body());        // echo the body back, byte-exact
    });
    app.get("/", [](api::Request&, api::Response& res) {
        res.ok().json("{\"server\":\"bolt-api\",\"alpn\":\"h1/h2/h3\"}");
    });

    std::printf("Bolt API http3_server on http://127.0.0.1:%u  "
                "(HTTP/1.1 + HTTP/3 over UDP :%u; routes /ping /echo /)\n",
                port, port);
    return app.run("127.0.0.1", port);
}
