// h2spec_server_main.cpp — the server h2spec is pointed at (see
// h2spec_conformance.py): one App serving h2c (prior knowledge) on the
// cleartext port and h2 over TLS (ALPN, self-signed) on the TLS port.
//   usage: boltapi_h2spec_server <cleartext_port> <tls_port>
#include "boltapi/app.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <cleartext_port> <tls_port>\n", argv[0]);
        return 2;
    }
    const auto h2c_port = static_cast<std::uint16_t>(std::atoi(argv[1]));
    const auto tls_port = static_cast<std::uint16_t>(std::atoi(argv[2]));
    assert(h2c_port != 0 && tls_port != 0);

    bolt::api::App::Config cfg;
    cfg.server.enable_tls = true;
    cfg.server.tls_port = tls_port;
    cfg.server.host = "0.0.0.0";  // docker reaches us through the host gateway
    bolt::api::App app(cfg);
    app.get("/", [](bolt::api::Request&, bolt::api::Response& res) { res.text("h2spec"); });
    app.post("/", [](bolt::api::Request& req, bolt::api::Response& res) {
        res.text(std::string(req.body()));
    });
    return app.run("0.0.0.0", h2c_port);
}
