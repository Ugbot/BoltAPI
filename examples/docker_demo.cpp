// docker_demo.cpp — ALL FOUR protocols on one App, for the Docker browser demo.
//
//   HTTP/1.1  cleartext on :8080            -> http://localhost:8080/
//   HTTP/1.1 + HTTP/2 over TLS on :8443     -> https://localhost:8443/
//   HTTP/3 (QUIC) over UDP :8443            -> advertised via Alt-Svc
//   WebRTC (data + audio/video echo)        -> UDP :9000, pages on either origin
//
// Config via env (set by the Dockerfile; all optional):
//   BOLTAPI_WEB_ROOT  static dir served at "/"     (default "testing/web")
//   BOLTAPI_CERT      TLS cert PEM (enables H2/H3 over TLS when present)
//   BOLTAPI_KEY       TLS key  PEM
//   BOLTAPI_H1_PORT   cleartext HTTP/1.1 TCP port  (default 8080)
//   BOLTAPI_TLS_PORT  TLS + QUIC port              (default 8443)
//   BOLTAPI_RTC_PORT  WebRTC UDP port              (default 9000)
//
// getUserMedia (camera/mic) needs a secure context — http://localhost AND
// https://localhost both qualify, so the media page works on either origin.
#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

namespace api = bolt::api;

static std::string env_or(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v != nullptr && *v != 0) ? std::string(v) : std::string(dflt);
}
static std::uint16_t env_port(const char* k, std::uint16_t dflt) {
    const char* v = std::getenv(k);
    if (v == nullptr || *v == 0) return dflt;
    const long p = std::strtol(v, nullptr, 10);
    return (p > 0 && p < 65536) ? static_cast<std::uint16_t>(p) : dflt;
}

int main() {
    api::net::sys::startup();

    const std::string web_root = env_or("BOLTAPI_WEB_ROOT", "testing/web");
    const std::string cert     = env_or("BOLTAPI_CERT", "");
    const std::string key      = env_or("BOLTAPI_KEY", "");
    const std::uint16_t h1_port  = env_port("BOLTAPI_H1_PORT", 8080);
    const std::uint16_t tls_port = env_port("BOLTAPI_TLS_PORT", 8443);
    const std::uint16_t rtc_port = env_port("BOLTAPI_RTC_PORT", 9000);

    // Build the server config: cleartext H1 always; TLS (H1+H2) + QUIC when a
    // cert is supplied. ALPN advertises h2 then http/1.1.
    api::App::Config cfg;
    cfg.server.enable_http1_cleartext = true;
    cfg.server.alpn_protocols         = {"h2", "http/1.1"};
    cfg.server.num_io_threads         = 1;
    const bool tls = !cert.empty() && !key.empty();
    if (tls) {
        cfg.server.enable_tls = true;
        cfg.server.tls_port   = tls_port;
        cfg.server.cert_file  = cert;
        cfg.server.key_file   = key;
    } else {
        cfg.server.enable_tls = false;
    }

    api::App app(std::move(cfg));

    // HTTP/3 (QUIC) on the TLS port number over UDP, when TLS is configured.
    if (tls) {
        app.enable_http3(tls_port);
        char alt[64];
        std::snprintf(alt, sizeof(alt), "h3=\":%u\"; ma=86400; persist=1",
                      static_cast<unsigned>(tls_port));
        const std::string alt_svc = alt;
        app.use([alt_svc](api::Request&, api::Response& res,
                          std::function<void()> next) {
            next();
            res.header("alt-svc", alt_svc);
        });
    }

    // WebRTC: data-channel echo + audio/video echo on its own UDP port.
    api::WebRtcConfig wcfg;
    wcfg.udp_port         = rtc_port;
    wcfg.ice_lite         = true;
    wcfg.max_message_size = 262144;
    app.enable_webrtc(wcfg);
    app.enable_media_echo();
#if defined(BOLTAPI_WITH_WEBRTC)
    app.on_data_channel("chat",
        [](api::webrtc::DataChannel& ch, const void* data, std::size_t len,
           bool is_binary) {
            if (is_binary) ch.send_binary(data, len);
            else ch.send_text(std::string_view(
                     reinterpret_cast<const char*>(data), len));
        });
#endif

    // Plain HTTP surfaces (reachable over H1, H2, and H3).
    app.get("/ping", [](api::Request&, api::Response& res) { res.ok().text("pong"); });
#if defined(BOLTAPI_WITH_HTTP3)
    // WebTransport cert pin: SHA-256 of the QUIC server cert (DER) as lowercase hex.
    // The browser uses this in new WebTransport(url, {serverCertificateHashes:[...]})
    // so a self-signed cert is accepted (Chrome's WebTransport rejects untrusted
    // certs and ignores --ignore-certificate-errors; pinning the hash is the path).
    app.get("/wt/cert-hash", [](api::Request&, api::Response& res) {
        std::uint8_t h[32];
        if (!api::quic::server_cert_sha256(h)) {
            res.status(500).content_type("text/plain").send("no quic cert");
            return;
        }
        static const char hx[] = "0123456789abcdef";
        char hex[64];
        for (int i = 0; i < 32; ++i) {
            hex[2 * i]     = hx[(h[i] >> 4) & 0xF];
            hex[2 * i + 1] = hx[h[i] & 0xF];
        }
        res.ok().content_type("text/plain").send(std::string_view(hex, 64));
    });
#endif
    app.post("/echo", [](api::Request& req, api::Response& res) { res.ok().send(req.body()); });
    app.get("/api/info", [tls, h1_port, tls_port, rtc_port]
                         (api::Request&, api::Response& res) {
        char body[256];
        std::snprintf(body, sizeof(body),
            "{\"server\":\"bolt-api\",\"tls\":%s,\"h1\":%u,\"tls_port\":%u,"
            "\"webrtc_udp\":%u,\"protocols\":[\"http/1.1\",\"h2\",\"h3\"]}",
            tls ? "true" : "false", h1_port, tls_port, rtc_port);
        res.ok().json(body);
    });
    app.websocket("/ws", [](api::http::WebSocketConnection& ws) {
        ws.on_text_message = [&ws](const std::string& m) { ws.send_text(m); };
    });

    // SSE: stream a short burst of numbered events then a "done" event.
    app.sse_coro("/events",
        [](api::net::IODispatcher& io, int fd, const api::http::CoroHttpRequest&)
            -> api::core::coro_task<void> {
            api::http::SSEWriter sse(io, fd);
            for (int i = 0; i < 20; ++i) {
                const bool ok = co_await sse.send_event(
                    "tick", "{\"n\":" + std::to_string(i) + "}");
                if (!ok) break;  // client disconnected
            }
            co_await sse.send_event("done", "bye");
            co_return;
        });

    app.static_files("/", web_root);

    std::printf(
        "Bolt API docker demo\n"
        "  HTTP/1.1   http://localhost:%u/        (+ WebRTC, getUserMedia ok)\n"
        "  HTTP/2+3   %s://localhost:%u/   (TLS=%s; H3 via Alt-Svc on UDP :%u)\n"
        "  WebRTC     UDP :%u   pages: /webrtc.html (data)  /media.html (a/v)\n"
        "  routes     GET /ping  POST /echo  GET /api/info  WS /ws\n"
        "  web root   %s\n",
        h1_port, tls ? "https" : "http", tls_port, tls ? "on" : "off",
        tls_port, rtc_port, web_root.c_str());

    return app.run("0.0.0.0", h1_port);  // blocking
}
