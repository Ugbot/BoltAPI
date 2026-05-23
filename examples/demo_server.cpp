// demo_server.cpp — Bolt API WebRTC interop demo server (data + media echo).
//
// One server tying HTTP + WS + SSE + data-channel echo + MEDIA echo together
// behind the POST /webrtc/offer signaling route. Brings up an App on :8080 that:
//   * enables WebRTC (ICE-lite + DTLS server + SCTP/DCEP data channels + SRTP
//     media) and the POST /webrtc/offer signaling route (offer -> answer),
//   * MEDIA ECHO (WM6, aiortc `server` shape): received audio + video RTP is
//     looped straight back out (re-SRTP, relay, no transcode) via
//     enable_media_echo(),
//   * echoes every data-channel message on the "chat" label (text + binary),
//   * a GET /health route + a WebSocket /ws echo + an SSE /events stream, to show
//     the media/data surfaces coexisting with H1/H2/WS/SSE on one App,
//   * serves the testing/web/ directory at "/" so http://localhost:8080/
//     webrtc.html (data) and /media.html (audio+video) load the browser pages.
//
// This is the server the interop harness points at:
//   * browser (data):  open http://localhost:8080/webrtc.html
//   * browser (media): open http://localhost:8080/media.html  (getUserMedia)
//   * headless (data): uv run --with aiortc python tests/interop/aiortc_datachannel.py 8080
//   * headless (media):uv run --with aiortc python tests/interop/aiortc_media.py 8080
//
// Built only under BOLTAPI_WITH_WEBRTC (the CMake target is guarded), so the
// default build is unaffected. Run from the repo root so the relative
// static-files root ("testing/web") resolves; pass an alternate web root and/or
// port on the command line: demo_server [port] [web_root].
#include "boltapi/app.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

int main(int argc, char** argv) {
    const std::uint16_t port =
        argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8080;
    const std::string web_root = argc > 2 ? argv[2] : "testing/web";

    bolt::api::App app;

    bolt::api::WebRtcConfig wcfg;          // signaling_path defaults to /webrtc/offer
    wcfg.ice_lite         = true;          // Bolt is the ICE-lite controlled peer
    wcfg.max_message_size = 262144;
    app.enable_webrtc(wcfg);

    // HTTP/3 (W5c): serve H3 alongside H1/H2 on the SAME port number over UDP
    // (QUIC). enable_http3(port) binds the QUIC server endpoint to that UDP port;
    // requests bridge through the SAME App dispatch path as H1/H2. Under a build
    // without BOLTAPI_WITH_HTTP3 this is a harmless no-op (it logs + ignores).
    app.enable_http3(port);

    // Alt-Svc advertisement (RFC 7838) so browsers (Chrome/Firefox) learn the
    // HTTP/3 endpoint and upgrade. Added as DEMO middleware (App::use) — NOT in
    // core app.cpp — so every H1/H2 response carries `alt-svc: h3=":<port>"`.
    // `ma` is the advertisement lifetime (seconds); `persist=1` keeps it across
    // network changes. The middleware runs the rest of the chain, then stamps the
    // header on the way out.
    {
        char alt_svc[64];
        std::snprintf(alt_svc, sizeof(alt_svc),
                      "h3=\":%u\"; ma=86400; persist=1",
                      static_cast<unsigned>(port));
        const std::string alt_svc_value = alt_svc;
        app.use([alt_svc_value](bolt::api::Request&, bolt::api::Response& res,
                                std::function<void()> next) {
            next();  // run the matched handler first
            res.header("alt-svc", alt_svc_value);  // then advertise H3
        });
    }

    // WM6: MEDIA ECHO (aiortc `server` shape). Loop received audio + video RTP
    // straight back out (re-SRTP, relay, no transcode). The signaling answer
    // negotiates the offered audio/video m-lines sendrecv so the peer's media
    // returns to it. H1/H2 + data channels are untouched.
    app.enable_media_echo();

#if defined(BOLTAPI_WITH_WEBRTC)
    // "chat" data channel: echo each message straight back, preserving type.
    app.on_data_channel("chat",
        [](bolt::api::webrtc::DataChannel& ch, const void* data,
           std::size_t len, bool is_binary) {
            std::fprintf(stderr, "[demo] chat msg len=%zu binary=%d\n", len,
                         static_cast<int>(is_binary));
            if (is_binary) {
                ch.send_binary(data, len);
            } else {
                ch.send_text(std::string_view(
                    reinterpret_cast<const char*>(data), len));
            }
        });
#endif

    // Plain HTTP/WS/SSE surfaces alongside the WebRTC ones — one App, all wired.
    app.get("/health", [](bolt::api::Request&, bolt::api::Response& res) {
        res.status(200).content_type("text/plain; charset=utf-8").send("ok");
    });
    app.websocket("/ws", [](bolt::api::http::WebSocketConnection& ws) {
        ws.on_text_message = [&ws](const std::string& msg) {
            ws.send_text(msg);  // echo
        };
    });

    // Serve the browser test harness (and anything else under testing/web/).
    app.static_files("/", web_root);

    std::fprintf(stderr,
        "Bolt API demo server on http://127.0.0.1:%u\n"
        "  open  http://127.0.0.1:%u/webrtc.html  (browser data-channel test)\n"
        "  open  http://127.0.0.1:%u/media.html   (browser audio+video echo)\n"
        "  GET   /health   WS /ws                 (HTTP/WS surfaces)\n"
        "  POST  /webrtc/offer                    (signaling: data + media)\n"
        "  HTTP/3 (QUIC) on UDP :%u (ALPN h3); H1/H2 advertise alt-svc h3=\":%u\"\n"
        "  static root: %s\n",
        port, port, port, port, port, web_root.c_str());

    return app.run("127.0.0.1", port);
}
