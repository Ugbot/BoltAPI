// demo_server.cpp — Bolt API WebRTC interop demo server.
//
// Brings up an App on :8080 that:
//   * enables WebRTC (ICE-lite + DTLS server + SCTP/DCEP data channels) and the
//     POST /webrtc/offer signaling route (offer SDP -> our answer SDP),
//   * echoes every data-channel message on the "chat" label (text + binary),
//   * serves the testing/web/ directory at "/" so http://localhost:8080/
//     webrtc.html loads the browser RTCPeerConnection test page.
//
// This is the server the interop harness points at:
//   * browser:  open http://localhost:8080/webrtc.html, click "Connect & echo"
//   * headless: uv run --with aiortc python testing/aiortc_datachannel.py 8080
//
// Built only under BOLTAPI_WITH_WEBRTC (the CMake target is guarded), so the
// default build is unaffected. Run from the repo root so the relative
// static-files root ("testing/web") resolves; pass an alternate web root and/or
// port on the command line: demo_server [port] [web_root].
#include "boltapi/app.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

    // Serve the browser test harness (and anything else under testing/web/).
    app.static_files("/", web_root);

    std::fprintf(stderr,
        "Bolt API demo server on http://127.0.0.1:%u\n"
        "  open  http://127.0.0.1:%u/webrtc.html  (browser WebRTC test)\n"
        "  POST  /webrtc/offer                    (signaling)\n"
        "  static root: %s\n",
        port, port, web_root.c_str());

    return app.run("127.0.0.1", port);
}
