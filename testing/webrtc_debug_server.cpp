// testing/webrtc_debug_server.cpp — a tiny, manual WebRTC demo/debug server.
//
// Starts the full App with the WebRTC surface (ICE-lite + DTLS + Bolt-native
// SCTP/DCEP) and an on_data_channel("chat") echo, plus enable_media_echo(), on a
// fixed port, then blocks until Ctrl-C. Used to:
//   * drive the interop python harnesses (tests/interop/aiortc_datachannel.py)
//     manually with full stdout/stderr,
//   * attach a step-through debugger (cdb / VS) to the SCTP/DCEP handlers,
//   * back the browser test pages (testing/web/{webrtc,media}.html).
//
// This is a DEBUG/MANUAL tool: it is NOT a ctest gate (the bounded gtest legs in
// tests/aiortc_interop_test.cpp are the automated gate). It serves the
// testing/web/ static pages so a browser can be pointed at it directly.

#include "boltapi/app.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <thread>

#if defined(BOLTAPI_WITH_WEBRTC)
#include "boltapi/webrtc/data_channel.h"
#endif

namespace {

constexpr std::uint16_t kDefaultPort = 8080;

}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = kDefaultPort;
    if (argc >= 2) {
        const long p = std::strtol(argv[1], nullptr, 10);
        if (p > 0 && p < 65536) port = static_cast<std::uint16_t>(p);
    }

    bolt::api::App app;
    app.get("/health", [](bolt::api::Request&, bolt::api::Response& res) {
        res.text("ok");
    });

#if defined(BOLTAPI_WITH_WEBRTC)
    bolt::api::WebRtcConfig wcfg;
    wcfg.ice_lite = true;
    wcfg.max_message_size = 262144;
    app.enable_webrtc(wcfg);
    // 2nd arg "nomedia" => match the data-channel-only gtest (no enable_media_echo)
    const bool with_media = !(argc >= 3 && std::string_view(argv[2]) == "nomedia");
    if (with_media) app.enable_media_echo();
    app.on_data_channel("chat",
        [](bolt::api::webrtc::DataChannel& ch, const void* data, std::size_t len,
           bool is_binary) {
            if (is_binary) ch.send_binary(data, len);
            else ch.send_text(std::string_view(
                     reinterpret_cast<const char*>(data), len));
        });
    std::printf("[debug-server] WebRTC ENABLED (data + media echo)\n");
#else
    std::printf("[debug-server] built WITHOUT BOLTAPI_WITH_WEBRTC\n");
#endif

    if (app.start_background("127.0.0.1", port) != 0) {
        std::fprintf(stderr, "[debug-server] failed to start on :%u\n", port);
        return 1;
    }
    std::printf("[debug-server] listening on http://127.0.0.1:%u "
                "(Ctrl-C to stop)\n", static_cast<unsigned>(port));
    std::fflush(stdout);

    // Block forever; the test harness / browser drives it. Ctrl-C kills it.
    while (app.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    app.stop();
    return 0;
}
