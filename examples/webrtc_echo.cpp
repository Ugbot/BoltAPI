// webrtc_echo.cpp — minimal WebRTC data-channel echo server (debug/example).
// Starts an App with enable_webrtc + a /webrtc/offer signaling route and an
// on_data_channel("chat") echo. Blocks. Usage: webrtc_echo <port>.
#include "boltapi/app.h"

#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    const std::uint16_t port =
        argc > 1 ? static_cast<std::uint16_t>(std::atoi(argv[1])) : 8090;

    bolt::api::App app;
    bolt::api::WebRtcConfig wcfg;
    wcfg.ice_lite = true;
    wcfg.max_message_size = 262144;
    app.enable_webrtc(wcfg);

#if defined(BOLTAPI_WITH_WEBRTC)
    app.on_data_channel("chat",
        [](bolt::api::webrtc::DataChannel& ch, const void* data,
           std::size_t len, bool is_binary) {
            std::fprintf(stderr, "[echo] msg len=%zu binary=%d\n", len,
                         (int)is_binary);
            if (is_binary) ch.send_binary(data, len);
            else ch.send_text(std::string_view(
                     reinterpret_cast<const char*>(data), len));
        });
#endif

    std::fprintf(stderr, "webrtc_echo listening on 127.0.0.1:%u\n", port);
    return app.run("127.0.0.1", port);
}
