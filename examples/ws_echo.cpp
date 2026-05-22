// ws_echo.cpp — M2 example: a WebSocket echo server via the bolt::api::App facade.
//
// Run:   boltapi_ws_echo [port]   (default 8080)
// Then connect a WebSocket client to ws://127.0.0.1:<port>/ws and send text
// frames; the server echoes each text message straight back.
//
// The handler is invoked once per upgraded connection. We wire on_text_message
// to echo via send_text() (which enqueues an unmasked server text frame the
// engine flushes on the connection loop). A trivial GET /health route shows
// regular HTTP and WebSocket coexisting on the same App.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace api = bolt::api;

int main(int argc, char** argv) {
    api::net::sys::startup();  // WSAStartup on Windows; no-op on POSIX.

    uint16_t port = 8080;
    if (argc > 1) {
        const long p = std::strtol(argv[1], nullptr, 10);
        if (p > 0 && p < 65536) port = static_cast<uint16_t>(p);
    }

    api::App app;

    app.get("/health", [](api::Request&, api::Response& res) {
        res.ok().text("ws-echo up");
    });

    app.websocket("/ws", [](api::http::WebSocketConnection& ws) {
        ws.on_text_message = [&ws](const std::string& msg) {
            ws.send_text(msg);  // echo
        };
        ws.on_close = [](uint16_t code, const char* reason) {
            std::printf("[ws] closed code=%u reason=%s\n", code,
                        reason ? reason : "");
        };
    });

    std::printf("Bolt API ws-echo listening on http://127.0.0.1:%u "
                "(WebSocket at /ws)\n", port);
    return app.run("127.0.0.1", port);  // blocking
}
