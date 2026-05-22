// sse_stream.cpp — M2 example: a coroutine SSE stream via the bolt::api::App facade.
//
// Run:   boltapi_sse_stream [port]   (default 8080)
// Then:  curl -N http://127.0.0.1:<port>/events
//
// The engine sends the text/event-stream response headers before the handler
// runs; the handler uses SSEWriter to push a few named events then returns,
// which ends the stream and closes the connection.

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace api  = bolt::api;
namespace core = bolt::api::core;
namespace net  = bolt::api::net;
namespace http = bolt::api::http;

int main(int argc, char** argv) {
    api::net::sys::startup();

    uint16_t port = 8080;
    if (argc > 1) {
        const long p = std::strtol(argv[1], nullptr, 10);
        if (p > 0 && p < 65536) port = static_cast<uint16_t>(p);
    }

    api::App app;

    app.get("/health", [](api::Request&, api::Response& res) {
        res.ok().text("sse up");
    });

    app.sse_coro("/events",
        [](net::IODispatcher& io, int fd, const http::CoroHttpRequest&)
            -> core::coro_task<void> {
            http::SSEWriter sse(io, fd);
            for (int i = 0; i < 5; ++i) {
                const bool ok = co_await sse.send_event(
                    "tick", "event-" + std::to_string(i),
                    std::to_string(i));
                if (!ok) break;  // client disconnected
            }
            co_await sse.send_event("done", "bye");
            co_return;
        });

    std::printf("Bolt API sse-stream listening on http://127.0.0.1:%u "
                "(SSE at /events)\n", port);
    return app.run("127.0.0.1", port);  // blocking
}
