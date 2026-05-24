// rest_api.cpp — START HERE. A small REST API on the bolt::api::App facade.
//
// Run:   boltapi_rest_api [port]        (default 8080, cleartext HTTP/1.1)
// Try:
//   curl  http://127.0.0.1:8080/health
//   curl  http://127.0.0.1:8080/users/42
//   curl 'http://127.0.0.1:8080/search?q=bolt&limit=5'
//   curl -X POST http://127.0.0.1:8080/users -d '{"name":"ada","age":36}'
//   curl  http://127.0.0.1:8080/secret -H 'authorization: Bearer t0ken'
//
// Shows the pieces you actually use day to day:
//   * routing across verbs (GET/POST/DELETE) + a path param (:id) + query params
//   * reading a JSON body with req.json() (Bolt's fionn parser — no exceptions)
//   * building responses fluently: res.ok().json(...), res.created(), res.not_found()
//   * middleware: a request logger (runs for everything) and a bearer-token guard
//     that SHORT-CIRCUITS (does not call next()) on a protected route
//
// Pure HTTP/1.1, no flags needed. For HTTP/2 add TLS; for HTTP/3 see
// http3_server.cpp; for WebSocket/SSE/WebRTC see the other examples.
#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

namespace api = bolt::api;

int main(int argc, char** argv) {
    api::net::sys::startup();  // WSAStartup on Windows; no-op on POSIX.

    std::uint16_t port = 8080;
    if (argc > 1) {
        const long p = std::strtol(argv[1], nullptr, 10);
        if (p > 0 && p < 65536) port = static_cast<std::uint16_t>(p);
    }

    api::App app;

    // --- Middleware (the onion): outermost first. ---
    // 1) Request logger — runs for EVERY request, then lets the chain continue.
    app.use([](api::Request& req, api::Response&, std::function<void()> next) {
        std::fprintf(stderr, "[req] %.*s %.*s\n",
                     static_cast<int>(req.method().size()), req.method().data(),
                     static_cast<int>(req.path().size()), req.path().data());
        next();  // not calling next() would short-circuit the request
    });

    // --- Routes ---
    app.get("/health", [](api::Request&, api::Response& res) {
        res.ok().text("up");
    });

    // Path param: GET /users/:id  ->  req.path_param("id")
    app.get("/users/:id", [](api::Request& req, api::Response& res) {
        const std::string id = req.path_param("id");
        res.ok().json("{\"id\":\"" + id + "\",\"name\":\"user-" + id + "\"}");
    });

    // Query params: GET /search?q=...&limit=...
    app.get("/search", [](api::Request& req, api::Response& res) {
        const std::string q     = req.query_param("q");
        const std::string limit = req.query_param("limit");
        if (q.empty()) { res.bad_request().json("{\"error\":\"missing q\"}"); return; }
        res.ok().json("{\"q\":\"" + q + "\",\"limit\":\"" +
                      (limit.empty() ? "10" : limit) + "\"}");
    });

    // JSON body in: POST /users  {"name":"...","age":N}
    app.post("/users", [](api::Request& req, api::Response& res) {
        auto doc = req.json();                       // Bolt fionn — never throws
        if (!doc.ok()) { res.bad_request().json("{\"error\":\"invalid json\"}"); return; }
        const std::string_view name = doc["name"].as_string();
        const std::int64_t     age  = doc["age"].as_int();
        if (name.empty()) { res.bad_request().json("{\"error\":\"name required\"}"); return; }
        res.created().json("{\"created\":true,\"name\":\"" + std::string(name) +
                           "\",\"age\":" + std::to_string(age) + "}");
    });

    app.del("/users/:id", [](api::Request& req, api::Response& res) {
        std::fprintf(stderr, "[del] user %s\n", req.path_param("id").c_str());
        res.no_content();
    });

    // 2) A protected route guarded by its OWN middleware-style check. (Global
    //    middleware runs for everything; for per-route auth we check inline.)
    app.get("/secret", [](api::Request& req, api::Response& res) {
        const std::string_view auth = req.header_view("authorization");
        if (auth != "Bearer t0ken") {
            res.unauthorized().json("{\"error\":\"unauthorized\"}");
            return;  // short-circuit
        }
        res.ok().json("{\"secret\":\"42\"}");
    });

    std::printf("Bolt API rest_api on http://127.0.0.1:%u  "
                "(GET /health /users/:id /search  POST /users  GET /secret)\n",
                port);
    return app.run("127.0.0.1", port);  // blocking
}
