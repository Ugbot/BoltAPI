// boltapi/app.h — the public Bolt API facade (FastAPI-style, C++).
//
// bolt::api::App ties the forked CoroUnifiedServer engine and the Bolt-native
// Router together behind an ergonomic, chainable surface:
//
//     bolt::api::App app;
//     app.get("/health", [](Request& req, Response& res) { res.ok().text("up"); })
//        .post_async("/echo", [](Request& req, Response& res)
//                                   -> core::coro_task<void> {
//             res.created().json(req.body());
//             co_return;
//        })
//        .use([](Request&, Response& res, auto next) { next(); });
//     app.run("0.0.0.0", 8080);
//
// Dispatch bridge (built once on run/start):
//   1. All registered routes are added into a Router; router.build() is called
//      exactly once.
//   2. server.set_handler() installs a single coroutine that, per request:
//        method_from(req.method) -> router.match(method, path)
//        -> Request(req, params) + Response(into a CoroHttpResponse)
//        -> run the middleware chain whose terminal invokes the matched handler
//        -> return the filled CoroHttpResponse.
//      No route match => 404. (405 is a documented optional; v1 returns 404.)
//
// TigerStyle: bounded, assert >= 2 in non-trivial methods, no recursion in the
// hot path beyond the bounded middleware fold, std::function chain (per-request
// alloc TODO noted in middleware.h).
#pragma once

#include "boltapi/core/coro_task.h"
#include "boltapi/middleware.h"
#include "boltapi/request.h"
#include "boltapi/response.h"
#include "boltapi/router.h"
#include "boltapi/server/coro_unified_server.h"

#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api {

class App {
public:
    // Sync handler: fill the Response, return. Wrapped into a ready coro_task.
    using Handler = std::function<void(Request&, Response&)>;
    // Async handler: may co_await; fill the Response, co_return.
    using AsyncHandler =
        std::function<core::coro_task<void>(Request&, Response&)>;

    // Forwarding config: wraps a CoroUnifiedServerConfig plus facade-level knobs.
    struct Config {
        http::CoroUnifiedServerConfig server;
        bool        enable_cors  = false;
        std::string cors_origin  = "*";
        // M2 hook (declared now so the surface is stable; not wired yet).
        bool        enable_compression = false;

        Config() noexcept {
            // Facade defaults favor a cleartext HTTP/1.1 dev server. TLS stays
            // available via Config.server.* but is off by default for the App.
            server.enable_tls             = false;
            server.enable_http1_cleartext = true;
            server.enable_signal_handlers = false;
            server.num_io_threads         = 1;
            server.num_workers            = 0;  // auto
        }
    };

    App() : App(Config{}) {}
    explicit App(Config config) : config_(std::move(config)) {}

    App(const App&)            = delete;
    App& operator=(const App&) = delete;

    ~App() { stop(); }

    // -----------------------------------------------------------------------
    // Route registration — sync. Returns *this for chaining.
    // -----------------------------------------------------------------------
    App& get    (std::string_view path, Handler h) { return add_sync(Method::Get,     path, std::move(h)); }
    App& post   (std::string_view path, Handler h) { return add_sync(Method::Post,    path, std::move(h)); }
    App& put    (std::string_view path, Handler h) { return add_sync(Method::Put,     path, std::move(h)); }
    App& del    (std::string_view path, Handler h) { return add_sync(Method::Delete,  path, std::move(h)); }
    App& patch  (std::string_view path, Handler h) { return add_sync(Method::Patch,   path, std::move(h)); }
    App& head   (std::string_view path, Handler h) { return add_sync(Method::Head,    path, std::move(h)); }
    App& options(std::string_view path, Handler h) { return add_sync(Method::Options, path, std::move(h)); }

    // -----------------------------------------------------------------------
    // Route registration — async. (Includes head_async — FasterAPI lacked it.)
    // -----------------------------------------------------------------------
    App& get_async  (std::string_view path, AsyncHandler h) { return add_async(Method::Get,    path, std::move(h)); }
    App& post_async (std::string_view path, AsyncHandler h) { return add_async(Method::Post,   path, std::move(h)); }
    App& put_async  (std::string_view path, AsyncHandler h) { return add_async(Method::Put,    path, std::move(h)); }
    App& del_async  (std::string_view path, AsyncHandler h) { return add_async(Method::Delete, path, std::move(h)); }
    App& patch_async(std::string_view path, AsyncHandler h) { return add_async(Method::Patch,  path, std::move(h)); }
    App& head_async (std::string_view path, AsyncHandler h) { return add_async(Method::Head,   path, std::move(h)); }

    // -----------------------------------------------------------------------
    // WebSocket / SSE — forwarded straight to the engine.
    // -----------------------------------------------------------------------
    App& websocket(const std::string& path, http::WebSocketHandler handler) {
        assert(!path.empty());
        assert(handler != nullptr);
        ws_handlers_.push_back({path, std::move(handler)});
        return *this;
    }

    App& sse_coro(const std::string& path, http::CoroSSEHandler handler) {
        assert(!path.empty());
        assert(handler != nullptr);
        sse_handlers_.push_back({path, std::move(handler)});
        return *this;
    }

    // -----------------------------------------------------------------------
    // Middleware (global). Folded right-to-left at build time.
    // -----------------------------------------------------------------------
    App& use(Middleware mw) {
        assert(mw != nullptr);
        assert(!started_);
        middleware_.push_back(to_async(std::move(mw)));
        return *this;
    }

    App& use_async(AsyncMiddleware mw) {
        assert(mw != nullptr);
        assert(!started_);
        middleware_.push_back(std::move(mw));
        return *this;
    }

    // -----------------------------------------------------------------------
    // Lifecycle.
    // -----------------------------------------------------------------------
    // Blocking run on host:port (cleartext HTTP/1.1 by default).
    int run(std::string_view host, uint16_t port);
    // Non-blocking; server runs on background threads.
    int start_background(std::string_view host, uint16_t port);
    void stop();
    bool is_running() const noexcept;

    // Introspection.
    std::size_t route_count() const noexcept { return routes_.size(); }
    std::size_t middleware_count() const noexcept { return middleware_.size(); }

private:
    // One registered route. Exactly one of sync/async is populated.
    struct RouteEntry {
        Method        method;
        std::string   path;       // owned so router string_views stay valid
        Handler       sync;       // empty when async
        AsyncHandler  async_;     // empty when sync
        bool          is_async;
    };

    App& add_sync(Method m, std::string_view path, Handler h) {
        assert(h != nullptr);
        assert(!started_);
        routes_.push_back(RouteEntry{m, std::string(path), std::move(h),
                                     AsyncHandler{}, false});
        return *this;
    }

    App& add_async(Method m, std::string_view path, AsyncHandler h) {
        assert(h != nullptr);
        assert(!started_);
        routes_.push_back(RouteEntry{m, std::string(path), Handler{},
                                     std::move(h), true});
        return *this;
    }

    // Build the router + the engine handler. Called once from run/start.
    void build_dispatch();

    // Run the middleware chain for one matched route, terminal = handler.
    core::coro_task<void> run_chain(std::size_t route_index,
                                    Request& req, Response& res) const;

    Config config_;

    std::vector<RouteEntry>      routes_;
    std::vector<AsyncMiddleware> middleware_;

    struct WsReg  { std::string path; http::WebSocketHandler handler; };
    struct SseReg { std::string path; http::CoroSSEHandler   handler; };
    std::vector<WsReg>  ws_handlers_;
    std::vector<SseReg> sse_handlers_;

    std::unique_ptr<Router>                   router_;
    std::unique_ptr<http::CoroUnifiedServer>  server_;
    // route_id (from router.add) -> index into routes_. Sized at build().
    std::vector<std::size_t>                  route_id_to_index_;

    bool started_ = false;
};

}  // namespace bolt::api
