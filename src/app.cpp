// app.cpp — implementation of bolt::api::App: dispatch bridge + middleware fold.
//
// See app.h for the public contract. The hot path is build once, then per
// request: method_from -> router.match -> Request/Response -> middleware chain
// -> matched handler -> CoroHttpResponse.

#include "boltapi/app.h"

#include <cassert>
#include <utility>

namespace bolt::api {

// ---------------------------------------------------------------------------
// Built-in CORS middleware (M1: simple, single configured origin or "*").
// Inserted FIRST when Config.enable_cors so its headers wrap every response and
// it can short-circuit OPTIONS preflight. (The richer CorsMiddleware in
// http/cors.h operates on the engine's low-level Http1Response; this facade-level
// version works on Request/Response and is what M1 wires.)
// ---------------------------------------------------------------------------
namespace {

AsyncMiddleware make_cors_middleware(std::string origin) {
    assert(!origin.empty());
    return [origin = std::move(origin)](Request& req, Response& res, Next next)
               -> core::coro_task<void> {
        res.header("Access-Control-Allow-Origin", origin);
        res.header("Access-Control-Allow-Methods",
                   "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS");
        res.header("Access-Control-Allow-Headers",
                   "Content-Type, Authorization, X-Requested-With");
        // Preflight: answer OPTIONS immediately without invoking the chain.
        if (req.method() == "OPTIONS") {
            res.status(204);
            co_return;  // short-circuit: do not call next()
        }
        co_await next();
        co_return;
    };
}

}  // namespace

// ---------------------------------------------------------------------------
// Middleware fold: build the chain for a matched route. The terminal Next runs
// the matched handler; each middleware wraps the inner Next right-to-left. The
// fold is bounded by middleware_.size() (no unbounded recursion).
// ---------------------------------------------------------------------------
core::coro_task<void> App::run_chain(std::size_t route_index,
                                     Request& req, Response& res) const {
    assert(route_index < routes_.size());
    assert(router_ != nullptr);

    const RouteEntry& entry = routes_[route_index];

    // Terminal continuation: invoke the matched handler. Sync handlers run
    // inline and produce an already-ready coro_task; async handlers are awaited.
    Next terminal = [&entry, &req, &res]() -> core::coro_task<void> {
        if (entry.is_async) {
            assert(entry.async_ != nullptr);
            co_await entry.async_(req, res);
        } else {
            assert(entry.sync != nullptr);
            entry.sync(req, res);
        }
        co_return;
    };

    // Fold right-to-left: chain[i] wraps chain[i+1]. We keep the inner Next in a
    // shared_ptr so each captured lambda owns a stable continuation node. (This
    // is the per-request std::function/heap cost flagged in middleware.h.)
    auto inner = std::make_shared<Next>(std::move(terminal));
    const std::size_t n = middleware_.size();
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t i = n - 1 - k;  // right-to-left
        const AsyncMiddleware& mw = middleware_[i];
        auto next_node = inner;  // capture current inner as this link's next()
        auto wrapped = std::make_shared<Next>(
            [&mw, &req, &res, next_node]() -> core::coro_task<void> {
                co_await mw(req, res, *next_node);
                co_return;
            });
        inner = wrapped;
    }

    // Drive the outermost link to completion.
    co_await (*inner)();
    co_return;
}

// ---------------------------------------------------------------------------
// build_dispatch — register routes into the Router, build() once, install the
// single engine handler that performs match + chain + response.
// ---------------------------------------------------------------------------
void App::build_dispatch() {
    assert(!started_);
    assert(server_ != nullptr);

    // Prepend the CORS middleware so it wraps everything (must run before any
    // user middleware / handler). Done before the router so order is fixed.
    if (config_.enable_cors) {
        middleware_.insert(middleware_.begin(),
                           make_cors_middleware(config_.cors_origin));
    }

    router_ = std::make_unique<Router>();

    // route_id (monotonic from 0) -> index into routes_.
    route_id_to_index_.assign(routes_.size(), routes_.size());
    for (std::size_t i = 0; i < routes_.size(); ++i) {
        const RouteEntry& e = routes_[i];
        const uint32_t id = router_->add(e.method, e.path);
        assert(id != kInvalidRoute);
        if (id == kInvalidRoute) continue;  // skip malformed route, keep serving
        if (id >= route_id_to_index_.size()) {
            route_id_to_index_.resize(id + 1, routes_.size());
        }
        route_id_to_index_[id] = i;
    }
    router_->build();

    // Forward WebSocket / SSE handlers to the engine.
    for (const WsReg& w : ws_handlers_) {
        server_->add_websocket_handler(w.path, w.handler);
    }
    for (const SseReg& s : sse_handlers_) {
        server_->add_sse_handler(s.path, s.handler);
    }

    // The single dispatch handler. Captures `this`; App outlives the server
    // (server_ is owned by App and stopped in stop()/dtor).
    App* self = this;
    server_->set_handler(
        [self](const http::CoroHttpRequest& creq)
            -> core::coro_task<http::CoroHttpResponse> {
            assert(self != nullptr);
            assert(self->router_ != nullptr);

            http::CoroHttpResponse cresp;
            cresp.status = 200;
            cresp.status_message = "OK";

            // Path component only (router matches on path; query stripped).
            std::string_view target(creq.path);
            const std::size_t qm = target.find('?');
            const std::string_view match_path =
                (qm == std::string_view::npos) ? target : target.substr(0, qm);

            const Method method = method_from(creq.method);
            MatchResult mr;
            if (method != Method::Unknown) {
                mr = self->router_->match(method, match_path);
            }

            if (!mr.matched()) {
                // No route. 404. (405 is a documented optional for v1.)
                cresp.status = 404;
                cresp.status_message = "Not Found";
                cresp.headers["Content-Type"] = "text/plain; charset=utf-8";
                cresp.body = "Not Found";
                co_return cresp;
            }

            const std::size_t idx =
                (mr.route_id < self->route_id_to_index_.size())
                    ? self->route_id_to_index_[mr.route_id]
                    : self->routes_.size();
            if (idx >= self->routes_.size()) {
                cresp.status = 500;
                cresp.status_message = "Internal Server Error";
                cresp.body = "route table desync";
                co_return cresp;
            }

            Request  req(creq, mr.params, mr.param_count);
            Response res(cresp);

            co_await self->run_chain(idx, req, res);

            // Ensure the reason phrase tracks any status set via raw mutation.
            cresp.status_message = Response::reason_phrase(cresp.status);
            co_return cresp;
        });
}

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------
int App::run(std::string_view host, uint16_t port) {
    assert(!started_);
    assert(port != 0);

    config_.server.host        = std::string(host);
    config_.server.http1_port  = port;
    server_ = std::make_unique<http::CoroUnifiedServer>(config_.server);

    build_dispatch();
    started_ = true;
    return server_->start();  // blocking
}

int App::start_background(std::string_view host, uint16_t port) {
    assert(!started_);
    assert(port != 0);

    config_.server.host        = std::string(host);
    config_.server.http1_port  = port;
    server_ = std::make_unique<http::CoroUnifiedServer>(config_.server);

    build_dispatch();
    started_ = true;
    return server_->start_background();
}

void App::stop() {
    if (server_ && started_) {
        server_->stop();
    }
    started_ = false;
}

bool App::is_running() const noexcept {
    return started_ && server_ && server_->is_running();
}

}  // namespace bolt::api
