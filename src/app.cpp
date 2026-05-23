// app.cpp — implementation of bolt::api::App: dispatch bridge + middleware fold.
//
// See app.h for the public contract. The hot path is build once, then per
// request: method_from -> router.match -> Request/Response -> middleware chain
// -> matched handler -> CoroHttpResponse.

#include "boltapi/app.h"

#include "boltapi/compression.h"
#include "boltapi/core/logger.h"

#include <cassert>
#include <cstdio>
#include <utility>

// M3 seam: the protocol registry header is always available (header-only,
// inert). The stub factories (register_http3/register_webrtc) are only declared
// + linkable under their compile flags, so calls to them are guarded the same
// way below.
#include "boltapi/protocol.h"

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

// ---------------------------------------------------------------------------
// Built-in gzip compression middleware (M2). Inserted as the LAST link in the
// chain so it runs INNERMOST — closest to the handler — and therefore sees the
// final response body after the handler (and any user middleware) has produced
// it. Awaits next() (the handler), then conditionally replaces the body.
//
// Compresses only when ALL hold:
//   * Config.enable_compression                       (caller opted in)
//   * a real gzip backend is compiled in              (BOLTAPI_HAVE_GZIP)
//   * the request's Accept-Encoding lists gzip
//   * the response body exceeds kMinCompressBytes     (tiny bodies aren't worth it)
//   * no Content-Encoding is already set              (don't double-encode)
// Otherwise the body passes through untouched. On success it sets
// Content-Encoding: gzip, fixes Content-Length, and adds Vary: Accept-Encoding.
// ---------------------------------------------------------------------------
constexpr std::size_t kMinCompressBytes = 256;

AsyncMiddleware make_compression_middleware() {
    return [](Request& req, Response& res, Next next) -> core::coro_task<void> {
        co_await next();

        if (!compression::gzip_available()) {
            co_return;  // identity mode: nothing to do
        }

        http::CoroHttpResponse& raw = res.raw();

        // Already encoded? Leave it.
        if (raw.headers.find("Content-Encoding") != raw.headers.end()) {
            co_return;  // CoroResponseHeaders::find is case-insensitive, end()==entries+count
        }
        // Body below the threshold? Not worth the gzip framing overhead.
        if (raw.body.size() <= kMinCompressBytes) {
            co_return;
        }
        // Client must accept gzip.
        const std::string ae = req.header("Accept-Encoding");
        if (!compression::accepts_gzip(ae)) {
            co_return;
        }

        bool ok = false;
        std::string encoded = compression::gzip_encode(raw.body, ok);
        if (!ok) {
            co_return;  // backend hiccup: serve identity
        }

        raw.body.swap(encoded);
        raw.headers.set("Content-Encoding", "gzip");
        raw.headers.set("Content-Length", std::to_string(raw.body.size()));
        // Caches must key on Accept-Encoding now that the body varies by it.
        raw.headers.set("Vary", "Accept-Encoding");
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

    // Append the compression middleware LAST so it runs innermost (closest to
    // the handler) and observes the final response body. Added after the CORS
    // prepend so ordering is fixed before the router is built.
    if (config_.enable_compression) {
        middleware_.push_back(make_compression_middleware());
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
                cresp.headers.set("Content-Type", "text/plain; charset=utf-8");
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
// init_protocol_seams — M3 HTTP/3 + WebRTC seam hook.
//
// This is the runtime side of the M3 scaffold. It is deliberately conservative:
// enabling a seam at runtime NEVER affects the H1/H2 server. The four cases:
//
//   flag-runtime OFF                      -> nothing (the common path).
//   runtime ON  + compile option OFF      -> one-time stderr warning; no-op.
//   runtime ON  + compile option ON       -> register the stub factory, create
//                                            it, call serve() on a (stub)
//                                            UdpTransport; serve() returns
//                                            NotImplemented, which we log. The
//                                            stub instance is then dropped.
//                                            H1/H2 keeps serving regardless.
//
// No exceptions, no blocking, no crash on any path.
// ---------------------------------------------------------------------------
void App::init_protocol_seams() {
    // Fast exit: neither seam requested. Keep the default path branch-light.
    if (!config_.enable_http3 && !config_.enable_webrtc) {
        return;
    }

#if defined(BOLTAPI_WITH_HTTP3) || defined(BOLTAPI_WITH_WEBRTC)
    proto::ProtocolRegistry registry;
#endif

    if (config_.enable_http3) {
#if defined(BOLTAPI_WITH_HTTP3)
        const proto::Status reg = proto::register_http3(registry);
        if (reg.is_ok() && registry.has(proto::ProtocolId::Http3)) {
            std::unique_ptr<proto::IProtocol> h3 =
                registry.create(proto::ProtocolId::Http3);
            assert(h3 != nullptr);
            const uint16_t udp_port =
                config_.http3_port != 0 ? config_.http3_port
                                        : config_.server.http1_port;
            transport::UdpTransport udp(
                transport::Endpoint{config_.server.host, udp_port});
            // Stub serve() returns NotImplemented; log it and move on.
            const proto::Status served = h3->serve(udp);
            if (proto::is_not_implemented(served)) {
                std::fprintf(stderr,
                    "[boltapi] HTTP/3 enabled but not yet implemented "
                    "(seam stub on UDP :%u); continuing with HTTP/1.1+HTTP/2.\n",
                    static_cast<unsigned>(udp_port));
            }
        }
#else
        std::fprintf(stderr,
            "[boltapi] Config.enable_http3=true ignored: built without "
            "BOLTAPI_WITH_HTTP3. Reconfigure with -DBOLTAPI_WITH_HTTP3=ON.\n");
#endif
    }

    if (config_.enable_webrtc) {
        const uint16_t udp_port = webrtc_config_.udp_port != 0
                                      ? webrtc_config_.udp_port
                                      : config_.server.http1_port;

#if defined(BOLTAPI_WITH_WEBRTC)
        // WebRTC connection machinery wave: start a REAL UdpTransport + ICE-lite
        // IceAgent. Gather host candidates, bind the UDP port, route inbound
        // STUN to the agent's binding responder, and log candidates + creds. A
        // signaling route (POST /webrtc/offer producing build_answer) is a TODO
        // hook for the next wave. This is fully isolated from the H1/H2 server:
        // it owns its own socket + receive thread and shuts down with the App.
        webrtc_agent_ = std::make_unique<webrtc::IceAgent>();
        if (!webrtc_config_.ice_ufrag.empty() &&
            !webrtc_config_.ice_pwd.empty()) {
            webrtc_agent_->set_credentials(webrtc_config_.ice_ufrag,
                                           webrtc_config_.ice_pwd);
        }
        webrtc_agent_->generate_credentials(0);  // fills any missing creds

        webrtc_transport_ = std::make_unique<net::UdpTransport>();
        const bool bound =
            webrtc_transport_->bind(config_.server.host.c_str(), udp_port);
        if (bound) {
            const uint16_t actual = webrtc_transport_->bound_port();
            const std::size_t ncand =
                webrtc_agent_->gather_host_candidates(actual);

            net::UdpTransport* tp = webrtc_transport_.get();
            webrtc::IceAgent*  ag = webrtc_agent_.get();
            webrtc_transport_->set_stun_handler(
                [tp, ag](const sockaddr* peer, int plen,
                         const std::uint8_t* data, std::size_t len) {
                    ag->handle_stun(*tp, peer, plen, data, len);
                });
            webrtc_transport_->start();

            std::fprintf(stderr,
                "[boltapi] WebRTC: ICE-lite agent up on UDP :%u — "
                "ufrag=%.*s pwd=%.*s, %zu host candidate(s), %zu data-channel "
                "handler(s); signaling route is a next-wave TODO. H1/H2 "
                "unaffected.\n",
                static_cast<unsigned>(actual),
                static_cast<int>(ag->ufrag().size()), ag->ufrag().data(),
                static_cast<int>(ag->pwd().size()), ag->pwd().data(),
                ncand, dc_handlers_.size());
            for (std::size_t i = 0; i < ncand; ++i) {
                const std::string line = ag->candidate(i).to_string();
                std::fprintf(stderr, "[boltapi] WebRTC:   a=%s\n", line.c_str());
            }
        } else {
            std::fprintf(stderr,
                "[boltapi] WebRTC: failed to bind UDP :%u; ICE transport not "
                "started. H1/H2 unaffected.\n",
                static_cast<unsigned>(udp_port));
            webrtc_transport_.reset();
            webrtc_agent_.reset();
        }

        // Keep the protocol-registry path exercised so the seam can't rot.
        const proto::Status reg = proto::register_webrtc(registry);
        (void)reg;
#else
        std::fprintf(stderr,
            "[boltapi] Config.enable_webrtc=true ignored: built without "
            "BOLTAPI_WITH_WEBRTC. Reconfigure with -DBOLTAPI_WITH_WEBRTC=ON. "
            "(would bind UDP :%u; %zu data-channel handler(s))\n",
            static_cast<unsigned>(udp_port), dc_handlers_.size());
#endif
    }
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
    init_protocol_seams();  // M3: no-op unless a seam flag is set
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
    init_protocol_seams();  // M3: no-op unless a seam flag is set
    started_ = true;
    return server_->start_background();
}

void App::stop() {
    if (server_ && started_) {
        server_->stop();
    }
#if defined(BOLTAPI_WITH_WEBRTC)
    // Clean WebRTC teardown: stop the receive thread + close the UDP socket
    // before the agent is destroyed. Idempotent (stop() guards on handle).
    if (webrtc_transport_) {
        webrtc_transport_->stop();
        webrtc_transport_.reset();
    }
    webrtc_agent_.reset();
#endif
    started_ = false;
}

bool App::is_running() const noexcept {
    return started_ && server_ && server_->is_running();
}

}  // namespace bolt::api
