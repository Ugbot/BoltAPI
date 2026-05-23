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

#if defined(BOLTAPI_WITH_WEBRTC)
#include "boltapi/net/udp_transport.h"
#include "boltapi/webrtc/ice.h"
#include "boltapi/webrtc/dtls.h"
#include "boltapi/webrtc/data_channel.h"
#include "boltapi/webrtc/peer_hub.h"
#endif

#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api {

// ---------------------------------------------------------------------------
// WebRtcConfig — minimal additive config for the WebRTC data-channel surface
// (Phase 1: signaling + codecs ready; transport not yet implemented). All
// fields have sane defaults so `app.enable_webrtc()` works with no arguments.
// ---------------------------------------------------------------------------
struct WebRtcConfig {
    // UDP port the future ICE/DTLS/SCTP transport will bind. 0 = reuse the
    // HTTP listen port number over UDP (decided when the transport lands).
    uint16_t    udp_port = 0;

    // Local ICE credentials policy. When empty, the (future) agent generates
    // random RFC 8445-conformant ufrag/pwd; supplying them here pins them
    // (useful for tests / deterministic signaling).
    std::string ice_ufrag;   // empty => auto-generate
    std::string ice_pwd;     // empty => auto-generate

    // Advertise a=ice-lite in the answer (server-side answerer optimisation).
    bool        ice_lite     = false;

    // SCTP association parameters surfaced into the SDP answer.
    uint16_t    sctp_port        = 5000;
    uint32_t    max_message_size = 262144;

    // The remote (browser/offerer) DTLS certificate fingerprint extracted from
    // the SDP offer's a=fingerprint line. When set, the DTLS server verifies the
    // peer cert's SHA-256 against it after the handshake (the WebRTC identity
    // binding) and rejects on mismatch. Empty => verification skipped (the
    // handshake alone establishes the channel — used before signaling lands).
    std::string offer_fingerprint;
};

class App {
public:
    // Sync handler: fill the Response, return. Wrapped into a ready coro_task.
    using Handler = std::function<void(Request&, Response&)>;
    // Async handler: may co_await; fill the Response, co_return.
    using AsyncHandler =
        std::function<core::coro_task<void>(Request&, Response&)>;

    // Data-channel message handler: (label, data, len). Mirrors the WS handler
    // registration shape. Wired to a real SCTP stream in a later wave; today it
    // is recorded and the surface logs that transport is not yet implemented.
    using DataChannelHandler =
        std::function<void(std::string_view label, const void* data,
                           std::size_t len)>;

    // Forwarding config: wraps a CoroUnifiedServerConfig plus facade-level knobs.
    struct Config {
        http::CoroUnifiedServerConfig server;
        bool        enable_cors  = false;
        std::string cors_origin  = "*";
        // M2 hook (declared now so the surface is stable; not wired yet).
        bool        enable_compression = false;

        // M3 seam hooks (additive; default OFF). When a flag is set AND the
        // matching compile option (BOLTAPI_WITH_HTTP3 / BOLTAPI_WITH_WEBRTC) is
        // ON, App consults the ProtocolRegistry on start; the registered factory
        // is a STUB, so App logs "not yet implemented" (NotImplemented) and
        // CONTINUES serving H1/H2 — it never crashes or blocks. When the compile
        // option is OFF, setting the runtime flag is a no-op warning.
        bool        enable_http3  = false;
        uint16_t    http3_port    = 0;      // 0 = reuse http1_port number over UDP
        bool        enable_webrtc = false;

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
    // WebRTC (additive; Phase 1 — signaling/codecs ready, transport pending).
    //
    // enable_webrtc() turns on the WebRTC surface and stores its config. It is
    // purely additive: it never touches the H1/H2 serving path. Until the
    // ICE/DTLS/SCTP transport lands, init_protocol_seams() logs a clear
    // "WebRTC: signaling/codecs ready, transport not yet implemented" message.
    // Returns *this for chaining, mirroring the rest of the facade.
    // -----------------------------------------------------------------------
    App& enable_webrtc(WebRtcConfig cfg = {}) {
        assert(!started_);
        config_.enable_webrtc = true;
        webrtc_config_ = std::move(cfg);
        return *this;
    }

    // Register a data-channel message handler for a given label, mirroring the
    // websocket(...) registration shape. The handler is recorded now and will
    // be invoked by the data-channel layer once the transport is implemented.
    App& on_data_channel(std::string label, DataChannelHandler handler) {
        assert(!label.empty());
        assert(handler != nullptr);
        assert(!started_);
        dc_handlers_.push_back({std::move(label), std::move(handler)});
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

    // M3 seam hook: if enable_http3/enable_webrtc are set, consult the protocol
    // registry. Stub factories return NotImplemented, which is logged; H1/H2
    // serving is unaffected. Safe no-op when no seam flags are set. Called once
    // from run/start_background after build_dispatch().
    void init_protocol_seams();

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

    // WebRTC (additive; Phase 1). Config + per-label data-channel handlers.
    struct DcReg { std::string label; DataChannelHandler handler; };
    WebRtcConfig        webrtc_config_{};
    std::vector<DcReg>  dc_handlers_;

#if defined(BOLTAPI_WITH_WEBRTC)
    // When enable_webrtc is set AND the flag is on, App owns a real UdpTransport
    // + ICE-lite IceAgent: it gathers host candidates, binds the WebRtcConfig
    // UDP port, routes inbound STUN to the agent's binding responder, and logs
    // the gathered candidates + ufrag/pwd. Started in init_protocol_seams() and
    // torn down cleanly in stop(). A signaling route is a TODO hook (next wave).
    // None of this touches the H1/H2 server.
    std::unique_ptr<net::UdpTransport>   webrtc_transport_;
    std::unique_ptr<webrtc::IceAgent>    webrtc_agent_;
    // DTLS server (answerer, setup:passive): a shared context (self-signed cert
    // + SHA-256 fingerprint for the SDP a=fingerprint) and a per-peer session
    // manager wired as the transport's datagram handler (first byte 20..63).
    // Created in init_protocol_seams(); torn down before the transport in stop().
    std::unique_ptr<webrtc::DtlsContext>        webrtc_dtls_ctx_;
    std::unique_ptr<webrtc::DtlsSessionManager> webrtc_dtls_mgr_;
    // Data-channel hub: bridges DTLS app-data to per-peer SCTP/DCEP stacks and
    // surfaces established channels to the registered on_data_channel handlers.
    // Created in init_protocol_seams() after the DTLS manager; torn down before
    // the DTLS manager in stop().
    std::unique_ptr<webrtc::WebRtcPeerHub>      webrtc_hub_;
#endif

    std::unique_ptr<Router>                   router_;
    std::unique_ptr<http::CoroUnifiedServer>  server_;
    // route_id (from router.add) -> index into routes_. Sized at build().
    std::vector<std::size_t>                  route_id_to_index_;

    bool started_ = false;
};

}  // namespace bolt::api
