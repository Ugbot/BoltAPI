// app.cpp — implementation of bolt::api::App: dispatch bridge + middleware fold.
//
// See app.h for the public contract. The hot path is build once, then per
// request: method_from -> router.match -> Request/Response -> middleware chain
// -> matched handler -> CoroHttpResponse.

#include "boltapi/app.h"

#include "boltapi/compression.h"
#include "boltapi/core/logger.h"

#if defined(BOLTAPI_WITH_WEBRTC)
#include "boltapi/webrtc/sdp.h"
#endif

#include <cassert>
#include <cstdio>
#include <string>
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

#if defined(BOLTAPI_WITH_WEBRTC)
    // WebRTC signaling route (additive; never touches H1/H2). When enable_webrtc
    // is set AND a signaling_path is configured, register an ordinary POST route
    // that accepts the peer OFFER SDP and returns OUR ANSWER SDP. The handler
    // reads the live WebRTC stack (ICE/DTLS) lazily at request time — that state
    // is created in init_protocol_seams(), which runs after build_dispatch() but
    // before any request is served, so the captured `this` is fully wired.
    if (config_.enable_webrtc && !webrtc_config_.signaling_path.empty()) {
        App* self = this;
        routes_.push_back(RouteEntry{
            Method::Post, webrtc_config_.signaling_path,
            [self](Request& req, Response& res) {
                std::string answer;
                if (!self->handle_webrtc_offer(req.body(), answer)) {
                    res.status(400)
                       .content_type("text/plain; charset=utf-8")
                       .send("invalid WebRTC offer");
                    return;
                }
                // application/sdp is the canonical answer media type; aiortc /
                // browsers accept the raw SDP body for an HTTP-POST exchange.
                res.status(200).content_type("application/sdp").send(answer);
            },
            AsyncHandler{}, false});
    }

    // WI — Trickle ICE (RFC 8838): a POST route that accepts ONE incremental
    // remote candidate (RTCIceCandidateInit JSON, a bare candidate line, or
    // "end-of-candidates") after the offer/answer. Mirrors the /webrtc/offer
    // route style. Only wired when full_ice is set (trickle needs the full
    // agent's checklist) AND a trickle_path is configured.
    if (config_.enable_webrtc && webrtc_config_.full_ice &&
        !webrtc_config_.trickle_path.empty()) {
        App* self = this;
        routes_.push_back(RouteEntry{
            Method::Post, webrtc_config_.trickle_path,
            [self](Request& req, Response& res) {
                if (!self->handle_webrtc_trickle(req.body())) {
                    res.status(400)
                       .content_type("text/plain; charset=utf-8")
                       .send("invalid trickle candidate");
                    return;
                }
                // 204 No Content — the candidate was accepted (RFC 8838 has no
                // response body for incremental candidate delivery).
                res.status(204).send("");
            },
            AsyncHandler{}, false});
    }
#endif

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
    // (server_ is owned by App and stopped in stop()/dtor). The body lives in
    // dispatch_coro_ so the HTTP/3 path (dispatch_http3) reuses it verbatim.
    App* self = this;
    server_->set_handler(
        [self](const http::CoroHttpRequest& creq)
            -> core::coro_task<http::CoroHttpResponse> {
            assert(self != nullptr);
            assert(self->router_ != nullptr);
            co_return co_await self->dispatch_coro_(creq);
        });
}

// ---------------------------------------------------------------------------
// dispatch_coro_ — the shared match -> chain -> response coroutine. Reused by
// both the engine handler (H1/H2) and the synchronous HTTP/3 entry so all three
// protocols traverse the SAME router + middleware + handler path.
// ---------------------------------------------------------------------------
core::coro_task<http::CoroHttpResponse> App::dispatch_coro_(
    const http::CoroHttpRequest& creq) const {
    assert(router_ != nullptr);
    assert(route_id_to_index_.size() >= routes_.size() ||
           route_id_to_index_.empty());

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
        mr = router_->match(method, match_path);
    }

    if (!mr.matched()) {
        cresp.status = 404;
        cresp.status_message = "Not Found";
        cresp.headers.set("Content-Type", "text/plain; charset=utf-8");
        cresp.body = "Not Found";
        co_return cresp;
    }

    const std::size_t idx = (mr.route_id < route_id_to_index_.size())
                                ? route_id_to_index_[mr.route_id]
                                : routes_.size();
    if (idx >= routes_.size()) {
        cresp.status = 500;
        cresp.status_message = "Internal Server Error";
        cresp.body = "route table desync";
        co_return cresp;
    }

    Request  req(creq, mr.params, mr.param_count);
    Response res(cresp);

    co_await run_chain(idx, req, res);

    cresp.status_message = Response::reason_phrase(cresp.status);
    co_return cresp;
}

// ---------------------------------------------------------------------------
// dispatch_http3 — synchronous bridge entry. Drives the (lazy) dispatch
// coroutine to completion inline and returns the response. The App's sync
// handlers run inline (initial_suspend is suspend_always; the first resume runs
// the fully-synchronous chain through co_return), so one resume completes it.
// TigerStyle: asserts the router is built + the coroutine completes; no throw.
// ---------------------------------------------------------------------------
http::CoroHttpResponse App::dispatch_http3(const http::CoroHttpRequest& req) {
    assert(router_ != nullptr && "dispatch_http3 before build_dispatch");
    assert(started_ && "dispatch_http3 before start");

    core::coro_task<http::CoroHttpResponse> task = dispatch_coro_(req);
    // Take ownership of the typed handle so we can read the promise value and
    // destroy the frame deterministically (the task no longer owns it).
    auto handle = task.release();
    assert(handle && "dispatch coroutine has no handle");
    if (!handle.done()) {
        handle.resume();  // sync chain runs to co_return in one resume
    }
    assert(handle.done() && "HTTP/3 dispatch did not complete synchronously");

    http::CoroHttpResponse resp = std::move(handle.promise().value());
    handle.destroy();
    return resp;
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
        // Keep the protocol-registry path exercised (the seam stays honest).
        const proto::Status reg = proto::register_http3(registry);
        (void)reg;
        start_http3();  // W5b: a REAL QUIC/HTTP3 server endpoint over UDP.
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
        // hook for the next wave. The UdpTransport runs its receive loop as a
        // coroutine on the engine's UNIFIED async event loop (the global
        // IODispatcher — the same async_io backend that drives TCP/HTTP), NOT a
        // private receive thread. It owns only its UDP socket and shuts down
        // with the App. H1/H2 are unaffected.
        webrtc_agent_ = std::make_unique<webrtc::IceAgent>();
        if (!webrtc_config_.ice_ufrag.empty() &&
            !webrtc_config_.ice_pwd.empty()) {
            webrtc_agent_->set_credentials(webrtc_config_.ice_ufrag,
                                           webrtc_config_.ice_pwd);
        }
        webrtc_agent_->generate_credentials(0);  // fills any missing creds

        // WI — Full ICE (RFC 8445). When configured, stand up a FullIceAgent in
        // the CONTROLLED role (the browser/offerer is controlling) sharing OUR
        // ice-lite ufrag/pwd so a single signaled credential pair works for both
        // the ice-lite responder and the full agent. The STUN handler routes
        // inbound checks to it; trickle candidates are fed via the trickle route.
        if (webrtc_config_.full_ice) {
            webrtc_full_ice_ = std::make_unique<webrtc::FullIceAgent>();
            webrtc_full_ice_->set_role(webrtc::IceRole::Controlled);
            webrtc_full_ice_->set_credentials(webrtc_agent_->ufrag(),
                                              webrtc_agent_->pwd());
            webrtc_full_ice_->generate_credentials(0);
        }

        webrtc_transport_ = std::make_unique<net::UdpTransport>();
        // Bind the WebRTC UDP socket to ALL interfaces (0.0.0.0), independent of
        // the HTTP listen host. A peer (browser / aiortc) reaches us by sending
        // STUN from ITS host candidate (a real NIC) to OUR advertised candidate;
        // a socket bound to a single address (e.g. 127.0.0.1) would NOT receive
        // a datagram whose destination is a different local interface, which
        // breaks same-host interop on Windows (NIC source -> loopback dest is not
        // delivered to a loopback-bound socket). 0.0.0.0 receives on every
        // interface, so every advertised host candidate is actually reachable.
        const bool bound = webrtc_transport_->bind("0.0.0.0", udp_port);
        if (bound) {
            const uint16_t actual = webrtc_transport_->bound_port();
            // Gather host candidates from all real interfaces (+ loopback) so a
            // peer on the LAN, same host, or loopback can all reach us.
            const std::size_t ncand =
                webrtc_agent_->gather_host_candidates(actual, "0.0.0.0");

            net::UdpTransport*    tp = webrtc_transport_.get();
            webrtc::IceAgent*     ag = webrtc_agent_.get();
            webrtc::FullIceAgent* fa = webrtc_full_ice_.get();  // null if !full_ice
            webrtc_transport_->set_stun_handler(
                [tp, ag, fa](const sockaddr* peer, int plen,
                             const std::uint8_t* data, std::size_t len) {
                    // Full ICE first (when configured): it both RESPONDS to peer
                    // checks AND matches responses to its own checks. If it does
                    // not own the datagram it falls through to the ice-lite
                    // responder, preserving the existing live-STUN path.
                    if (fa != nullptr) {
                        const auto r = fa->handle_stun(*tp, peer, plen, data, len);
                        if (r != webrtc::FullIceAgent::HandleResult::Ignored)
                            return;
                    }
                    ag->handle_stun(*tp, peer, plen, data, len);
                });

            // DTLS server (answerer, setup:passive): build the shared context
            // (self-signed cert + SHA-256 fingerprint) and a per-peer session
            // manager, then route inbound DTLS datagrams (first byte 20..63) to
            // it. The manager creates a session on the first ClientHello and
            // drives SSL_do_handshake over memory BIOs, sending records back via
            // the transport. The offer's a=fingerprint (when known from
            // signaling) is the identity the peer cert is verified against.
            webrtc_dtls_ctx_ = webrtc::DtlsContext::create();
            if (webrtc_dtls_ctx_ && webrtc_dtls_ctx_->is_valid()) {
                webrtc_dtls_mgr_ = std::make_unique<webrtc::DtlsSessionManager>(
                    *webrtc_dtls_ctx_, *webrtc_transport_);
                if (!webrtc_config_.offer_fingerprint.empty()) {
                    webrtc_dtls_mgr_->set_offer_fingerprint(
                        webrtc_config_.offer_fingerprint);
                }
                // Data-channel hub: bridges DTLS app-data to per-peer SCTP/DCEP
                // stacks and surfaces established channels to the registered
                // on_data_channel handlers. The hub IS the datagram handler: it
                // feeds DTLS, then (once established) drains decrypted SCTP
                // packets into the per-peer association and routes channel
                // messages to the App handler that matches the channel's label
                // (with "" as a wildcard). The handler may echo by sending back
                // on the channel.
                webrtc_hub_ = std::make_unique<webrtc::WebRtcPeerHub>(
                    *webrtc_dtls_mgr_, *webrtc_transport_);
                // Snapshot the registered handlers for the channel-ready lambda.
                std::vector<DcReg>* regs = &dc_handlers_;
                webrtc_hub_->set_channel_ready(
                    [regs](webrtc::DataChannel& ch) {
                        // Match by exact label, else fall back to a "" wildcard.
                        const std::string label(ch.label());
                        DataChannelHandler matched;
                        for (const DcReg& r : *regs) {
                            if (r.label == label) { matched = r.handler; break; }
                        }
                        if (!matched) {
                            for (const DcReg& r : *regs) {
                                if (r.label.empty()) { matched = r.handler; break; }
                            }
                        }
                        if (!matched) return;  // no handler for this label
                        webrtc::DataChannel* chp = &ch;
                        ch.on_message(
                            [matched, chp](const void* data, std::size_t len,
                                           bool is_binary) {
                                matched(*chp, data, len, is_binary);
                            });
                    });

                // WM5 media: declare the outbound media tracks and wire the
                // on_track handler. The hub pre-registers each declared track per
                // peer once SRTP keying is ready and, on the first inbound RTP for
                // an SSRC, surfaces a track via the track-ready callback. We bind
                // the App's on_track handler as the track's deliver sink so every
                // inbound RTP packet reaches the App (which may echo via
                // track.write -> interceptors -> SRTP -> UDP).
                for (const WebRtcConfig::MediaTrackSpec& ms :
                         webrtc_config_.media_tracks) {
                    const webrtc::MediaKind k = ms.kind == 1
                        ? webrtc::MediaKind::kVideo : webrtc::MediaKind::kAudio;
                    webrtc_hub_->add_track_spec(k, ms.ssrc, ms.payload_type,
                                                ms.codec.c_str());
                }
                MediaTrackHandler* th = &track_handler_;
                webrtc_hub_->set_track_ready(
                    [th](webrtc::MediaTrack& tr) {
                        if (*th == nullptr) return;
                        tr.set_deliver_sink(&App::media_deliver_trampoline, th);
                    });

                webrtc::WebRtcPeerHub* hub = webrtc_hub_.get();
                webrtc_transport_->set_datagram_handler(
                    [hub](const sockaddr* peer, int plen,
                          const std::uint8_t* data, std::size_t len) {
                        hub->feed(peer, plen, data, len);
                    });
            }

            webrtc_transport_->start();

            std::fprintf(stderr,
                "[boltapi] WebRTC: ICE-lite agent up on UDP :%u — "
                "ufrag=%.*s pwd=%.*s, %zu host candidate(s), %zu data-channel "
                "handler(s); signaling route POST %s. H1/H2 unaffected.\n",
                static_cast<unsigned>(actual),
                static_cast<int>(ag->ufrag().size()), ag->ufrag().data(),
                static_cast<int>(ag->pwd().size()), ag->pwd().data(),
                ncand, dc_handlers_.size(),
                webrtc_config_.signaling_path.empty()
                    ? "(disabled)"
                    : webrtc_config_.signaling_path.c_str());
            if (webrtc_dtls_ctx_ && webrtc_dtls_ctx_->is_valid()) {
                std::fprintf(stderr,
                    "[boltapi] WebRTC:   DTLS server ready (setup:passive) "
                    "a=fingerprint:sha-256 %s\n",
                    webrtc_dtls_ctx_->fingerprint().c_str());
            }
            for (std::size_t i = 0; i < ncand; ++i) {
                const std::string line = ag->candidate(i).to_string();
                std::fprintf(stderr, "[boltapi] WebRTC:   a=%s\n", line.c_str());
            }
        } else {
            std::fprintf(stderr,
                "[boltapi] WebRTC: failed to bind UDP :%u; ICE transport not "
                "started. H1/H2 unaffected.\n",
                static_cast<unsigned>(udp_port));
            webrtc_hub_.reset();
            webrtc_dtls_mgr_.reset();
            webrtc_dtls_ctx_.reset();
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

#if defined(BOLTAPI_WITH_HTTP3)
// ---------------------------------------------------------------------------
// start_http3 — W5b: stand up a real QUIC server endpoint on the HTTP/3 UDP
// port and bridge decoded HTTP/3 requests to the SAME dispatch path H1/H2 use.
//
// A net::UdpTransport binds the port (sharing the engine's IODispatcher). Its
// datagram handler feeds the owning QuicConnection (server role) under a mutex;
// the QuicConnection's send fn pushes datagrams back to the last seen peer. An
// H3Connection bridges: once 1-RTT keys are up it opens its control/QPACK uni
// streams + SETTINGS; per inbound request it builds a CoroHttpRequest, runs
// dispatch_http3(), and sends the CoroHttpResponse back over the stream. Single
// active peer (v1). Never touches the H1/H2 server.
// ---------------------------------------------------------------------------
void App::start_http3() {
    assert(config_.enable_http3 && "start_http3 without enable_http3");
    assert(http3_conn_ == nullptr && "start_http3 called twice");

    const uint16_t udp_port = config_.http3_port != 0 ? config_.http3_port
                                                      : config_.server.http1_port;
    http3_transport_ = std::make_unique<net::UdpTransport>();
    if (!http3_transport_->bind(config_.server.host.c_str(), udp_port)) {
        std::fprintf(stderr,
            "[boltapi] HTTP/3: failed to bind UDP :%u; H3 not started. "
            "H1/H2 unaffected.\n", static_cast<unsigned>(udp_port));
        http3_transport_.reset();
        return;
    }

    http3_quic_ = std::make_unique<quic::QuicConnection>();
    http3_conn_ = std::make_unique<http3::H3Connection>();

    // The server's outbound send fn targets the last peer that reached us. The
    // peer address is captured by the datagram handler before feed_datagram.
    auto peer = std::make_shared<sockaddr_storage>();
    auto peer_len = std::make_shared<int>(0);
    net::UdpTransport* tp = http3_transport_.get();
    auto send_fn = [tp, peer, peer_len](const std::uint8_t* d, std::size_t n) {
        if (*peer_len <= 0) return;
        tp->send(reinterpret_cast<const sockaddr*>(peer.get()), *peer_len, d, n);
    };
    if (!http3_quic_->init(/*is_server=*/true, send_fn)) {
        std::fprintf(stderr, "[boltapi] HTTP/3: QUIC init failed; H3 not started.\n");
        http3_conn_.reset(); http3_quic_.reset(); http3_transport_.reset();
        return;
    }

    http3_conn_->attach(*http3_quic_, /*is_server=*/true);
    App* self = this;
    http3::H3Connection* h3 = http3_conn_.get();
    http3_conn_->set_request_handler([self, h3](const http3::H3Request& r) {
        self->serve_http3_request(*h3, r);
    });

    quic::QuicConnection* qc = http3_quic_.get();
    http3::H3Connection* hc = http3_conn_.get();
    std::mutex* mtx = &http3_mtx_;
    http3_transport_->set_datagram_handler(
        [qc, hc, peer, peer_len, mtx](const sockaddr* p, int plen,
                                      const std::uint8_t* d, std::size_t n) {
            std::lock_guard<std::mutex> lk(*mtx);
            if (p != nullptr && plen > 0 &&
                plen <= static_cast<int>(sizeof(sockaddr_storage))) {
                std::memcpy(peer.get(), p, static_cast<std::size_t>(plen));
                *peer_len = plen;
            }
            qc->feed_datagram(d, n);
            if (qc->one_rtt_keys_ready()) hc->send_settings();
        });
    http3_transport_->start();

    std::fprintf(stderr,
        "[boltapi] HTTP/3: QUIC server up on UDP :%u (ALPN h3); requests bridge "
        "to the shared App dispatch path. H1/H2 unaffected.\n",
        static_cast<unsigned>(http3_transport_->bound_port()));
}

// ---------------------------------------------------------------------------
// serve_http3_request — build a CoroHttpRequest from a decoded H3Request, route
// it through dispatch_http3(), and send the response back over the H3 stream.
// Bounded: header views are copied into a stable per-call store (the H3 request
// views borrow QPACK/stream storage; CoroHttpRequest holds views, so the bytes
// must outlive the dispatch call). TigerStyle: asserts, no exceptions.
// ---------------------------------------------------------------------------
void App::serve_http3_request(http3::H3Connection& h3,
                              const http3::H3Request& r) {
    assert(started_ && "serve_http3_request before start");
    assert(r.method.size() <= 16 && "implausible HTTP method");

    http::CoroHttpRequest creq;
    creq.method = r.method;
    creq.path   = r.path;
    creq.body   = std::string_view(reinterpret_cast<const char*>(r.body),
                                   r.body_len);
    for (std::size_t i = 0; i < r.header_count &&
                            i < http::CoroHttpRequest::MAX_HEADERS; ++i) {
        creq.add_header(r.headers[i].name, r.headers[i].value);
    }

    http::CoroHttpResponse resp = dispatch_http3(creq);

    // Marshal response headers into the H3 send shape (views into resp storage).
    http3::H3ResponseHeader hdrs[http::CoroResponseHeaders::MAX_RESPONSE_HEADERS];
    std::size_t hc = 0;
    for (const auto& e : resp.headers) {
        if (hc >= http::CoroResponseHeaders::MAX_RESPONSE_HEADERS) break;
        hdrs[hc].name  = e.name;
        hdrs[hc].value = e.value;
        ++hc;
    }
    const std::uint8_t* body =
        reinterpret_cast<const std::uint8_t*>(resp.body.data());
    (void)h3.send_response(r.stream_id, resp.status, hdrs, hc, body,
                           resp.body.size());
}
#endif  // BOLTAPI_WITH_HTTP3

#if defined(BOLTAPI_WITH_WEBRTC)
// ---------------------------------------------------------------------------
// handle_webrtc_offer — the signaling exchange (offer parse -> stack config ->
// answer). Reused by the POST signaling route and the interop/unit tests.
//
//   1. Accept the OFFER SDP from `body`: raw SDP, or a JSON envelope
//      {"sdp":"...", "type":"offer"} (browsers/aiortc often POST either form).
//   2. Parse with our SDP codec; locate the m=application (data-channel) media.
//   3. Extract the peer ice-ufrag/ice-pwd (the STUN USERNAME the peer will use)
//      and the offer's DTLS a=fingerprint (the identity to bind the peer cert
//      to). Configure the live stack: pin the agent's EXPECTED remote ufrag/pwd
//      for USERNAME validation (ourUfrag:peerUfrag), and set the offer
//      fingerprint on the DTLS session manager.
//   4. Build OUR ANSWER (ice-lite, setup:passive, our ufrag/pwd, our
//      a=fingerprint:sha-256, our host a=candidate lines, the application
//      m-line, sctp-port + max-message-size, a=group:BUNDLE/mid).
//
// V1: a SINGLE active peer. A second offer re-pins the stack to the new peer.
// Multi-peer keyed by ufrag is a documented follow-up (WEBRTC_PLAN §13).
// ---------------------------------------------------------------------------

namespace {
// Unwrap the offer SDP from the POST body: a JSON {"sdp":"..."} envelope OR a
// raw SDP body (detected by a leading '{' after optional whitespace). On JSON,
// the extracted SDP is copied into `owned` (which must outlive the returned
// view). Returns false on a malformed JSON envelope. Bounded, no throw.
bool unwrap_offer_sdp(std::string_view body, std::string& owned,
                      std::string_view& out_sdp) noexcept {
    assert(owned.empty() && "unwrap_offer_sdp: owned must start empty");
    assert(out_sdp.empty() || out_sdp.data() != nullptr);
    out_sdp = body;
    std::size_t i = 0;
    while (i < body.size() && (body[i] == ' ' || body[i] == '\t' ||
                               body[i] == '\r' || body[i] == '\n')) {
        ++i;
    }
    if (i >= body.size() || body[i] != '{') return true;  // raw SDP
    json::Document doc = json::parse(body);
    if (!doc.ok()) return false;
    const std::string_view s = doc["sdp"].as_string();
    if (s.empty()) return false;
    owned.assign(s.data(), s.size());
    out_sdp = owned;
    return true;
}
}  // namespace

bool App::handle_webrtc_offer(std::string_view body, std::string& out_answer) {
    out_answer.clear();
    // The transport must be up (init_protocol_seams ran and bound the socket).
    if (!webrtc_agent_ || !webrtc_dtls_ctx_ || !webrtc_dtls_ctx_->is_valid()) {
        return false;
    }

    // Accept a JSON {"sdp":"..."} envelope OR a raw SDP body.
    std::string sdp_owned;
    std::string_view sdp_text;
    if (!unwrap_offer_sdp(body, sdp_owned, sdp_text)) return false;

    webrtc::SdpSession offer;
    if (webrtc::parse(sdp_text, offer) != webrtc::SdpError::Ok) return false;
    const webrtc::SdpMedia* app_m = offer.application_media();
    // Pick a transport-carrying section to read BUNDLEd ICE creds + fingerprint:
    // the data m-line if present, else the first m= section (audio/video). WM6
    // offers (aiortc `server`) may carry only audio+video with no data channel.
    const webrtc::SdpMedia* xport = app_m;
    if (xport == nullptr && offer.media_count > 0) xport = &offer.media[0];
    if (xport == nullptr) return false;

    // Peer ICE credentials: m-line first, then session-level (Firefox places
    // some attrs at session scope). Both ufrag and pwd are required for STUN.
    std::string_view peer_ufrag = xport->ice_ufrag();
    std::string_view peer_pwd   = xport->ice_pwd();
    if (peer_ufrag.empty()) peer_ufrag = offer.session_attr("ice-ufrag");
    if (peer_pwd.empty())   peer_pwd   = offer.session_attr("ice-pwd");
    if (peer_ufrag.empty() || peer_pwd.empty()) return false;

    // Offer DTLS fingerprint: m-line first, then session-level. Used to bind the
    // peer cert at DTLS-handshake completion (the WebRTC identity check).
    std::string_view offer_fp = xport->fingerprint();
    if (offer_fp.empty()) offer_fp = offer.session_attr("fingerprint");
    if (offer_fp.empty()) return false;

    // ----- Configure the live stack for this peer. -----
    // Pin the expected remote ICE credentials so the IceAgent validates inbound
    // STUN Binding Requests carrying USERNAME "ourUfrag:peerUfrag".
    webrtc_agent_->set_expected_remote(peer_ufrag, peer_pwd);
    if (webrtc_dtls_mgr_) {
        webrtc_dtls_mgr_->set_offer_fingerprint(offer_fp);
    }

    // WI — Full ICE: pin the peer credentials on the full agent and register OUR
    // host candidates as locals so trickle/in-SDP remote candidates form pairs.
    if (webrtc_full_ice_) {
        webrtc_full_ice_->set_remote_credentials(peer_ufrag, peer_pwd);
        register_local_ice_candidates();
        // Any candidates already present in the offer SDP (non-trickle) form
        // pairs immediately.
        if (xport != nullptr) {
            for (std::size_t i = 0; i < xport->attr_count; ++i) {
                if (xport->attrs[i].key != "candidate") continue;
                webrtc::IceCandidate rc;
                if (webrtc::IceCandidate::from_string(xport->attrs[i].value, rc))
                    webrtc_full_ice_->add_remote_candidate(rc);
            }
        }
    }

    // Our host ICE candidate lines (IceCandidate::to_string form). Stored owned
    // so the string_views handed to the answer builder outlive the call.
    std::vector<std::string>      cand_strings;
    std::vector<std::string_view> cand_views;
    gather_candidate_views(cand_strings, cand_views);
    const std::string_view* cv =
        cand_views.empty() ? nullptr : cand_views.data();
    const std::size_t cvn = cand_views.size();

    // WM6: when media echo is enabled AND the offer carries audio/video,
    // negotiate the media (+ data) m-lines into ONE BUNDLEd echo answer. Else
    // fall back to the data-channel-only answer (the original behavior).
    if (media_echo_ && build_echo_answer_for(offer, cv, cvn, out_answer)) {
        return true;
    }
    return build_data_answer_for(app_m, cv, cvn, out_answer);
}

// Gather our host ICE candidate lines (IceCandidate::to_string form) into
// `owned` + `views`. `views` references `owned`, so they share a lifetime.
void App::gather_candidate_views(std::vector<std::string>& owned,
                                 std::vector<std::string_view>& views) {
    assert(webrtc_agent_ != nullptr && "gather_candidates: no agent");
    assert(owned.empty() && views.empty() && "gather_candidates: not empty");
    const std::size_t ncand = webrtc_agent_->candidate_count();
    owned.reserve(ncand);
    views.reserve(ncand);
    for (std::size_t i = 0; i < ncand; ++i) {
        owned.emplace_back(webrtc_agent_->candidate(i).to_string());
    }
    for (const std::string& s : owned) views.emplace_back(s);
}

// WI — register our gathered host candidates as the FullIceAgent's locals.
void App::register_local_ice_candidates() noexcept {
    if (!webrtc_full_ice_ || !webrtc_agent_ || !webrtc_transport_) return;
    if (webrtc_full_ice_->local_count() > 0) return;  // idempotent
    sockaddr_in base{};
    base.sin_family = AF_INET;
    base.sin_addr.s_addr = htonl(INADDR_ANY);
    base.sin_port = htons(webrtc_transport_->bound_port());
    const std::size_t n = webrtc_agent_->candidate_count();
    for (std::size_t i = 0; i < n; ++i) {
        webrtc_full_ice_->add_local_candidate(
            webrtc_agent_->candidate(i),
            reinterpret_cast<const sockaddr*>(&base), sizeof(base));
    }
    assert(webrtc_full_ice_->local_count() <= n);
}

// WI — Trickle ICE (RFC 8838): ingest one incremental remote candidate.
bool App::handle_webrtc_trickle(std::string_view body) noexcept {
    if (!webrtc_full_ice_) return false;  // trickle requires the full agent
    webrtc::TrickleCandidate tc;
    if (webrtc::parse_trickle(body, tc) != webrtc::SdpError::Ok) return false;
    if (tc.end_of_candidates) return true;  // end-of-candidates: nothing to add
    if (tc.candidate.empty()) return false;
    webrtc::IceCandidate rc;
    if (!webrtc::IceCandidate::from_string(tc.candidate, rc)) return false;
    register_local_ice_candidates();  // ensure locals exist to pair against
    const std::size_t idx = webrtc_full_ice_->add_remote_candidate(rc);
    return idx < webrtc::kMaxCandidates;
}

namespace {
// Find the a=extmap:<id> ... line whose URI ENDS WITH `uri` in this m-line, and
// return its id (1..14), or 0 if absent. Bounded scan; no allocation. (The offer
// may carry direction/attr suffixes after the URI, so we match a prefix token.)
std::uint8_t extmap_id_for_uri(const webrtc::SdpMedia& m,
                               std::string_view uri) noexcept {
    assert(uri.size() > 0 && "extmap_id_for_uri: empty uri");
    assert(m.attr_count <= webrtc::kSdpMaxAttrsPerSection && "extmap: overflow");
    for (std::size_t i = 0; i < m.attr_count; ++i) {
        if (m.attrs[i].key != "extmap") continue;
        std::string_view v = m.attrs[i].value;        // "<id>[/dir] <uri> ..."
        std::size_t sp = v.find(' ');
        if (sp == std::string_view::npos) continue;
        std::string_view id_tok = v.substr(0, sp);
        std::size_t slash = id_tok.find('/');
        if (slash != std::string_view::npos) id_tok = id_tok.substr(0, slash);
        std::string_view rest = v.substr(sp + 1);
        if (rest.find(uri) == std::string_view::npos) continue;
        unsigned id = 0;
        for (char c : id_tok) { if (c < '0' || c > '9') { id = 0; break; }
                                id = id * 10 + static_cast<unsigned>(c - '0'); }
        if (id >= 1 && id <= 14) return static_cast<std::uint8_t>(id);
    }
    return 0;
}

// Find an RTX (RFC 4588) mapping in this m-line: a rtpmap "rtx/<clock>" PT whose
// fmtp "apt=<media_pt>" references one of `media_pts`. Returns true + fills
// rtx_pt/media_pt. Bounded scan over the m-line PTs; no allocation.
bool find_rtx_mapping(const webrtc::SdpMedia& m, std::uint8_t* rtx_pt,
                      std::uint8_t* media_pt) noexcept {
    assert(rtx_pt != nullptr && media_pt != nullptr && "find_rtx: null out");
    assert(m.format_count <= webrtc::kSdpMaxFormatsPerMedia && "find_rtx: fmt");
    std::uint8_t pts[webrtc::kSdpMaxFormatsPerMedia];
    const std::size_t n = m.payload_types(pts, sizeof(pts));
    for (std::size_t i = 0; i < n; ++i) {
        const std::string_view rm = m.rtpmap_for(pts[i]);
        if (rm.size() < 4) continue;
        if (!(rm[0] == 'r' && rm[1] == 't' && rm[2] == 'x' && rm[3] == '/'))
            continue;                                   // not "rtx/..."
        const std::string_view fp = m.fmtp_for(pts[i]); // "apt=<pt>"
        const std::size_t apt = fp.find("apt=");
        if (apt == std::string_view::npos) continue;
        unsigned ap = 0; bool any = false;
        for (std::size_t k = apt + 4; k < fp.size(); ++k) {
            const char c = fp[k];
            if (c < '0' || c > '9') break;
            ap = ap * 10 + static_cast<unsigned>(c - '0'); any = true;
        }
        if (!any || ap > 127) continue;
        *rtx_pt = pts[i];
        *media_pt = static_cast<std::uint8_t>(ap);
        return true;
    }
    return false;
}
}  // namespace

// WM6: COMBINED media+data echo answer (audio/video sendrecv so the peer's media
// is echoed back, + the data m-line when present), all BUNDLEd. Returns false if
// no audio/video could be negotiated (the caller then tries the data-only path).
bool App::build_echo_answer_for(const webrtc::SdpSession& offer,
                                const std::string_view* cands,
                                std::size_t ncand, std::string& out_answer) {
    assert(webrtc_agent_ != nullptr && "echo answer: no agent");
    assert(webrtc_dtls_ctx_ != nullptr && "echo answer: no dtls ctx");
    webrtc::MediaNegotiation neg;
    if (webrtc::negotiate_media(offer, neg) != webrtc::SdpError::Ok) return false;
    if (neg.media_count == 0) return false;
    webrtc::EchoAnswerParams ep;
    ep.ice_ufrag          = webrtc_agent_->ufrag();
    ep.ice_pwd            = webrtc_agent_->pwd();
    ep.fingerprint_sha256 = webrtc_dtls_ctx_->fingerprint();
    ep.setup              = "passive";
    ep.ice_lite           = true;
    ep.negotiation        = &neg;
    const webrtc::SdpMedia* app_m = offer.application_media();
    if (app_m != nullptr) ep.data_mid = app_m->mid();
    ep.sctp_port        = webrtc_config_.sctp_port;
    ep.max_message_size = webrtc_config_.max_message_size;
    ep.candidates       = cands;
    ep.candidate_count  = ncand;
    if (webrtc::build_echo_answer(ep, out_answer) != webrtc::SdpError::Ok)
        return false;

    // WA live-wire: read the offered RTX / TWCC / abs-send-time from the offer's
    // video m-line and configure the live peer hub's interceptor chain. (The
    // answer SDP itself only echoes what the read-only sdp.* builder emits; this
    // wiring makes the inbound NACK->RTX and TWCC-arrival paths run for real.)
    if (webrtc_hub_ != nullptr) {
        webrtc::WebRtcPeerHub::MediaConfig mc;
        for (std::size_t i = 0; i < offer.media_count; ++i) {
            const webrtc::SdpMedia& m = offer.media[i];
            if (m.media_type != "video") continue;       // RTX/TWCC ride video
            std::uint8_t cc = extmap_id_for_uri(m, webrtc::kTransportCcExtUri);
            std::uint8_t ast = extmap_id_for_uri(m, webrtc::kAbsSendTimeExtUri);
            if (cc != 0)  mc.transport_cc_ext_id  = cc;
            if (ast != 0) mc.abs_send_time_ext_id = ast;
            std::uint8_t rtx_pt = 0, media_pt = 0;
            if (find_rtx_mapping(m, &rtx_pt, &media_pt)) {
                mc.media_pt = media_pt;
                mc.rtx_pt   = rtx_pt;
                // Echo/relay reuses the inbound SSRC; pick distinct rtx SSRC.
                for (const WebRtcConfig::MediaTrackSpec& ms :
                         webrtc_config_.media_tracks) {
                    if (ms.payload_type == media_pt) { mc.media_ssrc = ms.ssrc;
                        mc.rtx_ssrc = ms.ssrc ^ 0x52545800u /*"RTX"*/; break; }
                }
            }
            break;  // first video m-line drives the transport-wide config
        }
        webrtc_hub_->configure_media(mc);
    }
    return true;
}

// WM6: data-channel-only answer (the original behavior) for an offer with an
// m=application section. Returns false when there is nothing to answer.
bool App::build_data_answer_for(const webrtc::SdpMedia* app_m,
                                const std::string_view* cands,
                                std::size_t ncand, std::string& out_answer) {
    assert(webrtc_agent_ != nullptr && "data answer: no agent");
    assert(webrtc_dtls_ctx_ != nullptr && "data answer: no dtls ctx");
    if (app_m == nullptr) return false;  // nothing we can answer
    webrtc::AnswerParams p;
    const std::string_view offer_mid = app_m->mid();
    if (!offer_mid.empty()) p.mid = offer_mid;
    p.ice_ufrag          = webrtc_agent_->ufrag();
    p.ice_pwd            = webrtc_agent_->pwd();
    p.fingerprint_sha256 = webrtc_dtls_ctx_->fingerprint();
    p.setup              = "passive";   // we are the DTLS server (answerer)
    p.ice_lite           = true;         // Bolt is the ICE-lite controlled peer
    p.sctp_port          = webrtc_config_.sctp_port;
    p.max_message_size   = webrtc_config_.max_message_size;
    p.candidates         = cands;
    p.candidate_count    = ncand;
    return webrtc::build_answer(p, out_answer) == webrtc::SdpError::Ok;
}

// WM5: deliver an inbound RTP packet to the App's on_track handler. `ctx` is the
// MediaTrackHandler* (&App::track_handler_). noexcept: a handler that throws in
// an exception-free build is undefined; callers register noexcept handlers.
void App::media_deliver_trampoline(void* ctx, webrtc::MediaTrack& track,
                                   const webrtc::rtp::Packet& pkt,
                                   const std::uint8_t* data,
                                   std::size_t len) noexcept {
    assert(ctx != nullptr && "media_deliver: null ctx");
    assert(data != nullptr && "media_deliver: null data");
    (void)pkt;  // the App reads identity off `track`; pkt is the parsed view
    auto* handler = static_cast<MediaTrackHandler*>(ctx);
    if (*handler != nullptr) (*handler)(track, data, len);
}
#endif  // BOLTAPI_WITH_WEBRTC

// WM6 echo: loop one inbound RTP packet straight back out on its OWN track
// (re-SRTP, relay, NO transcode — the aiortc `server` shape). Defined
// UNCONDITIONALLY because enable_media_echo()'s handler lambda references it in
// both build modes; the MediaTrack write is only reachable under
// BOLTAPI_WITH_WEBRTC (where the SRTP transport is up). noexcept (the
// exception-free build requires it).
void App::echo_track(webrtc::MediaTrack& track, const std::uint8_t* rtp_data,
                     std::size_t rtp_len) noexcept {
    assert(rtp_data != nullptr && "echo_track: null rtp");
    assert(rtp_len >= 12u && "echo_track: short rtp (need >= RTP header)");
#if defined(BOLTAPI_WITH_WEBRTC)
    // track.write -> outbound interceptors -> SRTP-protect -> UdpTransport.
    track.write(rtp_data, rtp_len);
#else
    // No media transport in the default build; void all params (asserts compile
    // out under NDEBUG, so without this they would be unreferenced — C4100).
    (void)track;
    (void)rtp_data;
    (void)rtp_len;
#endif
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
#if defined(BOLTAPI_WITH_HTTP3)
    // Stop the HTTP/3 receive loop + close the UDP socket BEFORE freeing the
    // QUIC/H3 state (the connection's send fn uses the transport). Idempotent.
    if (http3_transport_) {
        http3_transport_->stop();
    }
    http3_conn_.reset();   // bridge (borrows the QuicConnection)
    http3_quic_.reset();   // QUIC endpoint (TLS/keys)
    http3_transport_.reset();
#endif
#if defined(BOLTAPI_WITH_WEBRTC)
    // Clean WebRTC teardown: stop the receive loop + close the UDP socket BEFORE
    // freeing the DTLS sessions (the manager's sessions send through the
    // transport), then free the DTLS context, then the agent. Idempotent
    // (transport.stop() guards on handle; resets are no-ops if already null).
    if (webrtc_transport_) {
        webrtc_transport_->stop();
    }
    webrtc_hub_.reset();        // frees per-peer SCTP/DCEP stacks (borrows DTLS)
    webrtc_dtls_mgr_.reset();   // frees all DtlsSessions (SSL/BIO)
    webrtc_dtls_ctx_.reset();   // frees the SSL_CTX
    if (webrtc_transport_) {
        webrtc_transport_.reset();
    }
    webrtc_full_ice_.reset();   // WI: full ICE agent (borrows the transport)
    webrtc_agent_.reset();
#endif
    started_ = false;
}

bool App::is_running() const noexcept {
    return started_ && server_ && server_->is_running();
}

}  // namespace bolt::api
