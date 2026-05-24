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

#if defined(BOLTAPI_WITH_HTTP3)
#include "boltapi/net/udp_transport.h"
#include "boltapi/quic/connection.h"
#include "boltapi/http3/h3_connection.h"
#include <mutex>
#endif

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api {

// Forward declaration so the data-channel handler signature is well-formed even
// in default (WEBRTC=OFF) builds, where the full type isn't included. A handler
// only ever fires under BOLTAPI_WITH_WEBRTC (it needs the transport up), so the
// incomplete type is fine for the std::function declaration; the App wiring that
// dereferences it is itself gated by BOLTAPI_WITH_WEBRTC.
namespace webrtc { class DataChannel; class MediaTrack; }

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

    // WI — Full ICE (RFC 8445). When set, the App also stands up a FullIceAgent
    // (controlled role by default: the browser/offerer is controlling) alongside
    // the ice-lite responder, enabling bidirectional connectivity checks, trickle
    // candidate intake, and ICE restart. The ice-lite responder stays wired so
    // the existing live-STUN path and ice-lite peers keep working.
    bool        full_ice     = false;

    // WI — Trickle ICE (RFC 8838). HTTP signaling route for INCREMENTAL remote
    // candidates POSTed after the offer/answer. Accepts the RTCIceCandidateInit
    // JSON envelope {"candidate":"candidate:...","sdpMid":"0","sdpMLineIndex":0}
    // (or a bare candidate line / "end-of-candidates"). Empty disables the route.
    std::string trickle_path = "/webrtc/candidate";

    // SCTP association parameters surfaced into the SDP answer.
    uint16_t    sctp_port        = 5000;
    uint32_t    max_message_size = 262144;

    // HTTP signaling route. When enable_webrtc is set AND the build has
    // BOLTAPI_WITH_WEBRTC, App registers a POST route at this path that accepts
    // the peer's OFFER SDP (raw body, or JSON {"sdp":"..."} — both accepted),
    // configures the WebRTC stack for that peer (remote ufrag/pwd + DTLS
    // fingerprint), and returns OUR ANSWER SDP. Empty disables the route (the
    // App still brings the ICE/DTLS/SCTP transport up; signaling is then the
    // caller's responsibility). Default "/webrtc/offer".
    std::string signaling_path = "/webrtc/offer";

    // The remote (browser/offerer) DTLS certificate fingerprint extracted from
    // the SDP offer's a=fingerprint line. When set, the DTLS server verifies the
    // peer cert's SHA-256 against it after the handshake (the WebRTC identity
    // binding) and rejects on mismatch. Empty => verification skipped (the
    // handshake alone establishes the channel — used before signaling lands).
    std::string offer_fingerprint;

    // -----------------------------------------------------------------------
    // Media (WM5). Outbound media tracks the App will write to. Each spec is a
    // negotiated SSRC + payload type + codec; the peer hub pre-registers them so
    // the on_track handler can write media (echo/relay). Inbound tracks are
    // discovered from received RTP (by SSRC/PT), so this list is only needed for
    // tracks Bolt SENDS. Bounded; mirrors the data-channel handler list shape.
    // 0 = audio, 1 = video (matches webrtc::MediaKind).
    // -----------------------------------------------------------------------
    struct MediaTrackSpec {
        uint8_t     kind = 0;          // 0 audio, 1 video
        uint32_t    ssrc = 0;
        uint8_t     payload_type = 0;
        std::string codec;             // "opus" / "VP8" / "H264" / ...
    };
    std::vector<MediaTrackSpec> media_tracks;
};

class App {
public:
    // Sync handler: fill the Response, return. Wrapped into a ready coro_task.
    using Handler = std::function<void(Request&, Response&)>;
    // Async handler: may co_await; fill the Response, co_return.
    using AsyncHandler =
        std::function<core::coro_task<void>(Request&, Response&)>;

    // Data-channel message handler: (channel, data, len, is_binary). The channel
    // reference lets the handler REPLY (echo) via ch.send_text/ch.send_binary,
    // and exposes ch.label(). Fired once per inbound message on an established
    // data channel whose label matched the registration (or the "" wildcard).
    // Only ever invoked under BOLTAPI_WITH_WEBRTC (the transport must be up).
    using DataChannelHandler =
        std::function<void(webrtc::DataChannel& ch, const void* data,
                           std::size_t len, bool is_binary)>;

    // Media-track handler (WM5): fired once per inbound RTP packet on a media
    // track, with (track, rtp_data, rtp_len). `rtp_data` is the decrypted RTP
    // packet (header + payload). The handler may RELAY/ECHO by calling
    // track.write(rtp_data, rtp_len) (or a re-stamped packet). Only ever invoked
    // under BOLTAPI_WITH_WEBRTC (the SRTP transport must be up). Mirrors
    // DataChannelHandler. The MediaTrack reference exposes ssrc()/kind()/codec().
    using MediaTrackHandler =
        std::function<void(webrtc::MediaTrack& track, const std::uint8_t* rtp_data,
                           std::size_t rtp_len)>;

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
    // Static file serving (demo / dev convenience).
    //
    // static_files(mount_prefix, fs_root) serves the files under the on-disk
    // directory `fs_root` at the URL space rooted at `mount_prefix`. It is a
    // demo/dev helper (the WebRTC harness page is served this way), NOT a hot
    // path: files are read from disk at request time with a hard size cap and a
    // path-traversal guard. A request to exactly `mount_prefix` (or
    // `mount_prefix/`) serves `index.html`.
    //
    // Implementation: registers a single GET wildcard route at
    // "<prefix>*" plus the exact "<prefix>" so both "/" and "/file" resolve.
    // The wildcard captures the path tail (router exposes it as param "*"),
    // which is appended to fs_root after a guard rejecting "..", embedded NUL,
    // backslashes and absolute/drive-letter escapes. MIME is by extension.
    // Returns *this for chaining.
    // -----------------------------------------------------------------------
    App& static_files(std::string mount_prefix, std::string fs_root) {
        assert(!mount_prefix.empty());
        assert(mount_prefix.front() == '/');
        assert(!started_);

        // Normalize the prefix to a single trailing form. We register two
        // routes: the exact prefix (serves index.html) and prefix + "*".
        std::string exact = mount_prefix;
        // strip a trailing '/' from exact unless it IS "/"
        if (exact.size() > 1 && exact.back() == '/') exact.pop_back();
        std::string wild = (exact == "/") ? std::string("/*")
                                          : (exact + "/*");

        auto serve = [root = std::move(fs_root)](Request& req, Response& res) {
            // The wildcard tail (everything after the mount). For the exact-
            // prefix route there is no '*' param, so tail is empty -> index.
            std::string_view tail = req.path_param_view("*");
            serve_file_(root, tail, res);
        };

        routes_.push_back(RouteEntry{Method::Get, exact, serve,
                                     AsyncHandler{}, false});
        routes_.push_back(RouteEntry{Method::Get, wild, serve,
                                     AsyncHandler{}, false});
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

    // -----------------------------------------------------------------------
    // HTTP/3 (W5b). enable_http3() turns on the HTTP/3 surface; when the build
    // has BOLTAPI_WITH_HTTP3, init_protocol_seams() brings a real QUIC endpoint
    // up on a UDP port (sharing net::UdpTransport) and serves decoded HTTP/3
    // requests through the SAME dispatch path as H1/H2. Purely additive: it never
    // touches the H1/H2 serving path. Returns *this for chaining.
    // -----------------------------------------------------------------------
    App& enable_http3(uint16_t udp_port = 0) {
        assert(!started_);
        config_.enable_http3 = true;
        if (udp_port != 0) config_.http3_port = udp_port;
        return *this;
    }

    // Synchronous dispatch entry: route a CoroHttpRequest through the SAME
    // router + middleware + handler the H1/H2 path uses and return the filled
    // CoroHttpResponse. Drives the (lazy) dispatch coroutine to completion inline
    // — the App's sync handlers run inline, so one resume completes the chain.
    // Unconditional (no BOLTAPI_WITH_HTTP3 gate) so the W5b gate test can route
    // HTTP/3 requests through the App in the default suite. Must be called after
    // build_dispatch() (i.e. after run/start_background). TigerStyle: bounded,
    // asserts the router is built, no exceptions.
    http::CoroHttpResponse dispatch_http3(const http::CoroHttpRequest& req);

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

    // Register a media-track handler (WM5), mirroring on_data_channel. The
    // handler is invoked for every inbound RTP packet on every media track once
    // the SRTP transport is up. Recorded now; wired into the WebRtcPeerHub in
    // init_protocol_seams(). Only one handler (the latest registration) is kept —
    // tracks are demuxed by SSRC inside the hub, so a single handler that
    // switches on track.kind()/ssrc() is the FastAPI-style shape. Returns *this.
    App& on_track(MediaTrackHandler handler) {
        assert(handler != nullptr);
        assert(!started_);
        track_handler_ = std::move(handler);
        return *this;
    }

    // WM6 ECHO (aiortc `server` shape). Install an on_track handler that loops
    // every inbound RTP packet straight back out on the SAME track — re-SRTP,
    // RELAY, NO transcode. This is the media analogue of an on_data_channel echo:
    // received audio + video RTP is mirrored to the peer (track.write -> outbound
    // interceptors -> SRTP-protect -> UDP). The peer hub creates ONE MediaTrack
    // per inbound SSRC and binds its write sink, so a track that echoes to itself
    // sends back on that SSRC — exactly what a sendrecv m-line's RTCRtpSender
    // expects. Idempotent with on_track (the latest registration wins). Returns
    // *this for chaining. Only meaningful under BOLTAPI_WITH_WEBRTC (the SRTP
    // transport must be up); in the default build it records the handler harmlessly.
    App& enable_media_echo() {
        assert(!started_);
        media_echo_ = true;
        track_handler_ = [](webrtc::MediaTrack& track,
                            const std::uint8_t* rtp_data, std::size_t rtp_len) {
            App::echo_track(track, rtp_data, rtp_len);
        };
        assert(track_handler_ != nullptr && "enable_media_echo: handler set");
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

    // Content-Type for a file by extension (lower-case match). Conservative
    // default of application/octet-stream for the unknown case. Total + simple.
    static std::string_view mime_for_(std::string_view path) noexcept {
        const std::size_t dot = path.rfind('.');
        if (dot == std::string_view::npos) return "application/octet-stream";
        std::string_view ext = path.substr(dot + 1);
        // Tiny fixed table (extend as needed). All lower-case.
        if (ext == "html" || ext == "htm") return "text/html; charset=utf-8";
        if (ext == "js"  || ext == "mjs")  return "text/javascript; charset=utf-8";
        if (ext == "css")  return "text/css; charset=utf-8";
        if (ext == "json") return "application/json";
        if (ext == "txt")  return "text/plain; charset=utf-8";
        if (ext == "svg")  return "image/svg+xml";
        if (ext == "png")  return "image/png";
        if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
        if (ext == "gif")  return "image/gif";
        if (ext == "ico")  return "image/x-icon";
        if (ext == "wasm") return "application/wasm";
        return "application/octet-stream";
    }

    // Resolve `tail` (the wildcard remainder, "" => index.html) against `root`,
    // reject path traversal, read the file (bounded), and fill `res`. 404 when
    // missing/forbidden. Static (no App state) so static_files() can capture it.
    static void serve_file_(const std::string& root, std::string_view tail,
                            Response& res) {
        // Default document for a directory-style request.
        std::string rel(tail);
        if (rel.empty() || rel.back() == '/') rel += "index.html";

        // Path-traversal / escape guard. Reject any segment that could climb
        // out of root or smuggle a drive/absolute path on Windows. We keep the
        // guard strict and allocation-light: scan the relative path once.
        bool bad = rel.find('\0') != std::string::npos ||
                   rel.find("..") != std::string::npos ||
                   rel.find('\\') != std::string::npos ||
                   (rel.size() >= 1 && rel.front() == '/') ||
                   (rel.size() >= 2 && rel[1] == ':');  // C:\ style
        if (bad) {
            res.status(404).content_type("text/plain; charset=utf-8")
               .send("Not Found");
            return;
        }

        std::string full = root;
        if (!full.empty() && full.back() != '/' && full.back() != '\\') {
            full += '/';
        }
        full += rel;

        // Read the file in binary, bounded. Demo helper: a hard cap keeps a
        // pathological file from ballooning the response buffer.
        constexpr long kMaxFileBytes = 16L * 1024 * 1024;  // 16 MiB
        std::FILE* f = std::fopen(full.c_str(), "rb");
        if (f == nullptr) {
            res.status(404).content_type("text/plain; charset=utf-8")
               .send("Not Found");
            return;
        }
        std::fseek(f, 0, SEEK_END);
        const long sz = std::ftell(f);
        if (sz < 0 || sz > kMaxFileBytes) {
            std::fclose(f);
            res.status(404).content_type("text/plain; charset=utf-8")
               .send("Not Found");
            return;
        }
        std::fseek(f, 0, SEEK_SET);
        std::string buf;
        buf.resize(static_cast<std::size_t>(sz));
        const std::size_t got =
            (sz == 0) ? 0
                      : std::fread(buf.data(), 1, static_cast<std::size_t>(sz), f);
        std::fclose(f);
        if (got != static_cast<std::size_t>(sz)) {
            res.status(404).content_type("text/plain; charset=utf-8")
               .send("Not Found");
            return;
        }

        res.status(200).content_type(mime_for_(rel)).send(buf);
    }

    // Build the router + the engine handler. Called once from run/start.
    void build_dispatch();

    // M3 seam hook: if enable_http3/enable_webrtc are set, consult the protocol
    // registry. Stub factories return NotImplemented, which is logged; H1/H2
    // serving is unaffected. Safe no-op when no seam flags are set. Called once
    // from run/start_background after build_dispatch().
    void init_protocol_seams();

#if defined(BOLTAPI_WITH_HTTP3)
    // W5b: bring a real QUIC server endpoint up on the HTTP/3 UDP port, bridge
    // decoded HTTP/3 requests to dispatch_http3(). Called from init_protocol_
    // seams() under BOLTAPI_WITH_HTTP3. Never touches the H1/H2 server.
    void start_http3();

    // (Re)create the single server QuicConnection + H3Connection and wire its
    // send fn + request handler. Called once from start_http3 and again from the
    // datagram handler when a NEW connection's Initial arrives after the current
    // one finished its handshake (single-peer endpoint v1 — lets sequential QUIC
    // connections, e.g. an H3 page load then a WebTransport session, both work).
    void http3_new_connection_(net::UdpTransport* tp,
                               std::shared_ptr<sockaddr_storage> peer,
                               std::shared_ptr<int> peer_len);

    // Build a CoroHttpRequest from a decoded H3Request, route it through
    // dispatch_http3(), and send the response back over the H3 stream.
    void serve_http3_request(http3::H3Connection& h3, const http3::H3Request& r);
#endif

#if defined(BOLTAPI_WITH_WEBRTC)
    // WebRTC signaling: parse the peer OFFER SDP (raw body or JSON {"sdp":...}),
    // configure the live ICE/DTLS stack for that peer (expected remote ufrag/pwd,
    // offer DTLS fingerprint), and fill `out_answer` with OUR ANSWER SDP
    // (ice-lite, setup:passive, our fingerprint + candidates, the application
    // m-line). Returns false (out_answer cleared) on a malformed offer or when
    // the WebRTC transport isn't up. Defined in app.cpp. Single active peer (v1).
    bool handle_webrtc_offer(std::string_view body, std::string& out_answer);

    // WI — Trickle ICE (RFC 8838): ingest ONE incremental remote candidate (or
    // an end-of-candidates signal) POSTed after the offer/answer. Parses the
    // RTCIceCandidateInit JSON envelope / bare candidate line, feeds the
    // candidate to the FullIceAgent (when full_ice) so a new pair is formed +
    // checked. Returns false (no transport / malformed) without crashing.
    // Defined in app.cpp.
    bool handle_webrtc_trickle(std::string_view body) noexcept;

    // WM6: build the COMBINED media+data echo answer for a parsed offer (when
    // enable_media_echo() is set and the offer carries audio/video). `cands` are
    // our host ICE candidate lines. Returns false if no media negotiated (caller
    // then falls back to the data-only answer). Keeps handle_webrtc_offer small.
    bool build_echo_answer_for(const webrtc::SdpSession& offer,
                               const std::string_view* cands, std::size_t ncand,
                               std::string& out_answer);

    // WM6: build the data-channel-only answer (the original behavior) for a
    // parsed offer with an m=application section. Returns false if none.
    bool build_data_answer_for(const webrtc::SdpMedia* app_m,
                               const std::string_view* cands, std::size_t ncand,
                               std::string& out_answer);

    // Gather our host ICE candidate lines into `owned` (the backing strings) and
    // `views` (string_views into them). `views` stays valid only while `owned`
    // lives. Keeps handle_webrtc_offer small. Defined in app.cpp.
    void gather_candidate_views(std::vector<std::string>& owned,
                                std::vector<std::string_view>& views);

    // WI — register OUR gathered host candidates as the FullIceAgent's LOCAL
    // candidates (idempotent: only runs once, when full_ice + the agent exist).
    // The send-base is the WebRTC UDP socket. Defined in app.cpp. noexcept.
    void register_local_ice_candidates() noexcept;

    // WM5: the C-style deliver trampoline bound as each MediaTrack's deliver
    // sink. `ctx` is &track_handler_ (a stable MediaTrackHandler*); it forwards
    // the inbound RTP to the App's on_track handler. noexcept (the handler must
    // not throw — the build is exception-free). Defined in app.cpp.
    static void media_deliver_trampoline(void* ctx, webrtc::MediaTrack& track,
                                         const webrtc::rtp::Packet& pkt,
                                         const std::uint8_t* data,
                                         std::size_t len) noexcept;
#endif

    // WM6 echo: loop one inbound RTP packet straight back out on its own track
    // (re-SRTP, relay, no transcode). Declared unconditionally so the
    // enable_media_echo() lambda compiles in BOTH build modes; the body is only
    // meaningful (touches MediaTrack) under BOLTAPI_WITH_WEBRTC. Defined in
    // app.cpp. noexcept (the exception-free build requires it).
    static void echo_track(webrtc::MediaTrack& track,
                           const std::uint8_t* rtp_data,
                           std::size_t rtp_len) noexcept;

    // Run the middleware chain for one matched route, terminal = handler.
    core::coro_task<void> run_chain(std::size_t route_index,
                                    Request& req, Response& res) const;

    // The shared dispatch coroutine: match -> Request/Response -> middleware
    // chain -> handler -> CoroHttpResponse. Used by BOTH the engine handler
    // (set_handler in build_dispatch) and the synchronous HTTP/3 entry
    // (dispatch_http3). Defined in app.cpp.
    core::coro_task<http::CoroHttpResponse> dispatch_coro_(
        const http::CoroHttpRequest& creq) const;

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
    // WM5 media: a single on_track handler (tracks demuxed by SSRC in the hub).
    MediaTrackHandler   track_handler_;
    // WM6: when set via enable_media_echo(), the signaling answer negotiates the
    // offered audio/video m-lines (sendrecv) so the peer's media is echoed back.
    bool                media_echo_ = false;

#if defined(BOLTAPI_WITH_WEBRTC)
    // When enable_webrtc is set AND the flag is on, App owns a real UdpTransport
    // + ICE-lite IceAgent: it gathers host candidates, binds the WebRtcConfig
    // UDP port, routes inbound STUN to the agent's binding responder, and logs
    // the gathered candidates + ufrag/pwd. Started in init_protocol_seams() and
    // torn down cleanly in stop(). A signaling route is a TODO hook (next wave).
    // None of this touches the H1/H2 server.
    std::unique_ptr<net::UdpTransport>   webrtc_transport_;
    std::unique_ptr<webrtc::IceAgent>    webrtc_agent_;
    // WI — Full ICE (RFC 8445). Created in init_protocol_seams() when
    // WebRtcConfig::full_ice is set: a FullIceAgent (controlled role) running
    // bidirectional connectivity checks + trickle candidate intake alongside the
    // ice-lite responder. The STUN handler routes inbound checks to BOTH agents.
    std::unique_ptr<webrtc::FullIceAgent> webrtc_full_ice_;
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

#if defined(BOLTAPI_WITH_HTTP3)
    // HTTP/3 (W5b): a real QUIC server endpoint over a shared net::UdpTransport.
    // init_protocol_seams() binds the UDP socket, routes inbound QUIC datagrams
    // (first byte >= 64, demuxed by UdpTransport) into the QuicConnection, and an
    // H3Connection bridges decoded requests to dispatch_http3(). Single-peer (v1),
    // serialized by h3_mtx_. Torn down before the transport in stop().
    std::unique_ptr<net::UdpTransport>     http3_transport_;
    std::unique_ptr<quic::QuicConnection>  http3_quic_;
    std::unique_ptr<http3::H3Connection>   http3_conn_;
    std::mutex                             http3_mtx_;
#endif

    std::unique_ptr<Router>                   router_;
    std::unique_ptr<http::CoroUnifiedServer>  server_;
    // route_id (from router.add) -> index into routes_. Sized at build().
    std::vector<std::size_t>                  route_id_to_index_;

    bool started_ = false;
};

}  // namespace bolt::api
