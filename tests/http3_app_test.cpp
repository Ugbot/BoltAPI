// http3_app_test.cpp — W5b GATE: HTTP/3 actually SERVES requests through the
// App router over a real QUIC transport (loopback our-client <-> our-server).
//
// Mirrors the wave-5a stream harness: two QuicConnections (client + server) on
// two net::UdpTransports over ephemeral loopback UDP ports, driven to
// Established. An H3Connection (boltapi/http3/h3_connection.h) bridges each side:
//   * the SERVER's H3Connection decodes inbound bidi-stream requests (QPACK
//     HEADERS + DATA) and routes them through a real bolt::api::App's shared
//     dispatch path (App::dispatch_http3 -> router + middleware + handler), then
//     sends the CoroHttpResponse back over the same stream as HEADERS(:status)+
//     DATA + FIN;
//   * the CLIENT's H3Connection sends requests and captures the decoded response
//     (status + body).
//
// Per the project testing rule this exercises MORE THAN ONE route, DIFFERENT
// HTTP verbs, and RANDOMIZED input:
//   1. GET  /ping            -> 200, body "pong"            (byte-exact)
//   2. POST /echo <random>   -> 200, body == the request body (multi-KB random)
//
// This runs in the DEFAULT suite: frame.h / h3_connection.h compile
// unconditionally (header-only over the always-compiled quic/* + http3 QPACK),
// and App::dispatch_http3 is unconditional, so no BOLTAPI_WITH_HTTP3 flag is
// needed. Bounded by wall-clock deadlines (no hang). Links OpenSSL + ws2_32/
// mswsock/iphlpapi on Windows, like quic_connection_test.

#include "boltapi/app.h"
#include "boltapi/http3/h3_connection.h"
#include "boltapi/quic/connection.h"
#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace api  = bolt::api;
namespace h3   = bolt::api::http3;
namespace q    = bolt::api::quic;
namespace net  = bolt::api::net;
namespace core = bolt::api::core;

namespace {

struct EventLoop {
    std::unique_ptr<core::WorkerThreadPool> pool;
    std::unique_ptr<net::IODispatcher>      disp;
    EventLoop() {
        pool = std::make_unique<core::WorkerThreadPool>(core::WorkerPoolConfig{});
        pool->start();
        disp = std::make_unique<net::IODispatcher>(pool.get());
        disp->start();
    }
    ~EventLoop() { disp->stop(); pool->stop(); }
};

net::IODispatcher& shared_dispatcher() {
    static EventLoop loop;
    return *loop.disp;
}

sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

std::string make_random_body(std::size_t n, std::uint32_t seed) {
    std::string s(n, '\0');
    std::mt19937 rng(seed);
    // Printable-ASCII so it is a valid HTTP body the echo handler can carry.
    for (std::size_t i = 0; i < n; ++i) {
        s[i] = static_cast<char>(0x20 + (rng() % 95));  // ' '..'~'
    }
    return s;
}

// Two QuicConnections + two H3Connections cross-wired over loopback UDP, with a
// real App on the server side. Single-threaded driver drains in order; each
// connection's send fn pushes to the peer's socket. Mirrors quic_stream_test.
struct H3Pair {
    net::UdpTransport client_udp{shared_dispatcher()};
    net::UdpTransport server_udp{shared_dispatcher()};
    q::QuicConnection client_qc, server_qc;
    h3::H3Connection  client_h3, server_h3;

    std::mutex qmtx;
    std::vector<std::vector<std::uint8_t>> to_client, to_server;

    api::App* app = nullptr;
    bool      server_settings_sent = false;
    bool      client_settings_sent = false;

    bool setup(api::App& a) {
        app = &a;
        if (!client_udp.bind("127.0.0.1", 0)) return false;
        if (!server_udp.bind("127.0.0.1", 0)) return false;
        const auto saddr = loopback(server_udp.bound_port());
        const auto caddr = loopback(client_udp.bound_port());

        auto csend = [this, saddr](const std::uint8_t* d, std::size_t n) {
            client_udp.send(reinterpret_cast<const sockaddr*>(&saddr),
                            sizeof(saddr), d, n);
        };
        auto ssend = [this, caddr](const std::uint8_t* d, std::size_t n) {
            server_udp.send(reinterpret_cast<const sockaddr*>(&caddr),
                            sizeof(caddr), d, n);
        };
        if (!client_qc.init(false, csend)) return false;
        if (!server_qc.init(true, ssend)) return false;

        // Server bridge: route each request through the real App and reply.
        server_h3.attach(server_qc, /*is_server=*/true);
        server_h3.set_request_handler([this](const h3::H3Request& r) {
            serve(r);
        });
        // Client bridge: capture decoded responses.
        client_h3.attach(client_qc, /*is_server=*/false);

        client_udp.set_datagram_handler(
            [this](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
                std::lock_guard<std::mutex> lk(qmtx);
                to_client.emplace_back(d, d + n);
            });
        server_udp.set_datagram_handler(
            [this](const sockaddr*, int, const std::uint8_t* d, std::size_t n) {
                std::lock_guard<std::mutex> lk(qmtx);
                to_server.emplace_back(d, d + n);
            });
        if (!client_udp.start() || !server_udp.start()) return false;
        return true;
    }

    // Build a CoroHttpRequest from the decoded H3 request, route it through the
    // App's shared dispatch path, send the response back over the H3 stream.
    void serve(const h3::H3Request& r) {
        api::http::CoroHttpRequest creq;
        creq.method = r.method;
        creq.path   = r.path;
        creq.body   = std::string_view(reinterpret_cast<const char*>(r.body),
                                       r.body_len);
        for (std::size_t i = 0; i < r.header_count; ++i) {
            creq.add_header(r.headers[i].name, r.headers[i].value);
        }
        api::http::CoroHttpResponse resp = app->dispatch_http3(creq);

        h3::H3ResponseHeader hdrs[16];
        std::size_t hc = 0;
        for (const auto& e : resp.headers) {
            if (hc >= 16) break;
            hdrs[hc].name = e.name; hdrs[hc].value = e.value; ++hc;
        }
        const auto* body = reinterpret_cast<const std::uint8_t*>(resp.body.data());
        server_h3.send_response(r.stream_id, resp.status, hdrs, hc, body,
                                resp.body.size());
    }

    void drain() {
        std::vector<std::vector<std::uint8_t>> c, s;
        { std::lock_guard<std::mutex> lk(qmtx); c.swap(to_client); s.swap(to_server); }
        for (auto& dg : c) client_qc.feed_datagram(dg.data(), dg.size());
        for (auto& dg : s) server_qc.feed_datagram(dg.data(), dg.size());
    }

    void pump_once() {
        drain();
        // Open the H3 control/QPACK streams + SETTINGS once 1-RTT keys exist.
        if (!server_settings_sent && server_qc.one_rtt_keys_ready()) {
            server_h3.send_settings(); server_settings_sent = true;
        }
        if (!client_settings_sent && client_qc.one_rtt_keys_ready()) {
            client_h3.send_settings(); client_settings_sent = true;
        }
        client_qc.tick();
        server_qc.tick();
        std::this_thread::sleep_for(std::chrono::microseconds(300));
    }

    bool handshake(std::chrono::seconds budget) {
        if (!client_qc.start()) return false;
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < deadline) {
            pump_once();
            if (client_qc.is_established() && server_qc.is_established() &&
                client_settings_sent && server_settings_sent) {
                return true;
            }
        }
        return false;
    }

    void stop() { client_udp.stop(); server_udp.stop(); }
};

// Drive the client request to a decoded response (or a deadline). Returns true
// if a response arrived. Bounded — never hangs.
bool round_trip(H3Pair& p, std::string_view method, std::string_view path,
                const std::string& body, std::uint16_t& status,
                std::string& out_body) {
    p.client_h3.clear_response();
    const std::uint8_t* b = body.empty()
        ? nullptr : reinterpret_cast<const std::uint8_t*>(body.data());
    const std::uint64_t sid = p.client_h3.send_request(
        method, path, "https", "localhost", nullptr, 0, b, body.size());
    if (sid == UINT64_MAX) return false;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        p.pump_once();
        if (p.client_h3.response_ready()) {
            status   = p.client_h3.response_status();
            out_body = p.client_h3.response_body();
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

}  // namespace

// ============================================================================
// UNIT: HTTP/3 frame layer round-trips (RFC 9114 §7.1 framing + SETTINGS).
// ============================================================================
TEST(Http3Frame, HeaderAndSettingsRoundTrip) {
    std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::uint8_t buf[64];
    const std::size_t hn = h3::frame_write_header(
        static_cast<std::uint64_t>(h3::FrameType::kData), sizeof(payload), buf,
        sizeof(buf));
    ASSERT_GT(hn, 0u);
    std::memcpy(buf + hn, payload, sizeof(payload));

    h3::FrameView fv{};
    std::size_t used = 0;
    ASSERT_EQ(h3::frame_parse(buf, hn + sizeof(payload), fv, used),
              h3::FrameStatus::kOk);
    EXPECT_EQ(fv.type, static_cast<std::uint64_t>(h3::FrameType::kData));
    EXPECT_EQ(fv.length, sizeof(payload));
    EXPECT_EQ(0, std::memcmp(fv.payload, payload, sizeof(payload)));
    EXPECT_EQ(used, hn + sizeof(payload));

    // Truncated input must report NeedMore, not Error/Ok.
    EXPECT_EQ(h3::frame_parse(buf, hn + 1, fv, used), h3::FrameStatus::kNeedMore);

    // SETTINGS payload round-trip.
    h3::SettingsFrame out{};
    out.qpack_max_table_capacity = 4096;
    out.max_field_section_size   = 65536;
    out.has_max_field_section    = true;
    out.qpack_blocked_streams    = 16;
    std::uint8_t sbuf[h3::kSettingsMaxBytes];
    const std::size_t sn = out.encode_payload(sbuf, sizeof(sbuf));
    ASSERT_GT(sn, 0u);
    h3::SettingsFrame in{};
    ASSERT_TRUE(in.parse_payload(sbuf, sn));
    EXPECT_EQ(in.qpack_max_table_capacity, 4096u);
    EXPECT_EQ(in.max_field_section_size, 65536u);
    EXPECT_EQ(in.qpack_blocked_streams, 16u);
}

// ============================================================================
// GATE: HTTP/3 serves real App routes over loopback QUIC — multi-route,
// multi-verb, randomized body.
// ============================================================================
TEST(Http3App, ServesRequestsThroughAppRouter) {
    // A real App with two routes and two verbs.
    api::App app;
    app.get("/ping", [](api::Request&, api::Response& res) {
        res.status(200).content_type("text/plain").send("pong");
    });
    app.post("/echo", [](api::Request& req, api::Response& res) {
        // Echo the request body back verbatim.
        res.status(200).content_type("application/octet-stream").send(req.body());
    });
    // build_dispatch runs on start_background; we drive dispatch_http3 directly.
    ASSERT_EQ(app.start_background("127.0.0.1", 0), 0);

    auto p_owner = std::make_unique<H3Pair>();
    H3Pair& p = *p_owner;
    ASSERT_TRUE(p.setup(app));
    ASSERT_TRUE(p.handshake(std::chrono::seconds(12)))
        << "QUIC handshake / H3 SETTINGS did not complete";

    // ---- Route 1: GET /ping -> 200 "pong" --------------------------------
    {
        std::uint16_t status = 0;
        std::string body;
        ASSERT_TRUE(round_trip(p, "GET", "/ping", "", status, body))
            << "no HTTP/3 response for GET /ping";
        EXPECT_EQ(status, 200u);
        EXPECT_EQ(body, "pong");
    }

    // ---- Route 2: POST /echo <random multi-KB> -> echoed body ------------
    {
        const std::string payload = make_random_body(8 * 1024, 0xC0FFEE);
        std::uint16_t status = 0;
        std::string body;
        ASSERT_TRUE(round_trip(p, "POST", "/echo", payload, status, body))
            << "no HTTP/3 response for POST /echo";
        EXPECT_EQ(status, 200u);
        ASSERT_EQ(body.size(), payload.size()) << "echo body length mismatch";
        EXPECT_EQ(body, payload) << "echo body not byte-exact";
    }

    // ---- A 404 path proves routing (negative space) ----------------------
    {
        std::uint16_t status = 0;
        std::string body;
        ASSERT_TRUE(round_trip(p, "GET", "/nope", "", status, body));
        EXPECT_EQ(status, 404u);
    }

    p.stop();
    app.stop();
}
