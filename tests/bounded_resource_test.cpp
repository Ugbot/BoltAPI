// bounded_resource_test.cpp — hardening: the server enforces its configured
// resource bounds and stays alive after rejecting abusive requests, and the
// Router degrades gracefully on over-deep / over-param paths (no UB, no crash).
//
// Part A (App, real socket on an ephemeral port, SMALL limits):
//   (a) body  > max_body_size   -> 413 Payload Too Large
//   (b) headers > max_header_size -> 431 Request Header Fields Too Large
//   (c) a normal request still   -> 200 (server responsive after rejects)
//   plus: many interleaved rejects then a final 200 (no crash / no wedge).
//
// Part B (Router, public API only):
//   over-deep path (> kMaxSegments) and over-param path (> kMaxParams) are
//   handled gracefully at registration and at match() (sentinel / no-match,
//   never UB).
//
// Mirrors tests/app_integration_test.cpp for the client + fixture pattern.

#include "boltapi/app.h"
#include "boltapi/router.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort           = 19223;  // distinct from other suites
constexpr std::size_t kMaxBody     = 1024;   // server max_body_size
constexpr std::size_t kMaxHeader   = 512;    // server max_header_size

// ---------------------------------------------------------------------------
// Minimal blocking client: send `raw`, read until the peer closes (the server
// sends Connection: close on rejects) or we have headers + Content-Length body.
// Returns parsed status (0 on transport failure).
// ---------------------------------------------------------------------------
struct HttpResponse {
    int status = 0;
    std::string headers_block;
    std::string body;
    bool ok = false;
};

std::string header_value_ci(const std::string& headers, const char* name) {
    std::string lname = name;
    for (char& c : lname) c = static_cast<char>(std::tolower((unsigned char)c));
    std::size_t pos = headers.find("\r\n");
    if (pos == std::string::npos) return {};
    pos += 2;
    while (pos < headers.size()) {
        std::size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            for (char& c : key) c = static_cast<char>(std::tolower((unsigned char)c));
            if (key == lname) {
                std::string val = line.substr(colon + 1);
                std::size_t b = 0, e = val.size();
                while (b < e && (val[b] == ' ' || val[b] == '\t')) ++b;
                while (e > b && (val[e - 1] == ' ' || val[e - 1] == '\t')) --e;
                return val.substr(b, e - b);
            }
        }
        pos = eol + 2;
    }
    return {};
}

HttpResponse do_request(const std::string& raw) {
    HttpResponse out;
    sys::startup();

    int fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) return out;

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        sys::close_socket(fd);
        return out;
    }

    std::size_t sent = 0;
    while (sent < raw.size()) {
        ssize_t n = sys::send_bytes(fd, raw.data() + sent, raw.size() - sent);
        if (n <= 0) break;
        sent += static_cast<std::size_t>(n);
    }

    std::string buf;
    char tmp[4096];
    std::size_t header_end = std::string::npos;
    long long content_length = -1;

    for (;;) {
        if (header_end != std::string::npos) {
            const std::size_t have_body = buf.size() - (header_end + 4);
            if (content_length >= 0 &&
                have_body >= static_cast<std::size_t>(content_length)) {
                break;
            }
            if (content_length < 0) break;
        }
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;  // peer closed (reject) or error
        buf.append(tmp, static_cast<std::size_t>(n));
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                out.headers_block = buf.substr(0, header_end);
                std::string cl = header_value_ci(out.headers_block, "Content-Length");
                if (!cl.empty()) content_length = std::stoll(cl);
            }
        }
        if (buf.size() > (1u << 20)) break;  // safety cap
    }

    sys::close_socket(fd);

    if (header_end == std::string::npos) return out;
    {
        const std::string& h = out.headers_block;
        std::size_t sp1 = h.find(' ');
        if (sp1 != std::string::npos) out.status = std::atoi(h.c_str() + sp1 + 1);
    }
    out.body = buf.substr(header_end + 4);
    if (content_length >= 0 &&
        out.body.size() > static_cast<std::size_t>(content_length)) {
        out.body.resize(static_cast<std::size_t>(content_length));
    }
    out.ok = true;
    return out;
}

// ---------------------------------------------------------------------------
// Fixture: App with deliberately small body/header limits.
// ---------------------------------------------------------------------------
class BoundedResource : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();

        api::App::Config cfg;
        cfg.server.max_body_size   = kMaxBody;
        cfg.server.max_header_size = kMaxHeader;
        app_ = new api::App(std::move(cfg));

        app_->get("/ping", [](api::Request&, api::Response& res) {
            res.ok().text("pong");
        });
        app_->post("/upload", [](api::Request& req, api::Response& res) {
            res.created().text(std::to_string(req.body().size()));
        });

        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }

    static void TearDownTestSuite() {
        if (app_) {
            app_->stop();
            delete app_;
            app_ = nullptr;
        }
    }

    static api::App* app_;
};

api::App* BoundedResource::app_ = nullptr;

// Build a request with an explicit Content-Length and `body_len` body bytes.
std::string make_body_request(const char* method, const char* target,
                              std::size_t body_len) {
    std::string r = method;
    r += ' ';
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: ";
    r += std::to_string(body_len);
    r += "\r\n\r\n";
    r.append(body_len, 'A');
    return r;
}

// Build a request whose header block alone exceeds `header_bytes` via one fat
// custom header value. No body.
std::string make_fat_header_request(const char* target, std::size_t header_bytes) {
    std::string r = "GET ";
    r += target;
    r += " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Pad: ";
    r.append(header_bytes, 'Z');
    r += "\r\nContent-Length: 0\r\n\r\n";
    return r;
}

// ---------------------------------------------------------------------------
// Part A — server resource bounds.
// ---------------------------------------------------------------------------
TEST_F(BoundedResource, NormalRequestSucceeds) {
    HttpResponse r = do_request(make_body_request("GET", "/ping", 0));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "pong");
}

TEST_F(BoundedResource, BodyUnderLimitSucceeds) {
    // A body comfortably under the limit must be accepted and echoed (length).
    const std::size_t n = kMaxBody / 2;
    HttpResponse r = do_request(make_body_request("POST", "/upload", n));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 201);
    EXPECT_EQ(r.body, std::to_string(n));
}

TEST_F(BoundedResource, OversizedBodyIs413) {
    // Content-Length beyond max_body_size -> 413, no crash.
    HttpResponse r = do_request(make_body_request("POST", "/upload", kMaxBody * 4));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 413);
}

TEST_F(BoundedResource, OversizedHeadersAre431) {
    // Header block well beyond max_header_size -> 431, no crash.
    HttpResponse r = do_request(make_fat_header_request("/ping", kMaxHeader * 4));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 431);
}

TEST_F(BoundedResource, ResponsiveAfterRejects) {
    // Interleave abusive requests with a good one; the server must keep serving.
    for (int i = 0; i < 5; ++i) {
        HttpResponse big_body = do_request(make_body_request("POST", "/upload",
                                                             kMaxBody * 4));
        ASSERT_TRUE(big_body.ok);
        EXPECT_EQ(big_body.status, 413) << "iter " << i;

        HttpResponse big_hdr = do_request(make_fat_header_request("/ping",
                                                                 kMaxHeader * 4));
        ASSERT_TRUE(big_hdr.ok);
        EXPECT_EQ(big_hdr.status, 431) << "iter " << i;
    }
    // Final good request proves the server is still alive and responsive.
    HttpResponse good = do_request(make_body_request("GET", "/ping", 0));
    ASSERT_TRUE(good.ok);
    EXPECT_EQ(good.status, 200);
    EXPECT_EQ(good.body, "pong");
}

// ---------------------------------------------------------------------------
// Part B — Router bounds (public API only; no UB).
// ---------------------------------------------------------------------------
TEST(RouterBounds, OverDeepPathRejectedAtAdd) {
    api::Router r;
    // Register a normal route so the router is non-empty + buildable.
    const uint32_t ok_id = r.add(api::Method::Get, "/ok");
    EXPECT_NE(ok_id, api::kInvalidRoute);

    // A path with more than kMaxSegments segments must be rejected gracefully.
    std::string deep;
    for (uint32_t i = 0; i < api::kMaxSegments + 5; ++i) deep += "/s";
    const uint32_t deep_id = r.add(api::Method::Get, deep);
    EXPECT_EQ(deep_id, api::kInvalidRoute) << "over-deep add must return sentinel";

    r.build();

    // Matching an over-deep path must not match and must not crash/UB.
    api::MatchResult m = r.match(api::Method::Get, deep);
    EXPECT_FALSE(m.matched());

    // The normal route still resolves.
    api::MatchResult ok = r.match(api::Method::Get, "/ok");
    EXPECT_TRUE(ok.matched());
    EXPECT_EQ(ok.route_id, ok_id);
}

TEST(RouterBounds, OverParamPathRejectedAtAdd) {
    api::Router r;
    // Build a route with more than kMaxParams parametric segments.
    std::string many;
    for (uint32_t i = 0; i < api::kMaxParams + 3; ++i) {
        many += "/{p";
        many += std::to_string(i);
        many += "}";
    }
    // This exceeds kMaxParams (and likely kMaxSegments too) — either way the
    // public contract is a sentinel, never UB.
    const uint32_t id = r.add(api::Method::Get, many);
    EXPECT_EQ(id, api::kInvalidRoute);

    // A within-bounds param route still works after the rejected add.
    const uint32_t good = r.add(api::Method::Get, "/users/{id}");
    EXPECT_NE(good, api::kInvalidRoute);
    r.build();

    api::MatchResult m = r.match(api::Method::Get, "/users/77");
    EXPECT_TRUE(m.matched());
    EXPECT_EQ(m.route_id, good);
    ASSERT_EQ(m.param_count, 1u);
    EXPECT_EQ(m.params[0].value, "77");
}

TEST(RouterBounds, MatchOverDeepRequestPathIsSafe) {
    api::Router r;
    r.add(api::Method::Get, "/a/{x}");
    r.build();

    // A request path far deeper than any route + kMaxSegments must miss safely.
    std::string deep;
    for (uint32_t i = 0; i < api::kMaxSegments + 10; ++i) deep += "/x";
    api::MatchResult m = r.match(api::Method::Get, deep);
    EXPECT_FALSE(m.matched());

    // Empty path is rejected, not UB.
    api::MatchResult e = r.match(api::Method::Get, "");
    EXPECT_FALSE(e.matched());
}

}  // namespace
