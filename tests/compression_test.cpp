// compression_test.cpp — gtest end-to-end coverage for the gzip middleware.
//
// Spins a REAL App with Config.enable_compression = true (background threads) on
// an ephemeral cleartext HTTP/1.1 port, with a route returning a >256-byte body,
// then drives it from a raw client socket.
//
// Dual-mode by design (BOLTAPI_HAVE_GZIP):
//   * gzip present (==1): request with Accept-Encoding: gzip ->
//       assert Content-Encoding: gzip AND decompressing the body yields the
//       original. (Decompress here also uses zlib, available in this mode.)
//   * gzip absent (==0): assert NO Content-Encoding and the plain body is
//       returned unchanged.
// In BOTH modes a request WITHOUT Accept-Encoding must never be compressed, and
// a tiny body must never be compressed.

#include "boltapi/app.h"
#include "boltapi/compression.h"
#include "boltapi/net/sys_compat.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#if BOLTAPI_HAVE_GZIP
#include <zlib.h>
#endif

namespace api = bolt::api;
namespace sys = bolt::api::net::sys;

namespace {

constexpr uint16_t kPort = 19291;

// A deterministic, compressible body well above the 256-byte threshold.
std::string big_body() {
    std::string s;
    for (int i = 0; i < 64; ++i) {
        s += "The quick brown fox jumps over the lazy dog. ";  // 45 bytes
    }
    return s;  // ~2880 bytes
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 client that reads headers + Content-Length body (binary-safe).
// ---------------------------------------------------------------------------
struct HttpResponse {
    int status = 0;
    std::string headers;
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
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    for (;;) {
        if (std::chrono::steady_clock::now() > deadline) break;
        if (header_end != std::string::npos) {
            const std::size_t have_body = buf.size() - (header_end + 4);
            if (content_length >= 0 &&
                have_body >= static_cast<std::size_t>(content_length)) break;
            if (content_length < 0) break;
        }
        ssize_t n = sys::recv_bytes(fd, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (header_end == std::string::npos) {
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                out.headers = buf.substr(0, header_end);
                std::string cl = header_value_ci(out.headers, "Content-Length");
                if (!cl.empty()) content_length = std::stoll(cl);
            }
        }
        if (buf.size() > (1u << 20)) break;
    }
    sys::close_socket(fd);

    if (header_end == std::string::npos) return out;
    {
        std::size_t sp1 = out.headers.find(' ');
        if (sp1 != std::string::npos) out.status = std::atoi(out.headers.c_str() + sp1 + 1);
    }
    out.body = buf.substr(header_end + 4);
    if (content_length >= 0 &&
        out.body.size() > static_cast<std::size_t>(content_length)) {
        out.body.resize(static_cast<std::size_t>(content_length));
    }
    out.ok = true;
    return out;
}

std::string make_get(const std::string& target, const char* accept_encoding) {
    std::string r = "GET " + target + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n";
    if (accept_encoding) {
        r += "Accept-Encoding: ";
        r += accept_encoding;
        r += "\r\n";
    }
    r += "\r\n";
    return r;
}

#if BOLTAPI_HAVE_GZIP
// Inflate a gzip stream (windowBits 15|16) for the roundtrip assertion.
std::string gunzip(const std::string& in) {
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 15 | 16) != Z_OK) return {};
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    std::string out;
    char chunk[8192];
    int rc = Z_OK;
    do {
        zs.next_out = reinterpret_cast<Bytef*>(chunk);
        zs.avail_out = sizeof(chunk);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) break;
        out.append(chunk, sizeof(chunk) - zs.avail_out);
    } while (rc != Z_STREAM_END);
    inflateEnd(&zs);
    return out;
}
#endif

class Compression : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        sys::startup();
        api::App::Config cfg;
        cfg.enable_compression = true;
        app_ = new api::App(cfg);
        app_->get("/big", [](api::Request&, api::Response& res) {
            res.ok().text(big_body());
        });
        app_->get("/tiny", [](api::Request&, api::Response& res) {
            res.ok().text("small");  // below 256B threshold
        });
        ASSERT_EQ(app_->start_background("127.0.0.1", kPort), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }
    static void TearDownTestSuite() {
        if (app_) { app_->stop(); delete app_; app_ = nullptr; }
    }
    static api::App* app_;
};
api::App* Compression::app_ = nullptr;

// ---------------------------------------------------------------------------
TEST_F(Compression, GzipWhenAcceptedAndLargeEnough) {
    const std::string original = big_body();
    HttpResponse r = do_request(make_get("/big", "gzip, deflate"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);

    const std::string ce = header_value_ci(r.headers, "Content-Encoding");

#if BOLTAPI_HAVE_GZIP
    EXPECT_EQ(ce, "gzip");
    EXPECT_NE(header_value_ci(r.headers, "Vary").find("Accept-Encoding"),
              std::string::npos);
    EXPECT_LT(r.body.size(), original.size());  // actually smaller
    EXPECT_EQ(gunzip(r.body), original);        // roundtrips
#else
    EXPECT_TRUE(ce.empty()) << "identity mode must not set Content-Encoding";
    EXPECT_EQ(r.body, original);                // plain body
#endif
}

TEST_F(Compression, NeverCompressWithoutAcceptEncoding) {
    const std::string original = big_body();
    HttpResponse r = do_request(make_get("/big", nullptr));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(header_value_ci(r.headers, "Content-Encoding").empty());
    EXPECT_EQ(r.body, original);
}

TEST_F(Compression, NeverCompressTinyBody) {
    HttpResponse r = do_request(make_get("/tiny", "gzip"));
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(header_value_ci(r.headers, "Content-Encoding").empty());
    EXPECT_EQ(r.body, "small");
}

// Unit-level check of the parser independent of the wire path.
TEST(CompressionParser, AcceptsGzipForms) {
    using api::compression::accepts_gzip;
    EXPECT_TRUE(accepts_gzip("gzip"));
    EXPECT_TRUE(accepts_gzip("gzip, deflate, br"));
    EXPECT_TRUE(accepts_gzip("deflate, gzip"));
    EXPECT_TRUE(accepts_gzip("*"));
    EXPECT_TRUE(accepts_gzip("gzip;q=0.9"));
    EXPECT_FALSE(accepts_gzip("gzip;q=0"));
    EXPECT_FALSE(accepts_gzip("gzip;q=0.0"));
    EXPECT_FALSE(accepts_gzip("deflate, br"));
    EXPECT_FALSE(accepts_gzip(""));
}

}  // namespace
