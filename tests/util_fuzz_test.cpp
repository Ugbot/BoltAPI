// util_fuzz_test.cpp — gtest coverage for tests/util/http_fuzz.h.
//
// Exercises the seeded HTTP/1.1 request generator across many seeds:
//   * determinism: same seed -> identical GeneratedRequest and serialized buffer
//   * bounds: every generated field stays within the named constants
//   * well-formedness: serialize_request emits a parseable HTTP/1.1 request
//     (request line + headers + CRLFCRLF, Content-Length == body size,
//      non-empty method + path).
//   * verb/route coverage: across seeds we see multiple methods and varied paths.

#include "util/http_fuzz.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>

namespace bt = boltapi::test;

namespace {

constexpr std::size_t kSeedCount = 2048;
constexpr std::uint64_t kSeedBase = 0x9E3779B97F4A7C15ULL;

// Locate the header/body boundary; returns std::string::npos when absent.
std::size_t find_header_end(const std::string& raw) {
    return raw.find("\r\n\r\n");
}

// Parse "Header-Name: value" lines between the request line and CRLFCRLF.
// Returns the integer value of the first Content-Length header (or -1).
long long content_length_of(const std::string& raw) {
    const std::size_t header_end = find_header_end(raw);
    if (header_end == std::string::npos) {
        return -1;
    }
    // Skip the request line.
    std::size_t line_start = raw.find("\r\n");
    if (line_start == std::string::npos || line_start > header_end) {
        return -1;
    }
    line_start += 2;
    const std::string key = "Content-Length:";
    while (line_start < header_end) {
        std::size_t line_end = raw.find("\r\n", line_start);
        if (line_end == std::string::npos || line_end > header_end) {
            line_end = header_end;
        }
        const std::string line = raw.substr(line_start, line_end - line_start);
        if (line.size() >= key.size() &&
            line.compare(0, key.size(), key) == 0) {
            std::string num = line.substr(key.size());
            // Trim leading OWS.
            std::size_t i = 0;
            while (i < num.size() && (num[i] == ' ' || num[i] == '\t')) {
                ++i;
            }
            num = num.substr(i);
            if (num.empty()) {
                return -1;
            }
            for (char c : num) {
                if (c < '0' || c > '9') {
                    return -1;
                }
            }
            return std::stoll(num);
        }
        line_start = line_end + 2;
    }
    return -1;
}

}  // namespace

TEST(HttpFuzz, DeterminismSameSeedSameRequest) {
    for (std::size_t s = 0; s < 64; ++s) {
        const std::uint64_t seed = kSeedBase + s;
        bt::FuzzRng a{seed};
        bt::FuzzRng b{seed};
        for (std::size_t i = 0; i < 16; ++i) {
            bt::GeneratedRequest ra = bt::generate_request(a);
            bt::GeneratedRequest rb = bt::generate_request(b);
            EXPECT_EQ(static_cast<int>(ra.method), static_cast<int>(rb.method));
            EXPECT_EQ(ra.path, rb.path);
            EXPECT_EQ(ra.query, rb.query);
            EXPECT_EQ(ra.body, rb.body);
            ASSERT_EQ(ra.headers.size(), rb.headers.size());
            for (std::size_t h = 0; h < ra.headers.size(); ++h) {
                EXPECT_EQ(ra.headers[h].name, rb.headers[h].name);
                EXPECT_EQ(ra.headers[h].value, rb.headers[h].value);
            }
            EXPECT_EQ(bt::serialize_request(ra), bt::serialize_request(rb));
        }
    }
}

TEST(HttpFuzz, DifferentSeedsDiverge) {
    // Not a strict guarantee per draw, but across a batch the buffers must differ.
    bt::FuzzRng a{1};
    bt::FuzzRng b{2};
    std::string ca, cb;
    for (std::size_t i = 0; i < 32; ++i) {
        ca += bt::serialize_request(bt::generate_request(a));
        cb += bt::serialize_request(bt::generate_request(b));
    }
    EXPECT_NE(ca, cb);
}

TEST(HttpFuzz, BoundsRespected) {
    for (std::size_t s = 0; s < kSeedCount; ++s) {
        bt::FuzzRng rng{kSeedBase ^ (s * 0x100000001B3ULL)};
        bt::GeneratedRequest req = bt::generate_request(rng);

        // Path: non-empty, starts with '/', bounded segment count + length.
        ASSERT_FALSE(req.path.empty());
        EXPECT_EQ(req.path.front(), '/');
        std::size_t segments = 0;
        std::size_t seg_len = 0;
        for (std::size_t i = 0; i < req.path.size(); ++i) {
            if (req.path[i] == '/') {
                ++segments;
                seg_len = 0;
            } else {
                ++seg_len;
                EXPECT_LE(seg_len, bt::kMaxSegmentLen);
            }
        }
        EXPECT_GE(segments, std::size_t{1});
        EXPECT_LE(segments, bt::kMaxPathSegments);

        // Headers: bounded count + name/value length (names carry an "X-" prefix).
        EXPECT_LE(req.headers.size(), bt::kMaxHeaders);
        for (const bt::Header& h : req.headers) {
            ASSERT_FALSE(h.name.empty());
            EXPECT_EQ(h.name.compare(0, 2, "X-"), 0);
            EXPECT_LE(h.name.size(), bt::kMaxHeaderNameLen + 2);  // + "X-"
            EXPECT_LE(h.value.size(), bt::kMaxHeaderValLen);
            // No CR/LF smuggling.
            EXPECT_EQ(h.name.find('\r'), std::string::npos);
            EXPECT_EQ(h.name.find('\n'), std::string::npos);
            EXPECT_EQ(h.value.find('\r'), std::string::npos);
            EXPECT_EQ(h.value.find('\n'), std::string::npos);
        }

        // Body: bounded, and only on body-bearing verbs.
        EXPECT_LE(req.body.size(), bt::kMaxBodyLen);
        if (!req.body.empty()) {
            EXPECT_TRUE(bt::method_allows_body(req.method));
        }
    }
}

TEST(HttpFuzz, SerializeIsWellFormed) {
    for (std::size_t s = 0; s < kSeedCount; ++s) {
        bt::FuzzRng rng{kSeedBase + s * 7919ULL};
        bt::GeneratedRequest req = bt::generate_request(rng);
        const std::string raw = bt::serialize_request(req);

        // Must contain a header/body separator.
        const std::size_t header_end = find_header_end(raw);
        ASSERT_NE(header_end, std::string::npos) << "missing CRLFCRLF";

        // Request line: METHOD SP target SP HTTP/1.1
        const std::size_t first_crlf = raw.find("\r\n");
        ASSERT_NE(first_crlf, std::string::npos);
        const std::string request_line = raw.substr(0, first_crlf);
        const std::size_t sp1 = request_line.find(' ');
        ASSERT_NE(sp1, std::string::npos);
        const std::string method = request_line.substr(0, sp1);
        EXPECT_FALSE(method.empty());
        EXPECT_EQ(method, std::string(bt::method_name(req.method)));

        const std::size_t sp2 = request_line.rfind(' ');
        ASSERT_NE(sp2, std::string::npos);
        ASSERT_GT(sp2, sp1);
        const std::string target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
        EXPECT_FALSE(target.empty());
        EXPECT_EQ(target.front(), '/');
        EXPECT_EQ(request_line.substr(sp2 + 1), "HTTP/1.1");

        // Host header present.
        EXPECT_NE(raw.find("\r\nHost: "), std::string::npos);

        // Content-Length present and equal to actual body length.
        const long long cl = content_length_of(raw);
        ASSERT_GE(cl, 0) << "missing/invalid Content-Length";
        const std::string body = raw.substr(header_end + 4);
        EXPECT_EQ(static_cast<std::size_t>(cl), body.size());
        EXPECT_EQ(body, req.body);
    }
}

TEST(HttpFuzz, CoversMultipleVerbsAndRoutes) {
    std::set<int> verbs;
    std::set<std::string> paths;
    bt::FuzzRng rng{0xABCDEF01u};
    for (std::size_t i = 0; i < kSeedCount; ++i) {
        bt::GeneratedRequest req = bt::generate_request(rng);
        verbs.insert(static_cast<int>(req.method));
        paths.insert(req.path);
    }
    // All seven methods should appear over a large sample.
    EXPECT_EQ(verbs.size(), bt::kMethodCount);
    // Routes should be highly varied.
    EXPECT_GT(paths.size(), std::size_t{100});
}
