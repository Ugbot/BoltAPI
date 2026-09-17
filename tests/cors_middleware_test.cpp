// cors_middleware_test.cpp — gtest coverage for http::CorsMiddleware.
//
// G2CHK-85: CorsMiddleware's allowed_methods_set_/allowed_headers_set_
// (std::unordered_set<std::string>) were removed in favor of a linear scan
// over the existing config_.allowed_methods/allowed_headers vectors -- the
// same shape is_origin_allowed already used, and strictly faster for the
// handful of entries a real config carries. No prior test touched
// CorsMiddleware at all (it is not yet wired into the live App path --
// src/app.cpp uses its own lightweight facade -- so this is the first
// coverage of the preflight allow/reject paths this change actually
// touches).

#include "boltapi/http/cors.h"

#include <gtest/gtest.h>

namespace http = bolt::api::http;

namespace {
http::CorsConfig basic_config() {
    http::CorsConfig cfg;
    cfg.allowed_origins = {"https://example.com"};
    cfg.allowed_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
    cfg.allowed_headers = {"Content-Type", "Authorization"};
    return cfg;
}
}  // namespace

TEST(CorsMiddleware, PreflightAllowsConfiguredMethodAndHeader) {
    http::CorsMiddleware mw(basic_config());
    auto result = mw.check("OPTIONS", {
        {"Origin", "https://example.com"},
        {"Access-Control-Request-Method", "POST"},
        {"Access-Control-Request-Headers", "Content-Type, Authorization"},
    });
    EXPECT_TRUE(result.is_preflight);
    EXPECT_TRUE(result.allowed);
}

TEST(CorsMiddleware, PreflightRejectsDisallowedMethod) {
    http::CorsMiddleware mw(basic_config());
    auto result = mw.check("OPTIONS", {
        {"Origin", "https://example.com"},
        {"Access-Control-Request-Method", "PATCH"},  // not in allowed_methods
    });
    EXPECT_TRUE(result.is_preflight);
    EXPECT_FALSE(result.allowed);
}

TEST(CorsMiddleware, PreflightRejectsDisallowedHeaderCaseInsensitive) {
    http::CorsMiddleware mw(basic_config());
    // "content-type" (lowercase) must still match "Content-Type" in config,
    // but "X-Custom" must not.
    auto ok = mw.check("OPTIONS", {
        {"Origin", "https://example.com"},
        {"Access-Control-Request-Method", "GET"},
        {"Access-Control-Request-Headers", "content-type"},
    });
    EXPECT_TRUE(ok.allowed);

    auto rejected = mw.check("OPTIONS", {
        {"Origin", "https://example.com"},
        {"Access-Control-Request-Method", "GET"},
        {"Access-Control-Request-Headers", "X-Custom"},
    });
    EXPECT_FALSE(rejected.allowed);
}

TEST(CorsMiddleware, SetConfigRebuildsDerivedState) {
    http::CorsMiddleware mw(basic_config());
    http::CorsConfig narrowed = basic_config();
    narrowed.allowed_methods = {"GET"};
    mw.set_config(narrowed);

    auto result = mw.check("OPTIONS", {
        {"Origin", "https://example.com"},
        {"Access-Control-Request-Method", "POST"},  // was allowed, now isn't
    });
    EXPECT_FALSE(result.allowed);
}
