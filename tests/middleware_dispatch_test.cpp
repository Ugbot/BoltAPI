// middleware_dispatch_test.cpp — gtest coverage for Middleware's dispatch
// table (include/boltapi/http/middleware.h, src/http/middleware.cpp).
//
// G2CHK-85: middleware_funcs_ moved off
// std::unordered_map<Type, std::function<...>> onto a fixed
// std::array<std::function<...>, Type::_COUNT> indexed by
// static_cast<size_t>(Type) -- Type is a plain 0-based enum with a _COUNT
// sentinel, so direct indexing is exact and allocation-free. No prior test
// touched Middleware at all (it is dead code today -- not reachable from the
// live App/request path, see include/boltapi/middleware.h for the class
// that actually runs -- so this is new coverage for the dispatch logic this
// change touches, using add_middleware() to override each slot with a
// counting probe rather than driving the real (fragile, legacy) rate-limit/
// auth/CORS bodies).

#include "boltapi/http/middleware.h"
#include "boltapi/http/request.h"
#include "boltapi/http/response.h"

#include <gtest/gtest.h>

#include <array>

TEST(MiddlewareDispatch, AllSixTypesAreInvokedInOrder) {
    Middleware mw;
    std::array<int, 6> call_order{};
    int next = 0;

    auto probe = [&](int slot) {
        return [&call_order, &next, slot](HttpRequest*, HttpResponse*) -> int {
            call_order[static_cast<size_t>(slot)] = ++next;
            return 0;  // continue the chain
        };
    };

    mw.add_middleware(Middleware::Type::CORS, probe(0));
    mw.add_middleware(Middleware::Type::RATE_LIMIT, probe(1));
    mw.add_middleware(Middleware::Type::AUTHENTICATION, probe(2));
    mw.add_middleware(Middleware::Type::SECURITY, probe(3));
    mw.add_middleware(Middleware::Type::COMPRESSION, probe(4));
    mw.add_middleware(Middleware::Type::LOGGING, probe(5));

    HttpRequest req;
    HttpResponse res;
    int result = mw.process_request(&req, &res);

    EXPECT_EQ(result, 0);
    // process_request's fixed middleware_order is CORS, RATE_LIMIT,
    // AUTHENTICATION, SECURITY, COMPRESSION, LOGGING -- every slot must have
    // run exactly once, in that order.
    EXPECT_EQ(call_order[0], 1);  // CORS
    EXPECT_EQ(call_order[1], 2);  // RATE_LIMIT
    EXPECT_EQ(call_order[2], 3);  // AUTHENTICATION
    EXPECT_EQ(call_order[3], 4);  // SECURITY
    EXPECT_EQ(call_order[4], 5);  // COMPRESSION
    EXPECT_EQ(call_order[5], 6);  // LOGGING
}

TEST(MiddlewareDispatch, NonZeroReturnShortCircuitsChain) {
    Middleware mw;
    bool logging_ran = false;

    mw.add_middleware(Middleware::Type::RATE_LIMIT,
                       [](HttpRequest*, HttpResponse*) -> int { return 1; });  // blocked
    mw.add_middleware(Middleware::Type::LOGGING,
                       [&](HttpRequest*, HttpResponse*) -> int {
                           logging_ran = true;
                           return 0;
                       });
    // CORS/AUTHENTICATION/SECURITY/COMPRESSION keep their ctor defaults
    // (disabled-by-default configs, so they no-op and return 0) -- CORS runs
    // before RATE_LIMIT in middleware_order, so it must still fire.

    HttpRequest req;
    HttpResponse res;
    int result = mw.process_request(&req, &res);

    EXPECT_EQ(result, 1);
    EXPECT_FALSE(logging_ran);  // LOGGING is after RATE_LIMIT in the order
}

TEST(MiddlewareDispatch, AddMiddlewareOverwritesPriorRegistration) {
    Middleware mw;
    int calls = 0;
    mw.add_middleware(Middleware::Type::SECURITY,
                       [&](HttpRequest*, HttpResponse*) -> int { ++calls; return 0; });
    mw.add_middleware(Middleware::Type::SECURITY,
                       [&](HttpRequest*, HttpResponse*) -> int { calls += 10; return 0; });

    HttpRequest req;
    HttpResponse res;
    mw.process_request(&req, &res);

    EXPECT_EQ(calls, 10);  // only the second registration should have run
}
