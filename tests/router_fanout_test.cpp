// router_fanout_test.cpp — regression for the per-node literal fan-out limit.
//
// The original trie stored literal children in a fixed [16] array per node and
// only guarded overflow with a (Release-stripped) assert, so >16 distinct
// sibling literal routes caused an out-of-bounds dereference. Edges now live in
// a shared bolt::SwissTable, so fan-out is unbounded. These tests register far
// more than 16 distinct sibling segments (both parametric and static) and
// verify every route resolves correctly.

#include "boltapi/router.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using bolt::api::Method;
using bolt::api::Router;

namespace {

// Many distinct top-level segments, each a parametric route /rN/{id}. Every
// first segment becomes a distinct literal child of the method-root trie node —
// this is exactly what overflowed the old [16] array.
TEST(RouterFanout, ManyParametricSiblings) {
    constexpr int kN = 200;  // >> old kMaxChildren (16)
    Router r;
    std::vector<uint32_t> ids;
    ids.reserve(kN);
    for (int i = 0; i < kN; ++i) {
        const std::string path = "/r" + std::to_string(i) + "/{id}";
        const uint32_t id = r.add(Method::Get, path);
        ASSERT_NE(id, bolt::api::kInvalidRoute) << "register failed at " << i;
        ids.push_back(id);
    }
    r.build();

    for (int i = 0; i < kN; ++i) {
        const std::string req = "/r" + std::to_string(i) + "/42";
        auto m = r.match(Method::Get, req);
        ASSERT_TRUE(m.matched()) << "no match for " << req;
        EXPECT_EQ(m.route_id, ids[static_cast<size_t>(i)]);
        ASSERT_EQ(m.param_count, 1u);
        EXPECT_EQ(m.params[0].name, "id");
        EXPECT_EQ(m.params[0].value, "42");
    }
    // A sibling that was never registered must miss.
    EXPECT_FALSE(r.match(Method::Get, "/r9999/1").matched());
}

// Many distinct static siblings (these go through the static SwissTable, but we
// assert the router handles a large flat set correctly alongside the trie).
TEST(RouterFanout, ManyStaticSiblings) {
    constexpr int kN = 300;
    Router r;
    std::vector<uint32_t> ids;
    for (int i = 0; i < kN; ++i) {
        const uint32_t id = r.add(Method::Post, "/s" + std::to_string(i));
        ASSERT_NE(id, bolt::api::kInvalidRoute);
        ids.push_back(id);
    }
    r.build();
    for (int i = 0; i < kN; ++i) {
        auto m = r.match(Method::Post, "/s" + std::to_string(i));
        ASSERT_TRUE(m.matched());
        EXPECT_EQ(m.route_id, ids[static_cast<size_t>(i)]);
        EXPECT_EQ(m.param_count, 0u);
    }
    EXPECT_FALSE(r.match(Method::Get, "/s0").matched());  // method mismatch
}

// Deep nesting with many distinct literal children at an inner node.
TEST(RouterFanout, DeepInnerFanout) {
    constexpr int kN = 100;
    Router r;
    for (int i = 0; i < kN; ++i) {
        ASSERT_NE(r.add(Method::Get, "/api/v1/" + std::to_string(i) + "/{id}"),
                  bolt::api::kInvalidRoute);
    }
    r.build();
    for (int i = 0; i < kN; ++i) {
        auto m = r.match(Method::Get, "/api/v1/" + std::to_string(i) + "/xyz");
        ASSERT_TRUE(m.matched()) << i;
        ASSERT_EQ(m.param_count, 1u);
        EXPECT_EQ(m.params[0].value, "xyz");
    }
}

}  // namespace
