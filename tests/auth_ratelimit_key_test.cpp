// boltapi/auth/ratelimit_key gtest.

#include <gtest/gtest.h>
#include <thread>

#include "boltapi/auth/ratelimit_key.h"

using namespace bolt::api::auth;

TEST(RateLimitKey, BurstAllowedThenDenied) {
    RateLimitKey rl;
    RateLimitKey::Config c{5, 1};
    for (int i = 0; i < 5; ++i)
        EXPECT_TRUE(rl.consume("alice@example.com", c)) << "iter " << i;
    EXPECT_FALSE(rl.consume("alice@example.com", c));
}

TEST(RateLimitKey, DistinctKeysAreIndependent) {
    RateLimitKey rl;
    RateLimitKey::Config c{3, 1};
    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(rl.consume("alice", c));
        EXPECT_TRUE(rl.consume("bob",   c));
    }
    EXPECT_FALSE(rl.consume("alice", c));
    EXPECT_FALSE(rl.consume("bob",   c));
    EXPECT_TRUE (rl.consume("carol", c));
}

TEST(RateLimitKey, ResetReturnsToFullBucket) {
    RateLimitKey rl;
    RateLimitKey::Config c{2, 1};
    EXPECT_TRUE (rl.consume("k", c));
    EXPECT_TRUE (rl.consume("k", c));
    EXPECT_FALSE(rl.consume("k", c));
    rl.reset("k");
    EXPECT_TRUE (rl.consume("k", c));
    EXPECT_TRUE (rl.consume("k", c));
    EXPECT_FALSE(rl.consume("k", c));
}

TEST(RateLimitKey, ZeroCapacityDeniesAll) {
    RateLimitKey rl;
    RateLimitKey::Config c{0, 0};
    EXPECT_FALSE(rl.consume("anybody", c));
}

TEST(RateLimitKey, EmptyAndOversizedKeysGraceful) {
    RateLimitKey rl;
    RateLimitKey::Config c{1, 1};
    std::string huge(RateLimitKey::kMaxKeyBytes + 1, 'x');
    EXPECT_TRUE(rl.consume(huge, c));  // fail-open on unbounded key
}

TEST(RateLimitKey, RefillRestoresAfterSleep) {
    RateLimitKey rl;
    RateLimitKey::Config c{2, /*refill_per_sec=*/200};  // fast refill so the test is fast
    EXPECT_TRUE (rl.consume("k", c));
    EXPECT_TRUE (rl.consume("k", c));
    EXPECT_FALSE(rl.consume("k", c));
    // Sleep ~30ms — at 200/sec we expect ~6 tokens to have refilled, capped at 2.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(rl.consume("k", c));
    EXPECT_TRUE(rl.consume("k", c));
}
