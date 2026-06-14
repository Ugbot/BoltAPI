// boltapi/auth/password_policy gtest.

#include <gtest/gtest.h>
#include <cstring>

#include "boltapi/auth/password_policy.h"

using namespace bolt::api::auth::password_policy;

TEST(PasswordPolicy, DefaultsAcceptStrongPassword) {
    Config c;
    Result r = evaluate("Tr0ub4dor&3Long!", c);
    EXPECT_TRUE(r.ok) << "reason=" << r.reason;
}

TEST(PasswordPolicy, RejectsTooShort) {
    Config c; c.min_len = 12;
    Result r = evaluate("Abc1!", c);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.reason, "too_short");
}

TEST(PasswordPolicy, RejectsTooLong) {
    Config c; c.max_len = 16;
    Result r = evaluate("Abcdefghijklmnop1Q!extra", c);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.reason, "too_long");
}

TEST(PasswordPolicy, RejectsMissingUpperLowerDigit) {
    Config c;
    EXPECT_EQ(evaluate("alllowercase1!", c).reason, "missing_upper");
    EXPECT_EQ(evaluate("ALLUPPERCASE1!", c).reason, "missing_lower");
    EXPECT_EQ(evaluate("AllNoDigitsOk!", c).reason, "missing_digit");
}

TEST(PasswordPolicy, RejectsWhitespaceWhenForbidden) {
    Config c;
    EXPECT_EQ(evaluate("Has Whitespace1", c).reason, "has_whitespace");
}

TEST(PasswordPolicy, AllowsSymbolsWhenRequired) {
    Config c; c.require_symbol = true;
    EXPECT_EQ(evaluate("NoSymbolHere12", c).reason, "missing_symbol");
    EXPECT_TRUE(evaluate("HasSymbol1!?@", c).ok);
}

TEST(PasswordPolicy, Sha1HexMatchesKnownVector) {
    char hex[41] = {};
    // Known: SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    sha1_upper_hex("password", hex);
    hex[40] = '\0';
    EXPECT_STREQ("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", hex);
}

static bool always_pwned(const char[40], void*) noexcept { return true; }
static bool never_pwned (const char[40], void*) noexcept { return false; }

TEST(PasswordPolicy, PwnedCheckerOverridesEvenIfPolicyOk) {
    Config c;
    Result r = evaluate_with_pwned_check("Tr0ub4dor&3Long!", c, always_pwned, nullptr);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.reason, "pwned");
    r = evaluate_with_pwned_check("Tr0ub4dor&3Long!", c, never_pwned, nullptr);
    EXPECT_TRUE(r.ok);
}
