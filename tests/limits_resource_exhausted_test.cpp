// limits_resource_exhausted_test.cpp — G2CHK-330: boltapi carries
// resource_exhausted (error code, HTTP 413/507 reason phrases, SQLSTATE
// 54000), never labels an error "OK", enforces the RowDescription bound in
// release, and registers its limits table.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "../src/proto/postgres_wire_internal.h"
#include "boltapi/boltapi_limits.h"
#include "boltapi/core/result.h"
#include "boltapi/proto/postgres_wire.h"
#include "boltapi/response.h"

namespace pg = bolt::api::proto::pgwire;

TEST(LimitsResourceExhausted, ErrorCodeAndStatusMapping) {
    EXPECT_EQ(static_cast<int>(bolt::api::core::error_code::resource_exhausted), 9);
    EXPECT_STREQ(bolt::api::Response::reason_phrase(413), "Content Too Large");
    EXPECT_STREQ(bolt::api::Response::reason_phrase(507), "Insufficient Storage");
    EXPECT_STREQ(bolt::api::Response::reason_phrase(431), "Request Header Fields Too Large");
    EXPECT_STREQ(bolt::api::Response::reason_phrase(412), "Precondition Failed");
    EXPECT_STREQ(bolt::api::Response::reason_phrase(499), "Client Error");
    EXPECT_STREQ(bolt::api::Response::reason_phrase(599), "Server Error");
    EXPECT_STREQ(pg::kSqlStateProgramLimitExceeded, "54000");
}

TEST(LimitsResourceExhausted, RowDescriptionBoundEnforcedInRelease) {
    static std::uint8_t buf[1 << 16];
    pg::FieldDesc fields[pg::kMaxFields + 1];
    for (auto& f : fields) f.name = "c";
    pg::detail::MsgWriter ok_w(buf, sizeof(buf));
    EXPECT_TRUE(pg::detail::put_row_description(ok_w, fields, pg::kMaxFields, nullptr));
    pg::detail::MsgWriter bad_w(buf, sizeof(buf));
    EXPECT_FALSE(pg::detail::put_row_description(bad_w, fields, pg::kMaxFields + 1, nullptr));
}

TEST(LimitsResourceExhausted, LimitsTableRegisters) {
    const bolt::LimitTable& t = bolt::api::boltapi_limits();
    EXPECT_STREQ(t.owner, "boltapi");
    EXPECT_EQ(bolt::api::boltapi_limits_value(bolt::api::boltapi_limits_id::pgwire_max_fields),
              pg::kMaxFields);
    const bolt::LimitTable* found = nullptr;
    uint32_t idx = 0;
    ASSERT_TRUE(bolt::limits_find("router_max_params", &found, &idx));
    EXPECT_EQ(found, &t);
}
