// boltapi/auth/scim gtest.

#include <gtest/gtest.h>
#include <string>

#include "boltapi/auth/scim.h"

using namespace bolt::api::auth::scim;

TEST(ScimParse, UserBasic) {
    const std::string body = R"({
        "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName":"alice@example.com",
        "name":{"givenName":"Alice","familyName":"Smith"},
        "emails":[{"value":"alice@example.com","primary":true},
                  {"value":"alice@old.com","primary":false}],
        "active":true,
        "externalId":"ext-42"
    })";
    ScimUser u;
    std::string_view err;
    ASSERT_TRUE(parse_user(body, &u, &err)) << err;
    EXPECT_EQ(u.user_name.view(),   "alice@example.com");
    EXPECT_EQ(u.given_name.view(),  "Alice");
    EXPECT_EQ(u.family_name.view(), "Smith");
    EXPECT_EQ(u.external_id.view(), "ext-42");
    EXPECT_TRUE(u.active);
    ASSERT_EQ(u.n_emails, 2);
    EXPECT_EQ(u.emails[0].value.view(), "alice@example.com");
    EXPECT_TRUE (u.emails[0].primary);
    EXPECT_FALSE(u.emails[1].primary);
}

TEST(ScimParse, UserMissingUserNameRejected) {
    ScimUser u; std::string_view err;
    EXPECT_FALSE(parse_user("{\"active\":true}", &u, &err));
    EXPECT_EQ(err, "missing_userName");
}

TEST(ScimParse, GroupWithMembers) {
    const std::string body = R"({
        "displayName":"data-readers",
        "members":[{"value":"u-1","display":"alice"},
                   {"value":"u-2","display":"bob"}]
    })";
    ScimGroup g; std::string_view err;
    ASSERT_TRUE(parse_group(body, &g, &err)) << err;
    EXPECT_EQ(g.display_name.view(), "data-readers");
    ASSERT_EQ(g.n_members, 2);
    EXPECT_EQ(g.members[0].value.view(),   "u-1");
    EXPECT_EQ(g.members[0].display.view(), "alice");
    EXPECT_EQ(g.members[1].value.view(),   "u-2");
}

TEST(ScimParse, PatchReplaceActiveFalse) {
    const std::string body = R"({
        "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations":[{"op":"replace","path":"active","value":false}]
    })";
    PatchRequest p; std::string_view err;
    ASSERT_TRUE(parse_patch(body, &p, &err)) << err;
    ASSERT_EQ(p.n_ops, 1);
    EXPECT_EQ(p.ops[0].op, PatchAction::kReplace);
    EXPECT_EQ(p.ops[0].path.view(), "active");
    EXPECT_EQ(p.ops[0].value_simple.view(), "false");
}

TEST(ScimParse, PatchAddMembers) {
    const std::string body = R"({
        "Operations":[{"op":"add","path":"members",
                       "value":[{"value":"u-7","display":"new"}]}]
    })";
    PatchRequest p; std::string_view err;
    ASSERT_TRUE(parse_patch(body, &p, &err)) << err;
    ASSERT_EQ(p.n_ops, 1);
    EXPECT_EQ(p.ops[0].op, PatchAction::kAdd);
    EXPECT_EQ(p.ops[0].path.view(), "members");
    ASSERT_EQ(p.ops[0].n_members, 1);
    EXPECT_EQ(p.ops[0].members[0].value.view(), "u-7");
}

TEST(ScimParse, FilterEqRecognised) {
    ListQuery q;
    ASSERT_TRUE(parse_list_query("userName eq \"alice\"", 0, 0, &q));
    EXPECT_EQ(q.filter.op, ListFilter::Op::kEq);
    EXPECT_EQ(q.filter.attr.view(),  "userName");
    EXPECT_EQ(q.filter.value.view(), "alice");
}

TEST(ScimParse, FilterSwRecognised) {
    ListQuery q;
    ASSERT_TRUE(parse_list_query("displayName sw \"data-\"", 5, 50, &q));
    EXPECT_EQ(q.filter.op, ListFilter::Op::kSw);
    EXPECT_EQ(q.start_index, 5);
    EXPECT_EQ(q.count, 50);
}

TEST(ScimParse, FilterUnsupportedRejected) {
    ListQuery q;
    EXPECT_FALSE(parse_list_query("userName co \"a\"", 0, 0, &q));
}

TEST(ScimEmit, UserShape) {
    ScimUser u;
    u.id.assign("server-id-1");
    u.user_name.assign("alice");
    u.display_name.assign("Alice S.");
    u.given_name.assign("Alice");
    u.family_name.assign("S.");
    u.emails[u.n_emails++] = ScimEmail{};
    u.emails[0].value.assign("alice@x.com");
    u.emails[0].primary = true;
    u.active = true;

    std::string out;
    emit_user(u, &out);
    EXPECT_NE(out.find("\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"]"), std::string::npos);
    EXPECT_NE(out.find("\"id\":\"server-id-1\""), std::string::npos);
    EXPECT_NE(out.find("\"userName\":\"alice\""), std::string::npos);
    EXPECT_NE(out.find("\"emails\":[{\"value\":\"alice@x.com\""), std::string::npos);
    EXPECT_NE(out.find("\"active\":true"), std::string::npos);

    // Round-trip back to a ScimUser.
    ScimUser back;
    ASSERT_TRUE(parse_user(out, &back));
    EXPECT_EQ(back.user_name.view(), "alice");
    EXPECT_EQ(back.given_name.view(), "Alice");
    ASSERT_EQ(back.n_emails, 1);
}

TEST(ScimEmit, ListAndError) {
    std::string out;
    ListPage pg{3, 1, 3};
    emit_user_list_begin(pg, &out);
    ScimUser u; u.id.assign("1"); u.user_name.assign("a");
    emit_user(u, &out); emit_list_separator(&out);
    u.id.assign("2"); u.user_name.assign("b");
    emit_user(u, &out); emit_list_separator(&out);
    u.id.assign("3"); u.user_name.assign("c");
    emit_user(u, &out);
    emit_list_end(&out);
    EXPECT_NE(out.find("\"totalResults\":3"), std::string::npos);
    EXPECT_NE(out.find("\"Resources\":["), std::string::npos);
    EXPECT_NE(out.find("\"userName\":\"a\""), std::string::npos);
    EXPECT_NE(out.find("\"userName\":\"c\""), std::string::npos);
    EXPECT_EQ(out.back(), '}');

    std::string err;
    emit_error(404, "user not found", &err);
    EXPECT_NE(err.find("\"status\":\"404\""), std::string::npos);
    EXPECT_NE(err.find("\"detail\":\"user not found\""), std::string::npos);
}
