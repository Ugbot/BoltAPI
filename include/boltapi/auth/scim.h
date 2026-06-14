// boltapi/auth/scim.h — SCIM 2.0 (RFC 7643 / 7644) protocol layer.
//
// Pure protocol: parses incoming SCIM JSON into small POD records, emits
// the SCIM list/error wire shapes. STORAGE is the caller's job — the
// `ScimHandler` interface is what the consumer (e.g. Gestalt2) implements
// to plug the SCIM endpoints into its own UserStore/TeamStore.
//
// We implement the 80% that Okta + Azure AD actually use:
//   - User: userName, name.{givenName,familyName}, emails[primary], active,
//     externalId, displayName
//   - Group: displayName, members[{value,display}]
//   - List response (totalResults / Resources)
//   - Filter: `eq` on userName/externalId/displayName, `sw` (starts-with)
//   - PATCH op: `replace` on `active` (suspend); `add`/`remove` on `members`
//
// Fionn (bolt::parse) is used for parsing; no allocations past the
// caller's `out` records (fixed-cap strings, bounded arrays).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::auth::scim {

inline constexpr size_t kMaxStr        = 256;
inline constexpr size_t kMaxEmails     = 4;
inline constexpr size_t kMaxMembers       = 256;   // per Group resource
inline constexpr size_t kMaxPatchOpMembers = 32;    // per PATCH op (keeps stack small)
inline constexpr size_t kMaxPatchOps       = 16;

template <size_t N>
struct FixedStr {
    char     buf[N + 1] = {};
    uint16_t len        = 0;
    void assign(std::string_view s) noexcept {
        len = uint16_t(s.size() <= N ? s.size() : N);
        for (uint16_t i = 0; i < len; ++i) buf[i] = s[i];
        buf[len] = '\0';
    }
    std::string_view view() const noexcept { return {buf, len}; }
    bool empty() const noexcept { return len == 0; }
};

struct ScimEmail {
    FixedStr<kMaxStr> value;
    bool              primary = false;
};

struct ScimUser {
    FixedStr<64>      id;            // server-assigned (read on out, ignored on in)
    FixedStr<kMaxStr> external_id;
    FixedStr<kMaxStr> user_name;
    FixedStr<kMaxStr> display_name;
    FixedStr<kMaxStr> given_name;
    FixedStr<kMaxStr> family_name;
    ScimEmail         emails[kMaxEmails];
    uint8_t           n_emails = 0;
    bool              active   = true;
};

struct ScimGroupMember {
    FixedStr<64>      value;         // member id
    FixedStr<kMaxStr> display;
};

struct ScimGroup {
    FixedStr<64>       id;
    FixedStr<kMaxStr>  external_id;
    FixedStr<kMaxStr>  display_name;
    ScimGroupMember    members[kMaxMembers];
    uint16_t           n_members = 0;
};

enum class PatchAction : uint8_t { kReplace, kAdd, kRemove };

struct PatchOp {
    PatchAction        op = PatchAction::kReplace;
    FixedStr<kMaxStr>  path;            // e.g. "active", "members"
    FixedStr<kMaxStr>  value_simple;    // for scalar values (e.g. "false")
    // For members add/remove: we expose the parsed member list inline.
    // Smaller cap than Group's because real PATCH ops batch < 32 changes.
    ScimGroupMember    members[kMaxPatchOpMembers];
    uint16_t           n_members = 0;
};

struct PatchRequest {
    PatchOp ops[kMaxPatchOps];
    uint8_t n_ops = 0;
};

struct ListFilter {
    enum class Op : uint8_t { kNone, kEq, kSw };
    Op               op    = Op::kNone;
    FixedStr<32>     attr;             // "userName" | "externalId" | "displayName"
    FixedStr<kMaxStr> value;
};

struct ListQuery {
    int32_t     start_index = 1;       // SCIM is 1-indexed
    int32_t     count       = 100;
    ListFilter  filter;
};

// ---------------- Parsing -----------------------------------------------------

bool parse_user (std::string_view json, ScimUser*  out, std::string_view* err = nullptr) noexcept;
bool parse_group(std::string_view json, ScimGroup* out, std::string_view* err = nullptr) noexcept;
bool parse_patch(std::string_view json, PatchRequest* out, std::string_view* err = nullptr) noexcept;
// `filter` and `startIndex`/`count` come from query-string; caller decodes
// them and passes here. `filter_str` is the raw filter= value (e.g.
// `userName eq "alice"`). Returns false on unsupported filter shape.
bool parse_list_query(std::string_view filter_str,
                      int32_t start_index, int32_t count,
                      ListQuery* out) noexcept;

// ---------------- Emission ----------------------------------------------------
// Each emit_* function appends to a caller-owned std::string (the only place we
// allocate in this layer — std::string at the edge is the boltapi norm for
// JSON emission, matched throughout the Gestalt2 handlers).

void emit_user (const ScimUser&  u, std::string* out);
void emit_group(const ScimGroup& g, std::string* out);

struct ListPage {
    int32_t total_results = 0;
    int32_t start_index   = 1;
    int32_t items_per_page = 0;
};
void emit_user_list_begin (const ListPage& p, std::string* out);
void emit_group_list_begin(const ListPage& p, std::string* out);
void emit_list_end        (std::string* out);
void emit_list_separator  (std::string* out);   // call between resources

void emit_error(int http_status, std::string_view detail, std::string* out);

}  // namespace bolt::api::auth::scim
