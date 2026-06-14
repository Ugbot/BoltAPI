// boltapi/auth/scim.cpp — SCIM 2.0 parser + emitter.
//
// Parsing rides on bolt::api::json (fionn). Emission writes into a
// caller-owned std::string (the standard boltapi-edge convention for JSON
// serialization). Everything else is fixed-cap PODs.

#include "boltapi/auth/scim.h"

#include <cassert>
#include <cstdio>
#include <cstring>

#include "boltapi/json.h"

namespace bolt::api::auth::scim {

namespace {

constexpr std::string_view kSchemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User";
constexpr std::string_view kSchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group";
constexpr std::string_view kSchemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
constexpr std::string_view kSchemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
constexpr std::string_view kSchemaError = "urn:ietf:params:scim:api:messages:2.0:Error";

void json_escape_into(std::string_view s, std::string* out) {
    out->reserve(out->size() + s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out->append("\\\""); break;
            case '\\': out->append("\\\\"); break;
            case '\n': out->append("\\n");  break;
            case '\r': out->append("\\r");  break;
            case '\t': out->append("\\t");  break;
            default:
                if (uint8_t(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uint8_t(c));
                    out->append(buf);
                } else {
                    out->push_back(c);
                }
        }
    }
}

void emit_kv_str(std::string* out, std::string_view k, std::string_view v,
                 bool* first) {
    if (!*first) out->push_back(',');
    *first = false;
    out->push_back('"'); out->append(k.data(), k.size()); out->append("\":\"");
    json_escape_into(v, out);
    out->push_back('"');
}

void emit_kv_bool(std::string* out, std::string_view k, bool v, bool* first) {
    if (!*first) out->push_back(',');
    *first = false;
    out->push_back('"'); out->append(k.data(), k.size()); out->append("\":");
    out->append(v ? "true" : "false");
}

void emit_kv_int(std::string* out, std::string_view k, int64_t v, bool* first) {
    if (!*first) out->push_back(',');
    *first = false;
    out->push_back('"'); out->append(k.data(), k.size()); out->append("\":");
    char b[24]; std::snprintf(b, sizeof(b), "%lld", static_cast<long long>(v));
    out->append(b);
}

}  // namespace

// ---------- Parsing ---------------------------------------------------------

bool parse_user(std::string_view body, ScimUser* out, std::string_view* err) noexcept {
    assert(out != nullptr);
    *out = ScimUser{};
    auto doc = bolt::api::json::parse(body);
    if (!doc.ok()) { if (err) *err = "malformed_json"; return false; }
    auto root = doc.root();
    if (!root.is_object()) { if (err) *err = "not_object"; return false; }

    // Optional schema check (best-effort — many clients omit it on input).
    std::string_view sv;
    if (root["userName"].get_string(&sv))    out->user_name.assign(sv);
    if (root["externalId"].get_string(&sv))  out->external_id.assign(sv);
    if (root["displayName"].get_string(&sv)) out->display_name.assign(sv);
    out->active = root["active"].as_bool(true);

    auto name = root["name"];
    if (name.is_object()) {
        if (name["givenName"].get_string(&sv))  out->given_name.assign(sv);
        if (name["familyName"].get_string(&sv)) out->family_name.assign(sv);
    }
    auto emails = root["emails"];
    if (emails.is_array()) {
        const int32_t n = emails.size();
        for (int32_t i = 0; i < n && out->n_emails < kMaxEmails; ++i) {
            auto e = emails.at(i);
            if (!e.is_object()) continue;
            ScimEmail em;
            if (e["value"].get_string(&sv)) em.value.assign(sv);
            em.primary = e["primary"].as_bool(false);
            if (!em.value.empty()) out->emails[out->n_emails++] = em;
        }
    }
    if (out->user_name.empty()) { if (err) *err = "missing_userName"; return false; }
    return true;
}

bool parse_group(std::string_view body, ScimGroup* out, std::string_view* err) noexcept {
    assert(out != nullptr);
    *out = ScimGroup{};
    auto doc = bolt::api::json::parse(body);
    if (!doc.ok()) { if (err) *err = "malformed_json"; return false; }
    auto root = doc.root();
    if (!root.is_object()) { if (err) *err = "not_object"; return false; }

    std::string_view sv;
    if (root["displayName"].get_string(&sv)) out->display_name.assign(sv);
    if (root["externalId"].get_string(&sv))  out->external_id.assign(sv);
    auto members = root["members"];
    if (members.is_array()) {
        const int32_t n = members.size();
        for (int32_t i = 0; i < n && out->n_members < kMaxMembers; ++i) {
            auto m = members.at(i);
            if (!m.is_object()) continue;
            ScimGroupMember gm;
            if (m["value"].get_string(&sv))   gm.value.assign(sv);
            if (m["display"].get_string(&sv)) gm.display.assign(sv);
            if (!gm.value.empty()) out->members[out->n_members++] = gm;
        }
    }
    if (out->display_name.empty()) { if (err) *err = "missing_displayName"; return false; }
    return true;
}

bool parse_patch(std::string_view body, PatchRequest* out, std::string_view* err) noexcept {
    assert(out != nullptr);
    *out = PatchRequest{};
    auto doc = bolt::api::json::parse(body);
    if (!doc.ok()) { if (err) *err = "malformed_json"; return false; }
    auto root = doc.root();
    if (!root.is_object()) { if (err) *err = "not_object"; return false; }
    auto ops = root["Operations"];
    if (!ops.is_array()) { if (err) *err = "missing_Operations"; return false; }

    const int32_t n = ops.size();
    for (int32_t i = 0; i < n && out->n_ops < kMaxPatchOps; ++i) {
        auto e = ops.at(i);
        if (!e.is_object()) continue;
        PatchOp& op = out->ops[out->n_ops];
        std::string_view sv;
        // SCIM op names are case-insensitive in some clients; normalize lower.
        if (e["op"].get_string(&sv)) {
            char lower[16] = {};
            const size_t k = sv.size() < sizeof(lower) - 1 ? sv.size() : sizeof(lower) - 1;
            for (size_t j = 0; j < k; ++j)
                lower[j] = (sv[j] >= 'A' && sv[j] <= 'Z') ? char(sv[j] - 'A' + 'a') : sv[j];
            std::string_view lo(lower, k);
            if      (lo == "replace") op.op = PatchAction::kReplace;
            else if (lo == "add")     op.op = PatchAction::kAdd;
            else if (lo == "remove")  op.op = PatchAction::kRemove;
            else continue;  // unsupported op — skip
        }
        if (e["path"].get_string(&sv)) op.path.assign(sv);
        auto val = e["value"];
        if (val.is_string()) {
            if (val.get_string(&sv)) op.value_simple.assign(sv);
        } else if (val.is_bool()) {
            op.value_simple.assign(val.as_bool() ? "true" : "false");
        } else if (val.is_array()) {
            // Member list (add/remove members).
            const int32_t mn = val.size();
            for (int32_t j = 0; j < mn && op.n_members < kMaxPatchOpMembers; ++j) {
                auto m = val.at(j);
                if (!m.is_object()) continue;
                ScimGroupMember gm;
                if (m["value"].get_string(&sv))   gm.value.assign(sv);
                if (m["display"].get_string(&sv)) gm.display.assign(sv);
                if (!gm.value.empty()) op.members[op.n_members++] = gm;
            }
        }
        ++out->n_ops;
    }
    return out->n_ops > 0;
}

bool parse_list_query(std::string_view filter_str,
                      int32_t start_index, int32_t count,
                      ListQuery* out) noexcept {
    assert(out != nullptr);
    *out = ListQuery{};
    if (start_index > 0) out->start_index = start_index;
    if (count > 0)       out->count       = count;
    if (filter_str.empty()) return true;

    // Recognised shapes:
    //   <attr> eq "value"
    //   <attr> sw "value"
    // Anything else → unsupported (return false; caller should 501).
    size_t sp = filter_str.find(' ');
    if (sp == std::string_view::npos) return false;
    auto attr = filter_str.substr(0, sp);
    auto rest = filter_str.substr(sp + 1);
    sp = rest.find(' ');
    if (sp == std::string_view::npos) return false;
    auto op_sv = rest.substr(0, sp);
    auto value = rest.substr(sp + 1);
    if (value.size() < 2 || value.front() != '"' || value.back() != '"') return false;
    value = value.substr(1, value.size() - 2);

    if      (op_sv == "eq") out->filter.op = ListFilter::Op::kEq;
    else if (op_sv == "sw") out->filter.op = ListFilter::Op::kSw;
    else return false;

    out->filter.attr.assign(attr);
    out->filter.value.assign(value);
    return true;
}

// ---------- Emission --------------------------------------------------------

void emit_user(const ScimUser& u, std::string* out) {
    assert(out != nullptr);
    out->reserve(out->size() + 512);
    out->push_back('{');
    bool first = true;
    out->append("\"schemas\":[\""); out->append(kSchemaUser); out->append("\"]");
    first = false;
    if (!u.id.empty())           emit_kv_str (out, "id",          u.id.view(),           &first);
    if (!u.external_id.empty())  emit_kv_str (out, "externalId",  u.external_id.view(),  &first);
    if (!u.user_name.empty())    emit_kv_str (out, "userName",    u.user_name.view(),    &first);
    if (!u.display_name.empty()) emit_kv_str (out, "displayName", u.display_name.view(), &first);

    if (!u.given_name.empty() || !u.family_name.empty()) {
        out->append(",\"name\":{");
        bool nfirst = true;
        if (!u.given_name.empty())  emit_kv_str(out, "givenName",  u.given_name.view(),  &nfirst);
        if (!u.family_name.empty()) emit_kv_str(out, "familyName", u.family_name.view(), &nfirst);
        out->push_back('}');
    }
    if (u.n_emails > 0) {
        out->append(",\"emails\":[");
        for (uint8_t i = 0; i < u.n_emails; ++i) {
            if (i > 0) out->push_back(',');
            out->push_back('{');
            bool ef = true;
            emit_kv_str (out, "value",   u.emails[i].value.view(), &ef);
            emit_kv_bool(out, "primary", u.emails[i].primary,      &ef);
            out->push_back('}');
        }
        out->push_back(']');
    }
    emit_kv_bool(out, "active", u.active, &first);
    out->push_back('}');
}

void emit_group(const ScimGroup& g, std::string* out) {
    assert(out != nullptr);
    out->reserve(out->size() + 256 + g.n_members * 64);
    out->push_back('{');
    out->append("\"schemas\":[\""); out->append(kSchemaGroup); out->append("\"]");
    bool first = false;
    if (!g.id.empty())           emit_kv_str(out, "id",          g.id.view(),           &first);
    if (!g.external_id.empty())  emit_kv_str(out, "externalId",  g.external_id.view(),  &first);
    if (!g.display_name.empty()) emit_kv_str(out, "displayName", g.display_name.view(), &first);
    out->append(",\"members\":[");
    for (uint16_t i = 0; i < g.n_members; ++i) {
        if (i > 0) out->push_back(',');
        out->push_back('{');
        bool mf = true;
        emit_kv_str(out, "value",   g.members[i].value.view(),   &mf);
        if (!g.members[i].display.empty())
            emit_kv_str(out, "display", g.members[i].display.view(), &mf);
        out->push_back('}');
    }
    out->append("]}");
}

void emit_user_list_begin(const ListPage& p, std::string* out) {
    assert(out != nullptr);
    out->push_back('{');
    out->append("\"schemas\":[\""); out->append(kSchemaList); out->append("\"],");
    bool first = false;
    emit_kv_int(out, "totalResults", p.total_results, &first);
    emit_kv_int(out, "startIndex",   p.start_index,   &first);
    emit_kv_int(out, "itemsPerPage", p.items_per_page, &first);
    out->append(",\"Resources\":[");
}

void emit_group_list_begin(const ListPage& p, std::string* out) {
    emit_user_list_begin(p, out);  // identical shape; resources block follows
}

void emit_list_separator(std::string* out) {
    assert(out != nullptr);
    out->push_back(',');
}

void emit_list_end(std::string* out) {
    assert(out != nullptr);
    out->append("]}");
}

void emit_error(int http_status, std::string_view detail, std::string* out) {
    assert(out != nullptr);
    out->push_back('{');
    out->append("\"schemas\":[\""); out->append(kSchemaError); out->append("\"],");
    char st[16]; std::snprintf(st, sizeof(st), "\"%d\"", http_status);
    out->append("\"status\":"); out->append(st);
    out->append(",\"detail\":\"");
    json_escape_into(detail, out);
    out->append("\"}");
}

}  // namespace bolt::api::auth::scim
