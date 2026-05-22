// router_test.cpp — self-contained tests for bolt::api::Router.
//
// No gtest dependency: plain main() returning 0 on all-pass, 1 on any failure.
// Covers: static exact match, multiple verbs on one path, single + multi
// params, wildcard, priority (static > param > wildcard), no-match,
// trailing-slash behavior, method mismatch, and a randomized/seeded fuzz pass.

#include "boltapi/router.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using bolt::api::Method;
using bolt::api::Router;
using bolt::api::MatchResult;
using bolt::api::method_from;
using bolt::api::method_name;

namespace {

int g_failures = 0;
int g_checks   = 0;

void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_failures;
        std::printf("  FAIL: %s\n", what);
    }
}

// Find a param value by name in a MatchResult; returns empty view if absent.
std::string_view param(const MatchResult& r, std::string_view name) {
    for (uint32_t i = 0; i < r.param_count; ++i) {
        if (r.params[i].name == name) return r.params[i].value;
    }
    return std::string_view{};
}

// ---------------------------------------------------------------------------
void test_method_helpers() {
    std::printf("[method helpers]\n");
    check(method_from("GET") == Method::Get, "GET parses");
    check(method_from("HEAD") == Method::Head, "HEAD parses");
    check(method_from("POST") == Method::Post, "POST parses");
    check(method_from("PUT") == Method::Put, "PUT parses");
    check(method_from("DELETE") == Method::Delete, "DELETE parses");
    check(method_from("PATCH") == Method::Patch, "PATCH parses");
    check(method_from("OPTIONS") == Method::Options, "OPTIONS parses");
    check(method_from("get") == Method::Unknown, "lowercase is Unknown");
    check(method_from("WAT") == Method::Unknown, "garbage is Unknown");
    check(method_from("") == Method::Unknown, "empty is Unknown");
    check(std::strcmp(method_name(Method::Get), "GET") == 0, "name GET");
    check(std::strcmp(method_name(Method::Delete), "DELETE") == 0, "name DELETE");
}

// ---------------------------------------------------------------------------
void test_static_and_verbs() {
    std::printf("[static + multiple verbs]\n");
    Router r;
    const uint32_t g_users = r.add(Method::Get, "/users");
    const uint32_t p_users = r.add(Method::Post, "/users");
    const uint32_t g_health = r.add(Method::Get, "/health/live");
    const uint32_t d_users  = r.add(Method::Delete, "/users");
    const uint32_t g_root   = r.add(Method::Get, "/");
    r.build();

    check(r.route_count() == 5, "5 routes registered");

    MatchResult m1 = r.match(Method::Get, "/users");
    check(m1.matched() && m1.route_id == g_users, "GET /users -> g_users");

    MatchResult m2 = r.match(Method::Post, "/users");
    check(m2.matched() && m2.route_id == p_users, "POST /users -> p_users");

    MatchResult m3 = r.match(Method::Delete, "/users");
    check(m3.matched() && m3.route_id == d_users, "DELETE /users -> d_users");

    MatchResult m4 = r.match(Method::Get, "/health/live");
    check(m4.matched() && m4.route_id == g_health, "GET /health/live");

    MatchResult m5 = r.match(Method::Get, "/");
    check(m5.matched() && m5.route_id == g_root, "GET / -> root");

    // Method mismatch: PUT /users was never registered.
    MatchResult m6 = r.match(Method::Put, "/users");
    check(!m6.matched(), "PUT /users -> no match (method mismatch)");

    // No-match path.
    MatchResult m7 = r.match(Method::Get, "/nope");
    check(!m7.matched(), "GET /nope -> no match");
}

// ---------------------------------------------------------------------------
void test_params() {
    std::printf("[path params]\n");
    Router r;
    const uint32_t one = r.add(Method::Get, "/users/{id}");
    const uint32_t two = r.add(Method::Get, "/users/{id}/posts/{pid}");
    const uint32_t put = r.add(Method::Put, "/users/{id}");
    r.build();

    MatchResult m1 = r.match(Method::Get, "/users/42");
    check(m1.matched() && m1.route_id == one, "GET /users/42 -> one");
    check(param(m1, "id") == "42", "id == 42");
    check(m1.param_count == 1, "one param");

    MatchResult m2 = r.match(Method::Get, "/users/7/posts/99");
    check(m2.matched() && m2.route_id == two, "GET /users/7/posts/99 -> two");
    check(param(m2, "id") == "7", "id == 7");
    check(param(m2, "pid") == "99", "pid == 99");
    check(m2.param_count == 2, "two params");

    MatchResult m3 = r.match(Method::Put, "/users/abc");
    check(m3.matched() && m3.route_id == put, "PUT /users/abc -> put");
    check(param(m3, "id") == "abc", "id == abc");

    // Method mismatch on a param route.
    MatchResult m4 = r.match(Method::Post, "/users/1");
    check(!m4.matched(), "POST /users/1 -> no match");

    // Partial path (no terminal).
    MatchResult m5 = r.match(Method::Get, "/users/7/posts");
    check(!m5.matched(), "GET /users/7/posts -> no match (no terminal)");
}

// ---------------------------------------------------------------------------
void test_wildcard_and_priority() {
    std::printf("[wildcard + priority]\n");
    Router r;
    const uint32_t wild   = r.add(Method::Get, "/files/*");
    const uint32_t param_ = r.add(Method::Get, "/files/{name}");
    const uint32_t exact  = r.add(Method::Get, "/files/readme");
    r.build();

    // Static beats param beats wildcard for the same concrete path.
    MatchResult m1 = r.match(Method::Get, "/files/readme");
    check(m1.matched() && m1.route_id == exact, "static beats param/wildcard");

    // Single segment that is not the static literal -> param wins over wildcard.
    MatchResult m2 = r.match(Method::Get, "/files/notes");
    check(m2.matched() && m2.route_id == param_, "param beats wildcard");
    check(param(m2, "name") == "notes", "name == notes");

    // Multi-segment tail only the wildcard can match.
    MatchResult m3 = r.match(Method::Get, "/files/a/b/c");
    check(m3.matched() && m3.route_id == wild, "wildcard catches deep tail");
    check(param(m3, "*") == "a/b/c", "wildcard value == a/b/c");

    // Method mismatch.
    MatchResult m4 = r.match(Method::Post, "/files/x");
    check(!m4.matched(), "POST /files/x -> no match");
}

// ---------------------------------------------------------------------------
void test_trailing_slash() {
    std::printf("[trailing slash]\n");
    Router r;
    const uint32_t a = r.add(Method::Get, "/api/v1");
    const uint32_t b = r.add(Method::Get, "/api/v1/{id}");
    r.build();

    // Trailing slash collapses (empty segment ignored) -> same as /api/v1.
    MatchResult m1 = r.match(Method::Get, "/api/v1/");
    check(m1.matched() && m1.route_id == a, "trailing slash collapses to static");

    // Double slash collapses too.
    MatchResult m2 = r.match(Method::Get, "/api//v1");
    check(m2.matched() && m2.route_id == a, "double slash collapses");

    MatchResult m3 = r.match(Method::Get, "/api/v1/55");
    check(m3.matched() && m3.route_id == b, "param still works");
}

// ---------------------------------------------------------------------------
// Randomized/seeded breadth test: generate a set of distinct routes across
// verbs, then assert each one round-trips and that a known-bad path misses.
void test_random_fuzz() {
    std::printf("[randomized fuzz]\n");
    std::mt19937 rng(0xB017AB1Eu);

    const Method verbs[] = {Method::Get, Method::Post, Method::Put,
                            Method::Delete, Method::Patch};
    const int kVerbs = 5;

    Router r;
    struct Spec { Method m; std::string path; bool has_param; std::string concrete; };
    std::vector<Spec> specs;
    std::vector<uint32_t> ids;

    auto seg = [&](int n) {
        static const char* parts[] = {"alpha","beta","gamma","delta","epsilon",
                                      "zeta","eta","theta","iota","kappa"};
        return std::string(parts[n % 10]);
    };

    // Build 200 distinct routes; ensure path uniqueness per (method,path).
    std::vector<std::string> seen;
    int built = 0;
    for (int attempt = 0; attempt < 2000 && built < 200; ++attempt) {
        const Method m = verbs[rng() % kVerbs];
        const int depth = 1 + static_cast<int>(rng() % 4);
        std::string path;
        std::string concrete;
        bool has_param = false;
        for (int d = 0; d < depth; ++d) {
            path += "/";
            concrete += "/";
            if ((rng() % 3) == 0) {  // param segment
                std::string pname = "p" + std::to_string(d);
                path += "{" + pname + "}";
                std::string val = "v" + std::to_string(rng() % 1000);
                concrete += val;
                has_param = true;
            } else {
                std::string lit = seg(static_cast<int>(rng() % 10));
                path += lit;
                concrete += lit;
            }
        }
        std::string key = method_name(m) + path;
        bool dup = false;
        for (auto& k : seen) if (k == key) { dup = true; break; }
        if (dup) continue;
        // Also avoid concrete-path collisions across param/static which would
        // make the expected id ambiguous; require unique concrete+method too.
        std::string ckey = method_name(m) + std::string(":") + concrete;
        bool cdup = false;
        for (auto& s2 : specs) {
            if ((std::string(method_name(s2.m)) + ":" + s2.concrete) == ckey) {
                cdup = true; break;
            }
        }
        if (cdup) continue;
        seen.push_back(key);
        const uint32_t id = r.add(m, path);
        if (id == bolt::api::kInvalidRoute) continue;
        ids.push_back(id);
        specs.push_back(Spec{m, path, has_param, concrete});
        ++built;
    }
    r.build();
    check(built > 100, "fuzz built > 100 routes");
    check(r.route_count() == static_cast<uint32_t>(built), "route_count matches");

    int ok = 0;
    for (size_t i = 0; i < specs.size(); ++i) {
        MatchResult mr = r.match(specs[i].m, specs[i].concrete);
        if (mr.matched() && mr.route_id == ids[i]) ++ok;
    }
    check(ok == static_cast<int>(specs.size()), "every route round-trips");
    if (ok != static_cast<int>(specs.size())) {
        std::printf("    (%d/%zu round-tripped)\n", ok, specs.size());
    }

    // Wrong-method probes: a match is only legitimate if it lands on a route
    // that was actually registered under that probe verb. Anything matched
    // under the WRONG method's tag would be a method-isolation bug. (A probe
    // may still legitimately match a *param* route registered under the probe
    // verb, so we validate the matched route's method, not just a miss.)
    int wm_ok = 0, wm_total = 0;
    for (size_t i = 0; i < specs.size(); ++i) {
        Method wrong = specs[i].m == Method::Get ? Method::Options : Method::Get;
        // Skip if the probe verb equals the registered verb (not "wrong").
        if (wrong == specs[i].m) continue;
        ++wm_total;
        MatchResult mr = r.match(wrong, specs[i].concrete);
        // Pass iff: no match, OR the matched route's method == probe verb.
        bool good = !mr.matched() || specs[mr.route_id].m == wrong;
        if (good) ++wm_ok;
    }
    check(wm_ok == wm_total, "wrong-method probes never leak across methods");
    if (wm_ok != wm_total) {
        std::printf("    (%d/%d isolated as expected)\n", wm_ok, wm_total);
    }
}

}  // namespace

int main() {
    std::printf("== bolt::api::Router tests ==\n");
    test_method_helpers();
    test_static_and_verbs();
    test_params();
    test_wildcard_and_priority();
    test_trailing_slash();
    test_random_fuzz();

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures == 0) {
        std::printf("ALL PASS\n");
        return 0;
    }
    std::printf("FAILED\n");
    return 1;
}
