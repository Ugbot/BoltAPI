// router_bench.cpp — micro-benchmark for bolt::api::Router.
//
// Headline claim: the Bolt SwissTable/dictionary router resolves routes far
// faster than naive baselines. We measure three workloads:
//   * static-hit  match() — exact path, resolves via the SwissTable (1 hash+probe)
//   * param-hit   match() — '{id}' route, resolves via the flat segment trie
//   * miss        match() — path that matches nothing
//
// and compare the static-hit number against two trivial baselines that a hand
// written router might use:
//   * linear scan over the registered (method, pattern) strings
//   * std::unordered_map<std::string, id> keyed on "METHOD path"
//
// No third-party benchmark library: a hand-rolled harness (warmup + a large
// fixed iteration count) with a volatile sink to defeat dead-code elimination.
// All timing is std::chrono::steady_clock.

#include "boltapi/router.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

using bolt::api::Method;
using bolt::api::Router;
using bolt::api::MatchResult;

namespace {

// Volatile sink — every measured call XORs a result into here so the optimizer
// cannot prove the work is dead.
volatile std::uint64_t g_sink = 0;

constexpr int kStaticRoutes = 100;
constexpr int kParamRoutes  = 30;

// Stable pseudo-word generator so route paths are realistic-ish and distinct.
std::string word(int n) {
    static const char* parts[] = {
        "users", "orders", "products", "cart", "search", "admin", "api",
        "v1", "v2", "health", "metrics", "billing", "auth", "session",
        "items", "catalog", "reviews", "images", "static", "reports"};
    constexpr int kParts = static_cast<int>(sizeof(parts) / sizeof(parts[0]));
    return std::string(parts[n % kParts]) + std::to_string(n);
}

struct Routes {
    std::vector<std::string> static_paths;   // concrete, all literal
    std::vector<std::string> param_patterns; // with '{id}'/'{pid}'
    std::vector<std::string> param_concrete; // a concrete instance of each
};

Routes make_routes() {
    Routes r;
    for (int i = 0; i < kStaticRoutes; ++i) {
        r.static_paths.push_back("/" + word(i) + "/" + word(i + 7) + "/list");
    }
    // Param routes share a small set of top-level resource segments (realistic:
    // an API has few resources, each with many sub-resources). This also keeps
    // the trie within its per-node literal fan-out (kMaxChildren) — distinct
    // top-level literals are bounded by kResources, not kParamRoutes.
    static const char* resources[] = {"users", "orders", "teams", "repos"};
    constexpr int kResources = static_cast<int>(sizeof(resources) / sizeof(resources[0]));
    for (int i = 0; i < kParamRoutes; ++i) {
        const std::string base = std::string("/") + resources[i % kResources];
        const std::string sub  = word(i + 200);  // distinct sub-resource literal
        r.param_patterns.push_back(base + "/{id}/" + sub + "/{sid}");
        r.param_concrete.push_back(base + "/" + std::to_string(1000 + i) +
                                   "/" + sub + "/" + std::to_string(2000 + i));
    }
    return r;
}

// ---------------------------------------------------------------------------
// Timing harness. Runs `fn` `iters` times after `warmup` warmup iterations,
// returns ns/op. `fn` takes the iteration index and must feed g_sink.
// ---------------------------------------------------------------------------
template <typename Fn>
double bench_ns_per_op(const char* /*label*/, int warmup, long long iters, Fn&& fn) {
    for (int i = 0; i < warmup; ++i) fn(i);
    const auto t0 = std::chrono::steady_clock::now();
    for (long long i = 0; i < iters; ++i) fn(static_cast<int>(i));
    const auto t1 = std::chrono::steady_clock::now();
    const double ns =
        std::chrono::duration_cast<std::chrono::duration<double, std::nano>>(
            t1 - t0).count();
    return ns / static_cast<double>(iters);
}

void report(const char* label, double ns_per_op) {
    const double ops = ns_per_op > 0.0 ? 1e9 / ns_per_op : 0.0;
    std::printf("  %-26s %8.2f ns/op   %12.0f ops/s\n", label, ns_per_op, ops);
}

}  // namespace

int main() {
    std::printf("== bolt::api::Router micro-benchmark ==\n");
    std::printf("static routes=%d  param routes=%d  + 1 wildcard\n\n",
                kStaticRoutes, kParamRoutes);

    const Routes routes = make_routes();

    // --- Build the Bolt router. ---
    Router router;
    for (const auto& p : routes.static_paths) router.add(Method::Get, p);
    for (const auto& p : routes.param_patterns) router.add(Method::Get, p);
    router.add(Method::Get, "/files/*");
    router.build();

    // --- Baseline 1: linear scan over registered (method,pattern) strings. ---
    // We only model the STATIC fast path here (exact compare), which is the
    // most generous case for the baseline (no param parsing).
    std::vector<std::string> linear_keys;   // "GET /path"
    linear_keys.reserve(routes.static_paths.size());
    for (const auto& p : routes.static_paths) linear_keys.push_back("GET " + p);

    auto linear_find = [&](const std::string& key) -> long long {
        for (std::size_t i = 0; i < linear_keys.size(); ++i) {
            if (linear_keys[i] == key) return static_cast<long long>(i);
        }
        return -1;
    };

    // --- Baseline 2: std::unordered_map<std::string,id> for the static set. ---
    std::unordered_map<std::string, std::uint32_t> umap;
    umap.reserve(routes.static_paths.size() * 2);
    for (std::uint32_t i = 0; i < routes.static_paths.size(); ++i) {
        umap.emplace("GET " + routes.static_paths[i], i);
    }

    // Workload paths.
    const std::string& hit_static = routes.static_paths[kStaticRoutes / 2];
    const std::string& hit_param  = routes.param_concrete[kParamRoutes / 2];
    const std::string  miss_path  = "/this/does/not/exist/anywhere";
    const std::string  hit_static_key = "GET " + hit_static;

    constexpr int  kWarmup = 10000;
    constexpr long long kIters = 5'000'000;

    // --- Bolt router measurements. ---
    std::printf("[Bolt router]\n");
    const double bolt_static = bench_ns_per_op(
        "static-hit", kWarmup, kIters, [&](int) {
            MatchResult m = router.match(Method::Get, hit_static);
            g_sink ^= m.route_id;
        });
    report("static-hit match()", bolt_static);

    const double bolt_param = bench_ns_per_op(
        "param-hit", kWarmup, kIters, [&](int) {
            MatchResult m = router.match(Method::Get, hit_param);
            g_sink ^= m.route_id ^ m.param_count;
            if (m.param_count) g_sink ^= m.params[0].value.size();
        });
    report("param-hit  match()", bolt_param);

    const double bolt_miss = bench_ns_per_op(
        "miss", kWarmup, kIters, [&](int) {
            MatchResult m = router.match(Method::Get, miss_path);
            g_sink ^= m.route_id;
        });
    report("miss       match()", bolt_miss);

    // --- Baseline measurements (static-hit only — the head-to-head). ---
    std::printf("\n[Baselines — static-hit resolution]\n");
    const double base_linear = bench_ns_per_op(
        "linear", kWarmup, kIters, [&](int) {
            g_sink ^= static_cast<std::uint64_t>(linear_find(hit_static_key));
        });
    report("linear scan", base_linear);

    const double base_umap = bench_ns_per_op(
        "umap", kWarmup, kIters, [&](int) {
            auto it = umap.find(hit_static_key);
            g_sink ^= (it == umap.end()) ? ~0ull : it->second;
        });
    report("unordered_map<string,id>", base_umap);

    // --- Speedups. ---
    std::printf("\n[Speedup — Bolt static-hit vs baseline]\n");
    if (bolt_static > 0.0) {
        std::printf("  vs linear scan          %8.2fx faster\n",
                    base_linear / bolt_static);
        std::printf("  vs unordered_map        %8.2fx faster\n",
                    base_umap / bolt_static);
    }

    std::printf("\n(sink=%llu)\n", static_cast<unsigned long long>(g_sink));
    return 0;
}
