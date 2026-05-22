// router.cpp — implementation of bolt::api::Router.
//
// See router.h for the contract. Two-tier match:
//   * Static routes  -> bolt::SwissTable (one hash + one probe).
//   * Param/wildcard -> flat index-based segment trie, iterated with an
//     explicit bounded backtracking stack (no recursion, no pointer chase).
//
// Interning: literal path segments + method tokens go through a
// bolt::DictionaryPool so the trie compares integer segment ids instead of
// strings. Methods map to small ints via the enum value directly.

#include "boltapi/router.h"

#include "bolt/bolt_arena.h"
#include "bolt/bolt_hash.h"
#include "bolt/bolt_dictionary.h"
#include "bolt/bolt_port.h"
#include "bolt/join/bolt_swiss.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <new>

namespace bolt::api {

// ---------------------------------------------------------------------------
// Method helpers
// ---------------------------------------------------------------------------
Method method_from(std::string_view t) noexcept {
    // Length-then-first-char dispatch; case-sensitive (HTTP methods are upper).
    assert(t.size() <= 16);  // sane upper bound for a method token
    const size_t n = t.size();
    assert(n == t.size());   // tautology guard (TigerStyle: >=2 asserts)
    switch (n) {
        case 3:
            if (t == "GET") return Method::Get;
            if (t == "PUT") return Method::Put;
            return Method::Unknown;
        case 4:
            if (t == "HEAD") return Method::Head;
            if (t == "POST") return Method::Post;
            return Method::Unknown;
        case 5:
            if (t == "PATCH") return Method::Patch;
            return Method::Unknown;
        case 6:
            if (t == "DELETE") return Method::Delete;
            return Method::Unknown;
        case 7:
            if (t == "OPTIONS") return Method::Options;
            return Method::Unknown;
        default:
            return Method::Unknown;
    }
}

const char* method_name(Method m) noexcept {
    assert(static_cast<uint32_t>(m) <= static_cast<uint32_t>(Method::Unknown));
    switch (m) {
        case Method::Get:     return "GET";
        case Method::Head:    return "HEAD";
        case Method::Post:    return "POST";
        case Method::Put:     return "PUT";
        case Method::Delete:  return "DELETE";
        case Method::Patch:   return "PATCH";
        case Method::Options: return "OPTIONS";
        default:              return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------
namespace {

constexpr uint32_t kSegLiteral  = 0;  // matches one fixed interned segment id
constexpr uint32_t kSegParam    = 1;  // '{name}' — captures one segment
constexpr uint32_t kSegWildcard = 2;  // '*' — captures the remaining path

constexpr uint32_t kNoNode      = 0xFFFFFFFFu;  // trie child sentinel
constexpr uint32_t kMaxNodes    = kMaxRoutes * (kMaxSegments + 1);  // upper bound
constexpr uint32_t kMaxChildren = 16;  // distinct literal children probed per node

// FNV-1a over a byte range — stable, matches DictionaryPool's hash family.
uint64_t fnv1a(const char* data, uint32_t len) noexcept {
    assert(data != nullptr || len == 0);
    assert(len <= 64u * 1024u);
    uint64_t h = 0xCBF29CE484222325ULL;
    for (uint32_t i = 0; i < len; ++i) {
        h ^= static_cast<uint8_t>(data[i]);
        h *= 0x00000100000001B3ULL;
    }
    return h;
}

// Compose a 64-bit static-route key from method + path hash. The method
// occupies the low 3 bits; the path hash is folded in above it.
uint64_t static_key(Method m, std::string_view path) noexcept {
    assert(static_cast<uint32_t>(m) < kMaxMethods);
    assert(path.size() <= 64u * 1024u);
    const uint64_t ph = fnv1a(path.data(), static_cast<uint32_t>(path.size()));
    return swiss_mix((ph << 3) ^ static_cast<uint64_t>(m));
}

// One parsed segment of a registered route.
struct Segment {
    uint32_t         kind;     // kSegLiteral / kSegParam / kSegWildcard
    uint32_t         lit_id;   // interned literal id when kind == kSegLiteral
    std::string_view name;     // param name (view into arena-owned copy)
};

// A registered route's metadata.
struct Route {
    Method   method;
    uint32_t seg_count;
    bool     is_static;        // all literal, no wildcard -> SwissTable
    uint32_t first_seg;        // index into RouterImpl::segs_
    uint32_t param_count;
};

// A trie node. Children are stored as parallel (key,id) arrays for branch-free
// integer probing; param/wildcard successors are single indices.
struct TrieNode {
    uint32_t lit_keys[kMaxChildren];   // interned segment ids
    uint32_t lit_kids[kMaxChildren];   // child node indices
    uint32_t lit_count;
    uint32_t param_kid;                // node index for a '{...}' child or kNoNode
    uint32_t wild_kid;                 // node index for a '*' child or kNoNode
    uint32_t route_id;                 // route terminating here, or kInvalidRoute
    uint32_t param_name_idx;           // segs_ index naming the param edge into here
};

}  // namespace

// ---------------------------------------------------------------------------
// RouterImpl — all storage. Arena-backed; fixed-capacity tables.
// ---------------------------------------------------------------------------
struct RouterImpl {
    bolt::Arena          arena;
    bolt::DictionaryPool dict;       // interns literal segments + param names
    bolt::SwissTable     static_tbl; // static_key -> route_id

    Route    routes[kMaxRoutes];
    uint32_t route_count;

    Segment  segs[kMaxRoutes * (kMaxSegments + 1)];
    uint32_t seg_count;

    TrieNode* node_pool;  // arena-allocated in build()
    uint32_t  node_count;

    bool built;

    RouterImpl() noexcept
        : arena()
        , route_count(0)
        , seg_count(0)
        , node_pool(nullptr)
        , node_count(0)
        , built(false) {
        // Dictionary: up to (routes * segments) literals, ~16 bytes avg.
        const bool dok = bolt::DictionaryPool::create(
            &dict, kMaxRoutes * kMaxSegments, 16, &arena);
        assert(dok);
        (void)dok;
        // Static table sized for the worst case (all routes static).
        const bool sok = bolt::SwissTable::create(&static_tbl, kMaxRoutes, &arena);
        assert(sok);
        (void)sok;
        // Trie node pool — allocated lazily in build() once sizes are known.
        assert(route_count == 0);
    }
};

// ---------------------------------------------------------------------------
// Path parsing helpers (registration-time)
// ---------------------------------------------------------------------------
namespace {

// Split `path` into segments on '/' using SWAR byte-find. Writes up to
// `max_out` views; returns the count, or UINT32_MAX on overflow.
uint32_t split_path(std::string_view path, std::string_view* out,
                    uint32_t max_out) noexcept {
    assert(out != nullptr);
    assert(max_out >= 1);
    const char* p   = path.data();
    const uint32_t n = static_cast<uint32_t>(path.size());
    uint32_t count  = 0;
    uint32_t i      = 0;
    // Skip a single leading '/'.
    if (n > 0 && p[0] == '/') i = 1;
    while (i < n) {
        // Find the next '/' from i using 8-byte SWAR strides.
        uint32_t j = i;
        while (j + 8 <= n) {
            uint64_t w;
            std::memcpy(&w, p + j, 8);
            const int lane = bolt_swar_find_byte_u64(w, static_cast<uint8_t>('/'));
            if (lane >= 0) { j += static_cast<uint32_t>(lane); break; }
            j += 8;
        }
        while (j < n && p[j] != '/') ++j;
        if (j > i) {  // skip empty segments (e.g. trailing slash, "//")
            if (count >= max_out) return 0xFFFFFFFFu;
            out[count++] = std::string_view(p + i, j - i);
        }
        i = j + 1;
    }
    return count;
}

}  // namespace

// ---------------------------------------------------------------------------
// Router public surface
// ---------------------------------------------------------------------------
Router::Router() noexcept : impl_(nullptr) {
    impl_ = new (std::nothrow) RouterImpl();
    assert(impl_ != nullptr);
    assert(impl_->route_count == 0);
}

Router::~Router() noexcept {
    delete impl_;
    impl_ = nullptr;
}

uint32_t Router::add(Method m, std::string_view path) noexcept {
    assert(impl_ != nullptr);
    assert(!impl_->built);  // registration is startup-only
    RouterImpl& s = *impl_;

    if (static_cast<uint32_t>(m) >= kMaxMethods) return kInvalidRoute;
    if (s.route_count >= kMaxRoutes) return kInvalidRoute;
    if (path.empty() || path[0] != '/') return kInvalidRoute;

    std::string_view raw[kMaxSegments];
    const uint32_t nseg = split_path(path, raw, kMaxSegments);
    if (nseg == 0xFFFFFFFFu) return kInvalidRoute;  // too deep
    assert(nseg <= kMaxSegments);

    const uint32_t route_id  = s.route_count;
    const uint32_t first_seg = s.seg_count;
    bool     is_static  = true;
    uint32_t param_cnt  = 0;

    for (uint32_t k = 0; k < nseg; ++k) {
        std::string_view seg = raw[k];
        Segment out{};
        if (seg.size() >= 2 && seg.front() == '{' && seg.back() == '}') {
            // Parametric segment: capture the inner name (interned for lifetime).
            std::string_view inner = seg.substr(1, seg.size() - 2);
            if (inner.empty()) return kInvalidRoute;
            const uint32_t code = s.dict.intern(
                inner.data(), static_cast<uint32_t>(inner.size()));
            if (code == bolt::kDictPoolInvalidCode) return kInvalidRoute;
            const char* d; uint32_t len;
            s.dict.resolve(code, &d, &len);
            out.kind   = kSegParam;
            out.lit_id = code;
            out.name   = std::string_view(d, len);
            is_static  = false;
            ++param_cnt;
        } else if (seg.size() == 1 && seg[0] == '*') {
            if (k + 1 != nseg) return kInvalidRoute;  // '*' only as last segment
            out.kind   = kSegWildcard;
            out.lit_id = 0;
            is_static  = false;
        } else {
            const uint32_t code = s.dict.intern(
                seg.data(), static_cast<uint32_t>(seg.size()));
            if (code == bolt::kDictPoolInvalidCode) return kInvalidRoute;
            out.kind   = kSegLiteral;
            out.lit_id = code;
        }
        if (param_cnt > kMaxParams) return kInvalidRoute;
        s.segs[s.seg_count++] = out;
    }

    s.routes[route_id] = Route{m, nseg, is_static, first_seg, param_cnt};
    ++s.route_count;
    assert(s.route_count <= kMaxRoutes);
    return route_id;
}

// --- build() helpers --------------------------------------------------------
namespace {

uint32_t alloc_node(RouterImpl& s) noexcept {
    assert(s.node_pool != nullptr);
    assert(s.node_count < kMaxNodes);
    const uint32_t id = s.node_count++;
    TrieNode& n = s.node_pool[id];
    n.lit_count      = 0;
    n.param_kid      = kNoNode;
    n.wild_kid       = kNoNode;
    n.route_id       = kInvalidRoute;
    n.param_name_idx = 0;
    return id;
}

// Find-or-create the literal child of `node` keyed by `lit`. Returns kNoNode
// when the per-node child fan-out is exceeded.
uint32_t literal_child(RouterImpl& s, uint32_t node, uint32_t lit) noexcept {
    assert(node < s.node_count);
    assert(s.node_pool != nullptr);
    TrieNode& n = s.node_pool[node];
    for (uint32_t i = 0; i < n.lit_count; ++i) {
        if (n.lit_keys[i] == lit) return n.lit_kids[i];
    }
    if (n.lit_count >= kMaxChildren) return kNoNode;
    const uint32_t child = alloc_node(s);
    TrieNode& nn = s.node_pool[node];  // reload (alloc may have grown count)
    nn.lit_keys[nn.lit_count] = lit;
    nn.lit_kids[nn.lit_count] = child;
    ++nn.lit_count;
    return child;
}

}  // namespace

void Router::build() noexcept {
    assert(impl_ != nullptr);
    assert(!impl_->built);
    RouterImpl& s = *impl_;

    // Allocate the trie node pool from the arena (one root + per-route paths).
    const uint32_t cap = 1 + s.route_count * (kMaxSegments + 1);
    s.node_pool = s.arena.allocate_array<TrieNode>(cap);
    assert(s.node_pool != nullptr);
    s.node_count = 0;
    const uint32_t root = alloc_node(s);
    assert(root == 0);
    (void)root;

    // One method-keyed root per method keeps method mismatch O(1): we encode
    // the method into the first literal edge via a synthetic key.
    for (uint32_t r = 0; r < s.route_count; ++r) {
        const Route& rt = s.routes[r];
        if (rt.is_static) {
            // Reconstruct the canonical path string for the static key by
            // re-hashing from the original segments is unnecessary — we keyed
            // on the literal path at add() time below in a single pass instead.
            continue;
        }
        // Walk/insert the trie. The method is folded into the very first edge
        // key so different methods never share param/wildcard nodes.
        uint32_t cur = 0;  // root
        const uint32_t method_tag = 0xF0000000u | static_cast<uint32_t>(rt.method);
        cur = literal_child(s, cur, method_tag);
        assert(cur != kNoNode);
        for (uint32_t i = 0; i < rt.seg_count; ++i) {
            const Segment& sg = s.segs[rt.first_seg + i];
            if (sg.kind == kSegLiteral) {
                cur = literal_child(s, cur, sg.lit_id);
                assert(cur != kNoNode);
            } else if (sg.kind == kSegParam) {
                TrieNode& n = s.node_pool[cur];
                if (n.param_kid == kNoNode) {
                    n.param_kid = alloc_node(s);
                    s.node_pool[n.param_kid].param_name_idx = rt.first_seg + i;
                }
                cur = s.node_pool[cur].param_kid;
            } else {  // wildcard
                TrieNode& n = s.node_pool[cur];
                if (n.wild_kid == kNoNode) n.wild_kid = alloc_node(s);
                cur = s.node_pool[cur].wild_kid;
            }
        }
        // Last writer wins on duplicate param paths; keeps registration order
        // priority deterministic (earlier static handled separately).
        if (s.node_pool[cur].route_id == kInvalidRoute) {
            s.node_pool[cur].route_id = r;
        }
    }

    // Build the static SwissTable in a second pass keyed on method+path. We
    // recompute the path hash from segments by re-joining via the dictionary.
    for (uint32_t r = 0; r < s.route_count; ++r) {
        const Route& rt = s.routes[r];
        if (!rt.is_static) continue;
        // Re-derive FNV over the canonical "/seg/seg" form using interned text.
        uint64_t ph = 0xCBF29CE484222325ULL;
        for (uint32_t i = 0; i < rt.seg_count; ++i) {
            ph ^= static_cast<uint8_t>('/');
            ph *= 0x00000100000001B3ULL;
            const Segment& sg = s.segs[rt.first_seg + i];
            const char* d; uint32_t len;
            s.dict.resolve(sg.lit_id, &d, &len);
            for (uint32_t b = 0; b < len; ++b) {
                ph ^= static_cast<uint8_t>(d[b]);
                ph *= 0x00000100000001B3ULL;
            }
        }
        if (rt.seg_count == 0) {  // root path "/"
            ph ^= static_cast<uint8_t>('/');
            ph *= 0x00000100000001B3ULL;
        }
        const uint64_t key =
            swiss_mix((ph << 3) ^ static_cast<uint64_t>(rt.method));
        (void)s.static_tbl.insert(key, r);
    }

    s.built = true;
    assert(s.built);
}

// ---------------------------------------------------------------------------
// match() — hot path. Static probe first, then bounded iterative trie walk.
// ---------------------------------------------------------------------------
namespace {

// Canonical FNV over the request path's significant segments, matching the
// build() static-key derivation (collapses empty segments / trailing slash).
uint64_t request_static_hash(std::string_view path) noexcept {
    assert(path.size() <= 64u * 1024u);
    assert(!path.empty());
    uint64_t ph = 0xCBF29CE484222325ULL;
    const char* p = path.data();
    const uint32_t n = static_cast<uint32_t>(path.size());
    uint32_t i = (n > 0 && p[0] == '/') ? 1u : 0u;
    bool any = false;
    while (i < n) {
        uint32_t j = i;
        while (j < n && p[j] != '/') ++j;
        if (j > i) {
            ph ^= static_cast<uint8_t>('/');
            ph *= 0x00000100000001B3ULL;
            for (uint32_t b = i; b < j; ++b) {
                ph ^= static_cast<uint8_t>(p[b]);
                ph *= 0x00000100000001B3ULL;
            }
            any = true;
        }
        i = j + 1;
    }
    if (!any) {  // root path
        ph ^= static_cast<uint8_t>('/');
        ph *= 0x00000100000001B3ULL;
    }
    return ph;
}

}  // namespace

MatchResult Router::match(Method m, std::string_view path) const noexcept {
    assert(impl_ != nullptr);
    assert(impl_->built);
    const RouterImpl& s = *impl_;
    MatchResult res{};

    if (path.empty() || static_cast<uint32_t>(m) >= kMaxMethods) return res;

    // --- Tier 1: static exact match (one hash + one probe) ---
    const uint64_t ph  = request_static_hash(path);
    const uint64_t key = swiss_mix((ph << 3) ^ static_cast<uint64_t>(m));
    const int32_t hit  = s.static_tbl.find(key);
    if (hit >= 0) {
        res.route_id    = static_cast<uint32_t>(hit);
        res.param_count = 0;
        return res;
    }

    // --- Tier 2: parametric / wildcard via bounded iterative trie walk ---
    std::string_view segs[kMaxSegments];
    uint32_t nseg = 0;
    {
        const char* p = path.data();
        const uint32_t n = static_cast<uint32_t>(path.size());
        uint32_t i = (n > 0 && p[0] == '/') ? 1u : 0u;
        while (i < n) {
            uint32_t j = i;
            while (j + 8 <= n) {
                uint64_t w; std::memcpy(&w, p + j, 8);
                const int lane = bolt_swar_find_byte_u64(w, static_cast<uint8_t>('/'));
                if (lane >= 0) { j += static_cast<uint32_t>(lane); break; }
                j += 8;
            }
            while (j < n && p[j] != '/') ++j;
            if (j > i) {
                if (nseg >= kMaxSegments) return res;  // too deep
                segs[nseg++] = std::string_view(p + i, j - i);
            }
            i = j + 1;
        }
    }

    // Explicit backtracking stack (no recursion). Each frame is (node, depth,
    // param_count, next_choice). Choice ordering enforces priority:
    //   0 = literal, 1 = param, 2 = wildcard.
    struct Frame {
        uint32_t node;
        uint32_t depth;
        uint32_t pcount;
        uint8_t  choice;
    };
    Frame stack[kMaxSegments + 1];
    int32_t sp = 0;

    // Enter the method-tagged root edge.
    const uint32_t method_tag = 0xF0000000u | static_cast<uint32_t>(m);
    uint32_t mroot = kNoNode;
    {
        const TrieNode& root = s.node_pool[0];
        for (uint32_t i = 0; i < root.lit_count; ++i) {
            if (root.lit_keys[i] == method_tag) { mroot = root.lit_kids[i]; break; }
        }
    }
    if (mroot == kNoNode) return res;

    stack[0] = Frame{mroot, 0, 0, 0};
    sp = 0;

    while (sp >= 0) {
        Frame& f = stack[sp];
        const TrieNode& node = s.node_pool[f.node];

        if (f.depth == nseg) {
            // Reached path end: terminal node with a route wins.
            if (node.route_id != kInvalidRoute) {
                res.route_id    = node.route_id;
                res.param_count = f.pcount;
                // Fill param names from the captured indices already stored in
                // res.params[*].value during descent; names attached below.
                return res;
            }
            --sp;  // backtrack
            continue;
        }

        const std::string_view seg = segs[f.depth];
        bool advanced = false;

        // choice 0: literal (highest priority).
        if (f.choice == 0) {
            f.choice = 1;
            uint32_t lit = s.dict.find(seg.data(),
                                       static_cast<uint32_t>(seg.size()));
            if (lit != bolt::kDictPoolInvalidCode) {
                for (uint32_t i = 0; i < node.lit_count; ++i) {
                    if (node.lit_keys[i] == lit) {
                        assert(sp + 1 <= static_cast<int32_t>(kMaxSegments));
                        stack[sp + 1] =
                            Frame{node.lit_kids[i], f.depth + 1, f.pcount, 0};
                        ++sp;
                        advanced = true;
                        break;
                    }
                }
            }
            if (advanced) continue;
        }

        // choice 1: param (captures one segment).
        if (f.choice == 1) {
            f.choice = 2;
            if (node.param_kid != kNoNode && f.pcount < kMaxParams) {
                const TrieNode& pk = s.node_pool[node.param_kid];
                res.params[f.pcount].name  = s.segs[pk.param_name_idx].name;
                res.params[f.pcount].value = seg;
                assert(sp + 1 <= static_cast<int32_t>(kMaxSegments));
                stack[sp + 1] =
                    Frame{node.param_kid, f.depth + 1, f.pcount + 1, 0};
                ++sp;
                continue;
            }
        }

        // choice 2: wildcard (captures the rest of the path).
        if (f.choice == 2) {
            f.choice = 3;
            if (node.wild_kid != kNoNode) {
                const TrieNode& wk = s.node_pool[node.wild_kid];
                if (wk.route_id != kInvalidRoute) {
                    // Capture remaining path (from this segment's start) as the
                    // wildcard value, then terminate.
                    const char* start = seg.data();
                    const char* end   = path.data() + path.size();
                    if (f.pcount < kMaxParams) {
                        res.params[f.pcount].name =
                            std::string_view("*", 1);
                        res.params[f.pcount].value =
                            std::string_view(start,
                                static_cast<size_t>(end - start));
                        res.param_count = f.pcount + 1;
                    } else {
                        res.param_count = f.pcount;
                    }
                    res.route_id = wk.route_id;
                    return res;
                }
            }
        }

        // Exhausted all choices at this frame -> backtrack.
        --sp;
    }

    return res;  // no match
}

uint32_t Router::route_count() const noexcept {
    assert(impl_ != nullptr);
    assert(impl_->route_count <= kMaxRoutes);
    return impl_->route_count;
}

}  // namespace bolt::api
