// tests/neo4j_bolt_value_gen.h — random Bolt values + a canonical text form.
//
// TEST-ONLY. `gen_value` builds a random value tree (scalars, containers, and
// every graph/temporal structure of proto/neo4j_values.h) from any bit source:
// the echo executor drives it from a seeded splitmix64, the libFuzzer harness
// from the fuzz input. `describe` renders any decoded value, in either wire
// dialect, as one canonical string, so "what the server meant" and "what came
// back" compare as text. tests/neo4j_bolt_driver_value_fuzz.py renders the
// official driver's hydrated objects into the SAME grammar.
//
// Grammar: null | true | false | <int> | f:<ieee hex> | s:<utf8 hex> |
//   b:<hex> | [a,b] | {<keyhex>=v,...} | N(id,[lblhex..],{..}[,e:<hex>]) |
//   R(id,start,end,<typehex>,{..}[,e:..,e:..,e:..]) | P([N..],[R..]) |
//   D(days) | t(ns) | T(ns,off) | d(s,ns) | I(utc_s,ns,off) | i(utc_s,ns,<zonehex>) |
//   E(months,days,total_ns)

#pragma once

#include "boltapi/proto/neo4j_values.h"
#include "boltapi/proto/packstream.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace boltapi_test {

namespace psg = bolt::api::proto::packstream;
namespace nv = bolt::api::proto::neo4j::values;

struct SplitMix {
    std::uint64_t s;
    std::uint64_t next(std::uint64_t bound) noexcept {
        std::uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        return bound == 0 ? z : z % bound;
    }
};

// Consumes fuzz bytes; yields zeros once exhausted so every tree terminates.
struct ByteSource {
    const std::uint8_t* p;
    std::size_t n;
    std::uint64_t next(std::uint64_t bound) noexcept {
        std::uint64_t z = 0;
        for (int k = 0; k < 8 && n > 0; ++k, ++p, --n) z = (z << 8) | *p;
        return bound == 0 ? z : z % bound;
    }
};

struct GenOptions {
    bool allow_zone_id = true;     // DateTimeZoneId has no Bolt 4 form
    std::uint32_t max_depth = 3;
    // Entity ids are drawn from this sequence. A client merges every node and
    // relationship of one result by id, so ids must be unique across a result.
    std::int64_t* id_seq = nullptr;
};

namespace gen_detail {

inline const char* const kZones[] = {"UTC", "Europe/London", "America/New_York",
                                      "Asia/Tokyo", "Australia/Sydney"};
// One-, two-, three- and four-byte UTF-8 code points.
inline const char* const kAtoms[] = {"a", "Z", "7", "_", " ", "\xc3\xa9",
                                     "\xce\xbb", "\xe2\x82\xac", "\xf0\x9f\x98\x80"};

template <class Src>
std::int64_t in_range(Src& s, std::int64_t lo, std::int64_t hi) noexcept {
    const std::uint64_t span = static_cast<std::uint64_t>(hi - lo) + 1u;
    return lo + static_cast<std::int64_t>(s.next(span));
}

template <class Src>
std::string_view text(psg::PackArena& a, Src& s, std::uint32_t max_atoms) noexcept {
    const std::uint32_t n = static_cast<std::uint32_t>(s.next(max_atoms + 1u));
    char* buf = static_cast<char*>(a.alloc(4u * n + 1u, 1));
    if (buf == nullptr) return {};
    std::size_t len = 0;
    for (std::uint32_t k = 0; k < n; ++k) {
        const char* at = kAtoms[s.next(sizeof(kAtoms) / sizeof(kAtoms[0]))];
        const std::size_t l = std::strlen(at);
        std::memcpy(buf + len, at, l);
        len += l;
    }
    return std::string_view(buf, len);
}

inline std::int64_t next_id(const GenOptions& o) noexcept {
    static std::int64_t local = 0;
    std::int64_t* seq = o.id_seq != nullptr ? o.id_seq : &local;
    return (*seq)++;
}

template <class Src>
std::int64_t any_int(Src& s) noexcept {
    switch (s.next(4)) {
        case 0: return in_range(s, -16, 127);
        case 1: return in_range(s, -40000, 40000);
        case 2: return static_cast<std::int64_t>(s.next(0));
        default: return in_range(s, -3000000000LL, 3000000000LL);
    }
}

}  // namespace gen_detail

template <class Src>
psg::PackValue gen_value(psg::PackArena& a, Src& s, const GenOptions& o,
                         std::uint32_t depth);

template <class Src>
psg::PackValue gen_props(psg::PackArena& a, Src& s, const GenOptions& o,
                         std::uint32_t depth) {
    psg::PackValue d{};
    d.type = psg::PackType::Dict;
    const std::uint32_t n = depth >= o.max_depth ? 0u
                            : static_cast<std::uint32_t>(s.next(4));
    auto* pairs = n ? a.alloc_n<psg::PackPair>(n) : nullptr;
    auto* vals = n ? a.alloc_n<psg::PackValue>(n) : nullptr;
    if (n != 0 && (pairs == nullptr || vals == nullptr)) return d;
    for (std::uint32_t k = 0; k < n; ++k) {
        // "k<index>" prefix keeps keys unique, as a dictionary requires.
        const std::string_view tail = gen_detail::text(a, s, 3);
        char* key = static_cast<char*>(a.alloc(tail.size() + 4u, 1));
        if (key == nullptr) return d;
        const int hl = std::snprintf(key, 4, "k%u", static_cast<unsigned>(k));
        std::memcpy(key + hl, tail.data(), tail.size());
        vals[k] = gen_value(a, s, o, depth + 1);
        pairs[k].key = key;
        pairs[k].key_len = static_cast<std::uint32_t>(static_cast<std::size_t>(hl) + tail.size());
        pairs[k].value = &vals[k];
    }
    d.pairs = pairs;
    d.len = n;
    return d;
}

template <class Src>
psg::PackValue gen_node(psg::PackArena& a, Src& s, const GenOptions& o,
                        std::uint32_t depth, std::int64_t id) {
    std::string_view labels[3];
    const std::uint32_t nl = static_cast<std::uint32_t>(s.next(4));
    for (std::uint32_t k = 0; k < nl; ++k) {
        labels[k] = gen_detail::text(a, s, 4);
        if (labels[k].empty()) labels[k] = "L";
    }
    const psg::PackValue props = gen_props(a, s, o, depth);
    psg::PackValue out{};
    if (nv::make_node(a, id, labels, nl > 3 ? 3 : nl, props.pairs, props.len, &out) !=
        psg::PackError::Ok) {
        return psg::PackValue{};
    }
    return out;
}

template <class Src>
psg::PackValue gen_rel(psg::PackArena& a, Src& s, const GenOptions& o,
                       std::uint32_t depth, bool bound) {
    std::string_view type = gen_detail::text(a, s, 4);
    if (type.empty()) type = "T";
    const psg::PackValue props = gen_props(a, s, o, depth);
    psg::PackValue out{};
    const std::int64_t id = gen_detail::next_id(o);
    const psg::PackError e = bound
        ? nv::make_relationship(a, id, gen_detail::any_int(s), gen_detail::any_int(s),
                                type, props.pairs, props.len, &out)
        : nv::make_unbound_relationship(a, id, type, props.pairs, props.len, &out);
    return e == psg::PackError::Ok ? out : psg::PackValue{};
}

template <class Src>
psg::PackValue gen_path(psg::PackArena& a, Src& s, const GenOptions& o,
                        std::uint32_t depth) {
    const std::uint32_t hops = static_cast<std::uint32_t>(s.next(5));
    const std::uint32_t n_nodes = 1u + static_cast<std::uint32_t>(s.next(hops + 1u));
    // One relationship per hop, as in any MATCHed path: a client binds the
    // endpoints onto the relationship object, so a reused one would carry
    // only its last hop's.
    const std::uint32_t n_rels = hops;
    auto* nodes = a.alloc_n<psg::PackValue>(n_nodes);
    auto* rels = n_rels ? a.alloc_n<psg::PackValue>(n_rels) : nullptr;
    auto* idx = hops ? a.alloc_n<psg::PackValue>(2u * hops) : nullptr;
    if (nodes == nullptr || (n_rels && rels == nullptr) || (hops && idx == nullptr)) {
        return psg::PackValue{};
    }
    for (std::uint32_t k = 0; k < n_nodes; ++k) {
        nodes[k] = gen_node(a, s, o, depth + 1, gen_detail::next_id(o));
        if (nodes[k].type != psg::PackType::Struct) return psg::PackValue{};
    }
    for (std::uint32_t k = 0; k < n_rels; ++k) {
        rels[k] = gen_rel(a, s, o, depth + 1, false);
        if (rels[k].type != psg::PackType::Struct) return psg::PackValue{};
    }
    std::int64_t perm[8];
    for (std::uint32_t h = 0; h < hops; ++h) perm[h] = static_cast<std::int64_t>(h) + 1;
    for (std::uint32_t h = hops; h > 1; --h) {
        const std::uint32_t j = static_cast<std::uint32_t>(s.next(h));
        const std::int64_t t = perm[h - 1];
        perm[h - 1] = perm[j];
        perm[j] = t;
    }
    for (std::uint32_t h = 0; h < hops; ++h) {
        std::int64_t r = perm[h];
        if (s.next(2) != 0) r = -r;
        idx[2 * h] = psg::PackValue{};
        idx[2 * h].type = psg::PackType::Int;
        idx[2 * h].i = r;
        idx[2 * h + 1] = psg::PackValue{};
        idx[2 * h + 1].type = psg::PackType::Int;
        idx[2 * h + 1].i = static_cast<std::int64_t>(s.next(n_nodes));
    }
    psg::PackValue out{};
    if (nv::make_path(a, nodes, n_nodes, rels, n_rels, idx, 2u * hops, &out) !=
        psg::PackError::Ok) {
        return psg::PackValue{};
    }
    return out;
}

// Ranges are what the published drivers can represent (years 1..9999,
// whole-minute offsets), so a mismatch is the codec's and not the driver's.
template <class Src>
psg::PackValue gen_temporal(psg::PackArena& a, Src& s, const GenOptions& o) {
    using gen_detail::in_range;
    psg::PackValue out{};
    const std::int64_t secs = in_range(s, -62135596800LL + 86400, 253402300799LL - 86400);
    const std::int64_t ns = in_range(s, 0, nv::kNanosPerSecond - 1);
    const std::int64_t off = 60 * in_range(s, -18 * 60 + 1, 18 * 60 - 1);
    psg::PackError e = psg::PackError::Invalid;
    switch (s.next(o.allow_zone_id ? 7 : 6)) {
        case 0: e = nv::make_date(a, in_range(s, -719000, 2932000), &out); break;
        case 1: e = nv::make_local_time(a, in_range(s, 0, nv::kNanosPerDay - 1), &out); break;
        case 2: e = nv::make_time(a, in_range(s, 0, nv::kNanosPerDay - 1), off, &out); break;
        case 3: e = nv::make_local_date_time(a, secs, ns, &out); break;
        case 4: e = nv::make_date_time(a, secs, ns, off, &out); break;
        case 5:
            e = nv::make_duration(a, in_range(s, -100000, 100000), in_range(s, -1000000, 1000000),
                                  in_range(s, -1000000000LL, 1000000000LL), ns, &out);
            break;
        default: {
            const char* z = gen_detail::kZones[s.next(sizeof(gen_detail::kZones) /
                                                       sizeof(gen_detail::kZones[0]))];
            e = nv::make_date_time_zone_id(a, secs, ns, z, &out);
            break;
        }
    }
    return e == psg::PackError::Ok ? out : psg::PackValue{};
}

template <class Src>
psg::PackValue gen_value(psg::PackArena& a, Src& s, const GenOptions& o,
                         std::uint32_t depth) {
    psg::PackValue v{};
    const std::uint64_t kinds = depth >= o.max_depth ? 6u : 12u;
    switch (s.next(kinds)) {
        case 0: return v;
        case 1: v.type = psg::PackType::Bool; v.b = s.next(2) != 0; return v;
        case 2: v.type = psg::PackType::Int; v.i = gen_detail::any_int(s); return v;
        case 3: {
            std::uint64_t bits = s.next(0);
            double d = 0;
            std::memcpy(&d, &bits, 8);
            if (d != d) d = 1.5;   // NaN payloads are not bit-stable across clients
            v.type = psg::PackType::Float;
            v.f = d;
            return v;
        }
        case 4: {
            const std::string_view t = gen_detail::text(a, s, 6);
            v.type = psg::PackType::String;
            v.bytes = t.data();
            v.len = static_cast<std::uint32_t>(t.size());
            return v;
        }
        case 5: return gen_temporal(a, s, o);
        case 6: {
            const std::uint32_t n = static_cast<std::uint32_t>(s.next(4));
            auto* items = n ? a.alloc_n<psg::PackValue>(n) : nullptr;
            if (n != 0 && items == nullptr) return v;
            for (std::uint32_t k = 0; k < n; ++k) items[k] = gen_value(a, s, o, depth + 1);
            v.type = psg::PackType::List;
            v.items = items;
            v.len = n;
            return v;
        }
        case 7: return gen_props(a, s, o, depth);
        case 8: return gen_node(a, s, o, depth, gen_detail::next_id(o));
        case 9: return gen_rel(a, s, o, depth, true);
        case 10: return gen_path(a, s, o, depth);
        default: {
            const std::uint32_t n = static_cast<std::uint32_t>(s.next(5));
            char* p = n ? static_cast<char*>(a.alloc(n, 1)) : nullptr;
            for (std::uint32_t k = 0; p != nullptr && k < n; ++k) {
                p[k] = static_cast<char>(s.next(256));
            }
            v.type = psg::PackType::Bytes;
            v.bytes = p;
            v.len = p ? n : 0;
            return v;
        }
    }
}

// ---------------------------------------------------------------------------
// describe
// ---------------------------------------------------------------------------
namespace desc_detail {

inline void hex(std::string& out, std::string_view s) {
    static const char* d = "0123456789abcdef";
    for (char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        out.push_back(d[c >> 4]);
        out.push_back(d[c & 15]);
    }
}

inline void num(std::string& out, std::int64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "%lld", static_cast<long long>(v));
    out += b;
}

inline void eid(std::string& out, bool has, std::string_view e, std::int64_t id) {
    out += ",e:";
    if (has) {
        hex(out, e);
        return;
    }
    char b[24];
    const int n = std::snprintf(b, sizeof(b), "%lld", static_cast<long long>(id));
    hex(out, std::string_view(b, static_cast<std::size_t>(n)));
}

}  // namespace desc_detail

inline bool describe(const psg::PackValue& v, bool with_eid, std::string& out);

inline bool describe_props(const psg::PackValue& d, bool with_eid, std::string& out,
                           bool entity = false) {
    out += '{';
    bool first = true;
    for (std::uint32_t k = 0; k < d.len; ++k) {
        if (entity && d.pairs[k].value->is_null()) continue;   // absent, not null
        if (!first) out += ',';
        first = false;
        desc_detail::hex(out, d.pairs[k].key_view());
        out += '=';
        if (!describe(*d.pairs[k].value, with_eid, out)) return false;
    }
    out += '}';
    return true;
}

inline bool describe_node(const nv::NodeView& n, bool with_eid, std::string& out) {
    out += "N(";
    desc_detail::num(out, n.id);
    // Labels are a set to a client: sorted and de-duplicated.
    std::vector<std::string> ls;
    for (std::uint32_t k = 0; k < n.labels->len; ++k) {
        std::string h;
        desc_detail::hex(h, n.labels->items[k].str());
        ls.push_back(h);
    }
    std::sort(ls.begin(), ls.end());
    ls.erase(std::unique(ls.begin(), ls.end()), ls.end());
    out += ",[";
    for (std::size_t k = 0; k < ls.size(); ++k) {
        if (k) out += ',';
        out += ls[k];
    }
    out += "],";
    if (!describe_props(*n.props, with_eid, out, true)) return false;
    if (with_eid) desc_detail::eid(out, n.has_element_id, n.element_id, n.id);
    out += ')';
    return true;
}

inline bool describe_rel(const nv::RelView& r, std::int64_t s, std::int64_t e,
                         const nv::NodeView* sn, const nv::NodeView* en, bool with_eid,
                         std::string& out) {
    out += "R(";
    desc_detail::num(out, r.id);
    out += ',';
    desc_detail::num(out, s);
    out += ',';
    desc_detail::num(out, e);
    out += ',';
    desc_detail::hex(out, r.type);
    out += ',';
    if (!describe_props(*r.props, with_eid, out, true)) return false;
    if (with_eid) {
        desc_detail::eid(out, r.has_element_ids, r.element_id, r.id);
        if (sn != nullptr) {
            desc_detail::eid(out, sn->has_element_id, sn->element_id, sn->id);
            desc_detail::eid(out, en->has_element_id, en->element_id, en->id);
        } else {
            desc_detail::eid(out, r.has_element_ids, r.start_element_id, r.start_id);
            desc_detail::eid(out, r.has_element_ids, r.end_element_id, r.end_id);
        }
    }
    out += ')';
    return true;
}

// A Path renders as its walked node sequence and its relationships with the
// endpoints the walk gives them — what a client hydrates it into.
inline bool describe_path(const nv::PathView& p, bool with_eid, std::string& out) {
    nv::NodeView prev{};
    if (nv::as_node(p.nodes->items[0], &prev) != psg::PackError::Ok) return false;
    std::string nodes = "[";
    std::string rels = "[";
    if (!describe_node(prev, with_eid, nodes)) return false;
    for (std::uint32_t h = 0; h < p.hops; ++h) {
        const std::int64_t ri = p.indices->items[2 * h].i;
        const std::int64_t ni = p.indices->items[2 * h + 1].i;
        nv::NodeView next{};
        nv::RelView r{};
        if (nv::as_node(p.nodes->items[ni], &next) != psg::PackError::Ok) return false;
        const std::int64_t at = (ri > 0 ? ri : -ri) - 1;
        if (nv::as_relationship(p.rels->items[at], &r) != psg::PackError::Ok) return false;
        const nv::NodeView& s = ri > 0 ? prev : next;
        const nv::NodeView& e = ri > 0 ? next : prev;
        nodes += ',';
        if (!describe_node(next, with_eid, nodes)) return false;
        if (h) rels += ',';
        if (!describe_rel(r, s.id, e.id, &s, &e, with_eid, rels)) return false;
        prev = next;
    }
    out += "P(" + nodes + "]," + rels + "])";
    return true;
}

inline bool describe_temporal(const nv::TemporalView& t, std::string& out) {
    char tag = static_cast<char>(t.signature);
    if (t.signature == nv::kSigLegacyDateTime) tag = 'I';
    if (t.signature == nv::kSigLegacyDateTimeZoneId) tag = 'f';
    out += tag;
    out += '(';
    if (t.signature == nv::kSigDuration) {
        desc_detail::num(out, t.f[0]);
        out += ',';
        desc_detail::num(out, t.f[1]);
        out += ',';
        if (t.f[2] > -9000000000LL && t.f[2] < 9000000000LL &&
            t.f[3] > -nv::kNanosPerSecond * 9 && t.f[3] < nv::kNanosPerSecond * 9) {
            desc_detail::num(out, t.f[2] * nv::kNanosPerSecond + t.f[3]);
        } else {
            out += 'x';
            desc_detail::num(out, t.f[2]);
            out += ':';
            desc_detail::num(out, t.f[3]);
        }
    } else {
        for (std::uint8_t k = 0; k < t.n_int; ++k) {
            if (k) out += ',';
            desc_detail::num(out, t.f[k]);
        }
        if (!t.zone.empty()) {
            out += ',';
            desc_detail::hex(out, t.zone);
        }
    }
    out += ')';
    return true;
}

inline bool describe(const psg::PackValue& v, bool with_eid, std::string& out) {
    char b[32];
    switch (v.type) {
        case psg::PackType::Null: out += "null"; return true;
        case psg::PackType::Bool: out += v.b ? "true" : "false"; return true;
        case psg::PackType::Int: desc_detail::num(out, v.i); return true;
        case psg::PackType::Float: {
            std::uint64_t bits = 0;
            std::memcpy(&bits, &v.f, 8);
            std::snprintf(b, sizeof(b), "f:%016llx", static_cast<unsigned long long>(bits));
            out += b;
            return true;
        }
        case psg::PackType::String: out += "s:"; desc_detail::hex(out, v.str()); return true;
        case psg::PackType::Bytes: out += "b:"; desc_detail::hex(out, v.str()); return true;
        case psg::PackType::List:
            out += '[';
            for (std::uint32_t k = 0; k < v.len; ++k) {
                if (k) out += ',';
                if (!describe(v.items[k], with_eid, out)) return false;
            }
            out += ']';
            return true;
        case psg::PackType::Dict: return describe_props(v, with_eid, out);
        case psg::PackType::Struct: break;
    }
    if (v.signature == nv::kSigNode) {
        nv::NodeView n{};
        return nv::as_node(v, &n) == psg::PackError::Ok && describe_node(n, with_eid, out);
    }
    if (v.signature == nv::kSigRelationship) {
        nv::RelView r{};
        return nv::as_relationship(v, &r) == psg::PackError::Ok &&
               describe_rel(r, r.start_id, r.end_id, nullptr, nullptr, with_eid, out);
    }
    if (v.signature == nv::kSigPath) {
        nv::PathView p{};
        return nv::as_path(v, &p) == psg::PackError::Ok && describe_path(p, with_eid, out);
    }
    nv::TemporalView t{};
    if (nv::as_temporal(v, &t) != psg::PackError::Ok) return false;
    return describe_temporal(t, out);
}

}  // namespace boltapi_test
