// src/proto/neo4j_values.cpp — Bolt graph + temporal structures (neo4j_values.h).
//
// Compiled ONLY under BOLTAPI_WITH_NEO4J_BOLT. Field layouts are the published
// Bolt value spec (https://neo4j.com/docs/bolt/current/bolt/structure-semantics/);
// tests/neo4j_values_test.cpp pins the bytes for both dialects.

#include "boltapi/proto/neo4j_values.h"

#if defined(BOLTAPI_WITH_NEO4J_BOLT)

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace proto {
namespace neo4j {
namespace values {
namespace {

using ps::PackError;
using ps::PackType;
using ps::PackValue;

PackValue pv_int(std::int64_t v) noexcept {
    PackValue x{};
    x.type = PackType::Int;
    x.i = v;
    return x;
}

PackValue pv_str(std::string_view s) noexcept {
    PackValue x{};
    x.type = PackType::String;
    x.bytes = s.data();
    x.len = static_cast<std::uint32_t>(s.size());
    return x;
}

PackError alloc_struct(ps::PackArena& a, std::uint8_t sig, std::uint32_t n,
                       PackValue* out, PackValue** fields) noexcept {
    assert(out != nullptr && fields != nullptr);
    assert(n >= 1 && n <= 15);
    *fields = a.alloc_n<PackValue>(n);
    if (*fields == nullptr) return PackError::OutOfMemory;
    for (std::uint32_t k = 0; k < n; ++k) (*fields)[k] = PackValue{};
    *out = PackValue{};
    out->type = PackType::Struct;
    out->signature = sig;
    out->items = *fields;
    out->len = n;
    return PackError::Ok;
}

PackValue dict_of(const ps::PackPair* props, std::uint32_t n) noexcept {
    PackValue d{};
    d.type = PackType::Dict;
    d.pairs = const_cast<ps::PackPair*>(props);
    d.len = n;
    return d;
}

bool is_int(const PackValue& v) noexcept { return v.type == PackType::Int; }
bool is_str(const PackValue& v) noexcept { return v.type == PackType::String; }

bool valid_props(const PackValue& v) noexcept {
    if (v.type != PackType::Dict) return false;
    return v.len == 0 || v.pairs != nullptr;
}

bool valid_nanos(std::int64_t n) noexcept { return n >= 0 && n < kNanosPerSecond; }
bool valid_nanos_of_day(std::int64_t n) noexcept { return n >= 0 && n < kNanosPerDay; }
bool valid_offset(std::int64_t o) noexcept {
    return o >= -kMaxOffsetSeconds && o <= kMaxOffsetSeconds;
}
bool valid_zone(std::string_view z) noexcept {
    return !z.empty() && z.size() <= kMaxZoneIdBytes;
}

// |b| is bounded by an offset, so this cannot itself overflow while checking.
bool checked_add(std::int64_t a, std::int64_t b, std::int64_t* out) noexcept {
    assert(b >= -kMaxOffsetSeconds && b <= kMaxOffsetSeconds);
    constexpr std::int64_t kMax = INT64_MAX;
    constexpr std::int64_t kMin = INT64_MIN;
    if ((b > 0 && a > kMax - b) || (b < 0 && a < kMin - b)) return false;
    *out = a + b;
    return true;
}

// Decimal text of `v` into `buf`; the derived element id of a Bolt 4 value.
std::string_view decimal_id(std::int64_t v, char* buf, std::size_t cap) noexcept {
    assert(buf != nullptr && cap >= 24);
    const int n = std::snprintf(buf, cap, "%lld", static_cast<long long>(v));
    assert(n > 0 && static_cast<std::size_t>(n) < cap);
    return std::string_view(buf, static_cast<std::size_t>(n));
}

PackError write_at(ps::PackWriter& w, const PackValue& v, std::uint8_t major,
                   std::uint32_t depth) noexcept;

PackError write_props(ps::PackWriter& w, const PackValue& d, std::uint8_t major,
                      std::uint32_t depth) noexcept {
    assert(d.type == PackType::Dict);
    PackError e = w.begin_dict(d.len);
    for (std::uint32_t k = 0; e == PackError::Ok && k < d.len; ++k) {
        if (d.pairs[k].value == nullptr) return PackError::Invalid;
        e = w.put_string(d.pairs[k].key_view());
        if (e == PackError::Ok) e = write_at(w, *d.pairs[k].value, major, depth + 1);
    }
    return e;
}

// An entity property whose value is null does not exist (Bolt structure
// semantics); it is left out rather than sent for a client to drop or keep.
PackError write_entity_props(ps::PackWriter& w, const PackValue& d, std::uint8_t major,
                             std::uint32_t depth) noexcept {
    assert(d.type == PackType::Dict);
    std::uint32_t live = 0;
    for (std::uint32_t k = 0; k < d.len; ++k) {
        if (d.pairs[k].value == nullptr) return PackError::Invalid;
        if (!d.pairs[k].value->is_null()) ++live;
    }
    PackError e = w.begin_dict(live);
    for (std::uint32_t k = 0; e == PackError::Ok && k < d.len; ++k) {
        if (d.pairs[k].value->is_null()) continue;
        e = w.put_string(d.pairs[k].key_view());
        if (e == PackError::Ok) e = write_at(w, *d.pairs[k].value, major, depth + 1);
    }
    return e;
}

PackError write_node(ps::PackWriter& w, const PackValue& v, std::uint8_t major,
                     std::uint32_t depth) noexcept {
    NodeView n{};
    PackError e = as_node(v, &n);
    if (e != PackError::Ok) return e;
    const bool v5 = major >= 5;
    e = w.begin_struct(kSigNode, v5 ? 4 : 3);
    if (e == PackError::Ok) e = w.put_int(n.id);
    if (e == PackError::Ok) e = w.put_value(*n.labels);
    if (e == PackError::Ok) e = write_entity_props(w, *n.props, major, depth);
    if (e != PackError::Ok || !v5) return e;
    char buf[24];
    return w.put_string(n.has_element_id ? n.element_id
                                         : decimal_id(n.id, buf, sizeof(buf)));
}

PackError write_rel(ps::PackWriter& w, const PackValue& v, std::uint8_t major,
                    std::uint32_t depth) noexcept {
    RelView r{};
    PackError e = as_relationship(v, &r);
    if (e != PackError::Ok) return e;
    const bool v5 = major >= 5;
    const std::uint8_t n = r.bound ? (v5 ? 8 : 5) : (v5 ? 4 : 3);
    e = w.begin_struct(r.bound ? kSigRelationship : kSigUnboundRel, n);
    if (e == PackError::Ok) e = w.put_int(r.id);
    if (r.bound) {
        if (e == PackError::Ok) e = w.put_int(r.start_id);
        if (e == PackError::Ok) e = w.put_int(r.end_id);
    }
    if (e == PackError::Ok) e = w.put_string(r.type);
    if (e == PackError::Ok) e = write_entity_props(w, *r.props, major, depth);
    if (e != PackError::Ok || !v5) return e;
    char b0[24], b1[24], b2[24];
    e = w.put_string(r.has_element_ids ? r.element_id : decimal_id(r.id, b0, 24));
    if (e != PackError::Ok || !r.bound) return e;
    e = w.put_string(r.has_element_ids ? r.start_element_id
                                       : decimal_id(r.start_id, b1, 24));
    if (e != PackError::Ok) return e;
    return w.put_string(r.has_element_ids ? r.end_element_id
                                          : decimal_id(r.end_id, b2, 24));
}

PackError write_path(ps::PackWriter& w, const PackValue& v, std::uint8_t major,
                     std::uint32_t depth) noexcept {
    PathView p{};
    PackError e = as_path(v, &p);
    if (e != PackError::Ok) return e;
    e = w.begin_struct(kSigPath, 3);
    if (e == PackError::Ok) e = w.begin_list(p.nodes->len);
    for (std::uint32_t k = 0; e == PackError::Ok && k < p.nodes->len; ++k) {
        e = write_node(w, p.nodes->items[k], major, depth + 1);
    }
    if (e == PackError::Ok) e = w.begin_list(p.rels->len);
    for (std::uint32_t k = 0; e == PackError::Ok && k < p.rels->len; ++k) {
        e = write_rel(w, p.rels->items[k], major, depth + 1);
    }
    if (e == PackError::Ok) e = w.put_value(*p.indices);
    return e;
}

PackError write_temporal(ps::PackWriter& w, const PackValue& v,
                         std::uint8_t major) noexcept {
    TemporalView t{};
    PackError e = as_temporal(v, &t);
    if (e != PackError::Ok) return e;
    std::uint8_t sig = t.signature;
    const bool v5 = major >= 5;
    if (sig == kSigDateTime || sig == kSigLegacyDateTime) {
        // canonical f[0] is UTC seconds; the legacy form carries local seconds.
        std::int64_t s = t.f[0];
        if (!v5 && !checked_add(t.f[0], t.f[2], &s)) return PackError::Invalid;
        sig = v5 ? kSigDateTime : kSigLegacyDateTime;
        e = w.begin_struct(sig, 3);
        if (e == PackError::Ok) e = w.put_int(s);
        if (e == PackError::Ok) e = w.put_int(t.f[1]);
        if (e == PackError::Ok) e = w.put_int(t.f[2]);
        return e;
    }
    if (sig == kSigDateTimeZoneId || sig == kSigLegacyDateTimeZoneId) {
        // Converting between UTC and zone-local seconds needs a tz database
        // this layer does not carry; the two dialects meet only when equal.
        if ((sig == kSigDateTimeZoneId) != v5) return PackError::Unsupported;
        e = w.begin_struct(sig, 3);
        if (e == PackError::Ok) e = w.put_int(t.f[0]);
        if (e == PackError::Ok) e = w.put_int(t.f[1]);
        if (e == PackError::Ok) e = w.put_string(t.zone);
        return e;
    }
    e = w.begin_struct(sig, t.n_int);
    for (std::uint8_t k = 0; e == PackError::Ok && k < t.n_int; ++k) {
        e = w.put_int(t.f[k]);
    }
    return e;
}

PackError write_point(ps::PackWriter& w, const PackValue& v) noexcept {
    const std::uint32_t want = (v.signature == kSigPoint2D) ? 3u : 4u;
    if (v.len != want || v.items == nullptr || !is_int(v.items[0])) {
        return PackError::Invalid;
    }
    for (std::uint32_t k = 1; k < want; ++k) {
        if (v.items[k].type != PackType::Float) return PackError::Invalid;
    }
    return w.put_value(v);
}

PackError write_at(ps::PackWriter& w, const PackValue& v, std::uint8_t major,
                   std::uint32_t depth) noexcept {
    assert(major == 4 || major == 5);
    if (depth >= ps::kMaxDepth) return PackError::DepthExceeded;
    switch (v.type) {
        case PackType::List: {
            PackError e = w.begin_list(v.len);
            for (std::uint32_t k = 0; e == PackError::Ok && k < v.len; ++k) {
                e = write_at(w, v.items[k], major, depth + 1);
            }
            return e;
        }
        case PackType::Dict:
            if (v.len != 0 && v.pairs == nullptr) return PackError::Invalid;
            return write_props(w, v, major, depth);
        case PackType::Struct:
            if (v.len != 0 && v.items == nullptr) return PackError::Invalid;
            if (v.signature == kSigNode) return write_node(w, v, major, depth);
            if (v.signature == kSigRelationship || v.signature == kSigUnboundRel) {
                return write_rel(w, v, major, depth);
            }
            if (v.signature == kSigPath) return write_path(w, v, major, depth);
            if (is_temporal_signature(v.signature)) return write_temporal(w, v, major);
            if (v.signature == kSigPoint2D || v.signature == kSigPoint3D) {
                return write_point(w, v);
            }
            return PackError::Unsupported;
        default:
            return w.put_value(v);
    }
}

// The node/rel index walk every Path must satisfy (spec: "Path").
PackError check_indices(const PathView& p) noexcept {
    const PackValue& ix = *p.indices;
    const std::int64_t n_nodes = p.nodes->len;
    const std::int64_t n_rels = p.rels->len;
    for (std::uint32_t k = 0; k < ix.len; ++k) {
        if (!is_int(ix.items[k])) return PackError::Invalid;
        const std::int64_t x = ix.items[k].i;
        if ((k & 1u) == 0u) {
            if (x == 0 || x < -n_rels || x > n_rels) return PackError::Invalid;
        } else if (x < 0 || x >= n_nodes) {
            return PackError::Invalid;
        }
    }
    return PackError::Ok;
}

}  // namespace

bool is_temporal_signature(std::uint8_t sig) noexcept {
    switch (sig) {
        case kSigDate: case kSigTime: case kSigLocalTime: case kSigDateTime:
        case kSigDateTimeZoneId: case kSigLegacyDateTime:
        case kSigLegacyDateTimeZoneId: case kSigLocalDateTime: case kSigDuration:
            return true;
        default:
            return false;
    }
}

// --- builders ---------------------------------------------------------------
PackError make_node(ps::PackArena& a, std::int64_t id, const std::string_view* labels,
                    std::uint32_t n_labels, const ps::PackPair* props,
                    std::uint32_t n_props, PackValue* out) noexcept {
    assert(out != nullptr);
    assert(n_labels == 0 || labels != nullptr);
    if (n_props != 0 && props == nullptr) return PackError::Invalid;
    PackValue* f = nullptr;
    PackError e = alloc_struct(a, kSigNode, 3, out, &f);
    if (e != PackError::Ok) return e;
    PackValue* lv = (n_labels == 0) ? nullptr : a.alloc_n<PackValue>(n_labels);
    if (n_labels != 0 && lv == nullptr) return PackError::OutOfMemory;
    for (std::uint32_t k = 0; k < n_labels; ++k) lv[k] = pv_str(labels[k]);
    f[0] = pv_int(id);
    f[1].type = PackType::List;
    f[1].items = lv;
    f[1].len = n_labels;
    f[2] = dict_of(props, n_props);
    return PackError::Ok;
}

PackError make_relationship(ps::PackArena& a, std::int64_t id, std::int64_t start_id,
                            std::int64_t end_id, std::string_view type,
                            const ps::PackPair* props, std::uint32_t n_props,
                            PackValue* out) noexcept {
    assert(out != nullptr);
    if (type.empty() || (n_props != 0 && props == nullptr)) return PackError::Invalid;
    PackValue* f = nullptr;
    PackError e = alloc_struct(a, kSigRelationship, 5, out, &f);
    if (e != PackError::Ok) return e;
    f[0] = pv_int(id);
    f[1] = pv_int(start_id);
    f[2] = pv_int(end_id);
    f[3] = pv_str(type);
    f[4] = dict_of(props, n_props);
    assert(out->len == 5);
    return PackError::Ok;
}

PackError make_unbound_relationship(ps::PackArena& a, std::int64_t id,
                                    std::string_view type, const ps::PackPair* props,
                                    std::uint32_t n_props, PackValue* out) noexcept {
    assert(out != nullptr);
    if (type.empty() || (n_props != 0 && props == nullptr)) return PackError::Invalid;
    PackValue* f = nullptr;
    PackError e = alloc_struct(a, kSigUnboundRel, 3, out, &f);
    if (e != PackError::Ok) return e;
    f[0] = pv_int(id);
    f[1] = pv_str(type);
    f[2] = dict_of(props, n_props);
    assert(out->len == 3);
    return PackError::Ok;
}

PackError make_path(ps::PackArena& a, const PackValue* nodes, std::uint32_t n_nodes,
                    const PackValue* rels, std::uint32_t n_rels,
                    const PackValue* indices, std::uint32_t n_indices,
                    PackValue* out) noexcept {
    assert(out != nullptr);
    assert(n_nodes == 0 || nodes != nullptr);
    PackValue* f = nullptr;
    PackError e = alloc_struct(a, kSigPath, 3, out, &f);
    if (e != PackError::Ok) return e;
    f[0].type = PackType::List; f[0].items = const_cast<PackValue*>(nodes); f[0].len = n_nodes;
    f[1].type = PackType::List; f[1].items = const_cast<PackValue*>(rels);  f[1].len = n_rels;
    f[2].type = PackType::List; f[2].items = const_cast<PackValue*>(indices); f[2].len = n_indices;
    PathView pv{};
    return as_path(*out, &pv);
}

namespace {
PackError make_ints(ps::PackArena& a, std::uint8_t sig, const std::int64_t* v,
                    std::uint32_t n, PackValue* out) noexcept {
    assert(out != nullptr && v != nullptr);
    PackValue* f = nullptr;
    PackError e = alloc_struct(a, sig, n, out, &f);
    if (e != PackError::Ok) return e;
    for (std::uint32_t k = 0; k < n; ++k) f[k] = pv_int(v[k]);
    TemporalView t{};
    return as_temporal(*out, &t);
}
}  // namespace

PackError make_date(ps::PackArena& a, std::int64_t days, PackValue* out) noexcept {
    const std::int64_t v[1] = {days};
    return make_ints(a, kSigDate, v, 1, out);
}

PackError make_local_time(ps::PackArena& a, std::int64_t nanos, PackValue* out) noexcept {
    const std::int64_t v[1] = {nanos};
    return make_ints(a, kSigLocalTime, v, 1, out);
}

PackError make_time(ps::PackArena& a, std::int64_t nanos, std::int64_t offset,
                    PackValue* out) noexcept {
    const std::int64_t v[2] = {nanos, offset};
    return make_ints(a, kSigTime, v, 2, out);
}

PackError make_local_date_time(ps::PackArena& a, std::int64_t seconds,
                               std::int64_t nanos, PackValue* out) noexcept {
    const std::int64_t v[2] = {seconds, nanos};
    return make_ints(a, kSigLocalDateTime, v, 2, out);
}

PackError make_date_time(ps::PackArena& a, std::int64_t utc_seconds, std::int64_t nanos,
                         std::int64_t offset, PackValue* out) noexcept {
    const std::int64_t v[3] = {utc_seconds, nanos, offset};
    return make_ints(a, kSigDateTime, v, 3, out);
}

PackError make_date_time_zone_id(ps::PackArena& a, std::int64_t utc_seconds,
                                 std::int64_t nanos, std::string_view zone,
                                 PackValue* out) noexcept {
    assert(out != nullptr);
    PackValue* f = nullptr;
    PackError e = alloc_struct(a, kSigDateTimeZoneId, 3, out, &f);
    if (e != PackError::Ok) return e;
    f[0] = pv_int(utc_seconds);
    f[1] = pv_int(nanos);
    f[2] = pv_str(zone);
    TemporalView t{};
    return as_temporal(*out, &t);
}

PackError make_duration(ps::PackArena& a, std::int64_t months, std::int64_t days,
                        std::int64_t seconds, std::int64_t nanos,
                        PackValue* out) noexcept {
    const std::int64_t v[4] = {months, days, seconds, nanos};
    return make_ints(a, kSigDuration, v, 4, out);
}

PackError make_local_date_time_from_micros(ps::PackArena& a, std::int64_t us,
                                           PackValue* out) noexcept {
    std::int64_t s = us / 1000000;
    std::int64_t r = us % 1000000;
    if (r < 0) { r += 1000000; s -= 1; }
    assert(r >= 0 && r < 1000000);
    return make_local_date_time(a, s, r * 1000, out);
}

// --- views ------------------------------------------------------------------
PackError as_node(const PackValue& v, NodeView* out) noexcept {
    assert(out != nullptr);
    if (v.type != PackType::Struct || v.signature != kSigNode) return PackError::Invalid;
    if ((v.len != 3 && v.len != 4) || v.items == nullptr) return PackError::Invalid;
    const PackValue* f = v.items;
    if (!is_int(f[0]) || f[1].type != PackType::List || !valid_props(f[2])) {
        return PackError::Invalid;
    }
    if (f[1].len != 0 && f[1].items == nullptr) return PackError::Invalid;
    for (std::uint32_t k = 0; k < f[1].len; ++k) {
        if (!is_str(f[1].items[k])) return PackError::Invalid;
    }
    if (v.len == 4 && !is_str(f[3])) return PackError::Invalid;
    out->id = f[0].i;
    out->labels = &f[1];
    out->props = &f[2];
    out->has_element_id = (v.len == 4);
    out->element_id = out->has_element_id ? f[3].str() : std::string_view();
    return PackError::Ok;
}

PackError as_relationship(const PackValue& v, RelView* out) noexcept {
    assert(out != nullptr);
    if (v.type != PackType::Struct || v.items == nullptr) return PackError::Invalid;
    const bool bound = (v.signature == kSigRelationship);
    if (!bound && v.signature != kSigUnboundRel) return PackError::Invalid;
    const std::uint32_t base = bound ? 5u : 3u;
    const std::uint32_t full = bound ? 8u : 4u;
    if (v.len != base && v.len != full) return PackError::Invalid;
    const PackValue* f = v.items;
    const std::uint32_t t = bound ? 3u : 1u;
    if (!is_int(f[0]) || !is_str(f[t]) || !valid_props(f[t + 1])) return PackError::Invalid;
    if (bound && (!is_int(f[1]) || !is_int(f[2]))) return PackError::Invalid;
    for (std::uint32_t k = base; k < v.len; ++k) {
        if (!is_str(f[k])) return PackError::Invalid;
    }
    *out = RelView{};
    out->bound = bound;
    out->id = f[0].i;
    out->start_id = bound ? f[1].i : 0;
    out->end_id = bound ? f[2].i : 0;
    out->type = f[t].str();
    out->props = &f[t + 1];
    out->has_element_ids = (v.len == full);
    if (out->has_element_ids) {
        out->element_id = f[base].str();
        if (bound) {
            out->start_element_id = f[base + 1].str();
            out->end_element_id = f[base + 2].str();
        }
    }
    return PackError::Ok;
}

PackError as_path(const PackValue& v, PathView* out) noexcept {
    assert(out != nullptr);
    if (v.type != PackType::Struct || v.signature != kSigPath || v.len != 3 ||
        v.items == nullptr) {
        return PackError::Invalid;
    }
    const PackValue* f = v.items;
    for (std::uint32_t k = 0; k < 3; ++k) {
        if (f[k].type != PackType::List) return PackError::Invalid;
        if (f[k].len != 0 && f[k].items == nullptr) return PackError::Invalid;
    }
    if (f[0].len == 0 || (f[2].len & 1u) != 0 || f[2].len / 2 > kMaxPathHops) {
        return PackError::Invalid;
    }
    for (std::uint32_t k = 0; k < f[0].len; ++k) {
        NodeView n{};
        if (as_node(f[0].items[k], &n) != PackError::Ok) return PackError::Invalid;
    }
    for (std::uint32_t k = 0; k < f[1].len; ++k) {
        RelView r{};
        if (as_relationship(f[1].items[k], &r) != PackError::Ok || r.bound) {
            return PackError::Invalid;
        }
    }
    out->nodes = &f[0];
    out->rels = &f[1];
    out->indices = &f[2];
    out->hops = f[2].len / 2;
    return check_indices(*out);
}

PackError as_temporal(const PackValue& v, TemporalView* out) noexcept {
    assert(out != nullptr);
    if (v.type != PackType::Struct || !is_temporal_signature(v.signature) ||
        (v.len != 0 && v.items == nullptr)) {
        return PackError::Invalid;
    }
    const std::uint8_t sig = v.signature;
    const bool zoned = (sig == kSigDateTimeZoneId || sig == kSigLegacyDateTimeZoneId);
    std::uint32_t want = 0;
    switch (sig) {
        case kSigDate: case kSigLocalTime:              want = 1; break;
        case kSigTime: case kSigLocalDateTime:          want = 2; break;
        case kSigDuration:                              want = 4; break;
        default:                                        want = 3; break;
    }
    if (v.len != want) return PackError::Invalid;
    *out = TemporalView{};
    out->signature = sig;
    out->n_int = static_cast<std::uint8_t>(zoned ? 2 : want);
    for (std::uint32_t k = 0; k < out->n_int; ++k) {
        if (!is_int(v.items[k])) return PackError::Invalid;
        out->f[k] = v.items[k].i;
    }
    if (zoned) {
        if (!is_str(v.items[2]) || !valid_zone(v.items[2].str())) return PackError::Invalid;
        out->zone = v.items[2].str();
    }
    bool ok = true;
    switch (sig) {
        case kSigLocalTime: ok = valid_nanos_of_day(out->f[0]); break;
        case kSigTime:
            ok = valid_nanos_of_day(out->f[0]) && valid_offset(out->f[1]);
            break;
        case kSigLocalDateTime: ok = valid_nanos(out->f[1]); break;
        case kSigDateTime: case kSigLegacyDateTime:
            ok = valid_nanos(out->f[1]) && valid_offset(out->f[2]);
            break;
        case kSigDateTimeZoneId: case kSigLegacyDateTimeZoneId:
            ok = valid_nanos(out->f[1]);
            break;
        default: break;
    }
    if (!ok) return PackError::Invalid;
    if (sig == kSigLegacyDateTime) {
        // canonical field 0 is UTC seconds
        std::int64_t utc = 0;
        if (!checked_add(out->f[0], -out->f[2], &utc)) return PackError::Invalid;
        out->f[0] = utc;
    }
    return PackError::Ok;
}

PackError write_value(ps::PackWriter& w, const PackValue& v,
                      std::uint8_t bolt_major) noexcept {
    assert(bolt_major == 4 || bolt_major == 5);
    const std::size_t before = w.size();
    const PackError e = write_at(w, v, bolt_major, 0);
    assert(e != PackError::Ok || w.size() > before);
    (void)before;
    return e;
}

}  // namespace values
}  // namespace neo4j
}  // namespace proto
}  // namespace bolt::api

#endif  // BOLTAPI_WITH_NEO4J_BOLT
