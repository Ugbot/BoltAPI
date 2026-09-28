// boltapi/proto/neo4j_values.h — Neo4j Bolt STRUCTURE values: graph + temporal.
//
// "Bolt" is Neo4j's client wire protocol here, not extern/bolt.
//
// An executor builds a value in ONE canonical shape and the connection writes
// it in the dialect the session negotiated:
//
//   canonical (builders below)          Bolt 4.4 wire           Bolt 5.x wire
//   Node 'N' {id, labels, props}        3 fields                + element_id
//   Relationship 'R' {id,s,e,type,p}    5 fields                + 3 element ids
//   UnboundRelationship 'r' {id,t,p}    3 fields                + element_id
//   Path 'P' {nodes, rels, indices}     3 fields                3 fields
//   DateTime 'I' {utc_s, ns, offset}    legacy 'F' (local s)    'I'
//   DateTimeZoneId 'i' {utc_s,ns,zone}  REFUSED (needs tzdata)  'i'
//   Date 'D', Time 'T', LocalTime 't',
//   LocalDateTime 'd', Duration 'E'     unchanged               unchanged
//
// A missing element id is derived as the decimal integer id, which is what the
// published drivers themselves assume for a Bolt 4 value. An explicit element
// id is carried on 5.x and dropped on 4.4.
//
// Every value is VALIDATED on the way out: a wrong field count, a field of the
// wrong PackStream type, a nanosecond outside its range, or a Path whose
// indices do not walk its own nodes and relationships is PackError::Invalid,
// never a byte a driver would hydrate into something else. A structure
// signature that is not one of the types above is PackError::Unsupported.

#pragma once

#include "boltapi/proto/packstream.h"
#include "boltapi/wire_limits.h"

#include <cstdint>
#include <string_view>

namespace bolt::api {
namespace proto {
namespace neo4j {
namespace values {

namespace ps = ::bolt::api::proto::packstream;

inline constexpr std::uint8_t kSigNode           = 0x4E;  // 'N'
inline constexpr std::uint8_t kSigRelationship   = 0x52;  // 'R'
inline constexpr std::uint8_t kSigUnboundRel     = 0x72;  // 'r'
inline constexpr std::uint8_t kSigPath           = 0x50;  // 'P'
inline constexpr std::uint8_t kSigDate           = 0x44;  // 'D'
inline constexpr std::uint8_t kSigTime           = 0x54;  // 'T'
inline constexpr std::uint8_t kSigLocalTime      = 0x74;  // 't'
inline constexpr std::uint8_t kSigDateTime       = 0x49;  // 'I'  (Bolt 5)
inline constexpr std::uint8_t kSigDateTimeZoneId = 0x69;  // 'i'  (Bolt 5)
inline constexpr std::uint8_t kSigLegacyDateTime = 0x46;  // 'F'  (Bolt 4)
inline constexpr std::uint8_t kSigLegacyDateTimeZoneId = 0x66;  // 'f'
inline constexpr std::uint8_t kSigLocalDateTime  = 0x64;  // 'd'
inline constexpr std::uint8_t kSigDuration       = 0x45;  // 'E'
inline constexpr std::uint8_t kSigPoint2D        = 0x58;  // 'X'
inline constexpr std::uint8_t kSigPoint3D        = 0x59;  // 'Y'

inline constexpr std::int64_t  kNanosPerSecond   = 1000000000LL;
inline constexpr std::int64_t  kNanosPerDay      = 86400LL * kNanosPerSecond;
inline constexpr std::int64_t  kMaxOffsetSeconds = ::bolt::api::kBoltMaxOffsetSeconds;
inline constexpr std::uint32_t kMaxZoneIdBytes   = ::bolt::api::kBoltMaxZoneIdBytes;
inline constexpr std::uint32_t kMaxPathHops      = ::bolt::api::kBoltMaxPathHops;

// --- builders: canonical shapes, fields allocated in `a` -------------------
// Labels, type and zone strings and the property pairs are BORROWED: they must
// outlive the emit of the value. Each returns Invalid for an out-of-range
// argument and OutOfMemory when `a` is exhausted.
ps::PackError make_node(ps::PackArena& a, std::int64_t id,
                        const std::string_view* labels, std::uint32_t n_labels,
                        const ps::PackPair* props, std::uint32_t n_props,
                        ps::PackValue* out) noexcept;
ps::PackError make_relationship(ps::PackArena& a, std::int64_t id,
                                std::int64_t start_id, std::int64_t end_id,
                                std::string_view type,
                                const ps::PackPair* props, std::uint32_t n_props,
                                ps::PackValue* out) noexcept;
ps::PackError make_unbound_relationship(ps::PackArena& a, std::int64_t id,
                                        std::string_view type,
                                        const ps::PackPair* props,
                                        std::uint32_t n_props,
                                        ps::PackValue* out) noexcept;
// `nodes` are Node values, `rels` UnboundRelationship values, `indices` the
// 2*hops sequence (rel index, 1-based and negative when walked backwards;
// then node index). The arrays are borrowed.
ps::PackError make_path(ps::PackArena& a, const ps::PackValue* nodes,
                        std::uint32_t n_nodes, const ps::PackValue* rels,
                        std::uint32_t n_rels, const ps::PackValue* indices,
                        std::uint32_t n_indices, ps::PackValue* out) noexcept;

ps::PackError make_date(ps::PackArena& a, std::int64_t epoch_days,
                        ps::PackValue* out) noexcept;
ps::PackError make_local_time(ps::PackArena& a, std::int64_t nanos_of_day,
                              ps::PackValue* out) noexcept;
ps::PackError make_time(ps::PackArena& a, std::int64_t nanos_of_day,
                        std::int64_t offset_seconds, ps::PackValue* out) noexcept;
ps::PackError make_local_date_time(ps::PackArena& a, std::int64_t seconds,
                                   std::int64_t nanos, ps::PackValue* out) noexcept;
ps::PackError make_date_time(ps::PackArena& a, std::int64_t utc_seconds,
                             std::int64_t nanos, std::int64_t offset_seconds,
                             ps::PackValue* out) noexcept;
ps::PackError make_date_time_zone_id(ps::PackArena& a, std::int64_t utc_seconds,
                                     std::int64_t nanos, std::string_view zone_id,
                                     ps::PackValue* out) noexcept;
ps::PackError make_duration(ps::PackArena& a, std::int64_t months,
                            std::int64_t days, std::int64_t seconds,
                            std::int64_t nanos, ps::PackValue* out) noexcept;

// Epoch microseconds -> LocalDateTime {seconds, nanos}, flooring toward -inf
// so a pre-1970 instant keeps nanos in [0, 1e9).
ps::PackError make_local_date_time_from_micros(ps::PackArena& a,
                                               std::int64_t epoch_micros,
                                               ps::PackValue* out) noexcept;

// --- typed views over a decoded value (any dialect) ------------------------
struct NodeView {
    std::int64_t        id = 0;
    const ps::PackValue* labels = nullptr;   // List of String
    const ps::PackValue* props  = nullptr;   // Dict
    std::string_view    element_id{};
    bool                has_element_id = false;
};

struct RelView {
    std::int64_t        id = 0;
    std::int64_t        start_id = 0;        // bound only
    std::int64_t        end_id = 0;          // bound only
    std::string_view    type{};
    const ps::PackValue* props = nullptr;
    std::string_view    element_id{};
    std::string_view    start_element_id{};
    std::string_view    end_element_id{};
    bool                has_element_ids = false;
    bool                bound = false;       // 'R' vs 'r'
};

struct PathView {
    const ps::PackValue* nodes   = nullptr;  // List of Node, len >= 1
    const ps::PackValue* rels    = nullptr;  // List of UnboundRelationship
    const ps::PackValue* indices = nullptr;  // List of Int, even length
    std::uint32_t        hops    = 0;
};

// Field order is the canonical (Bolt 5) one for every signature; `zone` only
// for the zone-id forms.
struct TemporalView {
    std::uint8_t     signature = 0;
    std::int64_t     f[4] = {0, 0, 0, 0};
    std::uint8_t     n_int = 0;
    std::string_view zone{};
};

ps::PackError as_node(const ps::PackValue& v, NodeView* out) noexcept;
ps::PackError as_relationship(const ps::PackValue& v, RelView* out) noexcept;  // 'R' or 'r'
ps::PackError as_path(const ps::PackValue& v, PathView* out) noexcept;
ps::PackError as_temporal(const ps::PackValue& v, TemporalView* out) noexcept;

bool is_temporal_signature(std::uint8_t sig) noexcept;

// Write `v` in the dialect of Bolt `bolt_major` (4 or 5). Plain values go
// through unchanged; structures are validated and shaped per the table above.
ps::PackError write_value(ps::PackWriter& w, const ps::PackValue& v,
                          std::uint8_t bolt_major) noexcept;

}  // namespace values
}  // namespace neo4j
}  // namespace proto
}  // namespace bolt::api
