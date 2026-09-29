// src/proto/flight_sql_arrow.cpp — see boltapi/proto/flight_sql_arrow.h.

#include "boltapi/proto/flight_sql_arrow.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include <array>
#include <cassert>
#include <cstring>
#include <vector>

namespace bolt::api::proto::flightsql::arrow {

namespace {

static_assert(sizeof(std::int64_t) == 8 && sizeof(std::int32_t) == 4);

// ---------------------------------------------------------------------------
// Back-to-front flatbuffer builder. Positions are measured from the END of
// the buffer, so growing the buffer never moves an already-written offset.
// ---------------------------------------------------------------------------
class Fb {
public:
    Fb() : buf_(1024), head_(buf_.size()) {}

    std::uint32_t size() const noexcept {
        return static_cast<std::uint32_t>(buf_.size() - head_);
    }
    std::string_view data() const noexcept {
        return {reinterpret_cast<const char*>(buf_.data() + head_), size()};
    }

    void prep(std::size_t align, std::size_t extra) {
        assert(align == 1 || align == 2 || align == 4 || align == 8);
        if (align > minalign_) minalign_ = align;
        const std::size_t pad = (align - ((size() + extra) % align)) % align;
        for (std::size_t i = 0; i < pad; ++i) push<std::uint8_t>(0);
        assert((size() + extra) % align == 0);
    }

    template <class T>
    void push(T v) {
        ensure(sizeof(T));
        head_ -= sizeof(T);
        std::memcpy(buf_.data() + head_, &v, sizeof(T));   // little-endian hosts
    }

    void push_bytes(std::string_view b) {
        ensure(b.size());
        head_ -= b.size();
        if (!b.empty()) std::memcpy(buf_.data() + head_, b.data(), b.size());
    }

    std::uint32_t uoffset_to(std::uint32_t target) {
        prep(4, 0);
        assert(target <= size());
        push<std::uint32_t>(size() + 4u - target);
        return size();
    }

    std::uint32_t string(std::string_view s) {
        prep(4, s.size() + 1);
        push<std::uint8_t>(0);
        push_bytes(s);
        push<std::uint32_t>(static_cast<std::uint32_t>(s.size()));
        return size();
    }

    std::uint32_t offset_vector(const std::uint32_t* t, std::size_t n) {
        prep(4, 4 * n);
        for (std::size_t i = n; i > 0; --i) {
            assert(t[i - 1] <= size());
            push<std::uint32_t>(size() + 4u - t[i - 1]);
        }
        push<std::uint32_t>(static_cast<std::uint32_t>(n));
        return size();
    }

    std::uint32_t int32_vector(const std::int32_t* v, std::size_t n) {
        prep(4, 4 * n);
        for (std::size_t i = n; i > 0; --i) push<std::int32_t>(v[i - 1]);
        push<std::uint32_t>(static_cast<std::uint32_t>(n));
        return size();
    }

    // Vector of 16-byte structs {int64 a; int64 b} (FieldNode, Buffer).
    std::uint32_t pair_vector(const std::array<std::int64_t, 2>* v, std::size_t n) {
        prep(4, 16 * n);
        prep(8, 16 * n);
        for (std::size_t i = n; i > 0; --i) {
            push<std::int64_t>(v[i - 1][1]);
            push<std::int64_t>(v[i - 1][0]);
        }
        push<std::uint32_t>(static_cast<std::uint32_t>(n));
        return size();
    }

    void start_table() {
        assert(!in_table_);
        in_table_ = true;
        n_slots_ = 0;
        table_start_ = size();
    }

    template <class T>
    void field(std::uint16_t idx, T v) {
        prep(sizeof(T), 0);
        push<T>(v);
        slot(idx, size());
    }

    void field_offset(std::uint16_t idx, std::uint32_t target) {
        slot(idx, uoffset_to(target));
    }

    std::uint32_t end_table() {
        assert(in_table_);
        prep(4, 0);
        push<std::int32_t>(0);
        const std::uint32_t obj = size();
        const auto table_size = static_cast<std::uint16_t>(obj - table_start_);
        for (std::size_t i = n_slots_; i > 0; --i) {
            const std::uint32_t at = slots_[i - 1];
            push<std::uint16_t>(at == 0 ? std::uint16_t{0}
                                        : static_cast<std::uint16_t>(obj - at));
        }
        push<std::uint16_t>(table_size);
        push<std::uint16_t>(static_cast<std::uint16_t>(4 + 2 * n_slots_));
        const std::uint32_t vt = size();
        const std::int32_t soff = static_cast<std::int32_t>(vt - obj);
        std::memcpy(buf_.data() + (buf_.size() - obj), &soff, 4);
        in_table_ = false;
        return obj;
    }

    void finish(std::uint32_t root) {
        prep(minalign_, 4);
        push<std::uint32_t>(size() + 4u - root);
        assert(size() % 8 == 0);
    }

private:
    void ensure(std::size_t n) {
        if (head_ >= n) return;
        const std::size_t used = size();
        std::vector<std::uint8_t> bigger(buf_.size() * 2 + n);
        std::memcpy(bigger.data() + (bigger.size() - used), buf_.data() + head_, used);
        head_ = bigger.size() - used;
        buf_.swap(bigger);
    }

    void slot(std::uint16_t idx, std::uint32_t at) {
        assert(in_table_ && idx < kMaxSlots && at > table_start_);
        while (n_slots_ <= idx) slots_[n_slots_++] = 0;
        slots_[idx] = at;
    }

    static constexpr std::size_t kMaxSlots = 8;
    std::vector<std::uint8_t>    buf_;
    std::size_t                  head_;
    std::size_t                  minalign_ = 8;
    bool                         in_table_ = false;
    std::uint32_t                table_start_ = 0;
    std::size_t                  n_slots_ = 0;
    std::uint32_t                slots_[kMaxSlots] = {};
};

// ---------------------------------------------------------------------------
// Schema description (Schema.fbs).
// ---------------------------------------------------------------------------
enum class T : std::uint8_t {
    kUtf8, kBinary, kInt32, kUInt32, kUInt8, kInt64, kBool,
    kList, kStruct, kMap, kDenseUnion,
};

struct F {
    const char*   name;
    T             t;
    bool          nullable;
    const F*      kids;
    std::uint16_t nkids;
};

constexpr std::uint8_t kTypeInt = 2;
constexpr std::uint8_t kTypeBinary = 4;
constexpr std::uint8_t kTypeUtf8 = 5;
constexpr std::uint8_t kTypeBool = 6;
constexpr std::uint8_t kTypeList = 12;
constexpr std::uint8_t kTypeStruct = 13;
constexpr std::uint8_t kTypeUnion = 14;
constexpr std::uint8_t kTypeMap = 17;
constexpr std::int16_t kMetadataV5 = 4;
constexpr std::uint8_t kHeaderSchema = 1;
constexpr std::uint8_t kHeaderRecordBatch = 3;
constexpr int kMaxDepth = 8;

std::uint32_t encode_type(Fb& fb, const F& f, std::uint8_t* type_id) {
    auto int_type = [&](std::int32_t bits, bool is_signed) {
        fb.start_table();
        fb.field<std::int32_t>(0, bits);
        fb.field<std::uint8_t>(1, is_signed ? 1 : 0);
        *type_id = kTypeInt;
        return fb.end_table();
    };
    auto empty = [&](std::uint8_t id) {
        fb.start_table();
        *type_id = id;
        return fb.end_table();
    };
    switch (f.t) {
        case T::kUtf8:   return empty(kTypeUtf8);
        case T::kBinary: return empty(kTypeBinary);
        case T::kBool:   return empty(kTypeBool);
        case T::kList:   return empty(kTypeList);
        case T::kStruct: return empty(kTypeStruct);
        case T::kInt32:  return int_type(32, true);
        case T::kUInt32: return int_type(32, false);
        case T::kUInt8:  return int_type(8, false);
        case T::kInt64:  return int_type(64, true);
        case T::kMap: {
            fb.start_table();
            fb.field<std::uint8_t>(0, 0);   // keysSorted = false
            *type_id = kTypeMap;
            return fb.end_table();
        }
        case T::kDenseUnion: {
            std::int32_t ids[16];
            assert(f.nkids <= 16);
            for (std::uint16_t i = 0; i < f.nkids; ++i) ids[i] = i;
            const std::uint32_t idv = fb.int32_vector(ids, f.nkids);
            fb.start_table();
            fb.field<std::int16_t>(0, 1);   // UnionMode.Dense
            fb.field_offset(1, idv);
            *type_id = kTypeUnion;
            return fb.end_table();
        }
    }
    assert(false && "unhandled type");
    return 0;
}

std::uint32_t encode_field(Fb& fb, const F& f, int depth) {
    assert(depth < kMaxDepth);
    assert(f.name != nullptr);
    std::uint32_t kids[16];
    assert(f.nkids <= 16);
    for (std::uint16_t i = 0; i < f.nkids; ++i) kids[i] = encode_field(fb, f.kids[i], depth + 1);
    const std::uint32_t kidv = fb.offset_vector(kids, f.nkids);
    std::uint8_t type_id = 0;
    const std::uint32_t type = encode_type(fb, f, &type_id);
    const std::uint32_t name = fb.string(f.name);
    fb.start_table();
    fb.field_offset(0, name);
    fb.field<std::uint8_t>(1, f.nullable ? 1 : 0);
    fb.field<std::uint8_t>(2, type_id);
    fb.field_offset(3, type);
    fb.field_offset(5, kidv);
    return fb.end_table();
}

std::uint32_t encode_message(Fb& fb, std::uint8_t header_type, std::uint32_t header,
                             std::int64_t body_len) {
    fb.start_table();
    fb.field<std::int64_t>(3, body_len);
    fb.field_offset(2, header);
    fb.field<std::int16_t>(0, kMetadataV5);
    fb.field<std::uint8_t>(1, header_type);
    return fb.end_table();
}

void put_encapsulated(std::string* out, const Fb& fb, std::string_view body) {
    assert(fb.size() % 8 == 0);
    const std::uint32_t cont = 0xFFFFFFFFu;
    const std::int32_t len = static_cast<std::int32_t>(fb.size());
    out->append(reinterpret_cast<const char*>(&cont), 4);
    out->append(reinterpret_cast<const char*>(&len), 4);
    out->append(fb.data().data(), fb.data().size());
    out->append(body.data(), body.size());
}

void write_schema(std::string* out, const F* fields, std::uint16_t n) {
    assert(n > 0 && n <= 16);
    Fb fb;
    std::uint32_t fo[16];
    for (std::uint16_t i = 0; i < n; ++i) fo[i] = encode_field(fb, fields[i], 0);
    const std::uint32_t fv = fb.offset_vector(fo, n);
    fb.start_table();
    fb.field<std::int16_t>(0, 0);   // Endianness.Little
    fb.field_offset(1, fv);
    const std::uint32_t schema = fb.end_table();
    fb.finish(encode_message(fb, kHeaderSchema, schema, 0));
    put_encapsulated(out, fb, {});
}

// ---------------------------------------------------------------------------
// RecordBatch assembly: nodes and buffers in depth-first pre-order.
// ---------------------------------------------------------------------------
struct Batch {
    std::int64_t                             length = 0;
    std::vector<std::array<std::int64_t, 2>> nodes;
    std::vector<std::string>                 bufs;

    void node(std::int64_t len, std::int64_t nulls) { nodes.push_back({len, nulls}); }
    void buf(std::string b) { bufs.push_back(std::move(b)); }
};

std::string validity(std::size_t n, const char* valid, std::int64_t* nulls) {
    *nulls = 0;
    for (std::size_t i = 0; i < n; ++i) *nulls += valid[i] ? 0 : 1;
    if (*nulls == 0) return {};
    std::string bits((n + 7) / 8, '\0');
    for (std::size_t i = 0; i < n; ++i) {
        if (valid[i]) bits[i / 8] = static_cast<char>(bits[i / 8] | (1 << (i % 8)));
    }
    return bits;
}

template <class Get>
void col_utf8(Batch& b, std::size_t n, Get get) {
    std::vector<char> valid(n, 1);
    std::string offs(4 * (n + 1), '\0');
    std::string data;
    std::int32_t at = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const Str s = get(i);
        valid[i] = s.valid ? 1 : 0;
        if (s.valid) data.append(s.v.data(), s.v.size());
        at += static_cast<std::int32_t>(s.valid ? s.v.size() : 0);
        std::memcpy(&offs[4 * (i + 1)], &at, 4);
    }
    std::int64_t nulls = 0;
    std::string vb = validity(n, valid.data(), &nulls);
    b.node(static_cast<std::int64_t>(n), nulls);
    b.buf(std::move(vb));
    b.buf(std::move(offs));
    b.buf(std::move(data));
}

template <class V, class Get>
void col_fixed(Batch& b, std::size_t n, Get get) {
    std::string data(sizeof(V) * n, '\0');
    for (std::size_t i = 0; i < n; ++i) {
        const V v = get(i);
        std::memcpy(&data[sizeof(V) * i], &v, sizeof(V));
    }
    b.node(static_cast<std::int64_t>(n), 0);
    b.buf({});
    b.buf(std::move(data));
}

void col_bool(Batch& b, const std::vector<bool>& v) {
    std::string bits((v.size() + 7) / 8, '\0');
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (v[i]) bits[i / 8] = static_cast<char>(bits[i / 8] | (1 << (i % 8)));
    }
    b.node(static_cast<std::int64_t>(v.size()), 0);
    b.buf({});
    b.buf(std::move(bits));
}

std::string zero_offsets() { return std::string(4, '\0'); }

void write_batch(std::string* out, const Batch& b) {
    assert(b.length >= 0);
    std::string body;
    std::vector<std::array<std::int64_t, 2>> bufs;
    bufs.reserve(b.bufs.size());
    for (const std::string& x : b.bufs) {
        bufs.push_back({static_cast<std::int64_t>(body.size()),
                        static_cast<std::int64_t>(x.size())});
        body += x;
        body.append((8 - body.size() % 8) % 8, '\0');
    }
    Fb fb;
    const std::uint32_t bv = fb.pair_vector(bufs.data(), bufs.size());
    const std::uint32_t nv = fb.pair_vector(b.nodes.data(), b.nodes.size());
    fb.start_table();
    fb.field<std::int64_t>(0, b.length);
    fb.field_offset(1, nv);
    fb.field_offset(2, bv);
    const std::uint32_t rb = fb.end_table();
    fb.finish(encode_message(fb, kHeaderRecordBatch, rb,
                             static_cast<std::int64_t>(body.size())));
    put_encapsulated(out, fb, body);
}

void write_eos(std::string* out) {
    const std::uint32_t eos[2] = {0xFFFFFFFFu, 0};
    out->append(reinterpret_cast<const char*>(eos), 8);
}

template <std::size_t N>
void write_stream(std::string* out, const F (&fields)[N], const Batch& b) {
    assert(out != nullptr);
    write_schema(out, fields, static_cast<std::uint16_t>(N));
    write_batch(out, b);
    write_eos(out);
}

// Every column of an empty result: one node and the type's buffers.
void empty_column(Batch& b, const F& f, int depth) {
    assert(depth < kMaxDepth);
    b.node(0, 0);
    switch (f.t) {
        case T::kUtf8: case T::kBinary:
            b.buf({}); b.buf(zero_offsets()); b.buf({});
            return;
        case T::kList: case T::kMap:
            b.buf({}); b.buf(zero_offsets());
            break;
        case T::kStruct:
            b.buf({});
            break;
        case T::kDenseUnion:
            b.buf({}); b.buf({});
            break;
        default:
            b.buf({}); b.buf({});
            return;
    }
    for (std::uint16_t i = 0; i < f.nkids; ++i) empty_column(b, f.kids[i], depth + 1);
}

}  // namespace

void write_catalogs(std::string* out, const std::string_view* catalogs, std::size_t n) {
    static const F kF[] = {{"catalog_name", T::kUtf8, false, nullptr, 0}};
    Batch b;
    b.length = static_cast<std::int64_t>(n);
    col_utf8(b, n, [&](std::size_t i) { return Str{catalogs[i], true}; });
    write_stream(out, kF, b);
}

void write_db_schemas(std::string* out, const SchemaRow* rows, std::size_t n) {
    static const F kF[] = {{"catalog_name", T::kUtf8, true, nullptr, 0},
                           {"db_schema_name", T::kUtf8, false, nullptr, 0}};
    Batch b;
    b.length = static_cast<std::int64_t>(n);
    col_utf8(b, n, [&](std::size_t i) { return rows[i].catalog; });
    col_utf8(b, n, [&](std::size_t i) { return Str{rows[i].db_schema, true}; });
    write_stream(out, kF, b);
}

void write_tables(std::string* out, const TableRow* rows, std::size_t n,
                  bool include_schema) {
    static const F kF[] = {{"catalog_name", T::kUtf8, true, nullptr, 0},
                           {"db_schema_name", T::kUtf8, true, nullptr, 0},
                           {"table_name", T::kUtf8, false, nullptr, 0},
                           {"table_type", T::kUtf8, false, nullptr, 0},
                           {"table_schema", T::kBinary, false, nullptr, 0}};
    Batch b;
    b.length = static_cast<std::int64_t>(n);
    col_utf8(b, n, [&](std::size_t i) { return rows[i].catalog; });
    col_utf8(b, n, [&](std::size_t i) { return rows[i].db_schema; });
    col_utf8(b, n, [&](std::size_t i) { return Str{rows[i].table_name, true}; });
    col_utf8(b, n, [&](std::size_t i) { return Str{rows[i].table_type, true}; });
    if (!include_schema) {
        static const F kF4[] = {kF[0], kF[1], kF[2], kF[3]};
        write_stream(out, kF4, b);
        return;
    }
    col_utf8(b, n, [&](std::size_t i) { return Str{rows[i].table_schema, true}; });
    write_stream(out, kF, b);
}

void write_table_types(std::string* out, const std::string_view* types, std::size_t n) {
    static const F kF[] = {{"table_type", T::kUtf8, false, nullptr, 0}};
    Batch b;
    b.length = static_cast<std::int64_t>(n);
    col_utf8(b, n, [&](std::size_t i) { return Str{types[i], true}; });
    write_stream(out, kF, b);
}

void write_primary_keys(std::string* out, const PrimaryKeyRow* rows, std::size_t n) {
    static const F kF[] = {{"catalog_name", T::kUtf8, true, nullptr, 0},
                           {"db_schema_name", T::kUtf8, true, nullptr, 0},
                           {"table_name", T::kUtf8, false, nullptr, 0},
                           {"column_name", T::kUtf8, false, nullptr, 0},
                           {"key_name", T::kUtf8, true, nullptr, 0},
                           {"key_sequence", T::kInt32, false, nullptr, 0}};
    Batch b;
    b.length = static_cast<std::int64_t>(n);
    col_utf8(b, n, [&](std::size_t i) { return rows[i].catalog; });
    col_utf8(b, n, [&](std::size_t i) { return rows[i].db_schema; });
    col_utf8(b, n, [&](std::size_t i) { return Str{rows[i].table_name, true}; });
    col_utf8(b, n, [&](std::size_t i) { return Str{rows[i].column_name, true}; });
    col_utf8(b, n, [&](std::size_t i) { return rows[i].key_name; });
    col_fixed<std::int32_t>(b, n, [&](std::size_t i) { return rows[i].key_sequence; });
    write_stream(out, kF, b);
}

void write_foreign_keys_empty(std::string* out) {
    static const F kF[] = {{"pk_catalog_name", T::kUtf8, true, nullptr, 0},
                           {"pk_db_schema_name", T::kUtf8, true, nullptr, 0},
                           {"pk_table_name", T::kUtf8, false, nullptr, 0},
                           {"pk_column_name", T::kUtf8, false, nullptr, 0},
                           {"fk_catalog_name", T::kUtf8, true, nullptr, 0},
                           {"fk_db_schema_name", T::kUtf8, true, nullptr, 0},
                           {"fk_table_name", T::kUtf8, false, nullptr, 0},
                           {"fk_column_name", T::kUtf8, false, nullptr, 0},
                           {"key_sequence", T::kInt32, false, nullptr, 0},
                           {"fk_key_name", T::kUtf8, true, nullptr, 0},
                           {"pk_key_name", T::kUtf8, true, nullptr, 0},
                           {"update_rule", T::kUInt8, false, nullptr, 0},
                           {"delete_rule", T::kUInt8, false, nullptr, 0}};
    Batch b;
    for (const F& f : kF) empty_column(b, f, 0);
    write_stream(out, kF, b);
}

void write_sql_info(std::string* out, const SqlInfoRow* rows, std::size_t n) {
    static const F kStrItem[] = {{"string_data", T::kUtf8, true, nullptr, 0}};
    static const F kIntItem[] = {{"$data$", T::kInt32, true, nullptr, 0}};
    static const F kEntries[] = {{"key", T::kInt32, false, nullptr, 0},
                                 {"value", T::kList, true, kIntItem, 1}};
    static const F kMapEntries[] = {{"entries", T::kStruct, false, kEntries, 2}};
    static const F kUnion[] = {
        {"string_value", T::kUtf8, true, nullptr, 0},
        {"bool_value", T::kBool, true, nullptr, 0},
        {"bigint_value", T::kInt64, true, nullptr, 0},
        {"int32_bitmask", T::kInt32, true, nullptr, 0},
        {"string_list", T::kList, true, kStrItem, 1},
        {"int32_to_int32_list_map", T::kMap, true, kMapEntries, 1}};
    static const F kF[] = {{"info_name", T::kUInt32, false, nullptr, 0},
                           {"value", T::kDenseUnion, false, kUnion, 6}};
    Batch b;
    b.length = static_cast<std::int64_t>(n);
    col_fixed<std::uint32_t>(b, n, [&](std::size_t i) { return rows[i].id; });

    std::string types(n, '\0');
    std::string offs(4 * n, '\0');
    std::vector<std::string_view> strs;
    std::vector<bool> bools;
    std::vector<std::int64_t> bigs;
    std::vector<std::int32_t> masks;
    for (std::size_t i = 0; i < n; ++i) {
        std::int32_t off = 0;
        switch (rows[i].kind) {
            case InfoKind::kString:       off = static_cast<std::int32_t>(strs.size());  strs.push_back(rows[i].s);   break;
            case InfoKind::kBool:         off = static_cast<std::int32_t>(bools.size()); bools.push_back(rows[i].b);  break;
            case InfoKind::kBigint:       off = static_cast<std::int32_t>(bigs.size());  bigs.push_back(rows[i].i64); break;
            case InfoKind::kInt32Bitmask: off = static_cast<std::int32_t>(masks.size()); masks.push_back(rows[i].i32); break;
        }
        types[i] = static_cast<char>(rows[i].kind);
        std::memcpy(&offs[4 * i], &off, 4);
    }
    b.node(static_cast<std::int64_t>(n), 0);
    b.buf(std::move(types));
    b.buf(std::move(offs));
    col_utf8(b, strs.size(), [&](std::size_t i) { return Str{strs[i], true}; });
    col_bool(b, bools);
    col_fixed<std::int64_t>(b, bigs.size(), [&](std::size_t i) { return bigs[i]; });
    col_fixed<std::int32_t>(b, masks.size(), [&](std::size_t i) { return masks[i]; });
    empty_column(b, kUnion[4], 1);
    empty_column(b, kUnion[5], 1);
    write_stream(out, kF, b);
}

bool like_match(std::string_view pat, std::string_view s) noexcept {
    std::size_t p = 0, i = 0;
    std::size_t star = std::string_view::npos, mark = 0;
    const std::size_t budget = (pat.size() + 1) * (s.size() + 1) + pat.size() + 1;
    for (std::size_t step = 0; step < budget; ++step) {
        if (i < s.size()) {
            if (p < pat.size() && (pat[p] == '_' || pat[p] == s[i])) {
                ++p; ++i;
            } else if (p < pat.size() && pat[p] == '%') {
                star = p++;
                mark = i;
            } else if (star != std::string_view::npos) {
                p = star + 1;
                i = ++mark;
            } else {
                return false;
            }
            continue;
        }
        while (p < pat.size() && pat[p] == '%') ++p;
        return p == pat.size();
    }
    assert(false && "like_match exceeded its step budget");
    return false;
}

}  // namespace bolt::api::proto::flightsql::arrow

#endif  // BOLTAPI_WITH_FLIGHT_SQL
