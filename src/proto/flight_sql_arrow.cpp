// src/proto/flight_sql_arrow.cpp — see boltapi/proto/flight_sql_arrow.h.

#include "boltapi/proto/flight_sql_arrow.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include <cassert>
#include <cstring>
#include <string>
#include <vector>

namespace bolt::api::proto::flightsql::arrow {

namespace {

// ---------------------------------------------------------------------------
// Flatbuffer writer, front to back: a table is written whole, then the
// objects it references follow it and its uoffset slots are patched, so
// every uoffset points forward. The vtable sits right before its table
// (positive soffset). Tables start 8-aligned, so every scalar is naturally
// aligned relative to the buffer start, as the Arrow verifier requires.
// ---------------------------------------------------------------------------
class Fb {
public:
    std::string b;

    std::size_t pos() const noexcept { return b.size(); }
    void pad_to(std::size_t a) {
        assert(a == 1 || a == 2 || a == 4 || a == 8);
        while (b.size() % a != 0) b.push_back('\0');
    }
    template <class T>
    std::size_t push(T v) {
        const std::size_t p = b.size();
        b.append(reinterpret_cast<const char*>(&v), sizeof(T));
        return p;
    }
    template <class T>
    void put(std::size_t at, T v) noexcept {
        assert(at + sizeof(T) <= b.size());
        std::memcpy(&b[at], &v, sizeof(T));
    }
    void patch(std::size_t slot, std::size_t target) noexcept {
        assert(target > slot);
        put<std::uint32_t>(slot, static_cast<std::uint32_t>(target - slot));
    }
    std::size_t string(std::string_view s) {
        pad_to(4);
        const std::size_t p = push<std::uint32_t>(static_cast<std::uint32_t>(s.size()));
        b.append(s.data(), s.size());
        b.push_back('\0');
        return p;
    }
    // A vector of `n` uoffsets; slot i is at return + 4 + 4 * i.
    std::size_t ref_vector(std::size_t n) {
        pad_to(4);
        const std::size_t p = push<std::uint32_t>(static_cast<std::uint32_t>(n));
        for (std::size_t i = 0; i < n; ++i) push<std::uint32_t>(0);
        return p;
    }
    // Length prefix placed so the 8-byte elements that follow are aligned.
    std::size_t struct_vector_head(std::size_t n) {
        while ((b.size() + 4) % 8 != 0) b.push_back('\0');
        return push<std::uint32_t>(static_cast<std::uint32_t>(n));
    }
};

class Table {
public:
    Table(Fb& fb, std::uint16_t slots) : fb_(fb), n_(slots) {
        assert(slots <= 16);
        fb_.pad_to(2);
        vt_ = fb_.pos();
        for (std::uint32_t i = 0; i < 2u + slots; ++i) fb_.push<std::uint16_t>(0);
        fb_.pad_to(8);
        tbl_ = fb_.push<std::int32_t>(static_cast<std::int32_t>(fb_.pos() - vt_));
        assert(tbl_ > vt_);
    }
    template <class T>
    void scalar(std::uint16_t slot, T v) {
        fb_.pad_to(sizeof(T));
        set(slot, fb_.push(v));
    }
    std::size_t ref(std::uint16_t slot) {
        fb_.pad_to(4);
        const std::size_t p = fb_.push<std::uint32_t>(0);
        set(slot, p);
        return p;
    }
    std::size_t finish() {
        const std::size_t size = fb_.pos() - tbl_;
        assert(size <= 0xFFFFu);
        fb_.put<std::uint16_t>(vt_, static_cast<std::uint16_t>((2u + n_) * 2u));
        fb_.put<std::uint16_t>(vt_ + 2, static_cast<std::uint16_t>(size));
        return tbl_;
    }

private:
    void set(std::uint16_t slot, std::size_t at) noexcept {
        assert(slot < n_ && at > tbl_);
        fb_.put<std::uint16_t>(vt_ + 4u + 2u * slot, static_cast<std::uint16_t>(at - tbl_));
    }
    Fb&           fb_;
    std::uint16_t n_;
    std::size_t   vt_ = 0;
    std::size_t   tbl_ = 0;
};

// ---------------------------------------------------------------------------
// Schemas (Schema.fbs). Type union ids: Int 2, FloatingPoint 3, Binary 4,
// Utf8 5, Bool 6, List 12, Struct_ 13, Union 14, Map 17.
// ---------------------------------------------------------------------------
enum class Kind : std::uint8_t {
    kUtf8, kBinary, kBool, kInt, kList, kStruct, kMap, kDenseUnion, kDouble
};

struct FieldDesc {
    std::string_view name;
    bool             nullable;
    Kind             kind;
    std::int32_t     bit_width;
    bool             is_signed;
    const FieldDesc* children;
    std::uint32_t    n_children;
};

std::uint8_t type_id(Kind k) noexcept {
    switch (k) {
        case Kind::kUtf8:       return 5;
        case Kind::kBinary:     return 4;
        case Kind::kBool:       return 6;
        case Kind::kInt:        return 2;
        case Kind::kList:       return 12;
        case Kind::kStruct:     return 13;
        case Kind::kMap:        return 17;
        case Kind::kDenseUnion: return 14;
        case Kind::kDouble:     return 3;
    }
    return 0;
}

std::size_t write_fields(Fb& fb, const FieldDesc* f, std::uint32_t n);

std::size_t write_type(Fb& fb, const FieldDesc& f) {
    if (f.kind == Kind::kInt) {
        Table t(fb, 2);
        t.scalar<std::int32_t>(0, f.bit_width);
        t.scalar<std::uint8_t>(1, f.is_signed ? 1 : 0);
        return t.finish();
    }
    if (f.kind == Kind::kDouble) {
        Table t(fb, 1);
        t.scalar<std::int16_t>(0, 2);   // Precision.DOUBLE
        return t.finish();
    }
    if (f.kind == Kind::kMap) {
        Table t(fb, 1);
        t.scalar<std::uint8_t>(0, 0);   // keysSorted
        return t.finish();
    }
    if (f.kind == Kind::kDenseUnion) {
        Table t(fb, 2);
        t.scalar<std::int16_t>(0, 1);   // UnionMode.Dense
        const std::size_t ids = t.ref(1);
        const std::size_t at = t.finish();
        fb.pad_to(4);
        fb.patch(ids, fb.push<std::uint32_t>(f.n_children));
        for (std::uint32_t i = 0; i < f.n_children; ++i) fb.push<std::int32_t>(static_cast<std::int32_t>(i));
        return at;
    }
    Table t(fb, 0);
    return t.finish();
}

std::size_t write_field(Fb& fb, const FieldDesc& f) {
    assert(f.n_children == 0 || f.children != nullptr);
    Table t(fb, 6);
    const std::size_t name = t.ref(0);
    t.scalar<std::uint8_t>(1, f.nullable ? 1 : 0);
    t.scalar<std::uint8_t>(2, type_id(f.kind));
    const std::size_t type = t.ref(3);
    const std::size_t children = t.ref(5);
    const std::size_t at = t.finish();
    fb.patch(name, fb.string(f.name));
    fb.patch(type, write_type(fb, f));
    fb.patch(children, write_fields(fb, f.children, f.n_children));
    return at;
}

std::size_t write_fields(Fb& fb, const FieldDesc* f, std::uint32_t n) {
    const std::size_t v = fb.ref_vector(n);
    for (std::uint32_t i = 0; i < n; ++i) fb.patch(v + 4u + 4u * i, write_field(fb, f[i]));
    return v;
}

// ---------------------------------------------------------------------------
// Record batch body: buffers 8-aligned, field nodes depth-first pre-order.
// ---------------------------------------------------------------------------
struct Body {
    std::string                                       bytes;
    std::vector<std::pair<std::int64_t, std::int64_t>> nodes;     // length, null_count
    std::vector<std::pair<std::int64_t, std::int64_t>> buffers;   // offset, length

    void node(std::size_t len, std::size_t nulls) {
        nodes.emplace_back(static_cast<std::int64_t>(len), static_cast<std::int64_t>(nulls));
    }
    void buf(const void* p, std::size_t n) {
        const std::size_t at = bytes.size();
        if (n != 0) bytes.append(static_cast<const char*>(p), n);
        buffers.emplace_back(static_cast<std::int64_t>(at), static_cast<std::int64_t>(n));
        while (bytes.size() % 8 != 0) bytes.push_back('\0');
    }
    void none() { buf(nullptr, 0); }

    void strings(const Str* cells, std::size_t n) {
        std::vector<std::uint8_t> valid((n + 7) / 8, 0);
        std::vector<std::int32_t> offs(n + 1, 0);
        std::string data;
        std::size_t nulls = 0;
        for (std::size_t i = 0; i < n; ++i) {
            if (cells[i].valid) {
                valid[i / 8] = static_cast<std::uint8_t>(valid[i / 8] | (1u << (i % 8)));
                data.append(cells[i].v.data(), cells[i].v.size());
            } else {
                ++nulls;
            }
            assert(data.size() <= 0x7FFFFFFFu);
            offs[i + 1] = static_cast<std::int32_t>(data.size());
        }
        node(n, nulls);
        if (nulls != 0) buf(valid.data(), valid.size());
        else none();
        buf(offs.data(), offs.size() * sizeof(std::int32_t));
        buf(data.data(), data.size());
    }
    template <class T>
    void values(const T* v, std::size_t n) {
        node(n, 0);
        none();
        buf(v, n * sizeof(T));
    }
    void bools(const std::uint8_t* v, std::size_t n) {
        std::vector<std::uint8_t> bits((n + 7) / 8, 0);
        for (std::size_t i = 0; i < n; ++i) {
            if (v[i] != 0) bits[i / 8] = static_cast<std::uint8_t>(bits[i / 8] | (1u << (i % 8)));
        }
        node(n, 0);
        none();
        buf(bits.data(), bits.size());
    }
    // A nullable fixed-width column; `valid[i] == 0` is NULL.
    template <class T>
    void opt_values(const T* v, const std::uint8_t* valid, std::size_t n) {
        std::vector<std::uint8_t> bits((n + 7) / 8, 0);
        std::size_t nulls = 0;
        for (std::size_t i = 0; i < n; ++i) {
            if (valid[i] != 0) bits[i / 8] = static_cast<std::uint8_t>(bits[i / 8] | (1u << (i % 8)));
            else ++nulls;
        }
        node(n, nulls);
        if (nulls != 0) buf(bits.data(), bits.size());
        else none();
        buf(v, n * sizeof(T));
    }
    void opt_bools(const std::uint8_t* v, const std::uint8_t* valid, std::size_t n) {
        std::vector<std::uint8_t> bits((n + 7) / 8, 0);
        std::vector<std::uint8_t> vbits((n + 7) / 8, 0);
        std::size_t nulls = 0;
        for (std::size_t i = 0; i < n; ++i) {
            if (v[i] != 0) bits[i / 8] = static_cast<std::uint8_t>(bits[i / 8] | (1u << (i % 8)));
            if (valid[i] != 0) vbits[i / 8] = static_cast<std::uint8_t>(vbits[i / 8] | (1u << (i % 8)));
            else ++nulls;
        }
        node(n, nulls);
        if (nulls != 0) buf(vbits.data(), vbits.size());
        else none();
        buf(bits.data(), bits.size());
    }
    // `n` NULL list<utf8> entries: all-zero validity and offsets, empty child.
    void null_lists(std::size_t n) {
        const std::vector<std::uint8_t> bits((n + 7) / 8, 0);
        const std::vector<std::int32_t> offs(n + 1, 0);
        node(n, n);
        if (n != 0) buf(bits.data(), bits.size());
        else none();
        buf(offs.data(), offs.size() * sizeof(std::int32_t));
        strings(nullptr, 0);
    }
    // Zero-length list<T>: validity, offsets [0].
    void empty_list() {
        const std::int32_t zero = 0;
        node(0, 0);
        none();
        buf(&zero, sizeof(zero));
    }
};

// Message.fbs: Message{version=0, header_type=1, header=2, bodyLength=3}.
template <class Header>
void write_message(std::string* out, std::uint8_t header_type, std::int64_t body_len,
                   Header&& header) {
    assert(out != nullptr && body_len >= 0);
    Fb fb;
    const std::size_t root = fb.push<std::uint32_t>(0);
    Table m(fb, 4);
    m.scalar<std::int16_t>(0, 4);   // MetadataVersion.V5
    m.scalar<std::uint8_t>(1, header_type);
    const std::size_t hdr = m.ref(2);
    m.scalar<std::int64_t>(3, body_len);
    fb.patch(root, m.finish());
    fb.patch(hdr, header(fb));
    fb.pad_to(8);
    const std::uint32_t cont = 0xFFFFFFFFu;
    const auto len = static_cast<std::uint32_t>(fb.b.size());
    out->append(reinterpret_cast<const char*>(&cont), 4);
    out->append(reinterpret_cast<const char*>(&len), 4);
    out->append(fb.b);
}

void write_schema_message(std::string* out, const FieldDesc* fields, std::uint32_t n_fields);

void write_stream(std::string* out, const FieldDesc* fields, std::uint32_t n_fields,
                  std::size_t rows, const Body& body) {
    assert(out != nullptr && body.bytes.size() % 8 == 0);
    write_schema_message(out, fields, n_fields);
    const auto body_len = static_cast<std::int64_t>(body.bytes.size());
    write_message(out, 3, body_len, [&](Fb& fb) {
        Table t(fb, 3);
        t.scalar<std::int64_t>(0, static_cast<std::int64_t>(rows));
        const std::size_t nodes = t.ref(1);
        const std::size_t bufs = t.ref(2);
        const std::size_t at = t.finish();
        fb.patch(nodes, fb.struct_vector_head(body.nodes.size()));
        for (const auto& nd : body.nodes) {
            fb.push<std::int64_t>(nd.first);
            fb.push<std::int64_t>(nd.second);
        }
        fb.patch(bufs, fb.struct_vector_head(body.buffers.size()));
        for (const auto& bf : body.buffers) {
            fb.push<std::int64_t>(bf.first);
            fb.push<std::int64_t>(bf.second);
        }
        return at;
    });
    out->append(body.bytes);
    const std::uint32_t eos[2] = {0xFFFFFFFFu, 0u};
    out->append(reinterpret_cast<const char*>(eos), sizeof(eos));
}

void write_schema_message(std::string* out, const FieldDesc* fields, std::uint32_t n_fields) {
    write_message(out, 1, 0, [&](Fb& fb) {
        Table t(fb, 2);
        t.scalar<std::int16_t>(0, 0);   // Endianness.Little
        const std::size_t fs = t.ref(1);
        const std::size_t at = t.finish();
        fb.patch(fs, write_fields(fb, fields, n_fields));
        return at;
    });
}

constexpr FieldDesc utf8(std::string_view name, bool nullable) {
    return FieldDesc{name, nullable, Kind::kUtf8, 0, false, nullptr, 0};
}
constexpr FieldDesc integer(std::string_view name, std::int32_t bits, bool is_signed) {
    return FieldDesc{name, false, Kind::kInt, bits, is_signed, nullptr, 0};
}

template <class Row, class Get>
std::vector<Str> column(const Row* rows, std::size_t n, Get get) {
    std::vector<Str> c(n);
    for (std::size_t i = 0; i < n; ++i) c[i] = get(rows[i]);
    return c;
}

// CommandGetSqlInfo rows split into the dense union's type ids, offsets
// and per-member value arrays.
struct InfoColumns {
    std::vector<std::uint32_t> ids;
    std::vector<std::int8_t>   types;
    std::vector<std::int32_t>  offsets;
    std::vector<Str>           strs;
    std::vector<std::uint8_t>  bools;
    std::vector<std::int64_t>  bigs;
    std::vector<std::int32_t>  masks;

    InfoColumns(const SqlInfoRow* rows, std::size_t n) : ids(n), types(n), offsets(n) {
        for (std::size_t i = 0; i < n; ++i) {
            ids[i] = rows[i].id;
            types[i] = static_cast<std::int8_t>(rows[i].kind);
            switch (rows[i].kind) {
                case InfoKind::kString:
                    offsets[i] = static_cast<std::int32_t>(strs.size());
                    strs.push_back(Str{rows[i].s, true});
                    break;
                case InfoKind::kBool:
                    offsets[i] = static_cast<std::int32_t>(bools.size());
                    bools.push_back(rows[i].b ? 1 : 0);
                    break;
                case InfoKind::kBigint:
                    offsets[i] = static_cast<std::int32_t>(bigs.size());
                    bigs.push_back(rows[i].i64);
                    break;
                case InfoKind::kInt32Bitmask:
                    offsets[i] = static_cast<std::int32_t>(masks.size());
                    masks.push_back(rows[i].i32);
                    break;
            }
        }
        assert(strs.size() + bools.size() + bigs.size() + masks.size() == n);
    }
};

}  // namespace

void write_catalogs(std::string* out, const std::string_view* catalogs, std::size_t n) {
    assert(out != nullptr && (n == 0 || catalogs != nullptr));
    static constexpr FieldDesc kFields[] = {utf8("catalog_name", false)};
    std::vector<Str> c(n);
    for (std::size_t i = 0; i < n; ++i) c[i] = Str{catalogs[i], true};
    Body body;
    body.strings(c.data(), n);
    write_stream(out, kFields, 1, n, body);
}

void write_db_schemas(std::string* out, const SchemaRow* rows, std::size_t n) {
    assert(out != nullptr && (n == 0 || rows != nullptr));
    static constexpr FieldDesc kFields[] = {utf8("catalog_name", true),
                                            utf8("db_schema_name", false)};
    Body body;
    body.strings(column(rows, n, [](const SchemaRow& r) { return r.catalog; }).data(), n);
    body.strings(column(rows, n, [](const SchemaRow& r) { return Str{r.db_schema, true}; }).data(), n);
    write_stream(out, kFields, 2, n, body);
}

void write_tables(std::string* out, const TableRow* rows, std::size_t n, bool include_schema) {
    assert(out != nullptr && (n == 0 || rows != nullptr));
    static constexpr FieldDesc kFields[] = {
        utf8("catalog_name", true), utf8("db_schema_name", true), utf8("table_name", false),
        utf8("table_type", false),
        FieldDesc{"table_schema", false, Kind::kBinary, 0, false, nullptr, 0},
    };
    Body body;
    body.strings(column(rows, n, [](const TableRow& r) { return r.catalog; }).data(), n);
    body.strings(column(rows, n, [](const TableRow& r) { return r.db_schema; }).data(), n);
    body.strings(column(rows, n, [](const TableRow& r) { return Str{r.table_name, true}; }).data(), n);
    body.strings(column(rows, n, [](const TableRow& r) { return Str{r.table_type, true}; }).data(), n);
    if (include_schema) {
        body.strings(column(rows, n, [](const TableRow& r) { return Str{r.table_schema, true}; }).data(), n);
    }
    write_stream(out, kFields, include_schema ? 5u : 4u, n, body);
}

void write_table_types(std::string* out, const std::string_view* types, std::size_t n) {
    assert(out != nullptr && (n == 0 || types != nullptr));
    static constexpr FieldDesc kFields[] = {utf8("table_type", false)};
    std::vector<Str> c(n);
    for (std::size_t i = 0; i < n; ++i) c[i] = Str{types[i], true};
    Body body;
    body.strings(c.data(), n);
    write_stream(out, kFields, 1, n, body);
}

void write_primary_keys(std::string* out, const PrimaryKeyRow* rows, std::size_t n) {
    assert(out != nullptr && (n == 0 || rows != nullptr));
    static constexpr FieldDesc kFields[] = {
        utf8("catalog_name", true), utf8("db_schema_name", true), utf8("table_name", false),
        utf8("column_name", false), utf8("key_name", true), integer("key_sequence", 32, true),
    };
    Body body;
    body.strings(column(rows, n, [](const PrimaryKeyRow& r) { return r.catalog; }).data(), n);
    body.strings(column(rows, n, [](const PrimaryKeyRow& r) { return r.db_schema; }).data(), n);
    body.strings(column(rows, n, [](const PrimaryKeyRow& r) { return Str{r.table_name, true}; }).data(), n);
    body.strings(column(rows, n, [](const PrimaryKeyRow& r) { return Str{r.column_name, true}; }).data(), n);
    body.strings(column(rows, n, [](const PrimaryKeyRow& r) { return r.key_name; }).data(), n);
    std::vector<std::int32_t> seq(n);
    for (std::size_t i = 0; i < n; ++i) seq[i] = rows[i].key_sequence;
    body.values(seq.data(), n);
    write_stream(out, kFields, 6, n, body);
}

void write_foreign_keys_empty(std::string* out) {
    assert(out != nullptr);
    static constexpr FieldDesc kFields[] = {
        utf8("pk_catalog_name", true), utf8("pk_db_schema_name", true),
        utf8("pk_table_name", false),  utf8("pk_column_name", false),
        utf8("fk_catalog_name", true), utf8("fk_db_schema_name", true),
        utf8("fk_table_name", false),  utf8("fk_column_name", false),
        integer("key_sequence", 32, true),
        utf8("fk_key_name", true),     utf8("pk_key_name", true),
        integer("update_rule", 8, false), integer("delete_rule", 8, false),
    };
    static_assert(sizeof(kFields) / sizeof(kFields[0]) == 13);
    Body body;
    for (std::uint32_t i = 0; i < 13; ++i) {
        if (kFields[i].kind == Kind::kUtf8) {
            body.strings(nullptr, 0);
        } else {
            body.values<std::uint8_t>(nullptr, 0);
        }
    }
    write_stream(out, kFields, 13, 0, body);
}

// value: dense_union<string_value: utf8, bool_value: bool, bigint_value:
// int64, int32_bitmask: int32, string_list: list<utf8>,
// int32_to_int32_list_map: map<int32, list<int32>>> — the Arrow C++
// reference schema (SqlSchema::GetSqlInfoSchema), child names included.
void write_sql_info(std::string* out, const SqlInfoRow* rows, std::size_t n) {
    assert(out != nullptr && (n == 0 || rows != nullptr));
    static constexpr FieldDesc kItemUtf8[] = {utf8("item", true)};
    static constexpr FieldDesc kItemI32[] = {
        FieldDesc{"item", true, Kind::kInt, 32, true, nullptr, 0}};
    static constexpr FieldDesc kEntry[] = {
        integer("key", 32, true),
        FieldDesc{"value", true, Kind::kList, 0, false, kItemI32, 1},
    };
    static constexpr FieldDesc kMapChild[] = {
        FieldDesc{"entries", false, Kind::kStruct, 0, false, kEntry, 2}};
    static constexpr FieldDesc kArms[] = {
        utf8("string_value", false),
        FieldDesc{"bool_value", false, Kind::kBool, 0, false, nullptr, 0},
        integer("bigint_value", 64, true),
        integer("int32_bitmask", 32, true),
        FieldDesc{"string_list", false, Kind::kList, 0, false, kItemUtf8, 1},
        FieldDesc{"int32_to_int32_list_map", false, Kind::kMap, 0, false, kMapChild, 1},
    };
    static constexpr FieldDesc kFields[] = {
        integer("info_name", 32, false),
        FieldDesc{"value", false, Kind::kDenseUnion, 0, false, kArms, 6},
    };
    const InfoColumns c(rows, n);
    Body body;
    body.values(c.ids.data(), n);
    body.node(n, 0);                                   // union: no validity (V5)
    body.buf(c.types.data(), n);
    body.buf(c.offsets.data(), n * sizeof(std::int32_t));
    body.strings(c.strs.data(), c.strs.size());
    body.bools(c.bools.data(), c.bools.size());
    body.values(c.bigs.data(), c.bigs.size());
    body.values(c.masks.data(), c.masks.size());
    body.empty_list();                                 // string_list
    body.strings(nullptr, 0);                          //   item
    body.empty_list();                                 // map (same layout as list)
    body.node(0, 0);                                   //   entries struct
    body.none();
    body.values<std::int32_t>(nullptr, 0);             //     key
    body.empty_list();                                 //     value
    body.values<std::int32_t>(nullptr, 0);             //       item
    write_stream(out, kFields, 2, n, body);
}

// An untyped parameter is dense_union<string: utf8, bytes: binary, bigint:
// int64, double: float64> — the Arrow C++ "unknown column type" convention.
void write_parameter_schema(std::string* out, std::size_t n, const ParamType* types) {
    assert(out != nullptr && n > 0);
    static constexpr FieldDesc kArms[] = {
        utf8("string", true),
        FieldDesc{"bytes", true, Kind::kBinary, 0, false, nullptr, 0},
        FieldDesc{"bigint", true, Kind::kInt, 64, true, nullptr, 0},
        FieldDesc{"double", true, Kind::kDouble, 0, false, nullptr, 0},
    };
    std::vector<std::string> names(n);
    std::vector<FieldDesc> fields(n);
    for (std::size_t i = 0; i < n; ++i) {
        names[i] = "parameter_" + std::to_string(i + 1);
        const ParamType t = types != nullptr ? types[i] : ParamType::kUnknown;
        switch (t) {
            case ParamType::kInt64:
                fields[i] = FieldDesc{names[i], true, Kind::kInt, 64, true, nullptr, 0};
                break;
            case ParamType::kFloat64:
                fields[i] = FieldDesc{names[i], true, Kind::kDouble, 0, false, nullptr, 0};
                break;
            case ParamType::kUtf8:
                fields[i] = FieldDesc{names[i], true, Kind::kUtf8, 0, false, nullptr, 0};
                break;
            case ParamType::kBool:
                fields[i] = FieldDesc{names[i], true, Kind::kBool, 0, false, nullptr, 0};
                break;
            default:
                fields[i] = FieldDesc{names[i], true, Kind::kDenseUnion, 0, false, kArms, 4};
                break;
        }
    }
    assert(fields.size() == n);
    write_schema_message(out, fields.data(), static_cast<std::uint32_t>(n));
}

namespace {

// A nullable int32 column; a negative value is NULL.
template <class Get>
void opt_ints(Body* body, const XdbcTypeInfo* rows, std::size_t n, Get get) {
    std::vector<std::int32_t> v(n);
    std::vector<std::uint8_t> ok(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = get(rows[i]);
        ok[i] = v[i] >= 0 ? 1 : 0;
        if (v[i] < 0) v[i] = 0;
    }
    body->opt_values(v.data(), ok.data(), n);
}

}  // namespace

void write_xdbc_type_info(std::string* out, const XdbcTypeInfo* rows, std::size_t n) {
    assert(out != nullptr && (n == 0 || rows != nullptr));
    static constexpr FieldDesc kItem[] = {utf8("item", false)};
    auto opt_i32 = [](std::string_view name) {
        return FieldDesc{name, true, Kind::kInt, 32, true, nullptr, 0};
    };
    auto boolean = [](std::string_view name, bool nullable) {
        return FieldDesc{name, nullable, Kind::kBool, 0, false, nullptr, 0};
    };
    const FieldDesc fields[] = {
        utf8("type_name", false), integer("data_type", 32, true), opt_i32("column_size"),
        utf8("literal_prefix", true), utf8("literal_suffix", true),
        FieldDesc{"create_params", true, Kind::kList, 0, false, kItem, 1},
        integer("nullable", 32, true), boolean("case_sensitive", false),
        integer("searchable", 32, true), boolean("unsigned_attribute", true),
        boolean("fixed_prec_scale", false), boolean("auto_increment", true),
        utf8("local_type_name", true), opt_i32("minimum_scale"), opt_i32("maximum_scale"),
        integer("sql_data_type", 32, true), opt_i32("datetime_subcode"),
        opt_i32("num_prec_radix"), opt_i32("interval_precision"),
    };
    static_assert(sizeof(fields) / sizeof(fields[0]) == 19);
    auto str = [](std::string_view v) { return Str{v, !v.empty()}; };
    std::vector<std::uint8_t> flags(n);
    const std::vector<std::uint8_t> all(n, 1);
    const std::vector<std::uint8_t> none(n, 0);
    Body body;
    body.strings(column(rows, n, [](const XdbcTypeInfo& r) { return Str{r.type_name, true}; }).data(), n);
    std::vector<std::int32_t> dt(n);
    for (std::size_t i = 0; i < n; ++i) dt[i] = rows[i].data_type;
    body.values(dt.data(), n);
    opt_ints(&body, rows, n, [](const XdbcTypeInfo& r) { return r.column_size; });
    body.strings(column(rows, n, [&](const XdbcTypeInfo& r) { return str(r.literal_prefix); }).data(), n);
    body.strings(column(rows, n, [&](const XdbcTypeInfo& r) { return str(r.literal_suffix); }).data(), n);
    body.null_lists(n);
    const std::vector<std::int32_t> nullable(n, 1);   // NULLABILITY_NULLABLE
    body.values(nullable.data(), n);
    for (std::size_t i = 0; i < n; ++i) flags[i] = rows[i].case_sensitive ? 1 : 0;
    body.bools(flags.data(), n);
    std::vector<std::int32_t> searchable(n);
    for (std::size_t i = 0; i < n; ++i) searchable[i] = rows[i].searchable;
    body.values(searchable.data(), n);
    std::vector<std::uint8_t> uvalid(n);
    for (std::size_t i = 0; i < n; ++i) {
        flags[i] = rows[i].unsigned_attribute == 1 ? 1 : 0;
        uvalid[i] = rows[i].unsigned_attribute >= 0 ? 1 : 0;
    }
    body.opt_bools(flags.data(), uvalid.data(), n);
    for (std::size_t i = 0; i < n; ++i) flags[i] = rows[i].fixed_prec_scale ? 1 : 0;
    body.bools(flags.data(), n);
    body.opt_bools(none.data(), all.data(), n);   // auto_increment false
    body.strings(column(rows, n, [](const XdbcTypeInfo& r) { return Str{r.type_name, true}; }).data(), n);
    opt_ints(&body, rows, n, [](const XdbcTypeInfo& r) { return r.minimum_scale; });
    opt_ints(&body, rows, n, [](const XdbcTypeInfo& r) { return r.maximum_scale; });
    body.values(dt.data(), n);                    // sql_data_type
    const std::vector<std::int32_t> zeros(n, 0);
    body.opt_values(zeros.data(), none.data(), n);   // datetime_subcode
    opt_ints(&body, rows, n, [](const XdbcTypeInfo& r) { return r.num_prec_radix; });
    body.opt_values(zeros.data(), none.data(), n);   // interval_precision
    write_stream(out, fields, 19, n, body);
}

bool like_match(std::string_view pattern, std::string_view s) noexcept {
    // Iterative wildcard match with single-star backtracking: O(|p| * |s|).
    std::size_t p = 0;
    std::size_t i = 0;
    std::size_t star = std::string_view::npos;
    std::size_t mark = 0;
    const std::size_t bound = (pattern.size() + 1) * (s.size() + 1) + 1;
    for (std::size_t step = 0; step < bound; ++step) {
        if (i < s.size() && p < pattern.size() && (pattern[p] == '_' || pattern[p] == s[i])) {
            ++p;
            ++i;
        } else if (p < pattern.size() && pattern[p] == '%') {
            star = p++;
            mark = i;
        } else if (i < s.size() && star != std::string_view::npos) {
            p = star + 1;
            i = ++mark;
        } else if (i >= s.size()) {
            while (p < pattern.size() && pattern[p] == '%') ++p;
            return p == pattern.size();
        } else {
            return false;
        }
    }
    assert(false && "like_match exceeded its bound");
    return false;
}

}  // namespace bolt::api::proto::flightsql::arrow

#endif  // BOLTAPI_WITH_FLIGHT_SQL
