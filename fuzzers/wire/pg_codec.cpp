// pg_codec — the Postgres wire value codecs and statement classifiers the
// server runs on client-supplied SQL and Bind parameters.
// Layout: selector, then (for parameter paths) n_params and per-parameter
// {oid-byte, flags, len} headers, then the SQL text.
#include "fuzz_util.h"

#include "boltapi/proto/postgres_wire_codec.h"

#include <string_view>

namespace pg = bolt::api::proto::pgwire;

namespace {

constexpr std::int32_t kOids[] = {
    pg::oid::kUnspecified, pg::oid::kBool,    pg::oid::kBytea,   pg::oid::kName,
    pg::oid::kInt8,        pg::oid::kInt2,    pg::oid::kInt4,    pg::oid::kText,
    pg::oid::kOid,         pg::oid::kFloat4,  pg::oid::kFloat8,  pg::oid::kUnknown,
    pg::oid::kBpchar,      pg::oid::kVarchar, pg::oid::kDate,    pg::oid::kTimestamp,
    pg::oid::kNumeric,     1184,              114,               3802,
};
constexpr std::size_t kNumOids = sizeof(kOids) / sizeof(kOids[0]);
constexpr std::uint32_t kMaxParams = 16;
constexpr std::size_t kOutCap = 64u * 1024u;

std::string_view as_sv(const std::uint8_t* p, std::size_t n) {
    return std::string_view(reinterpret_cast<const char*>(p), n);
}

void classify_all(std::string_view sql) {
    pg::CodecError err;
    const char* tag = nullptr;
    const pg::SessionCommand sc = pg::classify_session_command(sql, tag, err);
    FUZZ_CHECK(sc != pg::SessionCommand::Accepted || tag != nullptr);
    pg::ShowAnswer sa;
    const pg::ShowCommand sh = pg::classify_show_command(sql, "14.9", sa, err);
    FUZZ_CHECK(sh != pg::ShowCommand::Answered || sa.column != nullptr);
    bool read_only = false;
    std::string_view savepoint;
    (void)pg::classify_transaction_command(sql, read_only, err, &savepoint);
    FUZZ_CHECK(savepoint.empty() ||
               (savepoint.data() >= sql.data() &&
                savepoint.data() + savepoint.size() <= sql.data() + sql.size()));
    pg::CursorCommand cc;
    const pg::CursorVerb cv = pg::classify_cursor_command(sql, cc, err);
    if (cv != pg::CursorVerb::None && cv != pg::CursorVerb::Refused) {
        FUZZ_CHECK(std::memchr(cc.name, 0, sizeof(cc.name)) != nullptr);
    }
    (void)pg::is_query_shaped(sql);
    (void)pg::max_param_ref(sql);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static char out[kOutCap];
    static std::uint8_t bout[kOutCap];
    boltapi_fuzz::Input in(data, size);
    const std::uint8_t sel = in.u8();
    pg::CodecError err;
    if (sel % 4 == 0) {
        classify_all(as_sv(in.p + in.off, in.left()));
        return 0;
    }
    const std::uint32_t n = in.u8() % (kMaxParams + 1);
    pg::BoundParam params[kMaxParams];
    std::size_t lens[kMaxParams] = {};
    for (std::uint32_t i = 0; i < n; ++i) {   // headers first, values after
        params[i].type_oid = kOids[in.u8() % kNumOids];
        const std::uint8_t flags = in.u8();
        params[i].is_null = (flags & 1) != 0;
        params[i].binary = (flags & 2) != 0;
        lens[i] = in.u8();
    }
    for (std::uint32_t i = 0; i < n; ++i) {
        std::size_t got = 0;
        const std::uint8_t* v = in.take(lens[i], &got);
        params[i].bytes = as_sv(v, got);
    }
    const std::string_view sql = as_sv(in.p + in.off, in.left());
    std::size_t out_len = 0;
    if (sel % 4 == 1) {
        if (pg::substitute_params(sql, params, n, out, kOutCap, out_len, err)) {
            FUZZ_CHECK(out_len <= kOutCap);
        }
    } else if (sel % 4 == 2) {
        for (std::uint32_t i = 0; i < n; ++i) {
            if (params[i].binary &&
                pg::binary_param_to_text(params[i], out, kOutCap, out_len, err)) {
                FUZZ_CHECK(out_len <= kOutCap);
            }
            std::size_t pos = 0;
            if (pg::render_literal(params[i].bytes, params[i].is_null, params[i].type_oid,
                                   out, kOutCap, pos, err)) {
                FUZZ_CHECK(pos <= kOutCap);
            }
        }
    } else {
        for (std::uint32_t i = 0; i < n; ++i) {
            if (pg::text_to_binary_result(params[i].bytes, params[i].type_oid, bout,
                                          sizeof(bout), out_len, err)) {
                FUZZ_CHECK(out_len <= sizeof(bout));
            }
        }
        classify_all(sql);
    }
    return 0;
}
