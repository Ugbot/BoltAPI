// flight_codec — the Flight SQL protobuf / gRPC / base64 / handle decoders
// the server runs on request bodies. First byte selects the decoder.
#include "fuzz_util.h"

#include "boltapi/proto/flight_sql_codec.h"
#include "boltapi/proto/flight_sql_params.h"

#include <string>
#include <string_view>
#include <vector>

namespace cd = bolt::api::proto::flightsql::codec;
namespace pm = bolt::api::proto::flightsql::params;

namespace {

bool inside(std::string_view v, std::string_view buf) {
    return v.empty() ||
           (v.data() >= buf.data() && v.data() + v.size() <= buf.data() + buf.size());
}

void pb_walk(std::string_view buf) {
    cd::PbReader r(buf);
    cd::PbField f;
    for (int guard = 0; guard < 4096 && r.next(&f); ++guard) {
        FUZZ_CHECK(inside(f.bytes, buf));
    }
    std::size_t pos = 0;
    std::uint64_t v = 0;
    for (int guard = 0; guard < 4096 && pos < buf.size(); ++guard) {
        const std::size_t before = pos;
        if (!cd::pb_read_varint(buf, &pos, &v)) break;
        FUZZ_CHECK(pos > before && pos <= buf.size());
    }
}

void handle(std::string_view buf) {
    std::string_view sql;
    bool bound = false;
    std::vector<pm::Value> row;
    if (!pm::decode_handle(buf, &sql, &bound, &row)) return;
    FUZZ_CHECK(inside(sql, buf));
    for (const pm::Value& x : row) FUZZ_CHECK(inside(x.s, buf));
    std::uint32_t n = 0;
    if (!pm::count_placeholders(sql, &n)) return;
    std::string out;
    const char* err = nullptr;
    if (bound && n == row.size()) {
        (void)pm::render(sql, row.data(), n, 1u << 20, &out, &err);
    }
    std::string again;
    if (bound) {
        pm::encode_bound(&again, sql, row.data(), static_cast<std::uint32_t>(row.size()));
    } else {
        pm::encode_unbound(&again, sql);
    }
    std::string_view sql2;
    bool bound2 = false;
    std::vector<pm::Value> row2;
    FUZZ_CHECK(pm::decode_handle(again, &sql2, &bound2, &row2));
    FUZZ_CHECK(sql2 == sql && bound2 == bound && row2.size() == row.size());
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    const std::string_view buf(reinterpret_cast<const char*>(data + 1), size - 1);
    switch (data[0] % 9) {
        case 0: pb_walk(buf); break;
        case 1: {
            cd::AnyMsg m;
            if (cd::decode_any(buf, &m)) FUZZ_CHECK(inside(m.value, buf));
            break;
        }
        case 2: {
            cd::Descriptor d;
            if (cd::decode_descriptor(buf, &d)) FUZZ_CHECK(inside(d.cmd, buf));
            break;
        }
        case 3: {
            std::string_view q, t;
            if (cd::decode_statement_query(buf, &q, &t)) {
                FUZZ_CHECK(inside(q, buf) && inside(t, buf));
            }
            std::string_view s;
            if (cd::decode_single_bytes(buf, &s)) FUZZ_CHECK(inside(s, buf));
            break;
        }
        case 4: {
            cd::FlightDataMsg m;
            if (cd::decode_flight_data(buf, &m)) {
                FUZZ_CHECK(inside(m.descriptor, buf) && inside(m.data_header, buf) &&
                           inside(m.data_body, buf));
            }
            break;
        }
        case 5: {
            std::string_view rest = buf;
            for (int guard = 0; guard < 4096 && !rest.empty(); ++guard) {
                std::string_view msg;
                std::size_t used = 0;
                if (cd::grpc_unframe(rest, &msg, &used) != cd::GrpcFrame::kOk) break;
                FUZZ_CHECK(used >= 5 && used <= rest.size() && inside(msg, rest));
                rest.remove_prefix(used);
            }
            break;
        }
        case 6: {
            char out[512];
            std::size_t n = 0;
            if (cd::base64_decode(buf, out, sizeof(out), &n)) FUZZ_CHECK(n <= sizeof(out));
            const std::size_t e = cd::grpc_percent_encode(buf, out, sizeof(out));
            FUZZ_CHECK(e <= sizeof(out));
            break;
        }
        case 7: handle(buf); break;
        default: {
            std::size_t pos = 0;
            cd::IpcMessage m;
            bool bad = false;
            for (int guard = 0; guard < 4096 && cd::ipc_next_message(buf, &pos, &m, &bad);
                 ++guard) {
                FUZZ_CHECK(pos <= buf.size() && inside(m.metadata, buf) && inside(m.body, buf));
                (void)pm::header_type(m.metadata);
            }
            break;
        }
    }
    return 0;
}
