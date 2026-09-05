// tests/neo4j_bolt_echo_executor.h — the loopback echo executor.
//
// TEST-ONLY. It is deliberately NOT shipped in the library: the wire layer must
// stay executor-agnostic, and a toy engine inside boltapi would be dead weight
// once the real one (chukonu, via gestaltd) lands in a later wave.
//
// Behaviour, pinned by both the C++ wire test and the official-driver test:
//   fields  = ["query", "params", "index", "kinds"]
//   records = N rows, where N = params["n"] when that is an integer in
//             [0, kMaxRows], else 1.
//   row k   = [ <the query text verbatim>,
//               <the parameters dictionary, echoed>,
//               k,
//               [null, true, -17, 3.5, "Größenmaßstäbe", [1,2,3], {"k":"v"}] ]
//
// The `kinds` column exists so a conformance run exercises every PackStream
// type this codec emits, end to end, through a real client's decoder — not
// just the two types a "RETURN 1" smoke test would touch.

#pragma once

#include "boltapi/proto/neo4j_bolt.h"

#include <cstring>
#include <string>
#include <vector>

namespace boltapi_test {

namespace ps = bolt::api::proto::packstream;
namespace nb = bolt::api::proto::neo4j;

inline constexpr std::int64_t kEchoMaxRows = 4096;

class EchoExecutor final : public nb::IQueryExecutor {
public:
    EchoExecutor()
        : params_buf_(1u << 16), params_arena_mem_(1u << 16) {}

    bool begin_query(std::string_view cypher, const ps::PackValue& params,
                     std::string_view* out_fields, std::uint32_t fields_cap,
                     std::uint32_t& out_field_count,
                     nb::QueryFailure& out_failure) noexcept override {
        if (fields_cap < 4) {
            out_failure = {"Neo.ClientError.Statement.ExecutionFailed",
                           "server field cap too small for the echo executor"};
            return false;
        }
        // Two refusal triggers, because they are reachable from different
        // clients. An empty query is what the raw-socket wire test sends; the
        // OFFICIAL driver rejects that CLIENT-SIDE (ValueError: "Cannot run an
        // empty query") and never puts it on the wire, so a query STARTING WITH
        // "FAIL" is the trigger the driver will actually transmit. Without the
        // second one the driver run could not reach the FAILURE path at all.
        if (cypher.empty() || cypher.rfind("FAIL", 0) == 0) {
            out_failure = {"Neo.ClientError.Statement.SyntaxError",
                           cypher.empty() ? "empty query"
                                          : "query rejected on request"};
            return false;
        }

        // `cypher` / `params` are borrowed from the per-message arena, so copy
        // both now (see the LIFETIME note on IQueryExecutor::begin_query).
        query_.assign(cypher.data(), cypher.size());
        ps::PackWriter w(params_buf_.data(), params_buf_.size());
        if (w.put_value(params) != ps::PackError::Ok || w.overflowed()) {
            out_failure = {"Neo.ClientError.Statement.ArgumentError",
                           "parameters too large to echo"};
            return false;
        }
        params_len_ = w.size();

        rows_ = 1;
        if (params.is_dict()) {
            const std::int64_t n = params.find_int("n", 1);
            if (n >= 0 && n <= kEchoMaxRows) rows_ = n;
        }
        emitted_ = 0;

        out_fields[0] = "query";
        out_fields[1] = "params";
        out_fields[2] = "index";
        out_fields[3] = "kinds";
        out_field_count = 4;
        return true;
    }

    bool pull(std::int64_t n, nb::IRecordSink& sink, bool& out_has_more,
              nb::QueryFailure& out_failure) noexcept override {
        (void)out_failure;
        const std::int64_t want = (n == nb::kPullAll) ? (rows_ - emitted_) : n;
        std::int64_t sent = 0;
        while (sent < want && emitted_ < rows_) {
            ps::PackArena arena(params_arena_mem_.data(), params_arena_mem_.size());
            ps::PackValue values[4];
            values[0] = make_string(arena, query_);
            {
                ps::PackReader r(params_buf_.data(), params_len_, arena);
                if (r.read(values[1]) != ps::PackError::Ok) values[1] = ps::PackValue{};
            }
            values[2] = make_int(emitted_);
            values[3] = make_kinds(arena);
            if (!sink.emit(values, 4)) return false;
            ++emitted_;
            ++sent;
        }
        out_has_more = (emitted_ < rows_);
        return true;
    }

    void discard() noexcept override { emitted_ = rows_; }

private:
    static ps::PackValue make_int(std::int64_t v) noexcept {
        ps::PackValue x{};
        x.type = ps::PackType::Int;
        x.i = v;
        return x;
    }

    static ps::PackValue make_string(ps::PackArena& a, const std::string& s) noexcept {
        ps::PackValue x{};
        x.type = ps::PackType::String;
        char* p = static_cast<char*>(a.alloc(s.size() + 1, 1));
        if (p == nullptr) return x;  // degrades to an empty string, never a crash
        std::memcpy(p, s.data(), s.size());
        x.bytes = p;
        x.len = static_cast<std::uint32_t>(s.size());
        return x;
    }

    static ps::PackValue lit_string(ps::PackArena& a, const char* s) noexcept {
        ps::PackValue x{};
        x.type = ps::PackType::String;
        const std::size_t n = std::strlen(s);
        char* p = static_cast<char*>(a.alloc(n, 1));
        if (p == nullptr) return x;
        std::memcpy(p, s, n);
        x.bytes = p;
        x.len = static_cast<std::uint32_t>(n);
        return x;
    }

    // [null, true, -17, 3.5, "Größenmaßstäbe", [1,2,3], {"k":"v"}]
    static ps::PackValue make_kinds(ps::PackArena& a) noexcept {
        ps::PackValue out{};
        auto* items = a.alloc_n<ps::PackValue>(7);
        if (items == nullptr) return out;
        items[0] = ps::PackValue{};                                   // null
        items[1] = ps::PackValue{}; items[1].type = ps::PackType::Bool; items[1].b = true;
        items[2] = make_int(-17);                                     // forces INT_8
        items[3] = ps::PackValue{}; items[3].type = ps::PackType::Float; items[3].f = 3.5;
        items[4] = lit_string(a, "Gr\xc3\xb6\xc3\x9f" "enma\xc3\x9f" "st\xc3\xa4" "be");
        {
            auto* nums = a.alloc_n<ps::PackValue>(3);
            items[5] = ps::PackValue{};
            if (nums != nullptr) {
                nums[0] = make_int(1); nums[1] = make_int(2); nums[2] = make_int(3);
                items[5].type = ps::PackType::List;
                items[5].items = nums;
                items[5].len = 3;
            }
        }
        {
            auto* pair = a.alloc_n<ps::PackPair>(1);
            auto* v = a.alloc_n<ps::PackValue>(1);
            items[6] = ps::PackValue{};
            if (pair != nullptr && v != nullptr) {
                *v = lit_string(a, "v");
                pair[0].key = "k";
                pair[0].key_len = 1;
                pair[0].value = v;
                items[6].type = ps::PackType::Dict;
                items[6].pairs = pair;
                items[6].len = 1;
            }
        }
        out.type = ps::PackType::List;
        out.items = items;
        out.len = 7;
        return out;
    }

    std::string               query_;
    std::vector<std::uint8_t> params_buf_;
    std::size_t               params_len_ = 0;
    std::vector<std::uint8_t> params_arena_mem_;
    std::int64_t              rows_ = 0;
    std::int64_t              emitted_ = 0;
};

class EchoFactory final : public nb::IExecutorFactory {
public:
    nb::IQueryExecutor* create() noexcept override { return new EchoExecutor(); }
    void destroy(nb::IQueryExecutor* e) noexcept override { delete e; }
};

}  // namespace boltapi_test
