// tests/pg_wire_echo_executor.h — a deterministic IQueryExecutor for the
// Postgres wire tests. TEST HARNESS ONLY.
//
//   "fail..."    -> ErrorResponse 42601
//   "rows N"     -> one int8 column "n", values 1..N
//   "types"      -> one row: int8, float8, text, date, numeric, bool, NULL text
//   "ddl..."     -> no columns, tag "OK"
//   anything else -> one text column "sql" holding the SQL it received, so a
//                    test can assert exactly what parameter binding produced.
#pragma once

#include "boltapi/proto/postgres_wire.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

namespace boltapi_test {

namespace pg = bolt::api::proto::pgwire;

class PgEchoExecutor final : public pg::IQueryExecutor {
public:
    bool execute(std::string_view sql, pg::FieldDesc* f, std::uint32_t cap,
                 std::uint32_t& n, pg::QueryFailure& qf) noexcept override {
        assert(f != nullptr && cap >= 8);
        ++executes;
        sql_.assign(sql.data(), sql.size());
        rows_ = 0;
        ncols_ = 0;
        mode_ = Mode::Echo;
        if (starts(sql, "fail")) {
            qf.sqlstate = "42601";
            qf.message = "echo executor: forced failure";
            return false;
        }
        if (starts(sql, "ddl")) {
            mode_ = Mode::Ddl;
        } else if (starts(sql, "rows ")) {
            mode_ = Mode::Rows;
            rows_ = static_cast<std::uint32_t>(std::atoi(sql_.c_str() + 5));
            ncols_ = 1;
            f[0] = {"n", 20, 8};
        } else if (starts(sql, "types")) {
            mode_ = Mode::Types;
            rows_ = 1;
            ncols_ = 7;
            f[0] = {"i", 20, 8};
            f[1] = {"f", 701, 8};
            f[2] = {"t", 25, -1};
            f[3] = {"d", 1082, 4};
            f[4] = {"num", 1700, -1};
            f[5] = {"b", 16, 1};
            f[6] = {"z", 25, -1};
        } else {
            rows_ = 1;
            ncols_ = 1;
            f[0] = {"sql", 25, -1};
        }
        n = ncols_;
        return true;
    }

    bool describe(std::string_view sql, pg::FieldDesc* f, std::uint32_t cap,
                  std::uint32_t& n, pg::QueryFailure& qf) noexcept override {
        ++describes;
        const bool ok = execute(sql, f, cap, n, qf);
        --executes;
        return ok;
    }

    bool row(std::uint32_t i, std::string_view* v, bool* nul,
             std::uint32_t cap) noexcept override {
        if (i >= rows_ || cap < ncols_) return false;
        for (std::uint32_t c = 0; c < ncols_; ++c) nul[c] = false;
        switch (mode_) {
            case Mode::Rows:
                std::snprintf(num_, sizeof(num_), "%u", i + 1);
                v[0] = num_;
                break;
            case Mode::Types:
                v[0] = "-42"; v[1] = "1.5"; v[2] = "x'y"; v[3] = "2024-02-29";
                v[4] = "-12.3450"; v[5] = "t"; nul[6] = true;
                break;
            default:
                v[0] = sql_;
                break;
        }
        return true;
    }

    std::uint32_t row_count() const noexcept override { return rows_; }

    void command_tag(char* out, std::size_t cap) const noexcept override {
        if (mode_ == Mode::Ddl) std::snprintf(out, cap, "OK");
        else std::snprintf(out, cap, "SELECT %u", rows_);
    }

    int executes = 0;
    int describes = 0;

private:
    enum class Mode { Echo, Rows, Types, Ddl };
    static bool starts(std::string_view s, const char* p) noexcept {
        return s.substr(0, std::strlen(p)) == p;
    }
    std::string   sql_;
    std::uint32_t rows_ = 0;
    std::uint32_t ncols_ = 0;
    Mode          mode_ = Mode::Echo;
    char          num_[16] = {};
};

class PgEchoFactory final : public pg::IExecutorFactory {
public:
    pg::IQueryExecutor* create() noexcept override {
        auto* e = new (std::nothrow) PgEchoExecutor();
        last = e;
        return e;
    }
    void destroy(pg::IQueryExecutor* e) noexcept override { delete e; }
    PgEchoExecutor* last = nullptr;
};

}  // namespace boltapi_test
