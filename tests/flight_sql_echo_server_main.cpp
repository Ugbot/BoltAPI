// tests/flight_sql_echo_server_main.cpp — a standalone Flight SQL server with
// a synthetic executor, so real Flight SQL clients (pyarrow.flight, ADBC)
// can be pointed at the wire layer alone.
//
// TEST HARNESS ONLY. Executor contract:
//   "SELECT <n>"   -> n rows (default 3): id int64 = i, name utf8 = "row<i>",
//                     score float64 = i * 0.5, in 8192-row batches.
//   "FAIL ..."     -> INVALID_ARGUMENT naming the statement.
// Catalog: tables "orders" (pk id), "customers" (pk region, id) and view
// "top_orders" (no pk), each with the "SELECT 0" schema.
// Usage: flight_sql_echo_server [--port N] [--token T]
// Prints "PORT <n>" on stdout, then serves until SIGTERM/SIGINT. With
// --token, only "Bearer T" (or Basic user:T) is accepted.

#include "boltapi/proto/flight_sql.h"

#include "bolt/bolt_arena.h"
#include "bolt/bolt_column.h"
#include "bolt/bolt_types.h"
#include "bolt/ingest/bolt_arrow_ipc.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace fs = bolt::api::proto::flightsql;

namespace {

std::atomic<bool> g_stop{false};
extern "C" void on_signal(int) { g_stop.store(true, std::memory_order_release); }

constexpr std::int64_t kBatchRows = 8192;
constexpr std::int64_t kMaxRows = 1 << 20;

class EchoExecutor final : public fs::IQueryExecutor {
public:
    EchoExecutor()
        : ids_(kBatchRows), scores_(kBatchRows), names_(kBatchRows),
          writer_(static_cast<bolt::ingest::ArrowIpcWriter*>(
              std::calloc(1, sizeof(bolt::ingest::ArrowIpcWriter)))),
          batch_(static_cast<bolt::BoltBatch*>(std::calloc(1, sizeof(bolt::BoltBatch)))) {
        assert(writer_ != nullptr && batch_ != nullptr);
    }
    ~EchoExecutor() override {
        std::free(writer_);
        std::free(batch_);
    }

    bool execute(std::string_view sql, std::string* out, std::int64_t* rows,
                 fs::QueryFailure& f) noexcept override {
        assert(out != nullptr && rows != nullptr);
        if (sql.substr(0, 4) == "FAIL") {
            std::snprintf(fail_, sizeof(fail_), "echo executor refused: %.*s",
                          static_cast<int>(sql.size() < 200 ? sql.size() : 200), sql.data());
            f.code = fs::GrpcCode::kInvalidArgument;
            f.message = fail_;
            return false;
        }
        std::int64_t n = 3;
        if (sql.size() > 7 && sql.substr(0, 7) == "SELECT ") {
            const std::string num(sql.substr(7));
            n = std::strtoll(num.c_str(), nullptr, 10);
        }
        if (n < 0 || n > kMaxRows) {
            f.code = fs::GrpcCode::kInvalidArgument;
            f.message = "row count out of range";
            return false;
        }
        *rows = n;
        return encode(n, out);
    }

    bool has_catalog() const noexcept override { return true; }
    std::uint32_t catalog_tables() noexcept override { return 3; }
    bool catalog_table(std::uint32_t i, fs::CatalogTable* out) noexcept override {
        assert(out != nullptr);
        if (i == 0) {
            out->name = "orders";
            out->table_type = "TABLE";
            out->n_key_columns = 1;
            out->key_columns[0] = "id";
        } else if (i == 1) {
            out->name = "customers";
            out->table_type = "TABLE";
            out->n_key_columns = 2;
            out->key_columns[0] = "region";
            out->key_columns[1] = "id";
        } else if (i == 2) {
            out->name = "top_orders";
            out->table_type = "VIEW";
            out->n_key_columns = 0;
        } else {
            return false;
        }
        return true;
    }
    bool catalog_table_schema(std::uint32_t i, std::string* out,
                              fs::QueryFailure& f) noexcept override {
        std::int64_t rows = 0;
        return i < 3 && execute("SELECT 0", out, &rows, f);
    }

private:
    bool encode(std::int64_t n, std::string* out) noexcept {
        std::FILE* fp = std::tmpfile();
        if (fp == nullptr) return false;
        const bolt::BoltType types[3] = {bolt::BoltType::Int64, bolt::BoltType::Utf8,
                                         bolt::BoltType::Float64};
        const char* names[3] = {"id", "name", "score"};
        bool ok = bolt::ingest::arrow_ipc_open(writer_, fp, types, names, 3);
        std::int64_t base = 0;
        for (std::int64_t b = 0; ok && (b == 0 || base < n); ++b) {   // bounded by n
            const std::int64_t m = (n - base) < kBatchRows ? (n - base) : kBatchRows;
            ok = write_batch(base, m);
            base += m;
        }
        const bool closed = bolt::ingest::arrow_ipc_close(writer_);
        if (!ok || !closed || std::fflush(fp) != 0) { std::fclose(fp); return false; }
        const long size = std::ftell(fp);
        std::rewind(fp);
        out->resize(static_cast<std::size_t>(size));
        const std::size_t got = std::fread(out->data(), 1, out->size(), fp);
        std::fclose(fp);
        return got == out->size();
    }

    bool write_batch(std::int64_t base, std::int64_t m) noexcept {
        for (std::size_t i = 0; i < static_cast<std::size_t>(m); ++i) {
            const std::int64_t v = base + static_cast<std::int64_t>(i);
            ids_[i] = v;
            scores_[i] = static_cast<double>(v) * 0.5;
            char tmp[16];
            const int len = std::snprintf(tmp, sizeof(tmp), "row%lld", static_cast<long long>(v));
            assert(len > 0 && len <= 12);
            bolt::StringView sv{};
            sv.length = static_cast<std::uint32_t>(len);
            std::memcpy(sv.prefix, tmp, static_cast<std::size_t>(len < 4 ? len : 4));
            if (len > 4) std::memcpy(sv.inline_data, tmp + 4, static_cast<std::size_t>(len - 4));
            names_[i] = sv;
        }
        bolt::Arena arena;
        bolt::BoltBatch::init_empty(batch_);
        if (!bolt::BoltBatch::alloc_columns(batch_, &arena, 3)) return false;
        batch_->num_rows = static_cast<std::uint32_t>(m);
        batch_->num_cols = 3;
        bolt::BoltColumn* cols = batch_->columns[batch_->read_epoch];
        void* data[3] = {ids_.data(), names_.data(), scores_.data()};
        const bolt::BoltType types[3] = {bolt::BoltType::Int64, bolt::BoltType::Utf8,
                                         bolt::BoltType::Float64};
        for (int c = 0; c < 3; ++c) {
            cols[c].type = types[c];
            cols[c].format = bolt::ColumnFormat::Flat;
            cols[c].length = static_cast<std::uint32_t>(m);
            cols[c].validity = nullptr;
            cols[c].data = data[c];
            cols[c].type_size_bytes = 8;
        }
        return bolt::ingest::arrow_ipc_write_batch(writer_, batch_);
    }

    std::vector<std::int64_t>     ids_;
    std::vector<double>           scores_;
    std::vector<bolt::StringView> names_;
    bolt::ingest::ArrowIpcWriter* writer_;
    bolt::BoltBatch*              batch_;
    char                          fail_[256] = {};
};

class EchoFactory final : public fs::IExecutorFactory {
public:
    fs::IQueryExecutor* create() noexcept override { return new EchoExecutor(); }
    void destroy(fs::IQueryExecutor* e) noexcept override { delete e; }
};

class TokenAuth final : public fs::IAuthenticator {
public:
    explicit TokenAuth(std::string token) : token_(std::move(token)) {}
    bool authenticate(std::string_view scheme, std::string_view,
                      std::string_view credentials) noexcept override {
        if (token_.empty()) return true;
        return (scheme == "bearer" || scheme == "basic") && credentials == token_;
    }

private:
    std::string token_;
};

}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    std::string token;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        }
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    fs::Config cfg;
    cfg.port = port;
    cfg.max_connections = 4;
    cfg.accept_poll_ms = 50;
    cfg.idle_timeout_ms = 30000;
    cfg.server_name = "boltapi-echo";
    cfg.server_version = "9.9.9";
    EchoFactory factory;
    TokenAuth auth(token);
    fs::Protocol proto(cfg, factory, &auth);
    if (proto.start_background().is_err()) {
        std::fprintf(stderr, "bind failed on %s:%u\n", cfg.host.c_str(),
                     static_cast<unsigned>(cfg.port));
        return 2;
    }
    std::printf("PORT %u\n", static_cast<unsigned>(proto.local_port()));
    std::fflush(stdout);
    while (!g_stop.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    proto.stop();
    return 0;
}
