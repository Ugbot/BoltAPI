// flight_session — one Flight SQL h2c connection (HTTP/2 framing, HPACK,
// gRPC framing, protobuf commands, DoPut Arrow IPC parameters) through
// Protocol::serve_socket. The harness supplies the connection preface; the
// input is the frame stream after it.
#include "fuzz_util.h"
#include "flight_sql_echo_executor.h"

#include "boltapi/proto/flight_sql.h"

#include <vector>

namespace fs = bolt::api::proto::flightsql;

namespace {

constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kPrefaceLen = 24;
constexpr std::size_t kMaxInput = 1u << 20;

fs::Config make_config() {
    fs::Config c;
    c.max_connections = 1;
    c.accept_poll_ms = 50;
    c.idle_timeout_ms = 2000;
    return c;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static boltapi_test::EchoFactory factory;
    static boltapi_test::TokenAuth auth("");
    static fs::Protocol proto(make_config(), factory, &auth);
    static fs::IQueryExecutor* exec = factory.create();
    static std::vector<std::uint8_t> buf(kPrefaceLen + kMaxInput);
    boltapi_test::g_max_rows = 2000;
    if (size > kMaxInput) return 0;
    std::memcpy(buf.data(), kPreface, kPrefaceLen);
    if (size > 0) std::memcpy(buf.data() + kPrefaceLen, data, size);
    boltapi_fuzz::run_session(buf.data(), kPrefaceLen + size,
                              [&](int fd) { proto.serve_socket(fd, *exec); });
    return 0;
}
