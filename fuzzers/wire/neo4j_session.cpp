// neo4j_session — one Neo4j Bolt connection (handshake, chunk framing,
// PackStream decode, HELLO/LOGON/RUN/PULL/... state machine) through
// Neo4jBoltProtocol::serve_socket.
#include "fuzz_util.h"
#include "neo4j_bolt_echo_executor.h"

#include "boltapi/proto/neo4j_bolt.h"

namespace nb = bolt::api::proto::neo4j;

namespace {

nb::Config make_config() {
    nb::Config c;
    c.max_connections = 1;
    c.message_buffer_bytes = 64u * 1024u;
    c.write_buffer_bytes = 64u * 1024u;
    c.value_arena_bytes = 256u * 1024u;
    c.accept_poll_ms = 50;
    c.idle_timeout_ms = 2000;
    return c;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static boltapi_test::EchoFactory factory;
    static nb::Neo4jBoltProtocol proto(make_config(), factory);
    static nb::IQueryExecutor* exec = factory.create();
    boltapi_fuzz::run_session(data, size, [&](int fd) { proto.serve_socket(fd, *exec); });
    return 0;
}
