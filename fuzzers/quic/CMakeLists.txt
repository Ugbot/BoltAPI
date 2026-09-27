# QUIC, HTTP/3, QPACK and WebSocket harnesses (G2ETL-114, quic-ws area). The
# QUIC/H3 stack is header-only, so the harness TU itself is the instrumented
# parser; WebSocket also instruments its two TUs.
set(_src ${PROJECT_SOURCE_DIR}/src)
set(_ws_srcs ${_src}/http/websocket.cpp ${_src}/http/websocket_parser.cpp)

boltapi_add_fuzz_target(quic_packet SOURCE quic_packet.cpp)
boltapi_add_fuzz_target(quic_conn SOURCE quic_conn.cpp)
boltapi_add_fuzz_target(h3_stream SOURCE h3_stream.cpp)
boltapi_add_fuzz_target(hq_stream SOURCE hq_stream.cpp)
boltapi_add_fuzz_target(qpack SOURCE qpack.cpp)
boltapi_add_fuzz_target(ws_conn SOURCE ws_conn.cpp INSTRUMENT ${_ws_srcs})
boltapi_add_fuzz_target(ws_parser SOURCE ws_parser.cpp INSTRUMENT ${_ws_srcs})
