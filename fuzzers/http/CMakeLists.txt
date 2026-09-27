# HTTP/1.1, HPACK, HTTP/2 and SSE harnesses. Each calls the parser the server
# runs; INSTRUMENT lists the TUs the replay ctest compiles with ASan/UBSan.
set(_src ${PROJECT_SOURCE_DIR}/src)
set(_hpack_srcs ${_src}/http/hpack.cpp ${_src}/http/huffman.cpp
                ${_src}/http/huffman_table.cpp ${_src}/http/huffman_table_data.cpp)
set(_h2_srcs ${_hpack_srcs} ${_src}/http/http2_frame.cpp
             ${_src}/http/http2_connection.cpp ${_src}/http/http2_connection_recv.cpp
             ${_src}/http/http2_stream.cpp)

boltapi_add_fuzz_target(http1_request SOURCE http1_request.cpp
    INSTRUMENT ${_src}/http/http1_parser.cpp)
boltapi_add_fuzz_target(http1_chunked SOURCE http1_chunked.cpp
    INSTRUMENT ${_src}/http/http1_parser.cpp)
boltapi_add_fuzz_target(http1_response SOURCE http1_response.cpp
    INSTRUMENT ${_src}/http/client.cpp)
boltapi_add_fuzz_target(hpack SOURCE hpack.cpp INSTRUMENT ${_hpack_srcs})
boltapi_add_fuzz_target(huffman SOURCE huffman.cpp INSTRUMENT ${_hpack_srcs})
boltapi_add_fuzz_target(h2_frame SOURCE h2_frame.cpp
    INSTRUMENT ${_src}/http/http2_frame.cpp)
boltapi_add_fuzz_target(h2_connection SOURCE h2_connection.cpp INSTRUMENT ${_h2_srcs})
boltapi_add_fuzz_target(sse SOURCE sse.cpp INSTRUMENT ${_src}/http/sse.cpp)
