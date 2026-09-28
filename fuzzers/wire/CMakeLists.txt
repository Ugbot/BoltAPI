# Wire-protocol and WebRTC harnesses. Each calls the parser the server runs;
# INSTRUMENT lists the TUs the replay ctest compiles with ASan/UBSan.
set(_src ${PROJECT_SOURCE_DIR}/src)
set(_tests ${PROJECT_SOURCE_DIR}/tests)

function(_wire_target name)
    if(TARGET fuzz_${name})
        set(_t fuzz_${name})
    else()
        set(_t boltapi_fuzz_replay_${name})
    endif()
    target_include_directories(${_t} PRIVATE ${_tests})
    if(WIN32)
        target_link_libraries(${_t} PRIVATE ws2_32 mswsock)
    endif()
    set(_wire_last ${_t} PARENT_SCOPE)
endfunction()

if(NOT WIN32)
    boltapi_add_fuzz_target(stun_turn SOURCE stun_turn.cpp
        INSTRUMENT ${_src}/webrtc/stun.cpp ${_src}/webrtc/ice.cpp
                   ${_src}/webrtc/ice_full.cpp ${_src}/webrtc/turn.cpp)
    _wire_target(stun_turn)
endif()
if(NOT WIN32)
    boltapi_add_fuzz_target(dtls SOURCE dtls.cpp INSTRUMENT ${_src}/webrtc/dtls.cpp)
    _wire_target(dtls)
endif()
boltapi_add_fuzz_target(sdp SOURCE sdp.cpp
    INSTRUMENT ${_src}/webrtc/sdp.cpp ${_src}/webrtc/ice.cpp)
_wire_target(sdp)
boltapi_add_fuzz_target(sctp SOURCE sctp.cpp
    INSTRUMENT ${_src}/webrtc/sctp.cpp ${_src}/webrtc/data_channel.cpp)
_wire_target(sctp)
boltapi_add_fuzz_target(media SOURCE media.cpp)
_wire_target(media)

if(BOLTAPI_WITH_PG_WIRE)
    set(_pg ${_src}/proto/postgres_wire_server.cpp ${_src}/proto/postgres_wire_extended.cpp
            ${_src}/proto/postgres_wire_codec.cpp ${_src}/proto/postgres_wire_cursor.cpp)
    boltapi_add_fuzz_target(pg_codec SOURCE pg_codec.cpp
        INSTRUMENT ${_src}/proto/postgres_wire_codec.cpp)
    _wire_target(pg_codec)
    if(NOT WIN32)
        boltapi_add_fuzz_target(pg_session SOURCE pg_session.cpp INSTRUMENT ${_pg})
        _wire_target(pg_session)
    endif()
endif()

if(BOLTAPI_WITH_NEO4J_BOLT)
    boltapi_add_fuzz_target(packstream SOURCE packstream.cpp
        INSTRUMENT ${_src}/proto/neo4j_bolt_packstream.cpp)
    _wire_target(packstream)
    boltapi_add_fuzz_target(neo4j_values SOURCE neo4j_values.cpp
        INSTRUMENT ${_src}/proto/neo4j_bolt_packstream.cpp
                   ${_src}/proto/neo4j_values.cpp)
    _wire_target(neo4j_values)
    if(NOT WIN32)
        boltapi_add_fuzz_target(neo4j_session SOURCE neo4j_session.cpp
            INSTRUMENT ${_src}/proto/neo4j_bolt_packstream.cpp
                       ${_src}/proto/neo4j_bolt_server.cpp)
        _wire_target(neo4j_session)
    endif()
endif()

if(BOLTAPI_WITH_FLIGHT_SQL)
    set(_fl ${_src}/proto/flight_sql_codec.cpp ${_src}/proto/flight_sql_params.cpp)
    boltapi_add_fuzz_target(flight_codec SOURCE flight_codec.cpp INSTRUMENT ${_fl})
    _wire_target(flight_codec)
    boltapi_add_fuzz_target(flight_params SOURCE flight_params.cpp INSTRUMENT ${_fl})
    _wire_target(flight_params)
    if(NOT WIN32 AND TARGET bolt::ingest)
        boltapi_add_fuzz_target(flight_session SOURCE flight_session.cpp
            INSTRUMENT ${_fl} ${_src}/proto/flight_sql_server.cpp
                       ${_src}/proto/flight_sql_arrow.cpp ${_src}/proto/flight_sql_metadata.cpp)
        _wire_target(flight_session)
        target_link_libraries(${_wire_last} PRIVATE bolt::ingest)
    endif()
endif()

# A regression whose bug is a hang must fail the replay, not stall ctest.
foreach(_t sctp stun_turn media sdp)
    if(TEST boltapi_fuzz_replay_${_t})
        set_tests_properties(boltapi_fuzz_replay_${_t} PROPERTIES TIMEOUT 60)
    endif()
endforeach()
