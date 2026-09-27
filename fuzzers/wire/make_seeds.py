#!/usr/bin/env python3
"""Writes the wire harnesses' seed corpora (fuzzers/wire/corpus/<target>/).

Seeds mirror the traffic the protocol tests and real clients send. The
flight_params / flight_session IPC seeds need pyarrow (skipped without it).
Usage: make_seeds.py [out_dir]
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "corpus")


def put(target, name, data):
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


# --------------------------------------------------------------------------
# Postgres wire
# --------------------------------------------------------------------------
def pg_msg(t, body):
    return t + struct.pack(">i", len(body) + 4) + body


def pg_startup(user=b"alice", db=b"db"):
    body = struct.pack(">i", 196608) + b"user\0" + user + b"\0database\0" + db + b"\0\0"
    return struct.pack(">i", len(body) + 4) + body


def cstr(s):
    return s + b"\0"


def pg_parse(name, sql, oids=()):
    return pg_msg(b"P", cstr(name) + cstr(sql) + struct.pack(">h", len(oids)) +
                  b"".join(struct.pack(">i", o) for o in oids))


def pg_bind(portal, stmt, params, fmts=(), rfmts=()):
    b = cstr(portal) + cstr(stmt) + struct.pack(">h", len(fmts))
    b += b"".join(struct.pack(">h", f) for f in fmts)
    b += struct.pack(">h", len(params))
    for p in params:
        b += struct.pack(">i", -1) if p is None else struct.pack(">i", len(p)) + p
    b += struct.pack(">h", len(rfmts)) + b"".join(struct.pack(">h", f) for f in rfmts)
    return pg_msg(b"B", b)


def pg_q(sql):
    return pg_msg(b"Q", cstr(sql))


def pg_seeds():
    t = "pg_session"
    trust, pw = b"\0", b"\1"
    put(t, "simple", trust + pg_startup() + pg_q(b"select 1") + pg_q(b"rows 3") +
        pg_q(b"types") + pg_q(b"") + pg_msg(b"X", b""))
    put(t, "ssl_then_startup", trust + struct.pack(">ii", 8, 80877103) + pg_startup() +
        pg_q(b"SET application_name = 'x'") + pg_q(b"SHOW server_version"))
    put(t, "gss_cancel", trust + struct.pack(">ii", 8, 80877104) +
        struct.pack(">iiii", 16, 80877102, 1, 2))
    put(t, "password", pw + pg_startup() + pg_msg(b"p", b"pw\0") + pg_q(b"select 1"))
    put(t, "bad_password", pw + pg_startup() + pg_msg(b"p", b"nope\0"))
    put(t, "extended", trust + pg_startup() +
        pg_parse(b"s1", b"select $1, $2::int8, $3", (25, 20, 1082)) +
        pg_msg(b"D", b"S" + cstr(b"s1")) +
        pg_bind(b"p1", b"s1", [b"it's", struct.pack(">q", -5), b"2024-02-29"], (0, 1, 0), (1,)) +
        pg_msg(b"D", b"P" + cstr(b"p1")) +
        pg_msg(b"E", cstr(b"p1") + struct.pack(">i", 1)) +
        pg_msg(b"E", cstr(b"p1") + struct.pack(">i", 0)) +
        pg_msg(b"C", b"P" + cstr(b"p1")) + pg_msg(b"C", b"S" + cstr(b"s1")) +
        pg_msg(b"H", b"") + pg_msg(b"S", b""))
    put(t, "extended_unnamed", trust + pg_startup() + pg_parse(b"", b"rows 5") +
        pg_bind(b"", b"", [], (), (1,)) + pg_msg(b"E", cstr(b"") + struct.pack(">i", 2)) +
        pg_msg(b"E", cstr(b"") + struct.pack(">i", 0)) + pg_msg(b"S", b"") +
        pg_parse(b"", b"fail now") + pg_bind(b"", b"", []) +
        pg_msg(b"E", cstr(b"") + struct.pack(">i", 0)) + pg_msg(b"S", b""))
    put(t, "binary_params", trust + pg_startup() +
        pg_parse(b"b", b"select $1,$2,$3,$4,$5,$6", (16, 21, 23, 700, 701, 1700)) +
        pg_bind(b"", b"b", [b"\1", struct.pack(">h", 7), struct.pack(">i", -9),
                            struct.pack(">f", 1.5), struct.pack(">d", -2.25),
                            struct.pack(">hhhh", 2, 0, 0, 2) + struct.pack(">hh", 12, 3400)],
                (1,), (1, 1, 1, 1, 1, 1)) +
        pg_msg(b"E", cstr(b"") + struct.pack(">i", 0)) + pg_msg(b"S", b""))
    put(t, "tx", trust + pg_startup() + pg_q(b"BEGIN") + pg_q(b"ddl insert 1") +
        pg_q(b"SAVEPOINT a") + pg_q(b"ddl insert 2") + pg_q(b"ROLLBACK TO SAVEPOINT a") +
        pg_q(b"RELEASE a") + pg_q(b"COMMIT") + pg_q(b"START TRANSACTION READ ONLY") +
        pg_q(b"ddl x") + pg_q(b"ROLLBACK") + pg_q(b"BEGIN") + pg_q(b"fail") + pg_q(b"select 1") +
        pg_q(b"END"))
    put(t, "cursors", trust + pg_startup() + pg_q(b"BEGIN") +
        pg_q(b"DECLARE c1 CURSOR WITH HOLD FOR select rows 10") + pg_q(b"FETCH 3 FROM c1") +
        pg_q(b"MOVE ABSOLUTE 5 IN c1") + pg_q(b"FETCH ALL c1") + pg_q(b"CLOSE c1") +
        pg_q(b"CLOSE ALL") + pg_q(b"COMMIT"))
    c = "pg_codec"
    put(c, "classify_set", b"\0SET extra_float_digits = 3")
    put(c, "classify_show", b"\0SHOW TimeZone")
    put(c, "classify_tx", b"\0ROLLBACK WORK TO SAVEPOINT \"sp 1\"")
    put(c, "classify_cursor", b"\0DECLARE \"Cur\" NO SCROLL CURSOR WITHOUT HOLD FOR SELECT 1")
    put(c, "substitute", b"\1\3" + bytes([7, 0, 5, 4, 0, 2, 16, 0, 1]) + b"it's" + b"42" + b"t" +
        b"select $1 || '$2' /* $3 */ -- $1\n, $$x$1$$, $2, $3, \"$1\"")
    put(c, "binary", b"\2\4" + bytes([4, 2, 8, 6, 2, 4, 16, 2, 1, 14, 2, 4]) +
        struct.pack(">q", -1) + struct.pack(">i", 7) + b"\1" + struct.pack(">i", -365))
    put(c, "numeric", b"\2\1" + bytes([16, 2, 16]) +
        struct.pack(">hhhh", 3, 1, 0x4000, 4) + struct.pack(">hhh", 1, 2345, 6700))
    put(c, "to_binary", b"\3\5" + bytes([4, 0, 3, 6, 0, 2, 10, 0, 3, 14, 0, 10, 16, 0, 5]) +
        b"-42" + b"77" + b"1.5" + b"2024-02-29" + b"-12.3" + b"SELECT 1")


# --------------------------------------------------------------------------
# PackStream / Neo4j Bolt
# --------------------------------------------------------------------------
def ps_str(s):
    b = s.encode() if isinstance(s, str) else s
    n = len(b)
    if n < 16:
        return bytes([0x80 | n]) + b
    if n < 256:
        return b"\xd0" + bytes([n]) + b
    return b"\xd1" + struct.pack(">H", n) + b


def ps_int(v):
    if -16 <= v < 128:
        return struct.pack(">b", v)
    if -128 <= v < 128:
        return b"\xc8" + struct.pack(">b", v)
    if -32768 <= v < 32768:
        return b"\xc9" + struct.pack(">h", v)
    if -(1 << 31) <= v < (1 << 31):
        return b"\xca" + struct.pack(">i", v)
    return b"\xcb" + struct.pack(">q", v)


def ps_map(d):
    out = bytes([0xA0 | len(d)])
    for k, v in d.items():
        out += ps_str(k) + v
    return out


def ps_list(items):
    return bytes([0x90 | len(items)]) + b"".join(items)


def ps_struct(sig, fields):
    return bytes([0xB0 | len(fields), sig]) + b"".join(fields)


def chunk(msg):
    return struct.pack(">H", len(msg)) + msg + b"\0\0"


def bolt_hs(*versions):
    vs = list(versions) + [0] * (4 - len(versions))
    return b"\x60\x60\xb0\x17" + b"".join(struct.pack(">I", v) for v in vs)


def neo4j_seeds():
    t = "neo4j_session"
    hello = ps_struct(0x01, [ps_map({"user_agent": ps_str("fuzz/1"), "scheme": ps_str("basic"),
                                     "principal": ps_str("neo4j"),
                                     "credentials": ps_str("pw")})])
    hello5 = ps_struct(0x01, [ps_map({"user_agent": ps_str("fuzz/1"),
                                      "bolt_agent": ps_map({"product": ps_str("x")})})])
    logon = ps_struct(0x6A, [ps_map({"scheme": ps_str("basic"), "principal": ps_str("u"),
                                     "credentials": ps_str("p")})])
    run = ps_struct(0x10, [ps_str("RETURN $n AS n"), ps_map({"n": ps_int(3)}), ps_map({})])
    pull = ps_struct(0x3F, [ps_map({"n": ps_int(-1)})])
    pull2 = ps_struct(0x3F, [ps_map({"n": ps_int(2), "qid": ps_int(-1)})])
    discard = ps_struct(0x2F, [ps_map({"n": ps_int(-1)})])
    begin = ps_struct(0x11, [ps_map({"mode": ps_str("r")})])
    commit = ps_struct(0x12, [])
    rollback = ps_struct(0x13, [])
    reset = ps_struct(0x0F, [])
    goodbye = ps_struct(0x02, [])
    logoff = ps_struct(0x6B, [])
    route = ps_struct(0x66, [ps_map({}), ps_list([]), ps_map({})])
    put(t, "v44", bolt_hs(0x00000404) + chunk(hello) + chunk(run) + chunk(pull) + chunk(goodbye))
    put(t, "v54", bolt_hs(0x00040405, 0x00000404) + chunk(hello5) + chunk(logon) + chunk(begin) +
        chunk(run) + chunk(pull2) + chunk(pull2) + chunk(commit) + chunk(logoff) + chunk(goodbye))
    put(t, "reset", bolt_hs(0x00000005) + chunk(hello) + chunk(ps_struct(0x10, [ps_str("FAIL")]))
        + chunk(pull) + chunk(reset) + chunk(run) + chunk(discard) + chunk(route) + chunk(rollback))
    big = ps_map({"n": ps_int(5), "list": ps_list([ps_int(1), b"\xc1" + struct.pack(">d", 2.5),
                                                   b"\xc3", b"\xc2", b"\xc0", b"\xcc\x03abc"])})
    split = chunk(ps_struct(0x10, [ps_str("RETURN 1"), big, ps_map({})]))
    # the same message in two chunks
    m = ps_struct(0x10, [ps_str("RETURN 1"), big, ps_map({})])
    two = struct.pack(">H", 5) + m[:5] + struct.pack(">H", len(m) - 5) + m[5:] + b"\0\0"
    put(t, "chunked", bolt_hs(0x00000404) + chunk(hello) + split + chunk(pull) + two + chunk(pull))
    p = "packstream"
    put(p, "scalars", b"\xc0\xc2\xc3" + ps_int(-17) + ps_int(300) + ps_int(1 << 40) +
        b"\xc1" + struct.pack(">d", 1.25) + ps_str("x" * 20) + ps_str("y" * 300))
    put(p, "containers", ps_map({"a": ps_list([ps_int(1), ps_str("b")]),
                                 "m": ps_map({"k": b"\xc0"})}) +
        b"\xd4\x02" + ps_int(1) + ps_int(2) + b"\xd8\x01" + ps_str("k") + ps_int(1) +
        b"\xcc\x02\x00\x01" + b"\xcd\x00\x01\x09")
    put(p, "structs", ps_struct(0x4E, [ps_int(1), ps_list([ps_str("L")]), ps_map({})]) +
        ps_struct(0x52, [ps_int(1), ps_int(2), ps_int(3), ps_str("T"), ps_map({})]))
    put(p, "wide", b"\xd6\x00\x00\x00\x03" + ps_int(1) + ps_int(2) + ps_int(3) +
        b"\xda\x00\x00\x00\x01" + ps_str("k") + ps_int(0) + b"\xd2\x00\x00\x00\x02hi")


# --------------------------------------------------------------------------
# Flight SQL: protobuf, gRPC, HTTP/2
# --------------------------------------------------------------------------
def varint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def pb_bytes(field, data):
    return varint((field << 3) | 2) + varint(len(data)) + data


def pb_varint(field, v):
    return varint(field << 3) + varint(v)


def any_msg(short, value):
    return pb_bytes(1, b"type.googleapis.com/arrow.flight.protocol.sql." + short) + pb_bytes(2, value)


def descriptor(cmd):
    return pb_varint(1, 2) + pb_bytes(2, cmd)


def grpc(msg):
    return b"\0" + struct.pack(">I", len(msg)) + msg


def h2_frame(t, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([t, flags]) + struct.pack(">I", sid) + payload


def hpack_lit(name, value):
    # literal header field without indexing, new name, no Huffman
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


def grpc_request(sid, method, body, extra=b""):
    hdrs = (b"\x83\x86" + hpack_lit(b":path", b"/arrow.flight.protocol.FlightService/" + method) +
            hpack_lit(b":authority", b"localhost") + hpack_lit(b"content-type", b"application/grpc") +
            hpack_lit(b"te", b"trailers") + extra)
    return h2_frame(1, 4, sid, hdrs) + h2_frame(0, 1, sid, grpc(body))


def ipc_params():
    try:
        import pyarrow as pa
    except ImportError:
        return {}
    out = {}
    def stream(batch):
        sink = pa.BufferOutputStream()
        with pa.ipc.new_stream(sink, batch.schema) as w:
            w.write_batch(batch)
        return sink.getvalue().to_pybytes()
    out["ints"] = stream(pa.record_batch([pa.array([1, -2, None], pa.int64()),
                                          pa.array([3, 4, 5], pa.uint8())], names=["a", "b"]))
    out["mixed"] = stream(pa.record_batch([pa.array(["x'y", None], pa.string()),
                                           pa.array([1.5, float("nan")], pa.float64()),
                                           pa.array([True, None], pa.bool_()),
                                           pa.array([2.5, 3.5], pa.float32()),
                                           pa.array(["big", "s"], pa.large_string()),
                                           pa.array([None, None], pa.null())],
                                          names=list("abcdef")))
    types = pa.array([0, 1, 2], pa.int8())
    offs = pa.array([0, 0, 0], pa.int32())
    u = pa.UnionArray.from_dense(types, offs, [pa.array([7], pa.int64()), pa.array(["s"]),
                                               pa.array([0.5])], ["i", "s", "f"])
    out["union"] = stream(pa.record_batch([u], names=["p"]))
    out["eight"] = stream(pa.record_batch([pa.array([i], pa.int32()) for i in range(8)],
                                          names=[str(i) for i in range(8)]))
    return out


def flight_seeds():
    c = "flight_codec"
    q = any_msg(b"CommandStatementQuery", pb_bytes(1, b"SELECT 3") + pb_bytes(2, b"tx"))
    put(c, "pb", b"\0" + q + pb_varint(5, 1 << 40) + b"\x0d\x01\x02\x03\x04" +
        b"\x09" + b"\0" * 8)
    put(c, "any", b"\1" + q)
    put(c, "descriptor", b"\2" + descriptor(q) + pb_bytes(3, b"path"))
    put(c, "statement", b"\3" + pb_bytes(1, b"SELECT 1") + pb_bytes(2, b"t"))
    put(c, "flightdata", b"\4" + pb_bytes(1, descriptor(q)) + pb_bytes(2, b"\x10\0\0\0") +
        pb_bytes(3, b"meta") + pb_bytes(1000, b"body"))
    put(c, "grpc", b"\5" + grpc(q) + grpc(b"") + b"\1\0\0\0\1x")
    put(c, "base64", b"\6dXNlcjp0b2tlbg==")
    put(c, "handle_unbound", b"\7boltapi-fsql-ps1:SELECT ?")
    put(c, "handle_bound", b"\7boltapi-fsql-ps2:" + b"\x08\0\0\0SELECT ?" + b"\x01\0\0\0" +
        b"\x01" + struct.pack("<q", 5))
    ipc = ipc_params()
    for k, v in ipc.items():
        put("flight_params", k, v)
        put(c, "ipc_" + k, b"\x08" + v)
    t = "flight_session"
    settings = h2_frame(4, 0, 0, b"") + h2_frame(4, 1, 0, b"")
    info = grpc_request(1, b"GetFlightInfo", descriptor(q))
    ticket = pb_bytes(1, any_msg(b"TicketStatementQuery", pb_bytes(1, b"SELECT 3")))
    put(t, "get_flight_info", settings + info + h2_frame(8, 0, 0, struct.pack(">I", 1 << 20)))
    put(t, "do_get", settings + grpc_request(1, b"DoGet", ticket) +
        grpc_request(3, b"GetSchema", descriptor(q)))
    put(t, "actions", settings + grpc_request(1, b"ListActions", b"") +
        grpc_request(3, b"DoAction",
                     pb_bytes(1, b"CreatePreparedStatement") +
                     pb_bytes(2, any_msg(b"ActionCreatePreparedStatementRequest",
                                         pb_bytes(1, b"SELECT ?")))) +
        grpc_request(5, b"DoAction", pb_bytes(1, b"ClosePreparedStatement") +
                     pb_bytes(2, any_msg(b"ActionClosePreparedStatementRequest",
                                         pb_bytes(1, b"boltapi-fsql-ps1:SELECT ?")))))
    put(t, "metadata", settings +
        grpc_request(1, b"GetFlightInfo", descriptor(any_msg(b"CommandGetCatalogs", b""))) +
        grpc_request(3, b"GetFlightInfo", descriptor(any_msg(b"CommandGetTables",
                                                            pb_bytes(4, b"orders")))) +
        grpc_request(5, b"GetFlightInfo", descriptor(any_msg(b"CommandGetSqlInfo", b""))) +
        grpc_request(7, b"GetFlightInfo", descriptor(any_msg(b"CommandGetXdbcTypeInfo", b""))))
    upd = any_msg(b"CommandStatementUpdate", pb_bytes(1, b"UPSERT 4"))
    put(t, "do_put_update", settings + grpc_request(1, b"DoPut",
                                                    pb_bytes(1, descriptor(upd)),
                                                    hpack_lit(b"authorization", b"Bearer t")))
    if "ints" in ipc:
        # DoPut of a parameter batch for a prepared statement
        body = ipc["eight"]
        msgs = []
        pos = 0
        while pos + 8 <= len(body):
            cont, mlen = struct.unpack("<Ii", body[pos:pos + 8])
            if mlen == 0:
                break
            meta = body[pos + 8:pos + 8 + mlen]
            pos += 8 + mlen
            msgs.append(meta)
        prep = any_msg(b"CommandPreparedStatementQuery",
                       pb_bytes(1, b"boltapi-fsql-ps1:SELECT ?"))
        first = pb_bytes(1, descriptor(prep)) + (pb_bytes(2, msgs[0]) if msgs else b"")
        put(t, "do_put_params", settings + h2_frame(1, 4, 1, b"\x83\x86" +
            hpack_lit(b":path", b"/arrow.flight.protocol.FlightService/DoPut") +
            hpack_lit(b"content-type", b"application/grpc")) +
            h2_frame(0, 0, 1, grpc(first)) + h2_frame(0, 1, 1, grpc(pb_bytes(1000, body))))
    put(t, "rst_ping_goaway", settings + h2_frame(6, 0, 0, b"12345678") +
        h2_frame(1, 0, 1, b"\x83\x86") + h2_frame(9, 4, 1, hpack_lit(b":path", b"/x")) +
        h2_frame(3, 0, 1, b"\0\0\0\x08") + h2_frame(7, 0, 0, b"\0\0\0\0\0\0\0\0"))


# --------------------------------------------------------------------------
# WebRTC
# --------------------------------------------------------------------------
CHROME_OFFER = (
    "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
    "a=group:BUNDLE 0 1 2\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS stream0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 110\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:4ZcD\r\na=ice-pwd:2/1muCWoOi3uLifh0NuRHlga\r\na=ice-options:trickle\r\n"
    "a=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n"
    "a=setup:actpass\r\na=mid:0\r\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    "a=sendrecv\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\na=rtcp-fb:111 transport-cc\r\n"
    "a=fmtp:111 minptime=10;useinbandfec=1\r\na=rtpmap:110 telephone-event/48000\r\n"
    "a=ssrc:1111111111 cname:audioCname\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97 102\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:4ZcD\r\n"
    "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlga\r\na=setup:actpass\r\na=mid:1\r\n"
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
    "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
    "a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
    "a=sendonly\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 nack\r\n"
    "a=rtcp-fb:96 nack pli\r\na=rtcp-fb:96 ccm fir\r\na=rtcp-fb:96 goog-remb\r\n"
    "a=rtcp-fb:96 transport-cc\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\n"
    "a=rtpmap:102 H264/90000\r\na=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1\r\n"
    "a=rid:h send\r\na=rid:l send\r\na=simulcast:send h;l\r\n"
    "a=ssrc-group:FID 2222222222 3333333333\r\na=ssrc:2222222222 cname:videoCname\r\n"
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:4ZcD\r\na=ice-pwd:2/1muCWoOi3uLifh0NuRHlga\r\na=setup:actpass\r\na=mid:2\r\n"
    "a=sctp-port:5000\r\na=max-message-size:262144\r\n"
    "a=candidate:1 1 udp 2122260223 192.168.1.2 54321 typ host generation 0\r\n"
    "a=candidate:2 1 udp 1686052607 203.0.113.9 40000 typ srflx raddr 192.168.1.2 rport 54321\r\n"
    "a=end-of-candidates\r\n")

DATA_OFFER = (
    "v=0\no=mozilla 1 0 IN IP4 0.0.0.0\ns=-\nt=0 0\na=fingerprint:sha-256 AA:BB\n"
    "a=ice-ufrag:ff\na=ice-pwd:0123456789abcdef012345\n"
    "m=application 9 DTLS/SCTP 5000\nc=IN IP4 0.0.0.0\na=mid:data\na=sctpmap:5000 webrtc-datachannel 256\n")


def stun_raw(cls, method, attrs, txn=b"T" * 12):
    t = ((method & 0xF80) << 2) | ((method & 0x70) << 1) | (method & 0xF)
    t |= ((cls & 2) << 7) | ((cls & 1) << 4)
    body = b""
    for at, v in attrs:
        body += struct.pack(">HH", at, len(v)) + v + b"\0" * ((4 - len(v) % 4) % 4)
    return struct.pack(">HHI", t, len(body), 0x2112A442) + txn + body


def built(flags, cls, method, attrs):
    out = bytes([1, flags, cls]) + struct.pack(">H", method) + b"B" * 12 + bytes([len(attrs)])
    for at, v in attrs:
        out += struct.pack(">H", at) + bytes([len(v)]) + v
    return out


def rawdg(d):
    return b"\0" + struct.pack(">H", len(d)) + d


def xor_addr(port, ip=(127, 0, 0, 1)):
    return (b"\0\x01" + struct.pack(">H", port ^ 0x2112) +
            bytes(b ^ m for b, m in zip(ip, b"\x21\x12\xa4\x42")))


def webrtc_seeds():
    s = "sdp"
    put(s, "chrome_offer", b"\0" + CHROME_OFFER.encode())
    put(s, "firefox_data", b"\0" + DATA_OFFER.encode())
    put(s, "trickle_json", b"\1" + b'{"candidate":"candidate:1 1 udp 2122260223 10.0.0.1 5000 '
        b'typ host","sdpMid":"0","sdpMLineIndex":0}')
    put(s, "trickle_end", b"\1end-of-candidates")
    put(s, "candidate", b"\1candidate:3 1 udp 41885439 198.51.100.1 3478 typ relay raddr "
        b"203.0.113.9 rport 40000")
    st = "stun_turn"
    prio = (0x0024, struct.pack(">I", 0x6E001EFF))
    ctl = (0x802A, struct.pack(">Q", 99))
    use = (0x0025, b"")
    # ICE-lite: USERNAME + MI + FP, with USE-CANDIDATE
    put(st, "lite_binding", b"\1" + built(0x0D, 0, 1, [prio, ctl, use]) + rawdg(
        stun_raw(0, 1, [(0x0006, b"ufrg:rmtu"), (0x0020, xor_addr(5000))])))
    put(st, "codec_resp", b"\0" + rawdg(stun_raw(2, 1, [(0x0020, xor_addr(4000)),
                                                    (0x0001, b"\0\x01\x0f\xa0\x7f\0\0\1"),
                                                    (0x0020, b"\0\x02" + b"\0" * 18)])))
    put(st, "full_ice", b"\2" + built(0x0D, 0, 1, [prio, (0x8029, struct.pack(">Q", 5))]) +
        built(0x0C, 2, 1, [(0x0020, xor_addr(40000))]) + built(0x0C, 3, 1,
                                                               [(0x0009, b"\0\0\x04\x07conflict")]))
    req_tr = (0x0019, b"\x11\0\0\0")
    put(st, "turn_alloc", b"\3" + built(0x08, 0, 3, [req_tr]) + built(0x0F, 0, 3, [req_tr]) +
        built(0x0F, 0, 8, [(0x0012, xor_addr(6000))]) +
        built(0x0F, 0, 9, [(0x000C, b"\x40\0\0\0"), (0x0012, xor_addr(6000))]) +
        built(0x08, 1, 6, [(0x0012, xor_addr(6000)), (0x0013, b"hello")]) +
        rawdg(b"\x40\0\0\x03abc\0") + b"\2" + struct.pack(">H", 4) + b"data" +
        built(0x0F, 0, 4, [(0x000D, b"\0\0\0\0")]))
    put(st, "turn_client", b"\4" + built(0x0A, 3, 3, [(0x0009, b"\0\0\x04\x01Unauthorized")]) +
        built(0x0C, 2, 3, [(0x0016, xor_addr(7000)), (0x0020, xor_addr(7001)),
                           (0x000D, b"\0\0\x02\x58")]) +
        built(0x08, 1, 7, [(0x0012, xor_addr(6000)), (0x0013, b"relayed")]) +
        rawdg(b"\x40\0\0\x02hi\0\0"))
    # SCTP: handshake then DCEP open + messages
    sc = "sctp"
    dcep_open = (b"\x03\x00" + struct.pack(">HIHH", 0, 0, 4, 0) + b"chat")
    def usermsg(sid, ppid_idx, data, op=1):
        return bytes([op]) + struct.pack(">H", sid) + bytes([ppid_idx]) + struct.pack(">H", len(data)) + data
    put(sc, "open_and_talk", b"\1" + usermsg(0, 0, dcep_open) + usermsg(0, 1, b"hello") +
        usermsg(0, 2, b"\0\1\2") + b"\4" + struct.pack(">H", 3) + b"srv" + b"\3\x13\x88")
    put(sc, "client_open", b"\1\2\x04chat" + usermsg(1, 1, b"x" * 3000) + usermsg(1, 3, b"")
        + usermsg(1, 1, b"u", op=0x11))
    common = struct.pack(">HHI", 5000, 5000, 0) + b"\0\0\0\0"
    init = common + struct.pack(">BBH", 1, 0, 20) + struct.pack(">IIHHI", 0x1234, 65536, 1024, 1024, 1)
    data_chunk = struct.pack(">BBH", 0, 3, 16 + 4) + struct.pack(">IHHI", 1, 0, 0, 51) + b"abcd"
    sack = struct.pack(">BBH", 3, 0, 16) + struct.pack(">IIHH", 0, 65536, 0, 0)
    fwd = struct.pack(">BBH", 192, 0, 8) + struct.pack(">I", 5)
    put(sc, "raw_init", b"\0\0" + struct.pack(">H", len(init)) + init)
    raw = common + data_chunk + sack + fwd
    put(sc, "raw_established", b"\1\x10" + struct.pack(">H", len(raw)) + raw)
    # media
    md = "media"
    def rtp(seq, pt=96, ssrc=0x11111111, ext=b"", payload=b"payload"):
        x = 0x90 if ext else 0x80
        h = struct.pack(">BBHII", x, pt, seq, 1000 + seq, ssrc)
        if ext:
            h += b"\xbe\xde" + struct.pack(">H", len(ext) // 4) + ext
        return h + payload
    ext = b"\x31\x00\x05\x22\x01\x02\x03\x00"   # tcc id 3 (2 bytes), abs-send id 2 (3 bytes)
    sr = struct.pack(">BBHI", 0x80, 200, 6, 0x42) + b"\0" * 20
    rr = struct.pack(">BBHI", 0x81, 201, 7, 0x42) + struct.pack(">IIIIII", 0x11111111, 0, 5, 0, 0, 0)
    nack = struct.pack(">BBHII", 0x81, 205, 3, 0x42, 0x11111111) + struct.pack(">HH", 2, 0x0003)
    pli = struct.pack(">BBHII", 0x81, 206, 2, 0x42, 0x11111111)
    sdes = struct.pack(">BBHI", 0x81, 202, 3, 0x42) + b"\x01\x03abc\0"
    twcc = struct.pack(">BBHII", 0x8F, 205, 5, 0x42, 0x11111111) + struct.pack(">HHI", 1, 3, 0x00000100) + b"\x20\x03\x04\x04\x04\0\0\0"
    def rec(kind, b):
        return bytes([kind]) + struct.pack(">H", len(b)) + b
    put(md, "plain", b"\0" + rec(0, rtp(1, ext=ext)) + rec(0, rtp(4)) + rec(1, sr + rr + sdes) +
        rec(1, nack + pli))
    put(md, "srtp_roundtrip", b"\2" + rec(2, rtp(1)) + rec(2, rtp(2, ext=ext)) + rec(4, rr + nack))
    put(md, "gcm_svc", b"\5" + rec(2, rtp(1, pt=97, ssrc=0x22222222, payload=b"\0\1orig")) +
        rec(4, twcc) + rec(3, rtp(9) + b"\0" * 16) + rec(5, rr + b"\x80\0\0\1" + b"\0" * 16))
    put(md, "fec_twcc", b"\0" + rec(6, b"\x80\x60\0\x01\0\0\0\0\0\x05" + b"\0\x03\x80\0" + b"xyz") +
        rec(7, struct.pack(">HHI", 1, 3, 0x00000100) + b"\x20\x03\x04\x04\x04\0\0\0"))


def dtls_seeds():
    """A real DTLS 1.2 ClientHello captured from `openssl s_client` (skipped
    when openssl is absent)."""
    import shutil
    import socket
    import subprocess
    if shutil.which("openssl") is None:
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(5)
    p = subprocess.Popen(["openssl", "s_client", "-dtls1_2", "-connect",
                          "127.0.0.1:%d" % s.getsockname()[1], "-use_srtp",
                          "SRTP_AES128_CM_SHA1_80"], stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        d, _ = s.recvfrom(4096)
    except socket.timeout:
        return
    finally:
        p.kill()
    rec = lambda peer: bytes([peer]) + struct.pack(">H", len(d)) + d
    put("dtls", "client_hello", b"\0" + rec(1) + rec(2) + rec(1))
    put("dtls", "client_hello_fp", b"\1" + rec(1) + rec(2) + rec(1))


def main():
    dtls_seeds()
    pg_seeds()
    neo4j_seeds()
    flight_seeds()
    webrtc_seeds()


if __name__ == "__main__":
    main()
