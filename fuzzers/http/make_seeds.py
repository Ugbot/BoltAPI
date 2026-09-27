#!/usr/bin/env python3
"""Regenerate the committed seed corpora under fuzzers/http/corpus/.

Seeds are the wire shapes the protocol tests already send (tests/*.cpp) plus
the RFC 7541 Appendix C HPACK examples. Deterministic: rerunning rewrites the
same files. Usage: python3 fuzzers/http/make_seeds.py
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")


def put(target, name, data):
    d = os.path.join(CORPUS, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def chunked(body, size, trailer=b""):
    out = b""
    for i in range(0, len(body), size):
        c = body[i:i + size]
        out += b"%x;ext=1\r\n" % len(c) + c + b"\r\n"
    return out + b"0\r\n" + trailer + b"\r\n"


REQUESTS = {
    "get_health": b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
    "get_query": b"GET /users/42?expand=true HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n",
    "post_login": b"POST /api/v1/login HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
    "post_chunked": b"POST /d HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + chunked(b"0123456789abcdef", 5, b"x-amz-checksum-crc64nvme: AAAA\r\n"),
    "expect_continue": b"PUT /s3/b/k HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"
                       b"Content-Length: 3\r\n\r\nabc",
    "ws_upgrade": b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                  b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                  b"Sec-WebSocket-Version: 13\r\n\r\n",
    "sse": b"GET /events HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n",
    "http10": b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    "delete": b"DELETE /users/7 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
}


def http1():
    for name, req in REQUESTS.items():
        put("http1_request", name, b"\x00" + req)
    pipe = REQUESTS["get_health"] + REQUESTS["post_login"] + REQUESTS["post_chunked"]
    put("http1_request", "pipelined", b"\x07" + pipe)
    put("http1_chunked", "small", chunked(b"hello world", 3))
    put("http1_chunked", "trailer", chunked(b"abc", 1, b"x-t: 1\r\n"))
    put("http1_chunked", "empty", b"0\r\n\r\n")
    put("http1_response", "ok", b"\x00HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                b"Content-Length: 4\r\n\r\nPONG")
    put("http1_response", "close", b"\x03HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
                                   b"Content-Length: 0\r\n\r\n")


# RFC 7541 C.3 / C.4 / C.5 header blocks.
C3 = [bytes.fromhex("828684410f7777772e6578616d706c652e636f6d"),
      bytes.fromhex("828684be58086e6f2d6361636865"),
      bytes.fromhex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")]
C4 = [bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"),
      bytes.fromhex("828684be5886a8eb10649cbf"),
      bytes.fromhex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")]
C5 = [bytes.fromhex("4803333032580770726976617465611d4d6f6e2c203231204f637420323031"
                    "332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d"
                    "706c652e636f6d"),
      bytes.fromhex("4803333037c1c0bf")]


def rec(op, payload):
    return bytes([op]) + struct.pack(">H", len(payload)) + payload


def hpack():
    put("hpack", "c3", b"".join(rec(0, b) for b in C3))
    put("hpack", "c4", b"".join(rec(0, b) for b in C4))
    put("hpack", "c5_resize", b"\x02\x01\x00" + b"".join(rec(0, b) for b in C5))
    put("hpack", "size_update", rec(0, b"\x3f\xe1\x1f" + C3[0]))
    put("huffman", "www", b"\x10" + bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff"))
    put("huffman", "nocache", b"\x10" + bytes.fromhex("a8eb10649cbf"))
    put("huffman", "custom", b"\x10" + bytes.fromhex("25a849e95bb8e8b4bf"))


def frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", sid) + payload


def settings(*pairs):
    return frame(4, 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in pairs))


def h2():
    get = frame(1, 0x5, 1, C3[0])                      # HEADERS END_STREAM|END_HEADERS
    post = frame(1, 0x4, 3, C3[2]) + frame(0, 0x1, 3, b"hello")
    seeds = {
        "get": settings((3, 100), (4, 65535)) + get,
        "post": settings() + frame(4, 1, 0, b"") + post,
        "ping": settings() + frame(6, 0, 0, b"12345678"),
        "window": settings() + frame(8, 0, 0, struct.pack(">I", 1 << 20)) + get,
        "continuation": settings() + frame(1, 0x1, 1, C3[0][:3]) + frame(9, 0x4, 1, C3[0][3:]),
        "rst": settings() + frame(1, 0x4, 1, C3[0]) + frame(3, 0, 1, struct.pack(">I", 8)),
        "priority": settings() + frame(2, 0, 1, b"\x00\x00\x00\x03\x10") + get,
        "goaway": settings() + get + frame(7, 0, 0, struct.pack(">II", 1, 0) + b"bye"),
        "padded": settings() + frame(1, 0x4 | 0x8 | 0x1, 1, b"\x02" + C3[0] + b"\0\0"),
        "big_window_body": settings((4, 1 << 20)) + frame(8, 0, 0, struct.pack(">I", 1 << 24)) + get,
    }
    for name, body in seeds.items():
        put("h2_connection", name, b"\x00\x00" + body)
    put("h2_connection", "big_body", b"\x05\x0a" + seeds["get"])
    put("h2_frame", "settings", settings((1, 4096), (4, 65535)))
    put("h2_frame", "headers", frame(1, 0x24, 1, b"\x00\x00\x00\x03\x10" + C3[0]))
    put("h2_frame", "data_padded", frame(0, 0x9, 1, b"\x03abc\0\0\0"))
    put("h2_frame", "goaway", frame(7, 0, 0, struct.pack(">II", 5, 1) + b"dbg"))
    put("h2_frame", "ping", frame(6, 0, 0, b"abcdefgh"))
    put("h2_frame", "push", frame(5, 0x4, 1, struct.pack(">I", 2) + C3[0]))


def sse():
    put("sse", "event", b"42\xffupdate\xffline one\nline two\xffkeep-alive")
    put("sse", "data_only", b"\xff\xff{\"a\":1}\xff")
    put("sse", "terminators", b"7\xfftick\xffa\r\nb\rc\xffhi\nevent: forged")


if __name__ == "__main__":
    sse()
    http1()
    hpack()
    h2()
