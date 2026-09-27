#!/usr/bin/env python3
"""Write the small seed corpora for the quic-ws fuzz targets (deterministic)."""
import os, struct, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")

def put(target, name, data):
    d = os.path.join(ROOT, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(bytes(data))

def varint(v):
    if v < 64: return bytes([v])
    if v < 16384: return struct.pack(">H", 0x4000 | v)
    if v < 2**30: return struct.pack(">I", 0x80000000 | v)
    return struct.pack(">Q", 0xC000000000000000 | v)

def chunk(b):  # fuzz_input.h chunk(): u16 length + bytes
    return struct.pack(">H", len(b)) + b

# --- QPACK field sections (static refs + literals) ---
def qstr(s, prefix_bits, first_bits=0):
    b = s.encode()
    assert len(b) < (1 << prefix_bits) - 1
    return bytes([first_bits | len(b)]) + b

GET = bytes([0, 0, 0xD1, 0xC1, 0xD7]) + bytes([0x50]) + qstr("localhost", 7)
POST = bytes([0, 0, 0xD4, 0xC1, 0xD7, 0x50]) + qstr("localhost", 7) + \
       bytes([0x20 | 7]) + b"x-trace" + qstr("abc", 7)
CONNECT = bytes([0, 0, 0xCF, 0xD7, 0x50]) + qstr("localhost", 7) + bytes([0xC1]) + \
          bytes([0x20 | 7]) + b":protoc"  # truncated name on purpose
WT = bytes([0, 0, 0xCF, 0xD7, 0x50]) + qstr("localhost", 7) + bytes([0xC1, 0x27, 0x02]) + \
     b":protocol" + qstr("webtransport", 7)
ENC_INSERT = bytes([0x3f, 0xe1, 0x1f]) + bytes([0xC0 | 0]) + qstr("h.example", 7) + \
             bytes([0x40 | 3]) + b"foo" + qstr("bar", 7)

def h3frame(t, payload):
    return varint(t) + varint(len(payload)) + payload

SETTINGS = varint(0) + h3frame(0x04, varint(0x01) + varint(0) + varint(0x07) + varint(0))

# qpack target: [kind][chunk]...
put("qpack", "get", bytes([1]) + chunk(GET))
put("qpack", "post", bytes([1]) + chunk(POST))
put("qpack", "wt", bytes([1]) + chunk(WT))
put("qpack", "enc_then_ref", bytes([0]) + chunk(ENC_INSERT) + bytes([1]) + chunk(bytes([2, 0, 0x80])))
put("qpack", "huff", bytes([2]) + chunk(bytes([0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff])))

# h3_stream target: [op][sel][chunk]...  op%8: 0..5 stream write, 6 pump, 7 datagram
def sw(slot, fin, data):
    return bytes([0, slot | (0x80 if fin else 0)]) + chunk(data)
put("h3_stream", "get", sw(8, False, SETTINGS) + sw(0, True, h3frame(1, GET)))
put("h3_stream", "post", sw(0, False, h3frame(1, POST)) + sw(0, True, h3frame(0, b"hello body")))
put("h3_stream", "wt", sw(4, False, h3frame(1, WT)) + bytes([7]) + chunk(varint(1) + b"dgram") +
    sw(8, False, varint(0x41) + varint(4) + b"wtdata"))
put("h3_stream", "encoder", sw(9, False, varint(2) + ENC_INSERT) + sw(0, True, h3frame(1, GET)))

# quic_conn target: [flags][op][...]  op%6: 0 c->s frames, 1 s->c, 2 raw->s, 3 raw->c, 4 tick, 5 pump
def frames(to_server, level, payload):
    return bytes([0 if to_server else 1, level]) + chunk(payload)
ping = bytes([0x01])
ack = bytes([0x02]) + varint(0) + varint(0) + varint(0) + varint(0)
stream = bytes([0x0e]) + varint(0) + varint(0) + varint(5) + b"hello"
crypto = bytes([0x06]) + varint(0) + varint(4) + b"\x01\x00\x00\x00"
put("quic_conn", "est_ping", bytes([1]) + frames(True, 2, ping) + bytes([5]))
put("quic_conn", "est_stream", bytes([1]) + frames(True, 2, stream + ack) + frames(False, 2, stream))
put("quic_conn", "initial_crypto", bytes([2]) + frames(True, 0, crypto + ping) + bytes([4]))
put("quic_conn", "raw_initial", bytes([0, 2]) + chunk(bytes([0xc0, 0, 0, 0, 1, 8]) + bytes(8) + bytes([0]) + bytes(1180)))
put("quic_conn", "close", bytes([1]) + frames(True, 2, bytes([0x1c]) + varint(0) + varint(0) + varint(3) + b"bye"))

# quic_packet target: [sel][...] sel%5: varint, headers, frames, tp, pn
put("quic_packet", "varint", bytes([0]) + varint(15293))
put("quic_packet", "long", bytes([1, 0xc3, 0, 0, 0, 1, 8]) + bytes(8) + bytes([8]) + bytes(8) + bytes([0]) + varint(40) + bytes(40))
put("quic_packet", "short", bytes([1, 0x43]) + bytes(24))
put("quic_packet", "ack", bytes([2, 0x02]) + varint(100) + varint(3) + varint(1) + varint(5) + varint(2) + varint(3))
put("quic_packet", "stream", bytes([2, 0x0f]) + varint(4) + varint(10) + varint(3) + b"abc")
put("quic_packet", "tp", bytes([3]) + varint(0x04) + varint(4) + varint(1048576) + varint(0x01) + varint(2) + varint(30000))

# ws targets: client frames are masked
def wsframe(op, payload, fin=True, mask=b"\x11\x22\x33\x44", rsv=0):
    b0 = (0x80 if fin else 0) | rsv | op
    n = len(payload)
    if n < 126: hdr = bytes([b0, 0x80 | n])
    elif n < 65536: hdr = bytes([b0, 0x80 | 126]) + struct.pack(">H", n)
    else: hdr = bytes([b0, 0x80 | 127]) + struct.pack(">Q", n)
    return hdr + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
seed = struct.pack("<I", 0x9e3779b9)
put("ws_conn", "text", seed + wsframe(1, b"hello"))
put("ws_conn", "binary_16bit", seed + wsframe(2, bytes(range(256)) * 2))
put("ws_conn", "fragmented", seed + wsframe(1, b"frag", fin=False) + wsframe(9, b"p") + wsframe(0, b"ment"))
put("ws_conn", "ping_close", seed + wsframe(9, b"ping") + wsframe(8, struct.pack(">H", 1000) + b"bye"))
put("ws_parser", "frame", bytes([0]) + wsframe(1, b"hello") + wsframe(8, b""))
put("ws_parser", "utf8", bytes([1]) + "héllo wörld €𝄞".encode())
put("ws_parser", "close", bytes([2]) + struct.pack(">H", 1001) + b"going away")
put("ws_parser", "subproto", bytes([3]) + b"chat, mqtt , superchat")
print("seeds written to", os.path.normpath(ROOT))
