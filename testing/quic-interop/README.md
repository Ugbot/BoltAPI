# QUIC interop runner endpoint

`Dockerfile` builds `boltapi-qns`, a server endpoint for
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner):
`boltapi_quic_interop_server` (examples/quic_interop_server.cpp) serves `/www`
on UDP 443 over h3 and hq-interop (HTTP/0.9, which the runner's transport
cases use). `run_endpoint.sh` maps `TESTCASE` to server options: `retry` adds
`--retry`, `zerortt` adds `--early-data`, and `/certs/{cert.pem,priv.key}` are
presented when present. Unlisted cases exit 127 (unsupported). The client role
is not implemented.

`run_interop.sh` runs the runner itself inside `boltapi-qir-runner`
(`Dockerfile.runner`: tshark 4.4 + compose 2.39) against the host daemon, so
nothing is installed on the host. The runner hardcodes `/tmp` for its bind
mounts, so host `/tmp` is mounted into that container and the workdir must be
under `/tmp`.

```sh
docker build -f testing/quic-interop/Dockerfile -t boltapi-qns .
docker build -f testing/quic-interop/Dockerfile.runner -t boltapi-qir-runner testing/quic-interop
testing/quic-interop/run_interop.sh /tmp/qir            # quic-go,ngtcp2; H,DC,S,R,M,Z,3
testing/quic-interop/run_interop.sh /tmp/qir quic-go chacha20,keyupdate,handshakeloss
```

`local_client.py` (aioquic) runs the same server-facing cases against a local
`boltapi_quic_interop_server` without docker:
`local_client.py --port P --www DIR --case {handshake,transfer,multiplexing,retry,resumption,zerortt,http3}`.

## Results (2026-09-27, runner 740c05a, arm64)

| client  | ✓                                            | ? | ✕ |
|---------|----------------------------------------------|---|---|
| quic-go | H, DC, S, R, M, Z, 3, C20, U, L1, L2, C1, C2 | – | – |
| ngtcp2  | H, DC, S, R, M, Z, 3, C20, U, L1, L2, C1, C2 | – | – |

H handshake, DC transfer, S retry, R resumption, M multiplexing, Z zerortt,
3 http3, C20 chacha20, U keyupdate, L1/L2 handshake/transfer loss, C1/C2
handshake/transfer corruption. Not run: amplificationlimit, blackhole, ecn,
rebinding, connectionmigration, ipv6 (the UDP transport binds IPv4 only), v2,
goodput/crosstraffic.

What each case needed (G2ETL-141/142):

- http3 (512000-byte file): streaming send. A stream's send buffer is a ring
  that releases acknowledged bytes; a body larger than it is held and fed in as
  ACKs arrive; FIN only after the last byte (50 MB tested in
  `Http3App.StreamsFiftyMegabyteResponse`).
- handshake/transfer/multiplexing: hq-interop ALPN; finished streams return to
  the pool and MAX_STREAMS credit follows closures (1999 files on one
  connection; initial_max_streams_bidi 48 for hq-interop, 8 for h3).
- retry: `App::http3_require_retry()`; the handshake echoes the original DCID
  and retry_source_connection_id.
- resumption: one server SSL_CTX (tickets decrypt across connections, stateless)
  and CRYPTO at 1-RTT for NewSessionTicket.
- zerortt: `App::http3_early_data()`; 0-RTT packets are opened with the early
  keys (held when coalesced ahead of TLS); tickets advertise early data only
  when it is enabled; the server waits for the client's Finished before
  HANDSHAKE_DONE. 0-RTT requests are replayable: enable only for idempotent
  routes.
- handshakeloss: Initial/Handshake keys are discarded (RFC 9001 §4.9) and a
  duplicate client Initial resends the flight (RFC 9002 §6.2.3).
