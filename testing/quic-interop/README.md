# QUIC interop runner endpoint

`Dockerfile` builds `boltapi-qns`, a server endpoint for
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner):
`boltapi_quic_interop_server` (examples/quic_interop_server.cpp) serves `/www`
over HTTP/3 on UDP 443. Only `TESTCASE=http3` is implemented; every other case
exits 127, which the runner reports as unsupported.

`run_interop.sh` runs the runner itself inside `boltapi-qir-runner`
(`Dockerfile.runner`: tshark 4.4 + compose 2.39) against the host daemon, so
nothing is installed on the host. The runner hardcodes `/tmp` for its bind
mounts, so host `/tmp` is mounted into that container and the workdir must be
under `/tmp`.

```sh
docker build -f testing/quic-interop/Dockerfile -t boltapi-qns .
docker build -f testing/quic-interop/Dockerfile.runner -t boltapi-qir-runner testing/quic-interop
testing/quic-interop/run_interop.sh /tmp/qir            # quic-go,ngtcp2; H,DC,S,R,M,Z,3
```

## Results (2026-09-27, runner 740c05a, arm64)

| client  | ✓ | ? (unsupported)   | ✕ |
|---------|---|-------------------|---|
| quic-go | – | H, DC, S, R, M, Z | 3 |
| ngtcp2  | – | H, DC, S, R, M, Z | 3 |

- http3: the QUIC + TLS handshake, QPACK and H3 exchange complete with both
  clients; the case fails on the runner's 512000-byte file. Before G2ETL-141
  the body was silently cut at ~256 KiB and FINed (quic-go exited 0 with a short
  file); now the server answers 500. Large responses need streaming send
  (G2ETL-141, open).
- H/DC/S/R/M/Z: unsupported (no hq-interop ALPN, Retry not enabled by App, no
  session tickets or 0-RTT). G2ETL-142.
