# Fixed-length responses

`Response::send_fixed` declares an identity-framed response of exactly `n`
bytes: `Content-Length: n`, with no `Transfer-Encoding`. The producer must emit
exactly that many bytes. A sink write that would exceed the declaration is
refused; the overrun is sticky, so later sink calls cannot fill the declaration
and turn the response into success. Do not retain the sink or call it
concurrently.

## Transport behavior

| Transport | Preparation and mismatch behavior |
|---|---|
| Cleartext HTTP/1.1 | Incremental socket streaming. Headers are sent before the producer runs. A length mismatch closes the connection; refused surplus bytes are never sent. The producer runs on an existing blocking worker and sends through one startup-allocated slice with backpressure. If no worker slot is available, the server sends 503 before fixed headers. |
| TLS H1/H2 | Materializes before publishing success headers, bounded by startup `max_fixed_materialization_bytes` (default 16 MiB). An over-cap declaration refuses before invoking the producer. A short or overlong body, or cap refusal, becomes a fresh empty 500 with no original body or representation metadata. A raised cap must remain finite and no larger than the public fixed-response limit. |
| HTTP/3 | Not covered by this policy. HTTP/3 is disabled in the current build and fixed-response behavior remains separately unqualified. Do not infer H1/H2 guarantees for H3. |

For H1/H2, `HEAD`, `204` and `304` skip the producer and skip the materialization
cap. They emit no body. Only legal representation metadata is retained: `HEAD`
and `304` may retain a legal content length, while `204` removes content length
and transfer framing.

Cleartext H1's void sink suppresses later writes after a peer disconnect, but
cannot cancel arbitrary producer code. The producer must finish bounded work
and keep its captured context valid until it returns. TLS H1/H2 materialization
limits retained response bytes; it does not bound producer CPU/time, aggregate
memory across concurrent responses, or guarantee recovery from allocation
failure. It is not incremental TLS/H2 transport streaming. There is no implicit
retry or producer replay.

## Configuration and ABI

`CoroUnifiedServerConfig::max_fixed_materialization_bytes` is startup
configuration, defaulting to 16 MiB. Zero and values above the 1 TiB maximum
fixed response limit are refused before listener or worker creation. Each
materialized declaration must also fit `std::string::max_size()` before reserve.
Append-only config changes still change its C++ layout:
rebuild the BoltAPI library and every consumer against the same header revision.
Do not mix old and new binaries.

`send_fixed` and its producer signature did not change. The documented
transport behavior is H1/H2 only; the current HTTP/3 source path has separate
source-derived fixed-body and bodyless-response issues and no matching runtime
qualification.

## Server HTTP/2 GOAWAY cutoff

The server advertises the highest peer stream ID it actually admitted, not the
largest ID merely observed or refused. After sending GOAWAY, the cutoff is
monotone nonincreasing: repeated, fatal, and connection-error GOAWAY frames
cannot raise it. Refused streams do not extend the accepted-stream drain set.
This is server-side graceful drain state; it adds no retry or replay policy and
does not change the single-owner-per-connection rule. The private
`Http2Connection` layout changed, so rebuild the library and all consumers with
the matching header.

## Verification status

The earlier macOS-native checkpoint recorded 70 BoltAPI cases passing, including
the existing fixed-stream and HTTP/2 client coverage. It predates the current
fixed-materialization and outgoing GOAWAY changes.

The final combined repository gate passed 127/127 CTest targets in 139.36
seconds, with 709 GoogleTest executions: 707 passed and two Azure/GCS emulator
cases skipped. The BoltAPI subset passed all 87 cases with no skips. All four
repository source-binding manifests and 49 executable bindings were verified
unchanged. The current fixed-materialization fixtures check pre-header empty-500
behavior, no producer invocation for bodyless/cap-refused responses,
connection/stream reuse, and the admitted-stream GOAWAY cutoff.

The companion Bolt S3 client/native SST fixture's final v5 run passed in 0.403
seconds. This invokes the owned S3 client directly, not a BoltAPI server. Its
signed `HEAD ?partNumber=1` reported five parts, an 8,388,608-byte first part,
and HTTP 206. The 34,508,928-byte MBLT SST's 32,768 rows and 256-wide vectors
matched bit-for-bit after download, with complete SHA-256
`a8228982c5d861265e2ccb30f449c38b1f1f63ff034711a090bfe9eceb3506b4`.

Windows/Linux, live HTTP/3, Flight, and performance qualification remain
separate gates.
