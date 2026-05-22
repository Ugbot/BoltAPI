# Response Compression (M2)

Bolt API ships a small codec **seam** for HTTP response compression. Today the
only codec is **gzip**, and the gzip backend is a **stopgap built on zlib**.

## Why a stopgap

Repo deps policy: *prefer Bolt over third-party*. Bolt currently has **no
compression codec**. Rather than block M2, we added a clean seam
(`include/boltapi/compression.h` / `src/compression.cpp`) whose public surface is
backend-agnostic, and wired a zlib backend behind a compile-time gate.

**TODO (Bolt-native):** replace the zlib `deflateInit2(... windowBits=15|16 ...)`
body of `compression::gzip_encode()` with a Bolt-native deflate/gzip codec when
one lands, and drop the zlib `find_package`/link. The header/middleware surface
and tests stay unchanged — only the encoder body and the CMake gating change.

## Build gating

Root `CMakeLists.txt`:

```
option(BOLTAPI_WITH_GZIP "gzip response compression (zlib stopgap)" ON)
find_package(ZLIB)   # QUIET
```

- `BOLTAPI_WITH_GZIP=ON` **and** ZLIB found → `BOLTAPI_HAVE_GZIP=1` defined
  (PUBLIC) on the `boltapi` target, links `ZLIB::ZLIB`. gzip is **active**.
- otherwise → `BOLTAPI_HAVE_GZIP=0`. The codec degrades to **graceful identity**:
  `compression::gzip_available()` is `false` and the middleware passes bodies
  through unchanged.

CMake prints the resolved state, e.g.:

```
-- Bolt API gzip: ENABLED (zlib 1.3.1 — stopgap; Bolt-native codec TODO)
-- Bolt API gzip: DISABLED (zlib not found; identity passthrough)
```

> On the current Windows dev machine zlib is **not installed**, so gzip builds in
> identity mode. The compression test passes in both modes via `#if BOLTAPI_HAVE_GZIP`.

## Middleware

When `App::Config.enable_compression` is set, App appends a built-in compression
middleware as the **last link** of the chain, so it runs **innermost** (closest
to the handler) and observes the final response body. It compresses only when:

- a real gzip backend is compiled in (`BOLTAPI_HAVE_GZIP`), and
- the request's `Accept-Encoding` lists `gzip` (q≠0; `*` accepted), and
- the response body exceeds **256 bytes**, and
- no `Content-Encoding` is already set.

On success it replaces the body with the gzip stream and sets
`Content-Encoding: gzip`, fixes `Content-Length`, and adds
`Vary: Accept-Encoding`. Otherwise the body passes through untouched.

## Tests

`tests/compression_test.cpp` runs end-to-end against a real App and is dual-mode:

- `BOLTAPI_HAVE_GZIP==1`: asserts `Content-Encoding: gzip` and that the body
  decompresses back to the original.
- `BOLTAPI_HAVE_GZIP==0`: asserts no `Content-Encoding` and the plain body.

In both modes it asserts that a request **without** `Accept-Encoding` and a
**sub-threshold** body are never compressed, plus a unit test of the
`Accept-Encoding` parser.

## Future codecs

`BOLTAPI_WITH_BROTLI` / `BOLTAPI_WITH_ZSTD` options exist but are off and unwired.
They would slot into the same seam (add `br_encode`/`zstd_encode`, extend the
middleware's coding negotiation).
