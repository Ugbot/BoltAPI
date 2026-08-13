# JSON in Bolt API

## Decision: fionn (`bolt::parse::json`) is THE JSON parser

Bolt API parses JSON with **Bolt's own parser, "fionn"**
(`bolt::parse::json`, in `extern/bolt/include/bolt/parse/bolt_json.h` +
`src/parse/bolt_json.cpp`). This is the **single, canonical** JSON path.

There is **no simdjson, no nlohmann, nothing hand-rolled**. Rationale:

- **Bolt-native, zero third-party.** fionn ships inside the `bolt::parse`
  static library we already vendor. No new dependency, no FetchContent, no
  transitive license/ABI surface. It is TigerStyle like the rest of the
  engine: `noexcept` everywhere, no STL in production code, all allocation
  through `bolt::Arena`.
- **Faster than simdjson on Bolt's target workloads.** Per Bolt's research
  log [`extern/bolt/docs/research/json-fionn.md`](https://github.com/Ugbot/bolt/blob/main/docs/research/json-fionn.md),
  fionn's skip-aware architecture reaches 8+ GiB/s (the upstream Rust project
  reports ~29.5x serde_json; the AVX2 path 4–8 GiB/s) by traversing JSON in a
  **single pass** and **never materialising a DOM tree**. Strings and numbers
  are zero-copy slices of the input; numbers are parsed lazily on demand. For
  selective field extraction it does O(1)-ish memory instead of
  O(document-size). The companion note
  [`json-skip-architecture.md`](https://github.com/Ugbot/bolt/blob/main/docs/research/json-skip-architecture.md)
  measures the path-filter skip at ~98.6% token reduction on its synthetic
  benchmark.
- **Right shape for request handling.** A request body is parsed once, fields
  are pulled, the handler returns. fionn's tape + cursor model fits this
  exactly with near-zero allocation.

## fionn's model (what we wrap)

fionn is a **tape-based SAX parser**, not a DOM:

1. `build_index(src, len, arena, &index)` does one linear pass and emits a flat
   array of 12-byte `Token`s into a `bolt::Arena`. Each token is a
   `(TokenType, start, length)` where `start`/`length` index back into the
   **source buffer**. Returns `false` on malformed JSON, invalid UTF-8, depth
   overflow (cap 64), or arena exhaustion — never throws.
2. Strings and object keys are **zero-copy** slices of the source.
3. Numbers are stored as raw byte spans and parsed **lazily** (`iter_int64` /
   `iter_float64` run `strtoll`/`strtod` on demand).
4. An `Iterator` plus `iter_skip_to_close` walks the tape at
   O(tokens-skipped). A `PathFilter` can prune uninteresting subtrees at scan
   time (not used by the request facade yet — see TODO).

## The Bolt API facility — `include/boltapi/json.h` (namespace `bolt::api::json`)

A thin, ergonomic cursor over the tape. **It does not re-implement parsing** —
it delegates to fionn and walks the resulting tape.

```cpp
#include "boltapi/json.h"
namespace json = bolt::api::json;

json::Document doc = json::parse(body);     // body is a std::string_view
if (!doc.ok()) { /* malformed: handle 400 */ }

std::string_view name = doc["name"].as_string();   // zero-copy, aliases body
int64_t          age  = doc["age"].as_int(0);
double            r   = doc["score"].as_double();
bool             on   = doc["active"].as_bool();
bool          absent  = doc["missing"].is_null();

// Nested + arrays
std::string_view city = doc["address"]["city"].as_string("?");
json::Value tags = doc["tags"];
for (auto e = tags.first_element(); e.valid(); e = e.next())
    use(e.value().as_string());
for (auto m = doc.root().first_member(); m.valid(); m = m.next())
    use(m.key(), m.value());
```

### Types

- **`json::Document`** — owns the parse arena (the tape) and the structural
  index. Move-only. `ok()` reports parse success. `root()`, `operator[]`,
  `at(i)` reach into the tree. The arena lives behind a `unique_ptr` because
  `bolt::Arena` is intentionally non-movable; that pointer is the **only** heap
  allocation in the JSON path (the tape itself lives in the arena's
  pre-allocated blocks — no per-token `new`).
- **`json::Value`** — a ~16-byte copyable cursor `(index, token-offset)`. Type
  queries (`is_object/is_array/is_string/is_int/is_double/is_bool/is_null`),
  scalar extraction (`get_string/get_int/get_double/get_bool` returning `bool`,
  plus `as_*` with fallbacks), object access (`member`/`operator[]`/`has`),
  array access (`at(i)`/`size()`), and allocation-free iteration
  (`first_member()`/`Member::next()`, `first_element()/Element::next()`).
- **`json::parse(sv) -> Document`** and
  **`json::parse_checked(sv) -> core::result<Document>`** — entry points. No
  exceptions; malformed input yields `ok()==false` /
  `error_code::parse_error`.
- **`json::is_valid(sv) -> bool`** — a discarding validity probe (defined in
  `src/json.cpp`).

### What it intentionally does NOT do (v1)

- **No escape decoding.** Returned string views are the raw JSON contents
  between the quotes; `\"`, `\\`, `\uXXXX` are **not** unescaped. Typical
  request fields are clean ASCII; callers needing decoding handle it. (fionn
  validates UTF-8 and string structure during the scan, but leaves the bytes
  as-is.)
- **No serializer.** `Response::json(std::string_view)` still just sets
  `Content-Type: application/json` + body; building the response JSON is the
  handler's job. fionn is a parser, not a writer — see TODO for a possible
  builder.

## `Request::json()`

```cpp
app.post("/sum", [](api::Request& req, api::Response& res) {
    auto doc = req.json();
    if (!doc.ok()) { res.bad_request(); return; }
    int64_t a = doc["a"].as_int(), b = doc["b"].as_int();
    res.ok().json("{\"sum\":" + std::to_string(a + b) + "}");
});
```

`Request::json()` parses `req.body()` through the fionn facade and returns a
`json::Document`.

## Lifetime contract (READ THIS)

> **All string/key views returned by a `json::Value` ALIAS the original input
> buffer** passed to `parse()` — they are *not* copied.

For request handling this is safe **by construction**:

- `req.body()` is a view into the engine-owned connection buffer, which is
  **alive for the entire handler invocation**.
- `req.json()` parses that body, so every view fionn produces points into a
  buffer that outlives the handler.
- The `Document` also owns the parse **tape** (its internal arena).

Therefore:

- Keep the `Document` alive (on the handler stack) for as long as you read
  fields from it.
- **Do not** stash a `Document`, a `json::Value`, or any `std::string_view`
  taken from one **past the handler return** — the connection buffer is
  recycled afterward and the views dangle. If you need a value to outlive the
  handler, copy it into an owned `std::string`/integer first.

## Build / link

- `CMakeLists.txt` sets `BOLT_BUILD_PARSE ON` (CACHE FORCE) before
  `add_subdirectory(extern/bolt)`, and links `boltapi` against `bolt::parse`.
- The facade is header-only (`include/boltapi/json.h`); `src/json.cpp` anchors
  the `bolt::parse` link dependency, forces a standalone header compile, and
  hosts `is_valid()`.

## Tests

`tests/json_test.cpp` (registered as `boltapi_json_test`):

- **Unit (11):** object scalars; missing keys + type mismatches return
  fallbacks safely; int-as-double; negative/exponent numbers; nested
  objects/arrays with chained access + iteration; object-member iteration;
  array-of-objects; **malformed input returns an error with no throw/crash**
  (8 malformed shapes); empty containers; `parse_checked` result plumbing;
  a 200-iteration **randomized round-trip** (id/name/ratio/flag).
- **Integration (4):** a real `App` on an ephemeral cleartext HTTP/1.1 port
  driven by a raw client socket (mirrors `app_integration_test`): `/sum` reads
  `req.json()` and adds two ints; `/profile` extracts mixed-type + **nested**
  (`address.city`) + **array** (`roles`) fields; a malformed body returns
  **400**; and a 60-iteration **randomized** body driver.

Full suite: **67/67 ctest green** (52 prior + 15 new).

## TODOs / fionn limitations

- **Escape decoding** for string views (`\uXXXX`, `\n`, …) — currently raw.
- **`PathFilter` projection.** fionn supports compiling an interest path-set
  (`compile_paths` + `build_index_filtered`) to skip uninteresting subtrees at
  scan time (~98.6% token reduction in Bolt's bench). A future
  `req.json(paths...)` could expose this for large bodies where the handler
  only reads a few fields.
- **No serializer/builder.** If a fast Bolt-native JSON *writer* lands, expose
  a minimal `json_build`/writer helper for `Response::json`. Out of scope now.
- **SIMD.** fionn's structural scan is scalar-fallback today (AVX2/SSE4.2 is a
  documented upstream TODO); throughput will rise for free when that lands.
- **`int32` length cap.** fionn takes an `int32_t` source length; `parse()`
  defensively rejects inputs > `INT32_MAX` (request bodies are bounded far
  below this by the engine).
```
