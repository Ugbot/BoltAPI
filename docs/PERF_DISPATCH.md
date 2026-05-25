# Dispatch & threading perf — diagnosis, work, measurements

Tracking the work to make BoltAPI's HTTP/1.1 dispatch path match/beat Drogon.
Plan: `~/.claude/plans/foamy-munching-reddy.md`. Harness: `benchmarks/tfb/`.

> **Measurement caveat:** numbers below were taken on a **loaded, thermally-busy
> 16-core dev box** under Docker-Desktop/WSL2 (server + wrk share the host CPU).
> Absolutes are depressed and noisy run-to-run; **read the BoltAPI:Drogon RATIO**,
> measured back-to-back in the same run. Allocation *counts* are load-independent
> and exact.

## Diagnosis (thread-trace + alloc audit)

Three FasterAPI-borrowed problems, in order of impact:
1. **~25–50 → measured 7 heap allocs/request** on the response path (status_message
   std::string, per-header std::string pairs, a `resp_str` that copied the body
   2–3×, `to_string`, coroutine frames).
2. **Per-request worker handoff** — every IO completion `resume_on_worker()` →
   shared MPMC + spin-yield; 2–3 handoffs/request. The dominant **tail-latency**
   cause. (Drogon runs the whole request inline on one loop thread: 0 handoffs.)
3. **Hot-path mutexes** — the epoll backend took a shared `ops_mutex` on *every*
   op + `make_unique`'d a `pending_op` + an `unordered_map` node per op.

## Phase 1 — response-path allocations  ✅  (7 → 3 / request, MSVC)

`dispatch_alloc_test` (real App on loopback + fixed-buffer client + global-new
counter; deterministic). Eliminated, with an alloc-size capture pinpointing each:
- per-request `resp_str` → per-connection **reusable buffer**; `to_chars` (was
  `to_string`); **branchless** header handling (was per-header std::string copies);
- the dispatch **pass-through coroutine frame** (`set_handler` returns the task
  directly); the `conn_read`/`conn_write` coroutine frames on the cleartext path.

Remaining 3 (sizes: 3840 B dispatch coroutine frame, 32 B Content-Type value,
16 B): need the per-IO-thread frame arena (Phase 2-gated by inline-resume) + a
no-alloc header store.

## Phase 2 slice 1 — epoll: lock-free pooled ops, no mutex  ✅

The epoll backend now: a **fixed index-based op pool** (no per-op alloc; stable
storage → no use-after-free in the close/complete race), the op carried in
`epoll_event.data.u64 = (index+1)<<32 | fd` (**no fd→op map**), a **lock-free
tagged free-list** of indices, and an **atomic fd→index slot** for `close_async`.
The `ops_mutex`, the `unordered_map`, and the per-op `make_unique` are **gone**.
(Caught one real bug: the slot must be published *before* arming the fd in epoll,
or a completion on another IO thread is dropped → hang. Fixed.)

## Measured impact (TFB harness, loaded box, ratio)

| | before (Phase-0) | after (P1 + epoll) | Drogon (same run) |
|---|---:|---:|---:|
| /plaintext req/s | ~22k (io8) — **1.9× behind** | **~16k ≈ Drogon** | ~16k |
| /json req/s | — | ~18k | ~30k (**~1.7× ahead**) |
| /plaintext p99 | high | ~134 ms | ~72 ms |
| /json p99 | high | ~172 ms | ~40 ms |

**The /plaintext throughput gap is CLOSED** (was ~1.9× behind → now even). What
remains — **/json throughput + tail latency** (Drogon 2–4× better on p99) — is the
**worker handoff**, untouched by slice 1. That is slice 2.

## /json path investigation (it is NOT slow / NOT fionn)

Measured deterministically (`dispatch_alloc_test` with a json handler): `/json` =
**4 allocs/req** vs `/plaintext` = 3 — exactly **+1 alloc** (the 27-char JSON body
exceeds std::string SSO). **fionn is not involved**: it's the *parser* (`req.json()`);
the response `res.json()` only sets a Content-Type + copies the body. So the response
path has no parsing/serialization cost and no fionn.

The TFB `/json`-looks-slower-than-`/plaintext` reading was a **test-ordering
artifact**: `/plaintext` ran first against a cold server (first traffic). The tell:
Drogon's `/json` (30k) > its own `/plaintext` (16k), which is backwards. Fixed in
`run_compare.sh` by warming each endpoint (discarded run) before timing it.

## Next — Phase 2 slice 2: inline resume + fast handoff (the tail)

Run fast requests end-to-end on the IO/event-loop thread (zero handoff); keep the
worker pool for opt-in blocking offload, and where a handoff remains make it fast
(per-worker SPSC + futex, not shared MPMC + yield). Expected to collapse p99 toward
Drogon's and close the /json gap. It also unlocks the per-IO-thread frame arena →
kills the remaining 3 allocs/request (single-threaded-per-loop → arena is safe).
Then Phase 3 (thread-per-core epoll) only if still behind.
