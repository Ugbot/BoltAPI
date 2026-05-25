# Thread-per-core — Remaining Work (ordered punch-card)

> Phase 3 of the dispatch/threading perf work. Execute top-to-bottom. Each slice:
> correctness-gated on **both** platforms (MSVC/IOCP + Linux/Clang), default `ctest`
> stays green, scaling sweep re-run, committed + pushed. Tiger Style + HFT; prefer
> Bolt; OpenSSL for crypto only; **no new third-party deps** (io_uring via raw
> syscalls, not liburing).
>
> Full design + decision rationale: `~/.claude/plans/foamy-munching-reddy.md`.
> Diagnosis + measurements so far: `docs/PERF_DISPATCH.md`. Targets: `docs/PERF_TARGETS.md`.

## Why (the gap this closes)

Phase 1 (allocs 7→3/req) + Phase 2 (lock-free pooled epoll ops; inline resume → ~2×,
/plaintext ≈ Drogon) are in. What remains is **tail latency + scaling**: the IO-thread
sweep **plateaus ~3.9× @16 threads** (flat 4→8) — the **shared-epoll ceiling** (all IO
threads poll one `epoll_fd`; a thread running a request inline isn't polling, so other
connections' events wait). Research confirmed **thread-per-core** (Drogon/Lithium/h2o/
Seastar) beats the "one IO loop + workers" reactor pattern for trivial TFB handlers (the
handoff costs more than the work) while a worker-pool offload kept for **heavy** handlers
gives the reactor benefit where it helps (hybrid). io_uring ring-per-thread is the next
2–2.3× lever and layers cleanly on top.

Outcome: near-linear scaling, collapsed p99, high throughput with *few* IO threads,
~0 allocs/req, a real io_uring backend (epoll stays the portable fallback). Windows/IOCP
+ macOS/kqueue **unaffected**.

## Done (Phase 1–2, committed)
- [x] **P1** response-path allocs 7→3/req (reusable buf, `to_chars`, branchless headers, no wrapper frames).
- [x] **P2-s1** epoll: fixed index op-pool + lock-free tagged free-list + atomic fd→index slot; `ops_mutex`/`unordered_map`/per-op `make_unique` gone (publish-slot-before-arm bug fixed).
- [x] **P2-s2** inline resume — `resume_on_worker` runs the coroutine on the IO thread (no per-request handoff); worker pool reserved for opt-in offload.

## Slice A — per-thread engine instances + thread-local current-io  ✅
- [x] `IODispatcher`: replaced single `io_` with `std::vector<std::unique_ptr<async_io>> ios_`. Per-core backends (epoll/kqueue/io_uring) get **one engine per IO thread** (probe `ios_[0]->backend()`); a shared-completion backend (IOCP) keeps **one** engine all threads poll (proven Windows model untouched). `io_thread_loop(i)` polls `ios_[engine_idx]` + publishes `thread_local {t_current_owner=this, t_current_io}`.
- [x] All 6 awaitables (`io_dispatcher.cpp`) + `async_close` register via `current_io()` (this thread's engine, owner-tagged; falls back to `ios_[0]` off an IO thread). `io_engine()` returns `ios_[0]` — single-socket `UdpTransport` pins to engine 0 (its ops+completions+re-arm stay consistent).
- [x] **Gate met:** MSVC `ctest` **252/252** (IOCP, single shared engine — unaffected). Linux/Clang/**epoll**: gateway lane **10/10** (HttpClient + MiddlewareAlloc) + WebRTC/UDP lane **96/96** (MediaRelay/DataChannel/UDP/DTLS/ICE/TURN — recvfrom/sendto + close_async drain). *(Interim: connections funnel to engine 0 until B/C distribute — correct, not yet the scaling win.)*

## Slice B — per-thread accept (SO_REUSEPORT)
- [ ] One listen socket per IO thread (each `SO_REUSEPORT` — already in `create_listen_socket()`), registered on **that thread's** engine; one `accept_loop` per IO thread.
- [ ] `coro_tcp_listener.cpp` (N listen fds + N accept loops) + `coro_unified_server.cpp` (start them). Kernel load-balances connections → first op of a connection lands on its accepting thread's engine.
- [ ] **Gate:** suites green; **scaling sweep ramps past the ~4-thread plateau.**

## Slice C — connection pinning + CPU affinity
- [ ] `spawn_connection`: resume the connection coroutine **inline on the accepting IO thread** (not `worker_pool->submit`) → all `co_await`s register on that thread via `t_io` → connection **pinned** for life (no migration).
- [ ] Wire `bolt_topology` + `scheduler_assign_cpus` to pin each IO thread to a core (P-core/NUMA aware); new `IODispatcherConfig` flag (default on Linux). Worker pool stays for heavy-handler offload (hybrid).
- [ ] **Gate:** suites green; scaling sweep **near-linear**; p99 collapses toward Drogon's.

## Slice D — per-IO-thread dispatch frame arena  *(depends on C)*
- [ ] New `dispatch_task<T>` (clone `coro_task<T>` for value return + `release()`/promise `value()`) with promise `operator new/delete` backed by a **thread_local bump arena** — new `include/boltapi/http/dispatch_arena.h` (modeled on `frame_arena.h:47-77`; `thread_local std::byte buf[8192]` → allocation-free). ONLY `dispatch_coro_` uses it (don't touch general `coro_task`).
- [ ] Flow the type end-to-end (option b2): `app.h`/`app.cpp:253` + `CoroHttpHandler` (`coro_unified_server.h:176`) + await sites (`:952`,`:1177`) + `dispatch_http3`.
- [ ] **Reset BEFORE acquire** (top of keep-alive loop, before `co_await handler_`) so 404/500/short-circuit paths are covered; `operator delete` range-checks arena-vs-heap.
- [ ] **D-a** pure single thread_local arena (sync handlers = TFB/bench path). **D-b** hybrid: fast arena if free else `FrameArenaPool` (async handlers can interleave a 2nd dispatch on one thread).
- [ ] **Migration guard:** stamp arena with owner-thread hash on first alloc; `operator delete` asserts `owns(p) && owner_tid==current` → loud abort on a slice-C regression (vs silent corruption).
- [ ] **Gate:** lower `dispatch_alloc_test.cpp:148` ceiling 3.0→**2.0** (remaining ~32 B Content-Type value + ~16 B → later no-alloc-header slices tighten →1.0→~0); runs in Linux gate.

## Slice E — io_uring ring-per-thread backend  *(depends on A; biggest/newest)*
- [ ] Implement declared `io_uring_io` in new `src/core/async_io_uring.cpp` via **raw syscalls** (`io_uring_setup`/`enter`/`register` through `syscall()` — no liburing). ABI from `<linux/io_uring.h>` guarded by CMake `check_include_file` (`BOLTAPI_HAVE_LINUX_IO_URING_H`) + hand-declared fallback in new private `src/core/io_uring_abi.h`.
- [ ] Ring-per-thread automatic (slice A). Single-owner ring → plain free-list (assert owner thread); keep **atomic fd-slot** (close_async is the lone cross-thread caller). Mirror the epoll op-pool discipline.
- [ ] Op→SQE: ACCEPT, RECV/READ, SEND/WRITE, CONNECT, RECVMSG/SENDMSG (recvfrom/sendto — `msghdr`+`iovec`+`sockaddr` live **in the op slot**; memcpy `dst` for sendto). `close_async` keeps synchronous cancel+close (preserves `UdpTransport::stop` drain). user_data = idx+1 (0 = wake). **Zero the SQE each submit.**
- [ ] `poll(timeout_us)`: lazy-submit + one `io_uring_enter` (batching win); reap CQEs bounded by `max_events`, `cqe->res` IS the result (−errno → −1). Timeout via `IORING_ENTER_EXT_ARG` (kernel 5.11+); if `IORING_FEAT_EXT_ARG` absent → fall back to epoll. `wake()` = eventfd + `IORING_OP_POLL_ADD` (re-arm). Probe opcodes via `IORING_REGISTER_PROBE`.
- [ ] **Robust fallback:** `create()` tries io_uring, `usable()` false (ENOSYS/EPERM under Docker default seccomp, kernel <5.11, missing opcode) → transparent `epoll_io`, **never abort**.
- [ ] **CI:** default container lanes run epoll; add a lane `docker run --security-opt seccomp=unconfined` on kernel ≥5.11 to exercise io_uring. New `async_io_uring_test` `GTEST_SKIP()`s when backend fell back.
- [ ] CMake: add `async_io_uring.cpp` to the Linux source list; no `find_package`, no link libs.
- [ ] **E-a** basic backend + fallback + test/CI lane. **E-b (deferred):** multishot accept (5.19+), provided buffer rings / zero-copy recv (6.0+), registered files.
- [ ] **Gate:** unconfined lane io_uring tests pass; default lanes (epoll) green; scaling sweep + TFB vs Drogon re-measured with io_uring active.

## Verification (every slice)
- **Correctness:** MSVC `ctest` full suite (IOCP, unaffected); Linux/Clang (LLVM+lld, never GCC) via `Dockerfile.linux-test` (WebRTC/UDP/close — epoll/pinning stress) + `Dockerfile.linux-gateway` (HTTP client + `dispatch_alloc_test`); zero `/WX`.
- **Scaling:** IO-thread sweep (1/2/4/8/16, /plaintext) — shape should move from ~3.9×@16 plateau toward **linear**. `benchmarks/tfb/run_compare.sh` for throughput + p99 vs Drogon (read the RATIO; absolutes need an idle box).
- **Allocs:** `dispatch_alloc_test` (deterministic) — ceiling tightened per slice D.
- Update this punch-card + `docs/PERF_DISPATCH.md` + `docs/PERF_TARGETS.md` as slices land.
