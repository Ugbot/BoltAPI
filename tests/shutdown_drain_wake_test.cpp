// G2CHK-1303: graceful shutdown must not lose the last-connection wake, and
// STOPPED must wake start(). The DrainGate wait hook runs with the gate mutex
// held after the waiter's predicate failed and before it blocks, so each test
// lands its notify exactly in the check-to-block window.

#include <gtest/gtest.h>

#include "boltapi/server/coro_unified_server.h"
#include "boltapi/server/drain_gate.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace {

using bolt::api::http::CoroHttpRequest;
using bolt::api::http::CoroHttpResponse;
using bolt::api::http::CoroUnifiedServer;
using bolt::api::http::CoroUnifiedServerConfig;
using bolt::api::http::DrainGate;
using namespace std::chrono_literals;

constexpr uint16_t kPort = 19341;
constexpr auto kWaitDeadline = 2000ms;
constexpr auto kPrompt = 1000ms;
constexpr auto kInWindowSleep = 50ms;

struct CloseInWindow {
    DrainGate* gate = nullptr;
    std::thread closer;
    std::atomic<int> fired{0};
};

void close_last_in_window(void* p) {
    auto* ctx = static_cast<CloseInWindow*>(p);
    if (ctx->fired.fetch_add(1) != 0) return;
    DrainGate* gate = ctx->gate;
    ctx->closer = std::thread([gate]() {
        if (gate->close_one()) gate->wake();
    });
    std::this_thread::sleep_for(kInWindowSleep);
}

TEST(DrainGateTest, LastCloseInWaitWindowWakesWaiter) {
    DrainGate gate;
    gate.open_one();
    CloseInWindow ctx;
    ctx.gate = &gate;
    gate.set_wait_hook(&close_last_in_window, &ctx);

    auto t0 = std::chrono::steady_clock::now();
    bool drained = gate.wait_drained(t0 + kWaitDeadline);
    auto elapsed = std::chrono::steady_clock::now() - t0;
    ctx.closer.join();
    gate.set_wait_hook(nullptr, nullptr);

    EXPECT_EQ(ctx.fired.load(), 1);
    EXPECT_TRUE(drained);
    EXPECT_EQ(gate.active(), 0u);
    EXPECT_LT(elapsed, kPrompt) << "last-close wake lost: waited to the deadline";
}

TEST(DrainGateTest, WaitTimesOutWhileConnectionsRemain) {
    DrainGate gate;
    gate.open_one();
    gate.open_one();
    auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(gate.wait_drained(t0 + 20ms));
    EXPECT_FALSE(gate.close_one());
    EXPECT_TRUE(gate.close_one());
    EXPECT_TRUE(gate.wait_drained(std::chrono::steady_clock::now()));
}

thread_local bool t_is_start_thread = false;

struct ShutdownWaiters {
    std::atomic<bool> start_waiting{false};
    std::atomic<bool> drain_waiting{false};
};

void note_waiter(void* p) {
    auto* w = static_cast<ShutdownWaiters*>(p);
    if (t_is_start_thread) {
        w->start_waiting.store(true);
    } else {
        w->drain_waiting.store(true);
    }
}

template <typename Pred>
bool spin_until(Pred pred) {
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

// start() waits on the gate for STOPPED; shutdown_gracefully() must wake it.
TEST(CoroUnifiedServerShutdownTest, StoppedWakesStart) {
    CoroUnifiedServerConfig config;
    config.enable_tls = false;
    config.enable_http1_cleartext = true;
    config.http1_port = kPort;
    config.host = "127.0.0.1";
    config.num_io_threads = 1;
    config.num_workers = 1;
    config.enable_signal_handlers = false;
    config.shutdown_timeout_ms = 3000;

    CoroUnifiedServer server(config);
    server.set_handler([](const CoroHttpRequest&)
                           -> bolt::api::http::dispatch_task<CoroHttpResponse> {
        CoroHttpResponse resp;
        resp.status = 200;
        co_return resp;
    });
    ShutdownWaiters waiters;
    server.drain_gate().set_wait_hook(&note_waiter, &waiters);

    std::atomic<int> start_rc{-2};
    std::atomic<int64_t> start_done_ns{0};
    std::thread starter([&]() {
        t_is_start_thread = true;
        start_rc.store(server.start());
        start_done_ns.store(std::chrono::steady_clock::now().time_since_epoch().count());
    });
    ASSERT_TRUE(spin_until([&]() { return server.is_running(); }));

    // Hold one connection so shutdown parks in its drain wait.
    ASSERT_TRUE(server.track_connection_open());
    std::atomic<bool> drained{false};
    std::thread stopper([&]() { drained.store(server.shutdown_gracefully()); });
    ASSERT_TRUE(spin_until([&]() {
        return waiters.start_waiting.load() && waiters.drain_waiting.load();
    }));

    auto t0 = std::chrono::steady_clock::now();
    server.track_connection_close();
    stopper.join();
    starter.join();
    server.drain_gate().set_wait_hook(nullptr, nullptr);

    auto start_done = std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(start_done_ns.load()));
    EXPECT_TRUE(drained.load());
    EXPECT_EQ(start_rc.load(), 0);
    EXPECT_FALSE(server.is_running());
    EXPECT_LT(start_done - t0, kPrompt) << "start() was not woken by STOPPED";
}

}  // namespace
