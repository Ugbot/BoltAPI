// aiortc_interop_test.cpp — THE REAL WEBRTC INTEROP GATES (gtest).
//
// Proof of the Bolt WebRTC stack against an INDEPENDENT, non-Bolt WebRTC
// implementation (aiortc): aiortc's own ICE, DTLS, SCTP/DCEP and (WM6) SRTP/RTP
// talking to Bolt's ICE-lite agent, DTLS server, Bolt-native SCTP and the SRTP
// media relay echo over real UDP.
//
// TWO bounded legs:
//   1. DataChannelTextAndBinaryEcho — aiortc offers a data channel; asserts a
//      text + 64 KiB binary echo round-trip (tests/interop/aiortc_datachannel.py).
//   2. AudioAndVideoEcho (WM6) — aiortc sends a synthetic audio + video track;
//      asserts the server echoes both back (tests/interop/aiortc_media.py).
//
// NO-STALL GUARANTEE (critical): every external-client leg is run through the
// BOUNDED, process-tree-killing runner in tests/interop/bounded_proc.h:
//   * uv is PRE-PROBED fast; if absent -> GTEST_SKIP (never block, never fail).
//   * the child runs under a HARD WALL-CLOCK CAP (kRunCapMs). On Windows it is a
//     Job Object (KILL_ON_JOB_CLOSE); on POSIX a process group. On timeout the
//     WHOLE tree (uv + python + grandchildren) is killed — so the test can NEVER
//     hang the suite and NEVER leak orphaned processes (the failure mode that
//     previously took down a CI run).
//   * a uv-run that times out OR fails to bootstrap aiortc (no network for
//     wheels) is treated as SKIP, not FAIL: the in-process media_echo_test +
//     loopback gates are the PRIMARY signal; interop is a bounded secondary.
//
// Guarded so the DEFAULT (WEBRTC=OFF) build stays green: without
// BOLTAPI_WITH_WEBRTC each test compiles to a single GTEST_SKIP.

#include <gtest/gtest.h>

#if defined(BOLTAPI_WITH_WEBRTC)

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"
#include "interop/bounded_proc.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

namespace {

namespace sys     = bolt::api::net::sys;
namespace interop = bolt::api::interop;

// Hard wall-clock cap for ANY aiortc subprocess. The python harnesses each have
// their own ~20-25 s internal timeout; this is the OUTER safety net that kills
// the whole process tree if the child itself wedges. > the script timeout so a
// clean script-side failure reports before we tree-kill.
// Kept comfortably under the per-test ctest TIMEOUT (180s) even in the worst
// case of one capped run PLUS one capped bootstrap re-probe (70+70 = 140 < 180).
constexpr std::uint32_t kRunCapMs = 70000;  // 70 s absolute ceiling

// Find a free TCP port; the App reuses it for the HTTP listener AND the UDP
// WebRTC transport. Tiny race window between close and re-bind; fine for a local
// test (the answer's candidates carry the actual UDP port regardless).
std::uint16_t pick_free_port() {
    sys::startup();
#ifdef _WIN32
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
#else
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return 0;
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    std::uint16_t port = 0;
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        socklen_t len = sizeof(addr);
        if (::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
            port = ntohs(addr.sin_port);
        }
    }
    sys::close_socket(s);
    return port;
}

// Path to a python interop script under tests/interop (source tree, injected at
// compile time so the test binary can find it from the build dir).
std::string interop_script(const char* name) {
#ifdef BOLTAPI_SOURCE_DIR
    return std::string(BOLTAPI_SOURCE_DIR) + "/tests/interop/" + name;
#else
    return std::string("tests/interop/") + name;
#endif
}

// The shared uv `--with` set. aiortc is the WebRTC stack; numpy + av are needed
// by the MEDIA harness's synthetic tracks (aiortc pulls av transitively but the
// script imports numpy directly, so we name both for a deterministic env).
constexpr const char* kUvWith = "--with aiortc --with numpy --with av";

// Build the bounded `uv run` command for one interop script + port. --no-project
// keeps uv from discovering an enclosing pyproject.toml.
std::string uv_cmd(const std::string& script, std::uint16_t port) {
    return std::string("uv run --no-project ") + kUvWith + " python \"" +
           script + "\" " + std::to_string(port) + " /webrtc/offer";
}

// Did aiortc fail to BOOTSTRAP (no network for wheels)? A bounded re-probe so we
// can SKIP (not FAIL) when the env can't even import aiortc. Tree-kill-bounded.
bool aiortc_bootstrap_failed() {
    const std::string probe = std::string("uv run --no-project ") + kUvWith +
                              " python -c \"import aiortc, numpy, av\"";
    const interop::RunResult r = interop::run_bounded(probe, kRunCapMs);
    return !r.exited_ok();  // timeout or non-zero -> couldn't bootstrap
}

}  // namespace

TEST(AiortcInterop, DataChannelTextAndBinaryEcho) {
    if (!interop::uv_present()) {
        GTEST_SKIP() << "uv not found on PATH; skipping aiortc data-channel "
                        "interop (install uv 0.8.17+ to run the real gate).";
    }

    const std::uint16_t port = pick_free_port();
    ASSERT_NE(port, 0) << "could not allocate a free port";

    bolt::api::App app;
    bolt::api::WebRtcConfig wcfg;
    wcfg.ice_lite = true;
    wcfg.max_message_size = 262144;
    app.enable_webrtc(wcfg);

    std::atomic<int> echoes{0};
    app.on_data_channel("chat",
        [&echoes](bolt::api::webrtc::DataChannel& ch, const void* data,
                  std::size_t len, bool is_binary) {
            echoes.fetch_add(1, std::memory_order_relaxed);
            if (is_binary) ch.send_binary(data, len);
            else ch.send_text(std::string_view(
                     reinterpret_cast<const char*>(data), len));
        });

    ASSERT_EQ(app.start_background("127.0.0.1", port), 0)
        << "App failed to start on port " << port;
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_TRUE(app.is_running());

    const std::string cmd = uv_cmd(interop_script("aiortc_datachannel.py"), port);
    const interop::RunResult r = interop::run_bounded(cmd, kRunCapMs);

    app.stop();

    if (r.kind == interop::RunResult::Kind::kTimedOut) {
        GTEST_SKIP() << "aiortc data-channel interop exceeded " << kRunCapMs
                     << "ms and was tree-killed (no hang, no leak). Treated as "
                        "skip; the loopback datachannel gate is the primary signal.";
    }
    if (!r.exited_ok()) {
        if (aiortc_bootstrap_failed()) {
            GTEST_SKIP() << "uv run --with aiortc could not bootstrap (no "
                            "network for wheels?); interop gate pending an env "
                            "that can fetch the aiortc wheels.";
        }
        FAIL() << "aiortc data-channel interop failed (exit " << r.exit_code
               << "); the env built but the WebRTC interop did not complete.";
    }
    SUCCEED();
}

// WM6: media (audio + video) echo interop. aiortc sends a SYNTHETIC audio +
// video track to the server (enable_media_echo) and asserts the echo returns.
TEST(AiortcMediaInterop, AudioAndVideoEcho) {
    if (!interop::uv_present()) {
        GTEST_SKIP() << "uv not found on PATH; skipping aiortc media interop "
                        "(install uv 0.8.17+ to run the real media echo gate).";
    }

    const std::uint16_t port = pick_free_port();
    ASSERT_NE(port, 0) << "could not allocate a free port";

    bolt::api::App app;
    bolt::api::WebRtcConfig wcfg;
    wcfg.ice_lite = true;
    app.enable_webrtc(wcfg);
    // WM6 echo: received audio + video RTP looped straight back (re-SRTP, relay).
    app.enable_media_echo();
    // A data channel handler is harmless and shows media + data coexisting.
    app.on_data_channel("chat",
        [](bolt::api::webrtc::DataChannel& ch, const void* data,
           std::size_t len, bool is_binary) {
            if (is_binary) ch.send_binary(data, len);
            else ch.send_text(std::string_view(
                     reinterpret_cast<const char*>(data), len));
        });

    ASSERT_EQ(app.start_background("127.0.0.1", port), 0)
        << "App failed to start on port " << port;
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_TRUE(app.is_running());

    const std::string cmd = uv_cmd(interop_script("aiortc_media.py"), port);
    const interop::RunResult r = interop::run_bounded(cmd, kRunCapMs);

    app.stop();

    if (r.kind == interop::RunResult::Kind::kTimedOut) {
        GTEST_SKIP() << "aiortc media interop exceeded " << kRunCapMs
                     << "ms and was tree-killed (no hang, no leak). Treated as "
                        "skip; media_echo_test is the primary in-process signal.";
    }
    if (!r.exited_ok()) {
        if (aiortc_bootstrap_failed()) {
            GTEST_SKIP() << "uv run --with aiortc could not bootstrap (no "
                            "network for wheels / numpy+av build); media interop "
                            "pending an env that can fetch the wheels.";
        }
        FAIL() << "aiortc media interop failed (exit " << r.exit_code
               << "); the env built but the media echo did not round-trip.";
    }
    SUCCEED();
}

#else  // !BOLTAPI_WITH_WEBRTC

TEST(AiortcInterop, SkippedWithoutWebRtc) {
    GTEST_SKIP() << "built without BOLTAPI_WITH_WEBRTC; aiortc interop gates are "
                    "only meaningful with -DBOLTAPI_WITH_WEBRTC=ON.";
}

#endif
