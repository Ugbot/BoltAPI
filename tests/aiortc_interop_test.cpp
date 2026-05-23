// aiortc_interop_test.cpp — THE REAL WEBRTC INTEROP GATE (gtest).
//
// This is the first proof of the Bolt WebRTC stack against an INDEPENDENT,
// non-Bolt WebRTC implementation (aiortc): aiortc's own ICE, DTLS, SCTP and
// DCEP talking to Bolt's ICE-lite agent, DTLS server, Bolt-native SCTP and DCEP
// over real UDP. Beyond the loopback-with-our-own-stack datachannel_test, this
// closes the interop loop.
//
// Flow:
//   1. Pick a free TCP port; start the full App on it with enable_webrtc — that
//      brings up the HTTP signaling route (POST /webrtc/offer) AND the UDP
//      ICE/DTLS/SCTP transport (which binds the SAME port number over UDP), with
//      an on_data_channel("chat") echo handler.
//   2. Shell out to `uv run --with aiortc python tests/interop/
//      aiortc_datachannel.py <port>` — aiortc creates the offer, POSTs it, gets
//      the answer, connects, and asserts a text + 64 KiB binary echo round-trip.
//   3. Assert the subprocess exits 0.
//
// SKIP (do NOT fail) when uv is missing or the `uv run --with aiortc` bootstrap
// fails (e.g. no network for the wheels): GTEST_SKIP with a clear message.
//
// Guarded so the DEFAULT (WEBRTC=OFF) build stays green: without
// BOLTAPI_WITH_WEBRTC the test compiles to a single GTEST_SKIP.

#include <gtest/gtest.h>

#if defined(BOLTAPI_WITH_WEBRTC)

#include "boltapi/app.h"
#include "boltapi/net/sys_compat.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

namespace {

namespace sys = bolt::api::net::sys;

// Find a free TCP port by binding an ephemeral socket and reading back the port,
// then closing it. The App reuses this port number for BOTH the HTTP signaling
// listener and the UDP WebRTC transport. (Tiny race window between close and
// re-bind; acceptable for a local test, and the answer's candidates carry the
// actual UDP bound port regardless.)
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

// Locate the python interop script relative to the source tree. The test binary
// runs from the build dir; the source dir is injected at compile time.
std::string interop_script_path() {
#ifdef BOLTAPI_SOURCE_DIR
    return std::string(BOLTAPI_SOURCE_DIR) +
           "/tests/interop/aiortc_datachannel.py";
#else
    return "tests/interop/aiortc_datachannel.py";
#endif
}

// Is `uv` callable at all? `uv --version` returns 0 when present.
bool uv_present() {
    const int rc = std::system("uv --version >"
#ifdef _WIN32
        "NUL 2>&1"
#else
        "/dev/null 2>&1"
#endif
    );
    return rc == 0;
}

}  // namespace

TEST(AiortcInterop, DataChannelTextAndBinaryEcho) {
    if (!uv_present()) {
        GTEST_SKIP() << "uv not found on PATH; skipping aiortc interop "
                        "(install uv 0.8.17+ to run the real interop gate).";
    }

    const std::uint16_t port = pick_free_port();
    ASSERT_NE(port, 0) << "could not allocate a free port";

    // ---- Start the full App: signaling route + WebRTC transport + echo. ----
    bolt::api::App app;
    bolt::api::WebRtcConfig wcfg;          // signaling_path defaults to /webrtc/offer
    wcfg.ice_lite = true;
    wcfg.max_message_size = 262144;
    app.enable_webrtc(wcfg);

    std::atomic<int> echoes{0};
    // on_data_channel("chat"): echo every message straight back on the channel,
    // preserving text/binary (so aiortc receives a str echo for a str send and a
    // bytes echo for a bytes send).
    app.on_data_channel("chat",
        [&echoes](bolt::api::webrtc::DataChannel& ch, const void* data,
                  std::size_t len, bool is_binary) {
            echoes.fetch_add(1, std::memory_order_relaxed);
            if (is_binary) {
                ch.send_binary(data, len);
            } else {
                ch.send_text(std::string_view(
                    reinterpret_cast<const char*>(data), len));
            }
        });

    ASSERT_EQ(app.start_background("127.0.0.1", port), 0)
        << "App failed to start on port " << port;

    // Give the listener + UDP transport a moment to come up.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_TRUE(app.is_running());

    // ---- Run the aiortc interop peer. ----
    // --no-project: do NOT let uv discover an enclosing pyproject.toml (a parent
    // dir may host an unrelated Python project that uv would try to build). The
    // ephemeral aiortc env is built purely from --with.
    const std::string script = interop_script_path();
    std::string cmd = "uv run --no-project --with aiortc python \"" + script +
                      "\" " + std::to_string(port) + " /webrtc/offer";

    const int rc = std::system(cmd.c_str());

    app.stop();

    // A bootstrap failure (no network for wheels) surfaces as a uv error exit;
    // distinguish "couldn't get aiortc" (skip) from "interop ran and failed".
    if (rc != 0) {
        // Re-probe: can the env even import aiortc? If not, treat as skip.
        const int boot = std::system(
            "uv run --no-project --with aiortc python -c \"import aiortc\" >"
#ifdef _WIN32
            "NUL 2>&1"
#else
            "/dev/null 2>&1"
#endif
        );
        if (boot != 0) {
            GTEST_SKIP() << "uv run --with aiortc bootstrap failed (no network "
                            "for wheels?); interop gate pending an env that can "
                            "fetch the aiortc wheels.";
        }
        FAIL() << "aiortc interop subprocess failed (exit " << rc
               << "); the env built but the WebRTC interop did not complete.";
    }

    SUCCEED();
}

#else  // !BOLTAPI_WITH_WEBRTC

TEST(AiortcInterop, SkippedWithoutWebRtc) {
    GTEST_SKIP() << "built without BOLTAPI_WITH_WEBRTC; aiortc interop gate is "
                    "only meaningful with -DBOLTAPI_WITH_WEBRTC=ON.";
}

#endif
