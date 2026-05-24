#!/usr/bin/env python3
# aiortc_datachannel.py — REAL WebRTC interop peer for the Bolt API data-channel
# gate. Run via `uv run --with aiortc python tests/interop/aiortc_datachannel.py
# <port> [signaling_path]` (uv builds the ephemeral env; no global install).
#
# This is the independent (non-Bolt) WebRTC stack the Bolt server is proven
# against: aiortc's own ICE, DTLS, SCTP and DCEP. It:
#   1. creates an RTCPeerConnection + a "chat" data channel,
#   2. createOffer / setLocalDescription,
#   3. POSTs the offer SDP to http://127.0.0.1:<port><signaling_path>
#      (raw SDP body; the Bolt route also accepts JSON {"sdp":...}),
#   4. setRemoteDescription(answer),
#   5. on the channel "open": sends a text message AND a 64 KiB binary message,
#   6. asserts BOTH echoes come back byte-exact,
#   7. exits 0 on success, nonzero on any failure, bounded (~20 s) so it can
#      never hang the test suite.
#
# Pure stdlib for the HTTP POST (urllib); aiortc for the WebRTC stack. No mocks:
# this drives a genuine ICE -> DTLS -> SCTP -> DCEP handshake over real UDP
# against the Bolt server's ICE-lite / DTLS-server / Bolt-native-SCTP answerer.

import asyncio
import os
import sys
import urllib.request

from aiortc import RTCPeerConnection, RTCSessionDescription

OVERALL_TIMEOUT_S = 20.0
TEXT_MSG = "bolt-aiortc-interop-roundtrip-✓-0123456789"
BIN_SIZE = 64 * 1024  # > 1 KiB: forces SCTP fragmentation/reassembly


def post_offer(url: str, sdp: str) -> str:
    """POST the offer SDP, return the answer SDP body (raw text)."""
    data = sdp.encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/sdp"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=8.0) as resp:
        if resp.status != 200:
            raise RuntimeError(f"signaling POST returned HTTP {resp.status}")
        return resp.read().decode("utf-8")


async def run(port: int, signaling_path: str) -> int:
    url = f"http://127.0.0.1:{port}{signaling_path}"
    pc = RTCPeerConnection()

    done = asyncio.get_event_loop().create_future()
    state = {"text_ok": False, "bin_ok": False}
    expected_bin = bytes((i * 37 + 11) & 0xFF for i in range(BIN_SIZE))

    channel = pc.createDataChannel("chat")

    @channel.on("open")
    def on_open():
        # Send a text message and a >1 KiB binary message once the DCEP channel
        # is open. The Bolt on_data_channel("chat") handler echoes both back.
        channel.send(TEXT_MSG)
        channel.send(expected_bin)

    @channel.on("message")
    def on_message(message):
        if isinstance(message, str):
            state["text_ok"] = (message == TEXT_MSG)
        else:
            state["bin_ok"] = (bytes(message) == expected_bin)
        if state["text_ok"] and state["bin_ok"] and not done.done():
            done.set_result(True)

    @pc.on("connectionstatechange")
    def on_state():
        if pc.connectionState in ("failed", "closed") and not done.done():
            done.set_exception(RuntimeError(f"connection {pc.connectionState}"))

    # 1) Offer.
    await pc.setLocalDescription(await pc.createOffer())

    # 2) Signaling: POST the offer, receive the answer (run blocking HTTP in a
    #    thread so we never block the event loop).
    answer_sdp = await asyncio.get_event_loop().run_in_executor(
        None, post_offer, url, pc.localDescription.sdp
    )

    # 3) Apply the answer; ICE/DTLS/SCTP now drive to "open" -> echo.
    await pc.setRemoteDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))

    try:
        await asyncio.wait_for(done, timeout=OVERALL_TIMEOUT_S)
        rc = 0
        print("INTEROP OK: text echo + 64KiB binary echo round-tripped", flush=True)
    except asyncio.TimeoutError:
        rc = 2
        print(
            f"INTEROP FAIL: timeout after {OVERALL_TIMEOUT_S}s "
            f"(text_ok={state['text_ok']} bin_ok={state['bin_ok']} "
            f"conn={pc.connectionState} ice={pc.iceConnectionState})",
            file=sys.stderr,
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001 — top-level test harness
        rc = 3
        print(f"INTEROP FAIL: {exc!r}", file=sys.stderr, flush=True)

    # Best-effort close, bounded so teardown can't hang the harness.
    try:
        await asyncio.wait_for(pc.close(), timeout=2.0)
    except Exception:  # noqa: BLE001 — close is best-effort
        pass
    return rc


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: aiortc_datachannel.py <port> [signaling_path]",
              file=sys.stderr)
        return 64
    port = int(sys.argv[1])
    signaling_path = sys.argv[2] if len(sys.argv) > 2 else "/webrtc/offer"
    try:
        return asyncio.run(run(port, signaling_path))
    except Exception as exc:  # noqa: BLE001
        print(f"INTEROP FAIL (startup): {exc!r}", file=sys.stderr, flush=True)
        return 4


if __name__ == "__main__":
    rc = main()
    # HARD EXIT (the interop regression fix): aiortc 1.14 leaves non-daemon
    # background threads (aioice datagram transports / event-loop executors) that
    # do NOT join on interpreter shutdown, so a normal `sys.exit(rc)` hangs the
    # python process AFTER the round-trip already succeeded — which made the
    # bounded gtest wait the full wall-clock cap and SKIP a PASSING interop run.
    # os._exit bypasses interpreter/atexit teardown for an immediate, bounded
    # exit with the real result code. Flush first so no output is lost.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
