# Bolt API — WebRTC data-channel interop test (headless, via aiortc).
#
# Run with uv (no install needed):
#     uv run --with aiortc python testing/aiortc_datachannel.py <port> [signal_path]
#
# Opens a data channel to a running Bolt API demo server, POSTs the offer SDP to
# the signaling route, applies the answer, sends a text + a 64KiB binary message,
# and asserts both echo back. Exit 0 on success, nonzero on failure/timeout.
import asyncio, os, sys, urllib.request

from aiortc import RTCPeerConnection, RTCSessionDescription


async def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    path = sys.argv[2] if len(sys.argv) > 2 else "/webrtc/offer"
    url = f"http://127.0.0.1:{port}{path}"

    pc = RTCPeerConnection()
    done = asyncio.get_event_loop().create_future()
    got = {"text": False, "bin": False}
    dc = pc.createDataChannel("chat")

    @dc.on("open")
    def _open() -> None:
        dc.send("hello from aiortc")
        dc.send(b"\x07" * (64 * 1024))

    @dc.on("message")
    def _msg(m) -> None:
        if isinstance(m, str):
            got["text"] = True
        else:
            got["bin"] = len(m) == 64 * 1024
        if got["text"] and got["bin"] and not done.done():
            done.set_result(True)

    await pc.setLocalDescription(await pc.createOffer())
    # non-trickle: wait for ICE gathering to complete
    while pc.iceGatheringState != "complete":
        await asyncio.sleep(0.05)

    req = urllib.request.Request(url, data=pc.localDescription.sdp.encode(),
                                 headers={"Content-Type": "application/sdp"}, method="POST")
    answer = urllib.request.urlopen(req, timeout=10).read().decode()
    await pc.setRemoteDescription(RTCSessionDescription(sdp=answer, type="answer"))

    try:
        await asyncio.wait_for(done, timeout=20)
        print("INTEROP OK: text + 64KiB binary echoed back")
        rc = 0
    except asyncio.TimeoutError:
        print(f"INTEROP FAIL: timed out (text={got['text']} bin={got['bin']})")
        rc = 1
    try:
        await asyncio.wait_for(pc.close(), timeout=2.0)
    except Exception:
        pass
    return rc


if __name__ == "__main__":
    rc = asyncio.run(main())
    # Hard exit: aiortc 1.14 leaves non-daemon threads that hang interpreter
    # shutdown after the round-trip succeeds. os._exit gives a prompt, bounded
    # exit with the real code (matches tests/interop/aiortc_datachannel.py).
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
