#!/usr/bin/env python3
# aiortc_media.py — REAL WebRTC MEDIA interop peer for the Bolt API echo gate
# (WM6). Run via:
#   uv run --no-project --with aiortc python tests/interop/aiortc_media.py \
#       <port> [signaling_path]
#
# This is the independent (non-Bolt) WebRTC stack the Bolt media-echo server is
# proven against: aiortc's own ICE, DTLS, SRTP, RTP. It:
#   1. creates an RTCPeerConnection and adds a SYNTHETIC audio + video track
#      (sendrecv) — pure generated samples, no camera/file needed,
#   2. createOffer / setLocalDescription,
#   3. POSTs the offer SDP to http://127.0.0.1:<port><signaling_path>,
#   4. setRemoteDescription(answer),
#   5. on each ECHOED track the Bolt server loops back, pulls frames and counts
#      them per kind,
#   6. asserts BOTH an audio AND a video echo track delivered >= MIN_FRAMES,
#   7. exits 0 on success, nonzero on any failure, hard-bounded (~25 s) so it can
#      never hang the test suite.
#
# No mocks: this drives a genuine ICE -> DTLS-SRTP -> RTP media flow over real
# UDP against the Bolt server's ICE-lite / DTLS-server / SRTP relay echo. The
# synthetic tracks make it deterministic and dependency-free (no media files).

import asyncio
import fractions
import os
import sys
import urllib.request

import numpy as np
from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    AudioStreamTrack,
    VideoStreamTrack,
)
from av import AudioFrame, VideoFrame

OVERALL_TIMEOUT_S = 25.0
MIN_FRAMES = 3          # echoed frames required per kind to call it a pass
SEND_FRAMES = 240       # bounded synthetic frames per track (then ends)


class SyntheticVideoTrack(VideoStreamTrack):
    """A bounded synthetic video track: a moving color gradient. No camera."""

    def __init__(self) -> None:
        super().__init__()
        self._count = 0

    async def recv(self) -> VideoFrame:
        if self._count >= SEND_FRAMES:
            # Slow to a trickle once we've sent enough; keep the track alive.
            await asyncio.sleep(0.1)
        pts, time_base = await self.next_timestamp()
        h, w = 120, 160
        arr = np.zeros((h, w, 3), dtype=np.uint8)
        arr[:, :, 0] = (self._count * 3) & 0xFF
        arr[:, :, 1] = np.linspace(0, 255, w, dtype=np.uint8)[None, :]
        arr[:, :, 2] = np.linspace(0, 255, h, dtype=np.uint8)[:, None]
        frame = VideoFrame.from_ndarray(arr, format="rgb24")
        frame.pts = pts
        frame.time_base = time_base
        self._count += 1
        return frame


class SyntheticAudioTrack(AudioStreamTrack):
    """A bounded synthetic audio track: a sine tone. No microphone."""

    def __init__(self) -> None:
        super().__init__()
        self._count = 0
        self._sample_rate = 48000
        self._samples = 960  # 20 ms @ 48 kHz

    async def recv(self) -> AudioFrame:
        if self._count >= SEND_FRAMES:
            await asyncio.sleep(0.1)
        pts = self._count * self._samples
        t = (np.arange(self._samples) + pts) / self._sample_rate
        tone = (np.sin(2 * np.pi * 440.0 * t) * 8000).astype(np.int16)
        data = np.tile(tone, (1, 1))  # mono, shape (1, samples)
        frame = AudioFrame.from_ndarray(data, format="s16", layout="mono")
        frame.sample_rate = self._sample_rate
        frame.pts = pts
        frame.time_base = fractions.Fraction(1, self._sample_rate)
        self._count += 1
        return frame


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


async def drain(track, kind: str, counts: dict, done: asyncio.Future) -> None:
    """Pull echoed frames from an inbound (echoed) track and count them."""
    try:
        while True:
            await track.recv()
            counts[kind] = counts.get(kind, 0) + 1
            if (counts.get("audio", 0) >= MIN_FRAMES and
                    counts.get("video", 0) >= MIN_FRAMES and not done.done()):
                done.set_result(True)
                return
    except Exception:  # noqa: BLE001 — track ended / connection closed
        return


async def run(port: int, signaling_path: str) -> int:
    url = f"http://127.0.0.1:{port}{signaling_path}"
    pc = RTCPeerConnection()
    counts: dict = {}
    done = asyncio.get_event_loop().create_future()
    drains = []

    @pc.on("track")
    def on_track(track):
        # The server echoes our audio + video straight back; drain to count.
        drains.append(asyncio.ensure_future(
            drain(track, track.kind, counts, done)))

    @pc.on("connectionstatechange")
    async def on_state():
        if pc.connectionState in ("failed", "closed") and not done.done():
            done.set_exception(RuntimeError(f"connection {pc.connectionState}"))

    pc.addTrack(SyntheticAudioTrack())
    pc.addTrack(SyntheticVideoTrack())

    await pc.setLocalDescription(await pc.createOffer())
    answer_sdp = await asyncio.get_event_loop().run_in_executor(
        None, post_offer, url, pc.localDescription.sdp
    )
    await pc.setRemoteDescription(
        RTCSessionDescription(sdp=answer_sdp, type="answer"))

    try:
        await asyncio.wait_for(done, timeout=OVERALL_TIMEOUT_S)
        rc = 0
        print(
            f"INTEROP OK: media echo round-tripped "
            f"(audio={counts.get('audio', 0)} video={counts.get('video', 0)})",
            flush=True,
        )
    except asyncio.TimeoutError:
        rc = 2
        print(
            f"INTEROP FAIL: timeout after {OVERALL_TIMEOUT_S}s "
            f"(audio={counts.get('audio', 0)} video={counts.get('video', 0)} "
            f"conn={pc.connectionState} ice={pc.iceConnectionState})",
            file=sys.stderr,
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001 — top-level test harness
        rc = 3
        print(f"INTEROP FAIL: {exc!r}", file=sys.stderr, flush=True)

    for d in drains:
        d.cancel()
    # Best-effort close, bounded so teardown can't hang the harness.
    try:
        await asyncio.wait_for(pc.close(), timeout=2.0)
    except Exception:  # noqa: BLE001 — close is best-effort
        pass
    return rc


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: aiortc_media.py <port> [signaling_path]", file=sys.stderr)
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
    # HARD EXIT (same aiortc 1.14 teardown-hang fix as aiortc_datachannel.py):
    # aiortc/aioice leave non-daemon background threads that don't join on
    # interpreter shutdown, so sys.exit hangs the python process AFTER the media
    # echo already round-tripped, making the bounded gtest SKIP a PASSING run.
    # os._exit gives an immediate, bounded exit with the real result code.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
