import asyncio, logging, sys, time, urllib.request
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
from aiortc import RTCPeerConnection, RTCSessionDescription

async def main():
    port = int(sys.argv[1]) if len(sys.argv)>1 else 8080
    url = f"http://127.0.0.1:{port}/webrtc/offer"
    pc = RTCPeerConnection()
    done = asyncio.get_event_loop().create_future()
    got = {"text": False, "bin": False}
    dc = pc.createDataChannel("chat")
    @dc.on("open")
    def _o():
        print("CLIENT: datachannel OPEN", flush=True)
        dc.send("hello from aiortc"); dc.send(b"\x07"*(64*1024))
    @dc.on("message")
    def _m(m):
        print(f"CLIENT: rx {'text' if isinstance(m,str) else 'bin'} len={len(m)}", flush=True)
        if isinstance(m,str): got["text"]=True
        else: got["bin"]=len(m)==64*1024
        if got["text"] and got["bin"] and not done.done(): done.set_result(True)
    @pc.on("connectionstatechange")
    def _c(): print("CLIENT: conn=", pc.connectionState, flush=True)
    @pc.on("iceconnectionstatechange")
    def _i(): print("CLIENT: ice=", pc.iceConnectionState, flush=True)
    await pc.setLocalDescription(await pc.createOffer())
    print("CLIENT: gathering...", flush=True)
    t0=time.time()
    while pc.iceGatheringState != "complete":
        await asyncio.sleep(0.05)
        if time.time()-t0>10: print("CLIENT: gather TIMEOUT", flush=True); break
    print("CLIENT: gather done state=", pc.iceGatheringState, flush=True)
    req = urllib.request.Request(url, data=pc.localDescription.sdp.encode(), headers={"Content-Type":"application/sdp"}, method="POST")
    answer = urllib.request.urlopen(req, timeout=10).read().decode()
    print("CLIENT: got answer", len(answer), "bytes", flush=True)
    await pc.setRemoteDescription(RTCSessionDescription(sdp=answer, type="answer"))
    try:
        await asyncio.wait_for(done, timeout=20)
        print("CLIENT: INTEROP OK", flush=True); rc=0
    except asyncio.TimeoutError:
        print(f"CLIENT: TIMEOUT text={got['text']} bin={got['bin']} conn={pc.connectionState} ice={pc.iceConnectionState}", flush=True); rc=1
    await pc.close(); return rc
sys.exit(asyncio.run(main()))
