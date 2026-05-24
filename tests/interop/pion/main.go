// main.go — Pion (Go) WebRTC data-channel interop peer for Bolt API.
//
// A third INDEPENDENT, non-Bolt WebRTC stack (Pion) the Bolt server is proven
// against, mirroring tests/interop/aiortc_datachannel.py:
//   1. create a PeerConnection + a "chat" data channel,
//   2. CreateOffer / SetLocalDescription, wait for ICE gathering complete
//      (non-trickle: the answerer is ICE-lite),
//   3. POST the offer SDP to http://127.0.0.1:<port><signaling_path>,
//   4. SetRemoteDescription(answer),
//   5. on the channel open: send a text + a 64 KiB binary message,
//   6. assert BOTH echoes return byte-exact,
//   7. exit 0 on success, nonzero on any failure, hard-bounded so it can never
//      hang the bounded gtest leg.
//
// Usage: go run . <port> [signaling_path]   (default path /webrtc/offer)
//
// No mocks: a genuine ICE -> DTLS -> SCTP -> DCEP handshake over real UDP
// against the Bolt ICE-lite / DTLS-server / Bolt-native-SCTP answerer.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	overallTimeout = 20 * time.Second
	// 48 KiB: ~45 SCTP fragments — exercises real fragmentation/reassembly while
	// staying UNDER Pion v4's hardcoded 64 KiB data-channel message ceiling.
	// Pion (sctptransport.go updateMessageSize, issue pion/webrtc#758) pins both
	// remoteMaxMessageSize and canSendSize to 65536 and IGNORES the answerer's
	// a=max-message-size, so any reassembled message >= 64 KiB is dropped by Pion
	// itself — confirmed with a step debugger: the Bolt server sends + the peer
	// cumulatively SACKs all 60 fragments of a 64 KiB echo, but Pion never
	// surfaces it. This is a Pion default, NOT a Bolt limit (aiortc's 64 KiB leg
	// and the in-process loopback both round-trip 64 KiB fine). 48 KiB keeps the
	// Pion gate a true multi-fragment interop proof without tripping that ceiling.
	defaultBinSize = 48 * 1024
	textMsg        = "bolt-pion-interop-roundtrip-0123456789"
)

var binSize = defaultBinSize

// postOffer POSTs the offer SDP and returns the answer SDP body (raw text).
func postOffer(url, sdp string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(sdp)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/sdp")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signaling POST returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func expectedBin() []byte {
	b := make([]byte, binSize)
	for i := range b {
		b[i] = byte((i*37 + 11) & 0xFF)
	}
	return b
}

func run(port int, signalingPath string) int {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, signalingPath)
	wantBin := expectedBin()

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "INTEROP FAIL (peerconnection): %v\n", err)
		return 4
	}
	defer pc.Close()

	dc, err := pc.CreateDataChannel("chat", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INTEROP FAIL (datachannel): %v\n", err)
		return 4
	}

	textOK := make(chan struct{}, 1)
	binOK := make(chan struct{}, 1)
	failed := make(chan error, 1)

	dc.OnOpen(func() {
		if e := dc.SendText(textMsg); e != nil {
			failed <- e
			return
		}
		if e := dc.Send(wantBin); e != nil {
			failed <- e
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if msg.IsString {
			if string(msg.Data) == textMsg {
				select {
				case textOK <- struct{}{}:
				default:
				}
			}
		} else if bytes.Equal(msg.Data, wantBin) {
			select {
			case binOK <- struct{}{}:
			default:
			}
		}
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed ||
			s == webrtc.PeerConnectionStateClosed {
			select {
			case failed <- fmt.Errorf("connection %s", s.String()):
			default:
			}
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INTEROP FAIL (offer): %v\n", err)
		return 4
	}
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(offer); err != nil {
		fmt.Fprintf(os.Stderr, "INTEROP FAIL (setlocal): %v\n", err)
		return 4
	}
	<-gatherComplete // non-trickle: send full SDP with candidates

	answerSDP, err := postOffer(url, pc.LocalDescription().SDP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INTEROP FAIL (signaling): %v\n", err)
		return 4
	}
	if err = pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: answerSDP,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "INTEROP FAIL (setremote): %v\n", err)
		return 4
	}

	gotText, gotBin := false, false
	deadline := time.After(overallTimeout)
	for !(gotText && gotBin) {
		select {
		case <-textOK:
			gotText = true
		case <-binOK:
			gotBin = true
		case e := <-failed:
			fmt.Fprintf(os.Stderr, "INTEROP FAIL: %v\n", e)
			return 3
		case <-deadline:
			fmt.Fprintf(os.Stderr,
				"INTEROP FAIL: timeout after %s (text=%v bin=%v)\n",
				overallTimeout, gotText, gotBin)
			return 2
		}
	}
	fmt.Printf("INTEROP OK: text echo + %dKiB binary echo round-tripped\n",
		binSize/1024)
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pion <port> [signaling_path]")
		os.Exit(64)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port <= 0 || port > 65535 {
		fmt.Fprintf(os.Stderr, "bad port %q\n", os.Args[1])
		os.Exit(64)
	}
	signalingPath := "/webrtc/offer"
	if len(os.Args) > 2 {
		signalingPath = os.Args[2]
	}
	if len(os.Args) > 3 { // optional binary size override (diagnostic)
		if n, e := strconv.Atoi(os.Args[3]); e == nil && n >= 0 {
			binSize = n
		}
	}
	os.Exit(run(port, signalingPath))
}
