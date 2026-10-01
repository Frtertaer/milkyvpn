package carrier

import (
	"context"
	"net"
	"testing"
	"time"
)

// startRTC wires an RTP-shaped (WebRTC-looking) listener onto the shared
// test server and returns its UDP address.
func startRTC(t *testing.T, ts *testServer) string {
	t.Helper()
	rl, err := NewRTCListener(ts.v, &QuasarConfig{WireKey: QuasarWireKey(ts.pub)}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go rl.Serve()
	t.Cleanup(func() { rl.Close() })
	return rl.Addr().String()
}

// End-to-end over RTP-shaped UDP: session up, bulk echo, ping.
func TestRTCSession(t *testing.T) {
	ts := newTestServer(t)
	addr := startRTC(t, ts)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, _, err := DialRTC(ctx, quasarCfg(ts, addr), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()

	bulkEchoTO(t, sess, 16<<10, 10*time.Second)
	if err := sess.Ping([]byte("rtc"), 10*time.Second); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// tapConn records every raw datagram leaving the socket — the wire bytes a
// middlebox would see.
type tapConn struct {
	net.PacketConn
	ch chan []byte
}

func (t *tapConn) WriteTo(b []byte, a net.Addr) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	t.ch <- cp
	return t.PacketConn.WriteTo(b, a)
}

// Wire format check: the datagram on the wire is a valid RTP packet, and
// padding round-trips back to the original payload on the peer.
func TestRTCEnvelope(t *testing.T) {
	ua, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	ub, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ub.Close()

	tap := &tapConn{PacketConn: ua, ch: make(chan []byte, 4)}
	side := newRTPConn(tap, ub.LocalAddr())
	peer := newRTPConn(ub, ua.LocalAddr())

	payload := []byte("kal2-datagram-payload")
	if n, err := side.WriteTo(payload, ub.LocalAddr()); err != nil || n != len(payload) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	wire := <-tap.ch
	if wire[0]>>6 != 2 {
		t.Fatal("not an RTP v2 packet")
	}
	if pt := wire[1] & 0x7f; pt != rtpPT {
		t.Fatalf("unexpected payload type %d", pt)
	}
	if len(wire) < rtpPadMin+rtpHdrLen {
		t.Fatalf("expected padding to ~1KB, got %d", len(wire))
	}

	got := make([]byte, 2048)
	n, _, err := peer.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("unwrap mismatch: %q", got[:n])
	}
}
