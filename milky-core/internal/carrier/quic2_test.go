package carrier

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// startQuic2 wires a QUIC v2 listener onto the shared test server and
// returns its UDP address.
func startQuic2(t *testing.T, ts *testServer) string {
	t.Helper()
	q2, err := NewQuic2Listener(ts.v, &tls.Config{
		Certificates: []tls.Certificate{ts.v.cfg.Cert},
	}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go q2.Serve()
	t.Cleanup(func() { q2.Close() })
	return q2.Addr().String()
}

// End-to-end over real QUIC v2: dial, session up, stream echoes, ping works.
// The client config pins Versions=v2 so no v1 fallback can sneak in.
func TestQuic2Session(t *testing.T) {
	ts := newTestServer(t)
	addr := startQuic2(t, ts)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, bc, err := DialQuic2(ctx, quasarCfg(ts, addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()

	bulkEchoTO(t, sess, 16<<10, 10*time.Second)
	if err := sess.Ping([]byte("q2"), 10*time.Second); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if len(bc.Binding()) == 0 {
		t.Fatal("expected exporter channel binding from QUIC TLS leg")
	}
}

// A second connection on the same listener must establish independently —
// catches listener state leaks between QUIC connections.
func TestQuic2SecondConn(t *testing.T) {
	ts := newTestServer(t)
	addr := startQuic2(t, ts)

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		sess, _, err := DialQuic2(ctx, quasarCfg(ts, addr))
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if err := sess.Ping([]byte("s"), 10*time.Second); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
		sess.Close()
	}
}
