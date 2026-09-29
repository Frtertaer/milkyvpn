package carrier

import (
	"context"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/cutproxy"
)

// TSPU per-flow truncation: the veil handshake must stay small enough to
// complete inside a truncation budget — otherwise the carrier can never be
// dialed across a cutting middlebox at all.
func TestVeilHandshakeFitsBudget(t *testing.T) {
	ts := newTestServer(t)
	cut := cutproxy.Start(t, ts.ln.Addr().String(), 256<<10)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _, err := DialVeil(ctx, ClientConfig{
		Addr:               cut.Addr(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial through cutter: %v", err)
	}
	defer sess.Close()
	if cut.MaxFlow() > 64<<10 {
		t.Fatalf("handshake consumed %d bytes — too fat for small budgets", cut.MaxFlow())
	}
	streamEchoTest(t, sess)
}
