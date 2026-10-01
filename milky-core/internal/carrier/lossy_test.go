package carrier

import (
	"context"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// udpLossProxy forwards UDP datagrams client↔upstream, dropping each with a
// configurable per-1000 probability in either direction — the netem-loss
// profile for quasar stress. Seeded RNG keeps runs reproducible.
type udpLossProxy struct {
	addr     string
	upstream *net.UDPAddr
	dropC2S  atomic.Int64 // per-1000, client→server direction
	dropS2C  atomic.Int64 // per-1000, server→client
	mu       sync.Mutex
	rng      *mrand.Rand
	seen     atomic.Int64
	passed   atomic.Int64
}

func startUDPLossProxy(t *testing.T, upstream string, seed uint64) *udpLossProxy {
	t.Helper()
	up, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	upConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	p := &udpLossProxy{addr: ln.LocalAddr().String(), upstream: up}
	p.mu.Lock()
	p.rng = mrand.New(mrand.NewPCG(seed, seed^0x9e37))
	p.mu.Unlock()

	var clientAddr atomic.Value // last client seen (single-client proxy)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, src, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddr.Store(src)
			p.seen.Add(1)
			if p.dropC2S.Load() > 0 {
				p.mu.Lock()
				d := p.rng.IntN(1000) < int(p.dropC2S.Load())
				p.mu.Unlock()
				if d {
					continue
				}
			}
			if _, err := upConn.WriteToUDP(buf[:n], p.upstream); err == nil {
				p.passed.Add(1)
			}
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, _, err := upConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cl, _ := clientAddr.Load().(*net.UDPAddr)
			if cl == nil {
				continue
			}
			p.seen.Add(1)
			if p.dropS2C.Load() > 0 {
				p.mu.Lock()
				d := p.rng.IntN(1000) < int(p.dropS2C.Load())
				p.mu.Unlock()
				if d {
					continue
				}
			}
			if _, err := ln.WriteToUDP(buf[:n], cl); err == nil {
				p.passed.Add(1)
			}
		}
	}()
	t.Cleanup(func() { ln.Close(); upConn.Close() })
	return p
}

// startQuasar wires a quasar (UDP/KCP) listener onto the shared test server
// and returns its UDP address.
func startQuasar(t *testing.T, ts *testServer) string {
	t.Helper()
	ql, err := NewQuasarListener(ts.v, &QuasarConfig{
		WireKey: QuasarWireKey(ts.pub),
	}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ql.Serve()
	t.Cleanup(func() { ql.Close() })
	return ql.Addr().String()
}

func quasarCfg(ts *testServer, addr string) ClientConfig {
	return ClientConfig{
		Addr:               addr,
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
		HandshakeTimeout:   20 * time.Second,
	}
}

// Quasar through an emulated lossy UDP path. KCP's ARQ must keep the session
// alive and moving data even when most datagrams die; the interesting edge is
// handshake survival and bounded degradation, not raw speed.
func TestQuasarLossMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		drop    int64 // per-1000 both directions
		budget  time.Duration
		payload int
	}{
		{"25%", 250, 30 * time.Second, 64 << 10},
		{"50%", 500, 45 * time.Second, 32 << 10},
		{"85%", 850, 120 * time.Second, 8 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t)
			qaddr := startQuasar(t, ts)
			lossy := startUDPLossProxy(t, qaddr, 0x5eed)
			lossy.dropC2S.Store(tc.drop)
			lossy.dropS2C.Store(tc.drop)

			ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
			defer cancel()
			cfg := quasarCfg(ts, lossy.addr)
			cfg.HandshakeTimeout = tc.budget / 2
			sess, _, err := DialQuasar(ctx, cfg, nil)
			if err != nil {
				t.Fatalf("dial under %s loss: %v", tc.name, err)
			}
			defer sess.Close()

			// Session handshake is up; a stream must still complete. Open and
			// ping timeouts scale with the leg budget: at 85% loss one ARQ
			// round-trip already eats tens of seconds.
			openTO := tc.budget / 2
			bulkEchoTO(t, sess, tc.payload, openTO)
			pingTO := tc.budget / 4
			if pingTO < 15*time.Second {
				pingTO = 15 * time.Second
			}
			if err := sess.Ping([]byte("loss"), pingTO); err != nil {
				t.Fatalf("ping under %s loss: %v", tc.name, err)
			}
			t.Logf("%s loss: seen=%d passed=%d", tc.name, lossy.seen.Load(), lossy.passed.Load())
		})
	}
}

// A quasar session whose path goes fully dark (100% loss both ways) must be
// detectable by Ping — this is the signal the lanes watchdog consumes.
func TestQuasarTotalLossDetectable(t *testing.T) {
	ts := newTestServer(t)
	qaddr := startQuasar(t, ts)
	lossy := startUDPLossProxy(t, qaddr, 0x5eed)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, _, err := DialQuasar(ctx, quasarCfg(ts, lossy.addr), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	if err := sess.Ping([]byte("alive"), 10*time.Second); err != nil {
		t.Fatalf("baseline ping: %v", err)
	}

	lossy.dropC2S.Store(1000)
	lossy.dropS2C.Store(1000)
	if err := sess.Ping([]byte("dead"), 3*time.Second); err == nil {
		t.Fatal("ping succeeded under total loss — zombie session is invisible")
	}
	// Restore the path: KCP has no session teardown on loss, so a session
	// whose packets now flow again must work without a redial.
	lossy.dropC2S.Store(0)
	lossy.dropS2C.Store(0)
	if err := sess.Ping([]byte("back"), 15*time.Second); err != nil {
		t.Fatalf("session did not resume after loss window: %v", err)
	}
}

// Mosaic under a per-flow cutoff tighter than a TLS handshake — every tile
// flow dies in the handshake, so probe must fail the dial cleanly, not hang.
func TestMosaicCutBelowHandshake(t *testing.T) {
	ts := newTestServer(t)
	// 2KiB is safely below any real TLS 1.3 handshake — a 4KiB cut sits at
	// the boundary and under -race timing a handshake can squeak through.
	cut := startCutProxy(t, ts.ln.Addr().String(), 2<<10)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, err := DialMosaic(ctx, mosaicCfg(ts, cut.addr), "")
	if err == nil {
		t.Fatal("mosaic dialed through a 2KiB cut — no tile can complete")
	}
}

// Mosaic under a cut just above the handshake: each flow carries a couple of
// tiles then dies — the session must still move data (slowly) by retiring
// connections early and re-dialing.
func TestMosaicSurvivesShallowCut(t *testing.T) {
	ts := newTestServer(t)
	cut := startCutProxy(t, ts.ln.Addr().String(), 12<<10)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, _, err := DialMosaic(ctx, mosaicCfg(ts, cut.addr), "")
	if err != nil {
		t.Fatalf("dial through 12KiB cut: %v", err)
	}
	defer sess.Close()
	bulkEcho(t, sess, 32<<10)
	t.Logf("flows=%d cuts=%d", cut.flows.Load(), cut.cuts.Load())
}

