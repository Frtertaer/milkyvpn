package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func TestMosaicStreamReassembly(t *testing.T) {
	s := newMosaicStream()
	msg := []byte("0123456789abcdefghij")
	s.ingest(10, msg[10:15])
	s.ingest(15, msg[15:])
	s.ingest(5, msg[5:12]) // overlaps the buffered segment
	if s.inAck() != 0 {
		t.Fatalf("ack advanced past a gap: %d", s.inAck())
	}
	s.ingest(0, msg[:7])
	s.ingest(0, msg[:3]) // duplicate
	if s.inAck() != uint64(len(msg)) {
		t.Fatalf("ack %d want %d", s.inAck(), len(msg))
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("reassembled %q err %v", got, err)
	}
}

func TestMosaicStreamRetransmit(t *testing.T) {
	s := newMosaicStream()
	_, _ = s.Write([]byte("hello world"))
	off, d := s.takeOut(5)
	if off != 0 || string(d) != "hello" {
		t.Fatalf("take %d %q", off, d)
	}
	off2, d2 := s.takeOut(100)
	if off2 != 5 || string(d2) != " world" {
		t.Fatalf("take %d %q", off2, d2)
	}
	s.rewind(off) // first tile failed
	if off, d := s.takeOut(100); off != 0 || string(d) != "hello world" {
		t.Fatalf("after rewind %d %q", off, d)
	}
	s.ackOut(11)
	if _, d := s.takeOut(100); len(d) != 0 {
		t.Fatalf("acked bytes re-sent: %q", d)
	}
}

// A tile fails after a later tile's ack already covered its range: the
// rewind must not move the send cursor below the acknowledged base.
func TestMosaicStreamRewindBelowAck(t *testing.T) {
	s := newMosaicStream()
	_, _ = s.Write([]byte("abcdefgh"))
	off, _ := s.takeOut(4)
	_, _ = s.takeOut(4)
	s.ackOut(8)
	_, _ = s.Write([]byte("ij"))
	s.rewind(off)
	if o, d := s.takeOut(100); o != 8 || string(d) != "ij" {
		t.Fatalf("after stale rewind: %d %q", o, d)
	}
}

func TestMosaicTileAuth(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, 32)
	tl := &tile{upOff: 42, downAck: 7, data: []byte("payload")}
	_, _ = rand.Read(tl.sid[:])
	b := tl.encode(psk)
	got, err := parseTile(b, psk)
	if err != nil || got.upOff != 42 || got.downAck != 7 || string(got.data) != "payload" || got.sid != tl.sid {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := parseTile(b, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("tile accepted under a different PSK")
	}
	b[mosaicHdrLen+mosaicMACLen] ^= 1
	if _, err := parseTile(b, psk); err == nil {
		t.Fatal("tampered tile accepted")
	}
	r := (&tileResp{downOff: 9, upAck: 3, data: []byte("x")}).encode(psk)
	if got, err := parseTileResp(r, psk); err != nil || got.downOff != 9 || string(got.data) != "x" {
		t.Fatalf("resp round trip: %+v %v", got, err)
	}
}

// cutProxy forwards TCP to upstream but kills every connection once limit
// bytes have flowed in both directions combined (TLS handshake included) —
// the per-flow truncation observed on Russian networks toward foreign
// hosting. It records the largest flow.
type cutProxy struct {
	addr    string
	limit   int64
	maxFlow atomic.Int64
	flows   atomic.Int64
	cuts    atomic.Int64
}

func startCutProxy(t *testing.T, upstream string, limit int64) *cutProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &cutProxy{addr: ln.Addr().String(), limit: limit}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.flows.Add(1)
			go p.handle(c, upstream)
		}
	}()
	return p
}

func (p *cutProxy) handle(c net.Conn, upstream string) {
	defer c.Close()
	up, err := net.Dial("tcp", upstream)
	if err != nil {
		return
	}
	defer up.Close()
	var n atomic.Int64
	pipe := func(dst, src net.Conn) {
		defer dst.Close()
		defer src.Close()
		buf := make([]byte, 4096)
		for {
			k, err := src.Read(buf)
			if k > 0 {
				total := n.Add(int64(k))
				if p.limit > 0 && total > p.limit {
					p.cuts.Add(1)
					return // truncate the flow
				}
				if _, werr := dst.Write(buf[:k]); werr != nil {
					return
				}
				for {
					old := p.maxFlow.Load()
					if total <= old || p.maxFlow.CompareAndSwap(old, total) {
						break
					}
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(up, c)
	pipe(c, up)
}

// bulkEcho pushes size random bytes through an echo stream and checks them.
func bulkEcho(t *testing.T, sess *kal2.Session, size int) {
	t.Helper()
	host, port := startEcho(t)
	st, err := sess.Open(host, port, 20*time.Second)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer st.Close()
	msg := make([]byte, size)
	_, _ = rand.Read(msg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = st.Write(msg)
	}()
	got := make([]byte, size)
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, msg) {
		t.Fatal("echo mismatch")
	}
}

func mosaicCfg(ts *testServer, eps ...string) ClientConfig {
	return ClientConfig{
		Addr:               eps[0],
		Endpoints:          eps,
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
		HandshakeTimeout:   5 * time.Second,
	}
}

func TestMosaicEndToEnd(t *testing.T) {
	ts := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _, err := DialMosaic(ctx, mosaicCfg(ts, ts.ln.Addr().String()), "")
	if err != nil {
		t.Fatalf("dial mosaic: %v", err)
	}
	defer sess.Close()
	streamEchoTest(t, sess)
	bulkEcho(t, sess, 64<<10)
}

// The headline property: every flow is truncated at 16 KiB, which kills a
// single-connection carrier, yet a mosaic session moves far more than that.
func TestMosaicSurvivesFlowTruncation(t *testing.T) {
	ts := newTestServer(t)
	cut := startCutProxy(t, ts.ln.Addr().String(), 16<<10)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Control: a single-connection carrier cannot move a bulk transfer.
	vs, _, err := DialVeil(ctx, ClientConfig{
		Addr: cut.addr, SNI: "kal.test", ServerPub: ts.pub, PSK: ts.psk, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("veil dial through cutter: %v", err)
	}
	if veilSurvives(t, vs, 64<<10) {
		t.Fatal("control: veil moved 64 KiB through a 16 KiB flow cut")
	}
	cut.cuts.Store(0)
	cut.flows.Store(0)
	cut.maxFlow.Store(0)

	sess, _, err := DialMosaic(ctx, mosaicCfg(ts, cut.addr), "")
	if err != nil {
		t.Fatalf("dial mosaic through cutter: %v", err)
	}
	defer sess.Close()
	bulkEcho(t, sess, 96<<10)
	t.Logf("flows=%d largest=%dB cuts=%d", cut.flows.Load(), cut.maxFlow.Load(), cut.cuts.Load())
	if c := cut.cuts.Load(); c > 0 {
		t.Fatalf("%d mosaic flows grew into the cut threshold", c)
	}
}

func veilSurvives(t *testing.T, sess *kal2.Session, size int) bool {
	defer sess.Close()
	host, port := startEcho(t)
	st, err := sess.Open(host, port, 5*time.Second)
	if err != nil {
		return false
	}
	defer st.Close()
	msg := make([]byte, size)
	go func() { _, _ = st.Write(msg) }()
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(st, make([]byte, size))
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(10 * time.Second):
		return false
	}
}

// One session over several entry points: a dead entry and one that goes
// dark mid-session cost retransmits, not the tunnel.
func TestMosaicEndpointLoss(t *testing.T) {
	ts := newTestServer(t)
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	flakyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dark atomic.Bool
	go func() {
		for {
			c, err := flakyLn.Accept()
			if err != nil {
				return
			}
			if dark.Load() {
				c.Close()
				continue
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", ts.ln.Addr().String())
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	t.Cleanup(func() { flakyLn.Close() })

	good := startCutProxy(t, ts.ln.Addr().String(), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, _, err := DialMosaic(ctx, mosaicCfg(ts, deadAddr, flakyLn.Addr().String(), good.addr), "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	bulkEcho(t, sess, 32<<10)
	dark.Store(true)
	bulkEcho(t, sess, 32<<10)
	// Dead endpoints must be sidelined, not keep taxing every tile.
	start := time.Now()
	bulkEcho(t, sess, 256<<10)
	el := time.Since(start)
	t.Logf("256KiB echo with 2/3 endpoints down: %s", el)
	if el > 15*time.Second {
		t.Fatalf("degraded throughput: 256KiB took %s", el)
	}
}

func TestMosaicRejectsProbes(t *testing.T) {
	ts := newTestServer(t)
	post := func(path string, body []byte) int {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "kal.test"}}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequest(http.MethodPost, "https://"+ts.ln.Addr().String()+path, bytes.NewReader(body))
		req.Host = "kal.test"
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	keyed := DefaultMosaicPath + "/" + MosaicPathToken(ts.psk)
	forged := (&tile{data: []byte("x")}).encode(bytes.Repeat([]byte{1}, 32))
	cases := map[string]struct {
		path string
		body []byte
	}{
		"bare path":   {DefaultMosaicPath, forged},
		"wrong token": {DefaultMosaicPath + "/0000000000000000", forged},
		"forged tile": {keyed, forged},
		"garbage":     {keyed, []byte("hello")},
	}
	for name, c := range cases {
		if code := post(c.path, c.body); code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", name, code)
		}
	}
}
