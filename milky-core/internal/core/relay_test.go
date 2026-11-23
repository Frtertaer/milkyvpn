package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// rawSessions builds a client/server session pair over an in-memory pipe,
// without an egress loop — the test drives the server's streams itself.
func rawSessions(t *testing.T) (client, server *kal2.Session) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := kal2.NewServerHandshake(priv)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := kal2.NewClientHandshake(pub, []byte("test-psk"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatal(err)
	}
	eph := ff[len(kal2.Magic)+1 : len(kal2.Magic)+1+32]
	srvFlight, err := sh.Start(eph, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ch.ServerFlight(srvFlight)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := sh.Finish()
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	cs.Attach(c1)
	ss.Attach(c2)
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs, ss
}

// tcpPair returns the two ends of a real loopback TCP connection: app is the
// application's socket, relay the one a local proxy would hold.
func tcpPair(t *testing.T) (app, relay *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acc <- c
		}
	}()
	a, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-acc
	t.Cleanup(func() { _ = a.Close(); _ = r.Close() })
	return a.(*net.TCPConn), r.(*net.TCPConn)
}

// readOutcome drains c and classifies how it ended.
func readOutcome(c net.Conn) (n int64, clean bool, err error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = io.Copy(io.Discard, c)
	return n, err == nil, err
}

// The far end resets the tunnel stream mid-response: the application's TCP
// connection must be reset too. It used to be closed cleanly, which told the
// application the response was complete.
func TestRelayStreamAbortResetsLocalConn(t *testing.T) {
	client, server := rawSessions(t)
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		_ = st.Ack(0)
		_, _ = st.Write([]byte("partial response"))
		time.Sleep(50 * time.Millisecond)
		_ = st.Reset()
	}()
	st, err := client.Open("abort.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	app, relay := tcpPair(t)
	go Relay(relay, st)

	n, clean, rerr := readOutcome(app)
	if clean {
		t.Fatalf("stream was reset but the application saw a clean EOF after %d bytes", n)
	}
	var ne net.Error
	if errors.As(rerr, &ne) && ne.Timeout() {
		t.Fatalf("application connection neither closed nor reset: %v", rerr)
	}
}

// The session carrying a relayed connection dies: same — a reset, not EOF.
func TestRelaySessionLossResetsLocalConn(t *testing.T) {
	client, server := rawSessions(t)
	accepted := make(chan *kal2.Stream, 1)
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		_ = st.Ack(0)
		_, _ = st.Write(make([]byte, 64<<10))
		accepted <- st
	}()
	st, err := client.Open("loss.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	app, relay := tcpPair(t)
	go Relay(relay, st)
	<-accepted
	time.Sleep(50 * time.Millisecond)
	_ = client.Close() // the tunnel is gone

	if n, clean, _ := readOutcome(app); clean {
		t.Fatalf("session was lost but the application saw a clean EOF after %d bytes", n)
	}
}

// A clean close stays a clean close: every byte, then EOF.
func TestRelayCleanCloseIsEOF(t *testing.T) {
	client, server := rawSessions(t)
	payload := make([]byte, 1<<20)
	_, _ = rand.Read(payload)
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		_ = st.Ack(0)
		_, _ = st.Write(payload)
		_ = st.Close()
	}()
	st, err := client.Open("clean.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	app, relay := tcpPair(t)
	go Relay(relay, st)

	n, clean, rerr := readOutcome(app)
	if !clean || n != int64(len(payload)) {
		t.Fatalf("clean close: got %d/%d bytes, err=%v", n, len(payload), rerr)
	}
}

// The application resets its connection: the far end of the tunnel must see
// an abort, not a clean end of the request.
func TestRelayLocalResetAbortsStream(t *testing.T) {
	client, server := rawSessions(t)
	got := make(chan error, 1)
	go func() {
		st, err := server.Accept()
		if err != nil {
			got <- err
			return
		}
		_ = st.Ack(0)
		_, err = io.Copy(io.Discard, st)
		got <- err
	}()
	st, err := client.Open("localreset.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	app, relay := tcpPair(t)
	go Relay(relay, st)
	if _, err := app.Write([]byte("half a request")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = app.SetLinger(0)
	_ = app.Close() // RST

	select {
	case err := <-got:
		if !kal2.IsAbort(err) {
			t.Fatalf("far end of a reset connection: want an abort, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("far end never learned the application reset its connection")
	}
}

// The application closes normally: the far end sees a clean end.
func TestRelayLocalCloseIsCleanForPeer(t *testing.T) {
	client, server := rawSessions(t)
	got := make(chan error, 1)
	go func() {
		st, err := server.Accept()
		if err != nil {
			got <- err
			return
		}
		_ = st.Ack(0)
		b, err := io.ReadAll(st)
		if err == nil && string(b) != "whole request" {
			err = errors.New("request truncated: " + string(b))
		}
		got <- err
	}()
	st, err := client.Open("localclose.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	app, relay := tcpPair(t)
	go Relay(relay, st)
	if _, err := app.Write([]byte("whole request")); err != nil {
		t.Fatal(err)
	}
	_ = app.Close()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("far end of a cleanly closed connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("far end never saw the close")
	}
}

// Server egress: the upstream target resets mid-response. The client's
// stream must end in an abort.
func TestEgressUpstreamResetAbortsClientStream(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Write([]byte("partial"))
				time.Sleep(50 * time.Millisecond)
				_ = c.(*net.TCPConn).SetLinger(0)
				_ = c.Close()
			}()
		}
	}()
	cs := egressPair(t, &EgressConfig{AllowPrivate: true})
	st, err := cs.Open("127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, st); !kal2.IsAbort(err) {
		t.Fatalf("upstream reset: want an abort on the client stream, got %v", err)
	}
}

// Server egress under optimistic open: a refused dial must reach the client
// as an abort.
func TestEgressRefusedDialAbortsOptimisticOpen(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close() // nothing listens there now
	cs := egressPair(t, &EgressConfig{AllowPrivate: true})
	st, err := cs.OpenOpt("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, st); !kal2.IsAbort(err) {
		t.Fatalf("refused dial: want an abort, got %v", err)
	}
}

// End to end through the local SOCKS5 entry: a target that refuses the
// connection must not look like an empty, successful response.
func TestSocksRefusedTargetResetsClient(t *testing.T) {
	dead, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(dead.Addr().(*net.TCPAddr).Port)
	_ = dead.Close()

	cs := egressPair(t, &EgressConfig{AllowPrivate: true})
	socks, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	go func() { _ = ServeSOCKS5(func() *kal2.Session { return cs }, socks) }()

	c, err := net.Dial("tcp4", socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatalf("socks reply: %v", err)
	}
	if n, clean, _ := readOutcome(c); clean {
		t.Fatalf("refused target looked like a clean, empty response (%d bytes)", n)
	}
}
