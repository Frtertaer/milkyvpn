package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// socksPair builds a completed client/server session pair over net.Pipe —
// the client feeds the socks listener's sessFn, the server side accepts and
// echoes a stream payload back.
func socksPair(t *testing.T) (client *kal2.Session) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sh, err := kal2.NewServerHandshake(priv)
	if err != nil {
		t.Fatalf("server hs: %v", err)
	}
	ch, err := kal2.NewClientHandshake(pub, []byte("test-psk"), nil)
	if err != nil {
		t.Fatalf("client hs: %v", err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatalf("first flight: %v", err)
	}
	srvFlight, err := sh.Start(ff[len(kal2.Magic)+1:len(kal2.Magic)+1+32], nil)
	if err != nil {
		t.Fatalf("server flight: %v", err)
	}
	cs, err := ch.ServerFlight(srvFlight)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	ss, err := sh.Finish()
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	c1, c2 := net.Pipe()
	cs.Attach(c1)
	ss.Attach(c2)
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })

	// Server side: accept one stream, ack ok, echo one line back.
	go func() {
		st, err := ss.Accept()
		if err != nil {
			return
		}
		defer st.Close()
		_, _, _, _ = st.Target()
		_ = st.Ack(0x00)
		buf := make([]byte, 64)
		for {
			n, err := st.Read(buf)
			if err != nil {
				return
			}
			if _, err := st.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return cs
}

// BUG-2026-10-02-02: Chromium browsers on Windows issue SOCKS4 CONNECT to a
// `socks=` system proxy; the handshake used to require VER=0x05 and closed —
// every page died while the tunnel was healthy.
func TestSocks4ConnectGranted(t *testing.T) {
	sess := socksPair(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeSOCKS5(func() *kal2.Session { return sess }, ln)

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS4a CONNECT: VER=04 CMD=01 PORT DOMAIN-as-0.0.0.x trick.
	req := []byte{0x04, 0x01, 0x01, 0xbb, 0, 0, 0, 1} // port 443, ip 0.0.0.1
	req = append(req, 'u', 0x00)                     // USERID
	req = append(req, []byte("example.com")...)
	req = append(req, 0x00) // DOMAIN
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 8)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if rep[0] != 0x00 || rep[1] != 0x5a {
		t.Fatalf("reply = %v, want 00 5a granted", rep)
	}
	// Granted: data round-trips through the tunnel stream.
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(c, pong); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if string(pong) != "ping" {
		t.Fatalf("echo = %q", pong)
	}
}

// Plain SOCKS4 with a real IPv4 destination (not the 0.0.0.x 4a form).
func TestSocks4IPv4(t *testing.T) {
	sess := socksPair(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeSOCKS5(func() *kal2.Session { return sess }, ln)

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	req := []byte{0x04, 0x01, 0x00, 0x50, 1, 2, 3, 4, 0x00} // port 80, 1.2.3.4, empty userid
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 8)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if rep[1] != 0x5a {
		t.Fatalf("reply[1] = %#x, want 0x5a", rep[1])
	}
	if binary.BigEndian.Uint16(rep[2:4]) != 80 {
		t.Fatalf("reply port = %d", binary.BigEndian.Uint16(rep[2:4]))
	}
}

// SOCKS5 path must still work through the version-routed handler.
func TestSocks5StillWorks(t *testing.T) {
	sess := socksPair(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeSOCKS5(func() *kal2.Session { return sess }, ln)

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil { // greeting
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil || sel[1] != 0x00 {
		t.Fatalf("method sel: %v %v", sel, err)
	}
	// CONNECT example.com:443 via domain atyp.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xbb)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("reply rep = %#x", rep[1])
	}
}
