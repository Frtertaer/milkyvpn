package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func TestPublicAddr(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.9.10", "::1", "0.0.0.0", "::", "10.1.2.3", "172.16.0.1",
		"192.168.1.1", "169.254.169.254", "100.64.0.1", "fc00::1", "fd12::1", "fe80::1",
		"224.0.0.1", "ff02::1", "255.255.255.255", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		"::ffff:10.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1",
		"198.18.0.1", "192.0.2.1",
	}
	for _, s := range blocked {
		if publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1", "64:ff9b::808:808"} {
		if !publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestPublicAddrRejectsOwnInterfaces(t *testing.T) {
	ifas, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	for _, a := range ifas {
		if pn, ok := a.(*net.IPNet); ok {
			ip, _ := netip.AddrFromSlice(pn.IP)
			if publicAddr(ip) {
				t.Errorf("own interface address %s must be blocked", ip)
			}
		}
	}
}

func egressPair(t *testing.T, cfg *EgressConfig) *kal2.Session {
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
	go func() { _ = ServeEgressCfg(ss, nil, cfg, t.Logf) }()
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs
}

func loopbackEcho(t *testing.T, network string) (net.Listener, uint16) {
	t.Helper()
	addr := "127.0.0.1:0"
	if network == "tcp6" {
		addr = "[::1]:0"
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		if network == "tcp6" {
			return nil, 0
		}
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln, uint16(ln.Addr().(*net.TCPAddr).Port)
}

// A VPN user must not reach loopback-only services (e.g. the panel ops API)
// through the server egress — literal IPv4/IPv6, mapped form and names.
func TestEgressRefusesLoopbackTCP(t *testing.T) {
	_, port := loopbackEcho(t, "tcp4")
	cs := egressPair(t, nil)
	for _, host := range []string{"127.0.0.1", "::ffff:127.0.0.1", "localhost", "LOCALHOST.", "169.254.169.254", "10.0.0.1"} {
		if st, err := cs.Open(host, port, 3*time.Second); err == nil {
			st.Close()
			t.Errorf("egress dialed %s:%d", host, port)
		}
	}
	if _, port6 := loopbackEcho(t, "tcp6"); port6 != 0 {
		if st, err := cs.Open("::1", port6, 3*time.Second); err == nil {
			st.Close()
			t.Errorf("egress dialed [::1]:%d", port6)
		}
	}
}

// Names resolving to loopback are refused after resolution (Dialer.Control),
// not only by name matching.
func TestGuardDialerChecksResolvedAddress(t *testing.T) {
	ln, port := loopbackEcho(t, "tcp4")
	_ = ln
	d := guardDialer(&net.Dialer{Timeout: 2 * time.Second})
	_, err := d.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if !errors.Is(err, ErrEgressBlocked) {
		t.Fatalf("want ErrEgressBlocked, got %v", err)
	}
	var cfg *EgressConfig
	if _, err := cfg.dial(&net.Dialer{Timeout: 2 * time.Second}, "tcp", "127.0.0.1", port, t.Logf); !errors.Is(err, ErrEgressBlocked) {
		t.Fatalf("nil cfg: want ErrEgressBlocked, got %v", err)
	}
	if _, err := (&EgressConfig{PreferIPv4: true}).dial(&net.Dialer{Timeout: 2 * time.Second}, "tcp", "127.0.0.1", port, t.Logf); !errors.Is(err, ErrEgressBlocked) {
		t.Fatalf("prefer4: want ErrEgressBlocked, got %v", err)
	}
	up := &EgressConfig{Upstream: &UpstreamSOCKS5{Addr: ln.Addr().String(), Timeout: time.Second}}
	if _, err := up.dial(&net.Dialer{}, "tcp", "localhost", 9449, t.Logf); !errors.Is(err, ErrEgressBlocked) {
		t.Fatalf("upstream: want ErrEgressBlocked, got %v", err)
	}
}

func TestEgressAllowPrivateOptIn(t *testing.T) {
	_, port := loopbackEcho(t, "tcp4")
	cs := egressPair(t, &EgressConfig{AllowPrivate: true})
	st, err := cs.Open("127.0.0.1", port, 3*time.Second)
	if err != nil {
		t.Fatalf("AllowPrivate dial: %v", err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func udpFrame(addr *net.UDPAddr, payload []byte) []byte {
	return appendUDPHeader(nil, addr, payload)
}

func TestEgressRefusesLoopbackUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	got := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 64)
		if _, _, err := pc.ReadFrom(buf); err == nil {
			got <- struct{}{}
		}
	}()
	cs := egressPair(t, nil)
	st, err := cs.OpenNet("udp", "0.0.0.0", 0, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dst := pc.LocalAddr().(*net.UDPAddr)
	if _, err := st.Write(udpFrame(dst, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	writeRaw := func(f []byte) {
		f = binary.BigEndian.AppendUint16(f, uint16(dst.Port))
		f = append(f, 'x')
		if _, err := st.Write(append(binary.LittleEndian.AppendUint16(nil, uint16(len(f))), f...)); err != nil {
			t.Fatal(err)
		}
	}
	// ATYP 0x04 carrying the IPv4-mapped form of 127.0.0.1
	writeRaw(append([]byte{0x04}, net.ParseIP("::ffff:127.0.0.1").To16()...))
	// domain ATYP resolving to loopback
	writeRaw(append([]byte{0x03, byte(len("localhost"))}, "localhost"...))
	select {
	case <-got:
		t.Fatal("egress relayed a UDP datagram to loopback")
	case <-time.After(500 * time.Millisecond):
	}
}
