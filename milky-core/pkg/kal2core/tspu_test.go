package kal2core

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/cutproxy"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func tspuSelfSigned(t *testing.T, domain string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// startTSPUServer stands up a real veil listener that proxies session
// streams to their targets — the kal2core-side counterpart of carrier's
// test server (carrier cannot import kal2core: import cycle).
func startTSPUServer(t *testing.T) (addr string, pub ed25519.PublicKey, psk []byte) {
	t.Helper()
	var priv ed25519.PrivateKey
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk = make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	v := carrier.NewVeilListener(carrier.VeilConfig{
		Domain:   "kal.test",
		Cert:     tspuSelfSigned(t, "kal.test"),
		Identity: priv,
		Users:    []carrier.User{{ID: "u1", PSK: psk}},
		Logf:     func(f string, a ...any) { t.Logf(f, a...) },
		OnSession: func(s *kal2.Session) {
			go func() {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() {
						defer st.Close()
						_, host, port, err := st.Target()
						if err != nil {
							st.Ack(0x01)
							return
						}
						up, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(int(port))), 5*time.Second)
						if err != nil {
							st.Ack(0x05)
							return
						}
						st.Ack(0x00)
						defer up.Close()
						done := make(chan struct{}, 2)
						go func() { io.Copy(up, st); done <- struct{}{} }()
						go func() { io.Copy(st, up); done <- struct{}{} }()
						<-done
					}()
				}
			}()
		},
	})
	go func() { _ = v.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), pub, psk
}

// startEcho starts a local TCP echo service for the stream to reach.
func startEcho(t *testing.T) (string, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	fmt.Sscanf(ps, "%d", &port)
	return "127.0.0.1", port
}

// TSPU per-flow truncation end-to-end: dial succeeds (the handshake fits
// the budget), a bulk transfer outgrows it and the middlebox kills the
// flow, then EnableReconnect stands up a fresh session on a new flow —
// the DESIGN.md truncation recovery path.
func TestVeilFlowTruncationReconnect(t *testing.T) {
	addr, pub, psk := startTSPUServer(t)
	cut := cutproxy.Start(t, addr, 384<<10)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cli, err := Dial(ctx, ClientConfig{
		Addr:               cut.Addr(),
		SNI:                "kal.test",
		ServerPub:          pub,
		PSK:                psk,
		Carrier:            "veil",
		Logf:               func(f string, a ...any) { t.Logf(f, a...) },
		InsecureSkipVerify: true,
		Cover:              false,
	})
	if err != nil {
		t.Fatalf("dial through cutter: %v", err)
	}
	defer cli.Close()
	cli.EnableReconnect()

	host, port := startEcho(t)
	st, err := cli.Session().Open(host, port, 10*time.Second)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	payload := make([]byte, 8<<20)
	if _, werr := st.Write(payload); werr == nil {
		_, _ = io.CopyN(io.Discard, st, int64(len(payload)))
	}
	_ = st.Close()

	deadline := time.Now().Add(45 * time.Second)
	for {
		sess := cli.Session()
		if sess != nil && cut.Cuts() > 0 {
			st2, err := sess.Open(host, port, 10*time.Second)
			if err == nil {
				if _, werr := st2.Write([]byte("ping")); werr == nil {
					got := make([]byte, 4)
					if _, rerr := io.ReadFull(st2, got); rerr == nil && string(got) == "ping" {
						_ = st2.Close()
						return
					}
				}
				_ = st2.Close()
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no fresh session; cuts=%d", cut.Cuts())
		}
		time.Sleep(400 * time.Millisecond)
	}
}
