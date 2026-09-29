package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

func TestVeilChannelBindingPresent(t *testing.T) {
	ts := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := 0; i < len(helloRotator)*2; i++ {
		sess, bc, err := DialVeil(ctx, ClientConfig{
			Addr:               ts.ln.Addr().String(),
			SNI:                "kal.test",
			ServerPub:          ts.pub,
			PSK:                ts.psk,
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if len(bc.Binding()) != 32 {
			t.Fatalf("channel binding missing (len %d)", len(bc.Binding()))
		}
		streamEchoTest(t, sess)
		_ = sess.Close()
	}
}

// startTLSInterceptor terminates the client's TLS with its own certificate and
// re-originates TLS to upstream — a MitM that holds a cert the client accepts.
func startTLSInterceptor(t *testing.T, upstream string) string {
	t.Helper()
	cert := mkSelfSigned(t, "kal.test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				front := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
				if err := front.Handshake(); err != nil {
					return
				}
				raw, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				back := tls.Client(raw, &tls.Config{ServerName: "kal.test", InsecureSkipVerify: true, NextProtos: []string{front.ConnectionState().NegotiatedProtocol}})
				defer back.Close()
				if err := back.Handshake(); err != nil {
					return
				}
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(back, front); done <- struct{}{} }()
				go func() { _, _ = io.Copy(front, back); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return ln.Addr().String()
}

// A TLS interceptor the client would accept (verification off) must not be
// able to relay the KAL/2 session: the exporter differs on each TLS leg.
func TestVeilBindingDefeatsTLSInterception(t *testing.T) {
	ts := newTestServer(t)
	mitm := startTLSInterceptor(t, ts.ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, _, err := DialVeil(ctx, ClientConfig{
		Addr:               mitm,
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
		HandshakeTimeout:   5 * time.Second,
	})
	if err == nil {
		_ = sess.Close()
		t.Fatal("session established through a TLS interceptor")
	}
}

func TestVeilSPKIPin(t *testing.T) {
	ts := newTestServer(t)
	cert, err := x509.ParseCertificate(ts.v.cfg.Cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cc := ClientConfig{
		Addr:      ts.ln.Addr().String(),
		SNI:       "kal.test",
		ServerPub: ts.pub,
		PSK:       ts.psk,
		PinSHA256: [][]byte{SPKIPin(cert)},
	}
	sess, _, err := DialVeil(ctx, cc)
	if err != nil {
		t.Fatalf("pinned dial: %v", err)
	}
	streamEchoTest(t, sess)
	_ = sess.Close()

	cc.PinSHA256 = [][]byte{make([]byte, 32)}
	if s, _, err := DialVeil(ctx, cc); err == nil {
		_ = s.Close()
		t.Fatal("wrong pin accepted")
	}
	cc.PinSHA256 = nil
	if s, _, err := DialVeil(ctx, cc); err == nil {
		_ = s.Close()
		t.Fatal("self-signed cert accepted without pin or insecure")
	}
}
