package carrier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func mkSelfSigned(t *testing.T, domain string) tls.Certificate {
	t.Helper()
	priv, err := rsaGenerate()
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// echo server target for egress emulation.
func startEcho(t *testing.T) (addr string, port uint16) {
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
			go io.Copy(c, c)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), uint16(a.Port)
}

type testServer struct {
	ln  *net.TCPListener
	v   *VeilListener
	pub ed25519.PublicKey
	psk []byte
}

func newTestServer(t *testing.T) *testServer {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	cert := mkSelfSigned(t, "kal.test")

	v := NewVeilListener(VeilConfig{
		Domain:   "kal.test",
		Cert:     cert,
		Identity: priv,
		Logf:     func(f string, a ...any) { t.Logf(f, a...) },
		Users:    []User{{ID: "u1", PSK: psk}},
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
	mux := http.NewServeMux()
	mux.Handle(DefaultDriftPath, v.DriftHandler())
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("DECOY-OK"))
	}))
	v.SetMux(mux)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go v.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return &testServer{ln: ln.(*net.TCPListener), v: v, pub: pub, psk: psk}
}

func streamEchoTest(t *testing.T, sess *kal2.Session) {
	host, port := startEcho(t)
	st, err := sess.Open(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	msg := []byte("hello-kal2")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch %q", buf)
	}
	st.Close()
}

func TestVeilEndToEnd(t *testing.T) {
	ts := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _, err := DialVeil(ctx, ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	streamEchoTest(t, sess)
}

func TestDriftEndToEnd(t *testing.T) {
	ts := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _, err := DialDrift(ctx, ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	}, "")
	if err != nil {
		t.Fatalf("dial drift: %v", err)
	}
	defer sess.Close()
	streamEchoTest(t, sess)
}

func TestDecoyHTTP(t *testing.T) {
	ts := newTestServer(t)
	raw, err := net.DialTimeout("tcp", ts.ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "kal.test", NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: kal.test\r\nConnection: close\r\n\r\n")
	out, err := io.ReadAll(tc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesContain(out, []byte("DECOY-OK")) {
		t.Fatalf("decoy response wrong: %q", out[:min(len(out), 200)])
	}
}

func TestWrongPSKRejected(t *testing.T) {
	ts := newTestServer(t)
	bad := make([]byte, 32)
	rand.Read(bad)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := DialVeil(ctx, ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                bad,
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}
}
