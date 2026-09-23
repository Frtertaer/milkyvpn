// Package kal2core is the public API surface of the milky VPN core. The app
// (and the test binaries) consume only this package.
package kal2core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

// ServerConfig configures a kal2 egress/entry server.
type ServerConfig struct {
	Listen   string // ":443"
	Domain   string // our domain, e.g. kal.example.dev
	CertFile string // fullchain PEM
	KeyFile  string // private key PEM
	// AutocertDir enables Let's Encrypt via x/crypto autocert (HTTP-01 on :80)
	// when CertFile/KeyFile are empty; certs cache in this directory.
	AutocertDir string
	// AutocertHTTPAddr is where the ACME challenge listener binds (":80").
	AutocertHTTPAddr string
	Identity         []byte // server ed25519 private key (64B) for KAL/2
	StealAddr        string // optional: decoy upstream for foreign SNI ("host:port")
	DriftPath        string // secret drift path, default carrier.DefaultDriftPath
	DecoyDir         string // directory served for plain HTTP probes
	Users            []User
	Logf             func(string, ...any)
}

// User is a provisioned client credential pair.
type User struct {
	ID  string // informational
	PSK []byte // 32 bytes
}

// ClientConfig configures dialing a kal2 server.
type ClientConfig struct {
	Addr      string // host:port of server or relay
	SNI       string // TLS SNI (server domain)
	ServerPub []byte // server Ed25519 public key (32B)
	PSK       []byte // per-user PSK (32B)
	Carrier   string // "veil" (default) or "drift"
	DriftPath string // secret path when Carrier=drift
	// DialContext overrides the base TCP dial (e.g. via HTTP CONNECT proxy).
	DialContext      func(ctx context.Context, network, addr string) (net.Conn, error)
	HandshakeTimeout time.Duration
}

// Client is an established kal2 tunnel end.
type Client struct {
	Sess *kal2.Session
}

// DecodeKey accepts hex or base64 key material.
func DecodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("key must decode to 32 bytes (hex or base64)")
}

// Serve runs a kal2 server until the listener fails.
func Serve(cfg ServerConfig) error {
	var cert *tls.Certificate
	var autocertMgr *autocert.Manager
	if cfg.CertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load cert: %w", err)
		}
		cert = &c
	} else if cfg.AutocertDir != "" {
		autocertMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache:      autocert.DirCache(cfg.AutocertDir),
		}
		httpAddr := cfg.AutocertHTTPAddr
		if httpAddr == "" {
			httpAddr = ":80"
		}
		go func() {
			// HTTP-01 challenge endpoint; non-ACME requests get the decoy page.
			h := autocertMgr.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(defaultDecoyPage))
			}))
			_ = http.ListenAndServe(httpAddr, h)
		}()
	} else {
		return fmt.Errorf("need CertFile/KeyFile or AutocertDir")
	}
	driftPath := cfg.DriftPath
	if driftPath == "" {
		driftPath = carrier.DefaultDriftPath
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	vc := carrier.VeilConfig{
		Domain:    cfg.Domain,
		Identity:  ed25519.PrivateKey(cfg.Identity),
		Users:     toCarrierUsers(cfg.Users),
		StealAddr: cfg.StealAddr,
		Logf:      logf,
		OnSession: func(s *kal2.Session) {
			go func() {
				_ = core.ServeEgress(s, nil, logf)
			}()
		},
	}
	if cert != nil {
		vc.Cert = *cert
	}
	if autocertMgr != nil {
		vc.GetCertificate = autocertMgr.GetCertificate
	}
	v := carrier.NewVeilListener(vc)

	mux := http.NewServeMux()
	mux.Handle(driftPath, v.DriftHandler())
	if cfg.DecoyDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(cfg.DecoyDir)))
	} else {
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(defaultDecoyPage))
		}))
	}
	v.SetMux(mux)

	logf("kal2: serving %s on %s", cfg.Domain, cfg.Listen)
	return v.Serve(ln)
}

// Dial establishes a kal2 session using the configured carrier.
func Dial(ctx context.Context, cfg ClientConfig) (*Client, error) {
	cc := carrier.ClientConfig{
		Addr:             cfg.Addr,
		SNI:              cfg.SNI,
		ServerPub:        cfg.ServerPub,
		PSK:              cfg.PSK,
		DialContext:      cfg.DialContext,
		HandshakeTimeout: cfg.HandshakeTimeout,
	}
	switch cfg.Carrier {
	case "", "veil":
		s, _, err := carrier.DialVeil(ctx, cc)
		if err != nil {
			return nil, err
		}
		return &Client{Sess: s}, nil
	case "drift":
		s, _, err := carrier.DialDrift(ctx, cc, cfg.DriftPath)
		if err != nil {
			return nil, err
		}
		return &Client{Sess: s}, nil
	default:
		return nil, fmt.Errorf("unknown carrier %q", cfg.Carrier)
	}
}

// ServeSocks exposes a local SOCKS5 proxy that forwards through the session.
func (c *Client) ServeSocks(laddr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	go func() { _ = core.ServeSOCKS5(c.Sess, ln) }()
	return ln, nil
}

// Ping checks liveness.
func (c *Client) Ping(ctx context.Context) error {
	return core.PingSession(ctx, c.Sess)
}

// Close ends the session.
func (c *Client) Close() error { return c.Sess.Close() }

func toCarrierUsers(in []User) []carrier.User {
	out := make([]carrier.User, len(in))
	for i, u := range in {
		out[i] = carrier.User{ID: u.ID, PSK: u.PSK}
	}
	return out
}

var _ = http2.ErrCodeNo // keep http2 linked for drift

const defaultDecoyPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>It works</h1></body></html>`
