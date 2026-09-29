//go:build live

package kal2mobile

// Live end-to-end check of the exact call an iOS PacketTunnel extension makes:
// Start(configJSON) → socks port → HTTPS request through the session.
// Not part of `go test ./...` — requires a reachable server and credentials:
//
//	KAL2MOBILE_LIVE_CONFIG='{"addr":"1.2.3.4:443","psk":"…","pub":"…","sni":"…","carrier":"veil","ech":"…"}' \
//	  go test -tags live -run TestKal2mobileLive -v ./pkg/kal2mobile
//
// KAL2MOBILE_LIVE_URL optionally overrides the probe URL (default https://ifconfig.me).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestKal2mobileLiveStartSocksTraffic(t *testing.T) {
	cfg := os.Getenv("KAL2MOBILE_LIVE_CONFIG")
	if cfg == "" {
		t.Skip("KAL2MOBILE_LIVE_CONFIG not set")
	}
	port, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()
	if port <= 0 || port > 65535 {
		t.Fatalf("bad socks port %d", port)
	}
	if !Alive() {
		t.Fatal("Alive()=false right after Start")
	}

	url := os.Getenv("KAL2MOBILE_LIVE_URL")
	if url == "" {
		url = "https://ifconfig.me"
	}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}
	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.(proxy.ContextDialer).DialContext,
		},
	}
	resp, err := hc.Get(url)
	if err != nil {
		t.Fatalf("GET %s via socks: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty body through tunnel")
	}
	t.Logf("GET %s → %d, body: %s", url, resp.StatusCode, string(body))

	Stop()
	if Alive() {
		t.Fatal("Alive()=true after Stop")
	}
	// A second Start must rebind the same socks addr cleanly (crash-restart path).
	if _, err := Start(cfg); err != nil {
		t.Fatalf("restart: %v", err)
	}
	Stop()
}

// silence unused-import check when the context import isn't otherwise needed.
var _ = context.Background
