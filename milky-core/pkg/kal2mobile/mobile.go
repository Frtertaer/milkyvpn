// Package kal2mobile is the gomobile-friendly facade over kal2core for the
// Flutter app (Android VpnService / iOS NetworkExtension). Only primitive
// types cross the boundary: Start takes a JSON config, everything else is
// status queries.
//
// configJSON keys (all strings):
//
//	{"addr":"ip:443[,ip2:443,...]", "sni":"kal.example.dev",
//	 "carrier":"auto|veil|drift", "path":"/api/v2/stream",
//	 "pub":"<hex>", "psk":"<hex>", "socks":"127.0.0.1:10808"}
//
// Point OS proxy / VPN routing at the returned SOCKS port.
package kal2mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/pkg/kal2core"
)

type mobileConfig struct {
	Addr      string `json:"addr"`
	SNI       string `json:"sni"`
	Carrier   string `json:"carrier"`
	DriftPath string `json:"path"`
	Pub       string `json:"pub"`
	PSK       string `json:"psk"`
	Socks     string `json:"socks"`
}

var (
	mu      sync.Mutex
	client  *kal2core.Client
	socksLn net.Listener
	logf    = func(string, ...any) {}
)

// LogSink receives 'kal2: ...' log lines. gomobile cannot bind SetLogger
// directly (function-typed parameters are unsupported), so ObjC/Swift and
// Java/Kotlin callers implement this interface instead.
type LogSink interface {
	Log(msg string)
}

// SetLogSink installs a LogSink for kal2 log lines (mobile entry point).
func SetLogSink(s LogSink) {
	if s == nil {
		SetLogger(nil)
		return
	}
	SetLogger(s.Log)
}

// SetLogger installs a callback receiving 'kal2: ...' lines — wire it to the
// platform logger.
func SetLogger(l func(msg string)) {
	mu.Lock()
	defer mu.Unlock()
	if l == nil {
		logf = func(string, ...any) {}
		return
	}
	logf = func(f string, a ...any) { l(fmt.Sprintf(f, a...)) }
}

// Start connects with the JSON config, enables the reconnect watchdog, and
// returns the local SOCKS5 listen port (e.g. 10808).
func Start(configJSON string) (int, error) {
	var mc mobileConfig
	if err := json.Unmarshal([]byte(configJSON), &mc); err != nil {
		return 0, fmt.Errorf("bad config JSON: %w", err)
	}
	if mc.Addr == "" || mc.Pub == "" || mc.PSK == "" {
		return 0, errors.New("config needs addr, pub, psk")
	}
	pub, err := kal2core.DecodeKey(mc.Pub)
	if err != nil {
		return 0, fmt.Errorf("bad pub: %w", err)
	}
	psk, err := kal2core.DecodeKey(mc.PSK)
	if err != nil {
		return 0, fmt.Errorf("bad psk: %w", err)
	}
	socks := mc.Socks
	if socks == "" {
		socks = "127.0.0.1:10808"
	}
	addrs := splitComma(mc.Addr)
	if len(addrs) == 0 {
		return 0, errors.New("no usable addr")
	}

	mu.Lock()
	defer mu.Unlock()
	stopLocked()

	cfg := kal2core.ClientConfig{
		Addr:      addrs[0],
		Addrs:     addrs,
		SNI:       mc.SNI,
		ServerPub: pub,
		PSK:       psk,
		Carrier:   mc.Carrier,
		DriftPath: mc.DriftPath,
		Logf:      logf,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cli, err := kal2core.Dial(ctx, cfg)
	if err != nil {
		return 0, err
	}
	ln, err := cli.ServeSocks(socks)
	if err != nil {
		_ = cli.Close()
		return 0, err
	}
	cli.EnableReconnect()
	client = cli
	socksLn = ln
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	logf("core: up (%s)", ln.Addr())
	return p, nil
}

// Stop tears the session down (idempotent).
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

func stopLocked() {
	if client != nil {
		_ = client.Close()
		client = nil
	}
	if socksLn != nil {
		_ = socksLn.Close()
		socksLn = nil
	}
}

// Alive reports whether a session is currently connected.
func Alive() bool {
	mu.Lock()
	defer mu.Unlock()
	return client != nil && client.Session() != nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
