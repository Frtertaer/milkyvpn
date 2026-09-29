// Package kal2mobile is the gomobile-friendly facade over kal2core for the
// Flutter app (Android VpnService / iOS NetworkExtension). Only primitive
// types cross the boundary: Start takes a JSON config, everything else is
// status queries.
//
// configJSON keys (all strings):
//
//	{"addr":"ip:443[,ip2:443,...]", "sni":"kal.example.dev",
//	 "carrier":"auto|veil|drift", "path":"/api/v2/stream",
//	 "pub":"<hex>", "psk":"<hex>", "socks":"127.0.0.1:10808",
//	 "ech":"<base64 ECHConfigList>", "cover":true,
//	 "pin":"<b64 or hex sha256(SPKI)>[,...]", "insecure":false,
//	 "tun":false, "tun_fd":0}
//
// The outer TLS certificate is verified against the system roots unless
// "pin" is given (SPKI pin replaces CA verification) or "insecure" is true
// (legacy devices whose root store lacks the server's CA).
//
// Point OS proxy / VPN routing at the returned SOCKS port. `tun` brings up
// the platform TUN adapter (root/admin); `tun_fd` adopts an existing fd —
// the Android VpnService.establish() parcel fd — instead.
package kal2mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/tun"
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
	ECH       string `json:"ech"`    // base64 ECHConfigList (link param ech=)
	Cover     *bool  `json:"cover"`  // default on: jittered chaff against timing DPI
	Pin       string `json:"pin"`
	Insecure  bool   `json:"insecure"`
	Tun       bool   `json:"tun"`    // platform TUN adapter (root/admin)
	TunFd     int    `json:"tun_fd"` // Android: adopt a VpnService fd
	TunAddr   string `json:"tun_addr"`
}

var (
	mu        sync.Mutex
	client    *kal2core.Client
	socksLn   net.Listener
	tunCancel context.CancelFunc
	logf      = func(string, ...any) {}
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

	var echList []byte
	if mc.ECH != "" {
		echList, err = base64.StdEncoding.DecodeString(mc.ECH)
		if err != nil {
			echList, err = base64.RawURLEncoding.DecodeString(mc.ECH)
		}
		if err != nil {
			return 0, fmt.Errorf("bad ech param: %w", err)
		}
	}
	cover := mc.Cover == nil || *mc.Cover
	var pins [][]byte
	for _, p := range splitComma(mc.Pin) {
		b, err := kal2core.DecodeKey(p)
		if err != nil {
			return 0, fmt.Errorf("bad pin: %w", err)
		}
		pins = append(pins, b)
	}

	cfg := kal2core.ClientConfig{
		Addr:               addrs[0],
		Addrs:              addrs,
		SNI:                mc.SNI,
		ServerPub:          pub,
		PSK:                psk,
		Carrier:            mc.Carrier,
		DriftPath:          mc.DriftPath,
		Logf:               logf,
		InsecureSkipVerify: mc.Insecure,
		PinSHA256:          pins,
		ECHConfigList:      echList,
		Cover:              cover,
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
	if mc.Tun || mc.TunFd > 0 {
		ctx2, cancel := context.WithCancel(context.Background())
		tunCancel = cancel
		go func() {
			if err := runTun(ctx2, mc, cli, addrs); err != nil && ctx2.Err() == nil {
				logf("core: tun stopped: %v", err)
			}
		}()
	}
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
	if tunCancel != nil {
		tunCancel()
		tunCancel = nil
	}
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

// runTun bridges the platform TUN device into the live session — same
// wiring as cmd/kal2-client's -tun flag.
func runTun(ctx context.Context, mc mobileConfig, cli *kal2core.Client, addrs []string) error {
	var serverIPs []string
	for _, a := range addrs {
		host, _, _ := net.SplitHostPort(a)
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			serverIPs = append(serverIPs, host)
			continue
		}
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					serverIPs = append(serverIPs, ip4.String())
				}
			}
		}
	}
	addr := mc.TunAddr
	if addr == "" {
		addr = tun.DefaultAddr
	}
	return tun.Run(ctx, &tun.Config{
		Name:      "milky0",
		Addr:      addr,
		ServerIPs: serverIPs,
		Fd:        uintptr(mc.TunFd),
		Logf:      logf,
		OpenTCP: func(_ context.Context, target string) (tun.Stream, error) {
			sess := cli.Session()
			if sess == nil {
				return nil, errors.New("no live session")
			}
			host, ps, err := net.SplitHostPort(target)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(ps)
			if err != nil {
				return nil, err
			}
			return sess.Open(host, uint16(port), 15*time.Second)
		},
		OpenUDP: func(_ context.Context) (tun.Stream, error) {
			sess := cli.Session()
			if sess == nil {
				return nil, errors.New("no live session")
			}
			return sess.OpenNet("udp", "0.0.0.0", 0, 15*time.Second)
		},
	})
}
