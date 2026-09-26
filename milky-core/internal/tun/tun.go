// Package tun provides a full-device VPN mode: a wintun adapter plus a
// userspace TCP/UDP stack whose flows are carried over a kal2 session.
//
// The data path is:
//
//	Windows app → wintun adapter → netstack (this package) → kal2 stream →
//	server wildcard relay → internet
//
// TUN mode requires elevation (adapter creation + route changes). The SOCKS5
// proxy mode remains the unprivileged default.
package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

// DefaultAddr is the IPv4 address assigned to the TUN interface.
const DefaultAddr = "10.85.0.1"

// Stream is the minimal shape of a kal2 stream for tunneling.
type Stream interface {
	io.ReadWriteCloser
}

// Config wires the TUN device into a kal2 session.
type Config struct {
	// Name is the adapter friendly name shown in the network UI.
	Name string
	// Addr is the IPv4 address assigned to the TUN interface.
	Addr string
	// ServerIPs are the tunnel server's own addresses. Each gets a /32 route
	// through the real default gateway so the tunnel's own traffic is not
	// routed back into the tunnel.
	ServerIPs []string
	// OpenTCP opens a kal2 TCP stream to host:port (netstack-side connect).
	OpenTCP func(ctx context.Context, addr string) (Stream, error)
	// OpenUDP opens a kal2 UDP relay stream (wildcard; datagrams are
	// framed with per-datagram destination headers).
	OpenUDP func(ctx context.Context) (Stream, error)
	// Logf receives lifecycle messages.
	Logf func(string, ...any)
}

func (c *Config) logf() func(string, ...any) {
	if c.Logf != nil {
		return c.Logf
	}
	return func(string, ...any) {}
}

// Run brings the adapter up, installs routes, and pumps packets until ctx is
// cancelled or the device dies. Routes are removed and the adapter closed on
// return (best effort).
func Run(ctx context.Context, cfg *Config) error {
	if cfg == nil || cfg.OpenTCP == nil || cfg.OpenUDP == nil {
		return fmt.Errorf("tun: OpenTCP/OpenUDP handlers required")
	}
	logf := cfg.logf()
	if !IsElevated() {
		return fmt.Errorf("tun: requires administrator rights")
	}
	dev, err := openDevice(cfg)
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	defer dev.Close()
	if err := dev.Configure(cfg.ServerIPs); err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	defer dev.Restore()
	logf("tun: adapter %s up at %s", cfg.Name, cfg.Addr)
	return runStack(ctx, dev, cfg)
}

// splice moves bytes both ways until either side ends; returns bytes a←b and b←a.
func splice(a, b io.ReadWriteCloser) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ab, _ = io.Copy(a, b)
		closeRW(a)
		closeRW(b)
	}()
	ba, _ = io.Copy(b, a)
	closeRW(b)
	closeRW(a)
	wg.Wait()
	return ab, ba
}

func closeRW(c io.ReadWriteCloser) { _ = c.Close() }

// hostPort formats a netstack flow id target.
func hostPort(ip fmt.Stringer, port uint16) string {
	return net.JoinHostPort(ip.String(), fmt.Sprint(port))
}
