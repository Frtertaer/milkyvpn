//go:build darwin

package tun

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Regression for BUG-2026-09-29-08: `route -n get default` output feeds the
// egress pair; the parser must read the gateway/interface fields.
func TestParseRouteGetDefault(t *testing.T) {
	out := "   route to: default\n" +
		"destination: default\n" +
		"       mask: default\n" +
		"    gateway: 172.16.5.1\n" +
		"  interface: en0\n" +
		"      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
	gw, dev, err := parseRouteGet(out)
	if err != nil {
		t.Fatalf("parseRouteGet: %v", err)
	}
	if gw != "172.16.5.1" || dev != "en0" {
		t.Fatalf("got gw=%q dev=%q", gw, dev)
	}
}

// Regression for BUG-2026-09-29-08: a bound (IP_BOUND_IF) socket must carry
// the recorded egress ifindex — without it connect() fails ENETUNREACH once
// the /1 routes land.
func TestControlBindsIfindex(t *testing.T) {
	dev := DefaultEgress()
	if dev == "" {
		t.Skip("no default egress on this host")
	}
	b := NewBindGuard()
	b.Set(dev)
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		t.Skipf("InterfaceByName(%s): %v", dev, err)
	}
	var bound int
	d := &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		if err := b.Control(network, address, c); err != nil {
			return err
		}
		return c.Control(func(fd uintptr) {
			v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF)
			if err == nil {
				bound = v
			}
		})
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// TEST-NET-1 is unroutable — connect fails, but Control already ran.
	conn, err := d.DialContext(ctx, "tcp", "192.0.2.1:1")
	if err == nil {
		conn.Close()
	}
	if bound != ifi.Index {
		t.Fatalf("IP_BOUND_IF=%d, want %d (%s)", bound, ifi.Index, dev)
	}
}

// Regression for BUG-2026-09-29-08: ensure() installs a /32 bypass via the
// real gateway and Restore() removes it. Root-gated (route(8) needs it).
func TestEnsureAndRestoreBypass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route(8) needs root")
	}
	gw, dev, err := defaultRoute()
	if err != nil || dev == "" {
		t.Skip("no default route")
	}
	b := NewBindGuard()
	b.setEgress(gw, dev)
	b.EnsureIPs([]string{"198.51.100.77"})
	if !routeExists("198.51.100.77") {
		t.Fatal("bypass /32 not installed")
	}
	b.Restore()
	if routeExists("198.51.100.77") {
		t.Fatal("bypass /32 survived Restore")
	}
}

// Stale entries from a crashed run (or a moved gateway) get replaced.
func TestEnsureReplacesStaleRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route(8) needs root")
	}
	gw, dev, err := defaultRoute()
	if err != nil || dev == "" {
		t.Skip("no default route")
	}
	b := NewBindGuard()
	b.setEgress(gw, dev)
	// Plant a stale route through a bogus gateway, then ensure the same dst.
	_ = run("route", "-n", "add", "-host", "198.51.100.78", "-gateway", "10.255.255.1")
	defer run("route", "-n", "delete", "-host", "198.51.100.78")
	b.EnsureIPs([]string{"198.51.100.78"})
	dst, rtgw, _ := routeGet("198.51.100.78")
	if dst != "198.51.100.78" || rtgw != gw {
		t.Fatalf("stale gateway not replaced: dst=%q gw=%q want %q", dst, rtgw, gw)
	}
	b.Restore()
}

// Regression for BUG-2026-09-29-10: the tun→local-SOCKS dial passes
// 127.0.0.1 through Control — it must neither bind to the egress device nor
// install a bypass route (a /32 for loopback hijacks all loopback traffic).
func TestControlSkipsLoopbackAndPrivate(t *testing.T) {
	for _, c := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:11808", false},
		{"10.0.0.5:443", false},
		{"192.168.1.1:443", false},
		{"169.254.1.1:80", false},
		{"224.0.0.1:53", false},
		{"23.133.88.167:443", true},
		{"8.8.8.8:443", true},
	} {
		ip := net.ParseIP(mustHost(t, c.addr))
		if got := bypassable(ip); got != c.want {
			t.Errorf("bypassable(%s)=%v want %v", c.addr, got, c.want)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("route(8) needs root")
	}
	gw, dev, err := defaultRoute()
	if err != nil || dev == "" {
		t.Skip("no default route")
	}
	b := NewBindGuard()
	b.setEgress(gw, dev)
	// Control on a loopback dial must not ensure a bypass for it.
	b.EnsureIPs([]string{"127.0.0.1", "10.99.99.99"})
	if routeExists("127.0.0.1") || routeExists("10.99.99.99") {
		b.Restore()
		t.Fatal("non-public destination got a bypass route")
	}
}

func mustHost(t *testing.T, addr string) string {
	t.Helper()
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The janitor ledger records every installed bypass and is removed on
// graceful Restore.
func TestBypassLedger(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route(8) needs root")
	}
	gw, dev, err := defaultRoute()
	if err != nil || dev == "" {
		t.Skip("no default route")
	}
	ledger := filepath.Join(t.TempDir(), "routes.ledger")
	b := NewBindGuard()
	b.setEgress(gw, dev)
	b.SetLedger(ledger)
	b.EnsureIPs([]string{"198.51.100.79"})
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if !strings.Contains(string(data), "198.51.100.79") {
		t.Fatalf("ledger missing bypass: %q", data)
	}
	b.Restore()
	if _, err := os.Stat(ledger); !os.IsNotExist(err) {
		t.Fatal("ledger not removed on Restore")
	}
}

// routeExists reports a dedicated host route — the covering /1 resolves too,
// so match the destination field, not the exit status.
func routeExists(ip string) bool {
	dst, _, err := routeGet(ip)
	return err == nil && dst == ip
}
