//go:build darwin

package tun

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ipv6BoundIF is net.inet6.ip6.bound_if — x/sys/unix does not define it.
const ipv6BoundIF = 125

// BindGuard keeps carrier traffic out of the tunnel on Darwin. Two pieces
// are needed — unlike Linux SO_BINDTODEVICE, an IP_BOUND_IF socket still
// resolves its destination through the FIB and connect() fails with
// ENETUNREACH once the /1 routes through utun beat the default. So in
// addition to binding the socket we maintain a scoped /32 host route via the
// real gateway for every carrier destination; without it the first session
// dies the first time the kernel revalidates the bound socket's route.
//
// The /32 entries are the only kernel state that does not die with the utun
// file descriptor, so kill -9 would leave them behind: each add is appended
// to a ledger file (SetLedger) that kal2-client's -route-janitor child
// replays as deletions once its parent is gone.
type BindGuard struct {
	idx       atomic.Uint32 // ifindex, 0 = unset
	mu        sync.Mutex
	gw        string              // current default gateway ("" = unknown/offline)
	dev       string              // current egress device
	hosts     map[string]struct{} // /32 bypass routes installed
	ledger    string              // janitor ledger file ("" = no crash watchdog)
	lastProbe time.Time           // throttle for route -n get default
}

func NewBindGuard() *BindGuard { return &BindGuard{} }

// Set records the egress device; called once Configure learns it.
func (b *BindGuard) Set(dev string) {
	if dev == "" {
		return
	}
	if ifi, err := net.InterfaceByName(dev); err == nil {
		b.idx.Store(uint32(ifi.Index))
	}
	b.mu.Lock()
	b.dev = dev
	b.mu.Unlock()
}

// setEgress records gateway+device together (Configure already resolved both).
func (b *BindGuard) setEgress(gw, dev string) {
	b.Set(dev)
	b.mu.Lock()
	b.gw = gw
	b.mu.Unlock()
}

// Dev is the currently recorded ifindex (0 until configured).
func (b *BindGuard) Dev() uint32 { return b.idx.Load() }

// SetLedger arms crash cleanup: every bypass /32 added is appended to the
// file; kal2-client's route janitor deletes them if the process dies before
// Restore runs.
func (b *BindGuard) SetLedger(path string) { b.ledger = path }

// Control is a net.Dialer.Control / net.ListenConfig.Control hook. It
// refreshes the cached egress (survives Wi-Fi/Ethernet moves), ensures the
// dial target has a scoped bypass route, then binds the socket.
// ListenConfig callers hand us the bind address, not the destination —
// UDP carriers must have their server IPs covered via Configure/ServerIPs.
//
// Non-public literal destinations (loopback hairpins like the tun→local
// SOCKS dial, RFC1918 LAN) are left entirely alone: a bound socket cannot
// reach 127.0.0.1 through en0, and a /32 for it hijacks all loopback.
func (b *BindGuard) Control(network, address string, c syscall.RawConn) error {
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		if ip := net.ParseIP(host); ip != nil {
			if !bypassable(ip) {
				return nil
			}
		}
		b.ensureFor(host)
	}

	idx := b.idx.Load()
	if idx == 0 {
		return nil
	}
	var serr error
	err = c.Control(func(fd uintptr) {
		// IP_BOUND_IF covers AF_INET sockets; AF_INET6 needs IPV6_BOUND_IF.
		if strings.HasSuffix(network, "6") {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, ipv6BoundIF, int(idx))
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(idx))
	})
	if err != nil {
		return err
	}
	return serr
}

// ensureFor bypasses a dial target: literal IPs directly, hostnames via the
// system resolver (resolution happens outside the mutex — the resolver's own
// dial re-enters Control for its DNS server, which is also fine to bypass).
func (b *BindGuard) ensureFor(host string) {
	if ip := net.ParseIP(host); ip != nil {
		b.ensure(ip)
		return
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return
	}
	for _, ip := range ips {
		b.ensure(ip)
	}
}

// ensure refreshes the cached egress and installs the /32 bypass for ip.
func (b *BindGuard) ensure(ip net.IP) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
	b.ensureLocked(ip)
}

// EnsureIPs covers destinations the Control hook cannot see — UDP carriers
// bound via ListenConfig get the listen address, not the server. Called by
// the device at Configure time with the resolved server list.
func (b *BindGuard) EnsureIPs(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			b.ensureLocked(ip)
		}
	}
}

// refreshLocked re-reads the default route (throttled); when the egress pair
// changed — network move, DHCP renew — the stale /32s point at a dead gateway
// and are dropped so they re-resolve under the new egress.
func (b *BindGuard) refreshLocked() {
	if time.Since(b.lastProbe) < 1500*time.Millisecond {
		return
	}
	b.lastProbe = time.Now()
	gw, dev, err := defaultRoute()
	if err != nil || dev == "" {
		return // offline: keep the old state, dials fail on their own
	}
	if gw == b.gw && dev == b.dev {
		return
	}
	for ip := range b.hosts {
		_ = delHostRoute(ip)
	}
	b.hosts = nil
	b.gw, b.dev = gw, dev
	if ifi, err := net.InterfaceByName(dev); err == nil {
		b.idx.Store(uint32(ifi.Index))
	}
}

// ensureLocked installs `-host <ip> -gateway <gw>`. The hosts map is only
// a Restore ledger — it is NOT trusted to decide whether the route still
// exists: the kernel silently evicts host routes whose gateway went down
// (ifconfig en0 down), and a stale "installed" mark would skip the re-add
// and strand the carrier dial inside the tunnel itself. Verify via
// `route get` destination match first; re-add on any mismatch.
func (b *BindGuard) ensureLocked(ip net.IP) {
	if ip == nil || ip.To4() == nil || b.gw == "" || !bypassable(ip) {
		return
	}
	s := ip.String()
	// The route must exist AND point at the current gateway — a stale gw
	// after a network move is as broken as a missing route.
	if dst, gw, err := routeGet(s); err == nil && dst == s && gw == b.gw {
		if b.hosts == nil {
			b.hosts = map[string]struct{}{}
		}
		b.hosts[s] = struct{}{}
		return
	}
	// Ledger first: a crash between the two leaves a deletable phantom
	// entry instead of an unrecorded route.
	b.ledgerAppend(s)
	// route(8) exits 0 even on "File exists", so an unconditional
	// delete+add is the only reliable replace — a stale entry (crashed
	// client, moved gateway, dead interface) must not survive.
	_ = delHostRoute(s)
	_ = run("route", "-n", "add", "-host", s, "-gateway", b.gw)
	// Verify by destination field — `route get` happily resolves through
	// the covering /1 and reports the exit status 0 either way.
	if dst, _, err := routeGet(s); err != nil || dst != s {
		return
	}
	if b.hosts == nil {
		b.hosts = map[string]struct{}{}
	}
	b.hosts[s] = struct{}{}
}

// Restore deletes every bypass /32 and disarms the janitor ledger. Called by
// the darwin device's graceful restore.
func (b *BindGuard) Restore() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ip := range b.hosts {
		_ = delHostRoute(ip)
	}
	b.hosts = nil
	if b.ledger != "" {
		_ = os.Remove(b.ledger)
	}
}

// bypassable reports whether a literal destination may legitimately need a
// /32 bypass — public unicast only. Loopback, LAN, link-local and multicast
// destinations keep the system route untouched.
func bypassable(ip net.IP) bool {
	return ip.IsGlobalUnicast() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

func delHostRoute(ip string) error {
	return run("route", "-n", "delete", "-host", ip)
}

// routeGet returns the destination/gateway of the best route for ip — the
// covering /1 answers with destination != ip, so an exact match means a
// dedicated host route exists.
func routeGet(ip string) (dst, gw string, err error) {
	out, err := exec.Command("route", "-n", "get", ip).Output()
	if err != nil {
		return "", "", fmt.Errorf("route get %s: %w", ip, err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "destination:" {
			dst = f[1]
		}
		if len(f) == 2 && f[0] == "gateway:" {
			gw = f[1]
		}
	}
	return dst, gw, nil
}

func (b *BindGuard) ledgerAppend(ip string) {
	if b.ledger == "" {
		return
	}
	f, err := os.OpenFile(b.ledger, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, ip)
}
