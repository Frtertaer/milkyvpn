package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrEgressBlocked is returned when a client asks the server egress to reach
// a non-public destination (loopback, private, link-local, the host's own
// addresses, ...). Without this guard any VPN user could reach services that
// are bound to loopback/LAN only, such as the panel ops API.
var ErrEgressBlocked = errors.New("egress: destination not allowed")

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this" network
		"100.64.0.0/10",   // CGNAT / tailnets
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved + broadcast
		"::/96",           // IPv4-compatible (deprecated)
		"100::/64",        // discard-only
		"2001:db8::/32",   // documentation
		"fec0::/10",       // site-local (deprecated)
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var (
	nat64Prefixes = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	}
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// publicAddr reports whether ip is a globally routable unicast address that
// does not belong to this host.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	if ip.Is6() {
		b := ip.As16()
		for _, p := range nat64Prefixes {
			if p.Contains(ip) {
				return publicAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
			}
		}
		if sixToFour.Contains(ip) {
			return publicAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		}
	}
	return !localAddrs.has(ip)
}

// localAddrSet caches the host's interface addresses: services bound to
// 0.0.0.0 and firewalled from the outside stay reachable from the host via
// its own public IP, so those are refused too.
type localAddrSet struct {
	mu      sync.Mutex
	addrs   map[netip.Addr]struct{}
	fetched time.Time
}

var localAddrs localAddrSet

func (s *localAddrSet) has(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addrs == nil || time.Since(s.fetched) > 30*time.Second {
		m := map[netip.Addr]struct{}{}
		if ifas, err := net.InterfaceAddrs(); err == nil {
			for _, a := range ifas {
				if pn, ok := a.(*net.IPNet); ok {
					if ad, ok := netip.AddrFromSlice(pn.IP); ok {
						m[ad.Unmap()] = struct{}{}
					}
				}
			}
		}
		s.addrs, s.fetched = m, time.Now()
	}
	_, ok := s.addrs[ip]
	return ok
}

func checkEgressIP(ip netip.Addr) error {
	if !publicAddr(ip) {
		return fmt.Errorf("%w: %s", ErrEgressBlocked, ip)
	}
	return nil
}

func checkEgressAddrPort(address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable %q", ErrEgressBlocked, address)
	}
	return checkEgressIP(ap.Addr())
}

func localName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// precheckHost rejects literal non-public IPs and localhost names before any
// dial or DNS lookup happens.
func precheckHost(host string) error {
	if localName(host) {
		return fmt.Errorf("%w: %s", ErrEgressBlocked, host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkEgressIP(ip)
	}
	return nil
}

// precheckResolved resolves host locally and refuses it if any answer is
// non-public. Used for the upstream SOCKS5 path, where the actual connect
// happens on the proxy (remote DNS) and Dialer.Control cannot see it.
func precheckResolved(host string) error {
	if err := precheckHost(host); err != nil {
		return err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("%w: resolve %s: %v", ErrEgressBlocked, host, err)
	}
	for _, ip := range ips {
		if err := checkEgressIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// guardDialer returns a copy of d whose socket control hook refuses
// non-public peers. The check runs on the resolved address of every connect
// attempt, so DNS names pointing at loopback/private ranges (and rebinding)
// are covered too.
func guardDialer(d *net.Dialer) *net.Dialer {
	g := *d
	if prev := d.ControlContext; prev != nil {
		g.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			if err := checkEgressAddrPort(address); err != nil {
				return err
			}
			return prev(ctx, network, address, c)
		}
		return &g
	}
	prev := d.Control
	g.Control = func(network, address string, c syscall.RawConn) error {
		if err := checkEgressAddrPort(address); err != nil {
			return err
		}
		if prev != nil {
			return prev(network, address, c)
		}
		return nil
	}
	return &g
}
