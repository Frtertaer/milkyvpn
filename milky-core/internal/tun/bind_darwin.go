//go:build darwin

package tun

import (
	"net"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// ipv6BoundIF is net.inet6.ip6.bound_if — x/sys/unix does not define it.
const ipv6BoundIF = 125

// BindGuard pins the client's carrier sockets to the physical egress device
// (IP_BOUND_IF), replacing per-server bypass routes so kill -9 leaves no
// kernel state behind. Mirrors VpnService's includeAllNetworks/exclude-route
// semantics.
type BindGuard struct {
	idx atomic.Uint32 // ifindex, 0 = unset
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
}

// Dev is the currently recorded ifindex (0 until configured).
func (b *BindGuard) Dev() uint32 { return b.idx.Load() }

// Control is a net.Dialer.Control / net.ListenConfig.Control hook that binds
// new inet sockets to the recorded egress interface. No-op until Set() ran.
func (b *BindGuard) Control(network, address string, c syscall.RawConn) error {
	idx := b.idx.Load()
	if idx == 0 {
		return nil
	}
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return nil
	}
	var serr error
	err := c.Control(func(fd uintptr) {
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
