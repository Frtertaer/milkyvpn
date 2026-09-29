//go:build linux

package tun

import (
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// BindGuard pins the client's carrier sockets to the physical egress device
// (SO_BINDTODEVICE), replacing per-server bypass routes. Unlike FIB entries
// the binding lives on each socket, so kill -9 leaves no kernel state behind.
type BindGuard struct {
	dev atomic.Value // string
}

func NewBindGuard() *BindGuard { return &BindGuard{} }

// Set records the egress device name; called once Configure learns it.
func (b *BindGuard) Set(dev string) {
	if dev != "" {
		b.dev.Store(dev)
	}
}

// Dev is the currently recorded egress device ("" until configured).
func (b *BindGuard) Dev() string {
	if v := b.dev.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Control is a net.Dialer.Control / net.ListenConfig.Control hook that binds
// new inet sockets to the recorded egress device. No-op until Set() ran.
func (b *BindGuard) Control(network, address string, c syscall.RawConn) error {
	dev := b.Dev()
	if dev == "" {
		return nil
	}
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return nil
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
	})
	if err != nil {
		return err
	}
	return serr
}
