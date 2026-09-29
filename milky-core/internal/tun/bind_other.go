//go:build !linux && !darwin

package tun

import "syscall"

// BindGuard is a no-op outside Linux/macOS. On Windows the elevated ctl
// channel owns lifecycle (wintun adapter persists by design); on Android the
// OS routes around the VPN via VpnService.protect().
type BindGuard struct{}

func NewBindGuard() *BindGuard { return &BindGuard{} }

func (b *BindGuard) Set(dev string) {}

// Control matches net.Dialer.Control / net.ListenConfig.Control.
func (b *BindGuard) Control(network, address string, c syscall.RawConn) error {
	return nil
}
