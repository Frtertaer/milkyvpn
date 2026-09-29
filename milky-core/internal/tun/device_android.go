//go:build android

package tun

import "fmt"

// Android TUN devices come from VpnService.Builder.establish() — the OS
// owns adapter creation, addressing and routing; the core only wraps the
// returned parcel fd (Config.Fd, no packet header).
func openDevice(cfg *Config) (Device, error) {
	if cfg.Fd == 0 {
		return nil, fmt.Errorf("tun: Android requires Config.Fd from VpnService.establish()")
	}
	return NewFdDevice(cfg.Fd, defaultMTU, 0), nil
}

// VpnService authorization replaces admin rights on Android.
func IsElevated() bool { return true }

// DefaultEgress is unused on Android — VpnService.protect() owns carrier
// socket bypass.
func DefaultEgress() string { return "" }
