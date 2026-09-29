//go:build linux && !android

package tun

import "testing"

// Requires /dev/net/tun + CAP_NET_ADMIN (Devin VMs have both).
func TestOpenLinuxDevice(t *testing.T) {
	dev, err := openDevice(&Config{Name: "milkytun0"})
	if err != nil {
		t.Skipf("no tun/cap: %v", err)
	}
	defer dev.Close()
	if dev.MTU() == 0 {
		t.Fatal("zero mtu")
	}
}
