//go:build linux && !android

package tun

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// BUG-2026-09-29-04: defaultRoute used to Fields() the whole `ip route`
// output, pairing a "via" from one default line with a "dev" from another
// when several defaults exist (multipath, stale DHCP lease) — carrier
// sockets then bound to the wrong egress or configure() failed outright.
func TestParseDefaultRoutePairsWithinFirstLine(t *testing.T) {
	out := "" +
		"default via 10.0.0.1 dev eth0 proto dhcp metric 100\n" +
		"default via 192.168.1.254 dev wlan0 proto dhcp metric 600\n" +
		"10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n" +
		"192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.9\n"
	gw, dev := parseDefaultRoute(out)
	if gw != "10.0.0.1" || dev != "eth0" {
		t.Fatalf("got gw=%q dev=%q, want 10.0.0.1/eth0", gw, dev)
	}
}

func TestParseDefaultRouteNoDefault(t *testing.T) {
	gw, dev := parseDefaultRoute("10.0.0.0/24 dev eth0\n")
	if gw != "" || dev != "" {
		t.Fatalf("got gw=%q dev=%q, want empty", gw, dev)
	}
}

// BUG-2026-09-29-05: Darwin utun ifname and ifreq names are NUL-padded
// kernel buffers; keeping the NULs produced exec args (ifconfig/route)
// the OS rejected, so configure() died after the device was already up.
func TestCstrTrimsNUL(t *testing.T) {
	if got := cstr([]byte{'u', 't', 'u', 'n', '5', 0, 0, 0}); got != "utun5" {
		t.Fatalf("got %q, want utun5", got)
	}
	if got := cstr([]byte("milky0")); got != "milky0" {
		t.Fatalf("got %q, want milky0", got)
	}
	if got := cstr(nil); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

// BUG-2026-09-29-03: the old /32 bypass routes survived kill -9 (kernel
// only auto-removes dev-scoped routes), stranding the box with a stale
// host route. BindGuard replaces them with SO_BINDTODEVICE — no FIB
// entries to leak. Requires CAP_NET_RAW to actually apply; skip without.
func TestBindGuardControlBindsSocket(t *testing.T) {
	g := NewBindGuard()
	g.Set("lo")
	lc := net.ListenConfig{Control: g.Control}
	l, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SO_BINDTODEVICE needs CAP_NET_RAW: %v", err)
	}
	defer l.Close()
	raw, err := l.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var bound string
	if cerr := raw.Control(func(fd uintptr) {
		s, gerr := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if gerr != nil {
			t.Fatalf("getsockopt: %v", gerr)
		}
		bound = s
	}); cerr != nil {
		t.Fatalf("Control: %v", cerr)
	}
	if bound != "lo" {
		t.Fatalf("SO_BINDTODEVICE = %q, want lo", bound)
	}
}

// Non-IP networks (unix, unixgram) must pass through unbound — applying
// SO_BINDTODEVICE there would break them outright.
func TestBindGuardControlIgnoresNonIPNetworks(t *testing.T) {
	g := NewBindGuard()
	g.Set("lo")
	for _, network := range []string{"unix", "unixgram", "ip4", "ip6"} {
		if err := g.Control(network, "x", nil); err != nil {
			t.Fatalf("Control(%q): %v", network, err)
		}
	}
}

func TestBindGuardEmptyDevIsNoop(t *testing.T) {
	g := NewBindGuard()
	g.Set("")
	if got := g.Dev(); got != "" {
		t.Fatalf("Dev() = %q, want empty", got)
	}
	if err := g.Control("tcp4", "x", nil); err != nil {
		t.Fatalf("Control with unset dev: %v", err)
	}
}

// BUG-2026-09-29-01: os.File.Read routes through the runtime poller and
// fails with "not pollable" on kernels/sandboxes refusing EPOLL_CTL_ADD
// on character devices. ReadPacket/WritePacket use raw unix.Read/Write —
// verified here against a character device (/dev/zero).
func TestReadPacketOnCharDevice(t *testing.T) {
	f, err := os.Open("/dev/zero")
	if err != nil {
		t.Skipf("no /dev/zero: %v", err)
	}
	defer f.Close()
	d := NewFdDevice(f.Fd(), 128, 0)
	pkt, release, err := d.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket on char device: %v", err)
	}
	release()
	if len(pkt) == 0 {
		t.Fatal("empty packet")
	}
}

// Packet round-trip through a pipe: WritePacket prepends the AF header
// (hdr=4, Darwin utun layout), ReadPacket strips it back off.
func TestFdDevicePacketRoundTrip(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	dr := NewFdDevice(r.Fd(), 256, 4)
	dw := NewFdDevice(w.Fd(), 256, 4)

	payload := []byte{0x45, 0x01, 0x02, 0x03} // v4 header nibble
	if err := dw.WritePacket(payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		pkt, release, rerr := dr.ReadPacket()
		if rerr != nil {
			done <- rerr
			return
		}
		defer release()
		if len(pkt) != len(payload) || pkt[0] != 0x45 {
			done <- errBadPkt
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadPacket timed out")
	}
}

var errBadPkt = errors.New("packet payload mismatch")

func TestAfFamily(t *testing.T) {
	if got := afFamily([]byte{0x45}); got != 2 {
		t.Fatalf("v4: got %d, want 2", got)
	}
	if got := afFamily([]byte{0x60}); got != 30 {
		t.Fatalf("v6: got %d, want 30", got)
	}
}
