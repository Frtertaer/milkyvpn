//go:build linux && !android

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	sysIoctl   = syscall.SYS_IOCTL
	tunSetIFF  = 0x400454ca // TUNSETIFF
	iffTun     = 0x0001
	iffNoPI    = 0x1000
	ifrNameLen = 16
)

// linuxDevice is a /dev/net/tun adapter; routes go through iproute2's `ip`
// (present on every distro with net-tools or iproute2).
type linuxDevice struct {
	*fileDevice
	name string
	conf *Config
	gw   string
	dev  string
}

func openDevice(cfg *Config) (Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (needs CAP_NET_ADMIN)", err)
	}
	name := cfg.Name
	if name == "" {
		name = "milky0"
	}
	var ifr [40]byte
	copy(ifr[:ifrNameLen-1], name)
	binary.NativeEndian.PutUint16(ifr[ifrNameLen:ifrNameLen+2], iffTun|iffNoPI)
	_, _, errno := syscall.Syscall(sysIoctl, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	if n := bytes.IndexByte(ifr[:ifrNameLen], 0); n > 0 {
		name = string(ifr[:n]) // kernel may have renamed (e.g. parallel milky0)
	}
	d := &linuxDevice{name: name, conf: cfg}
	fd := &fileDevice{f: f, mtu: defaultMTU}
	fd.cfg = d.configure
	fd.rst = d.restore
	d.fileDevice = fd
	return d, nil
}

// IsElevated reports whether TUN setup can run: root or CAP_NET_ADMIN.
// Cheap approximation — effective uid 0; capability-only setups should run
// the client with `cap_net_admin+ep` which still shows euid 0 in most cases.
func IsElevated() bool { return os.Geteuid() == 0 }

// DefaultEgress reports the current default-route egress device so carrier
// sockets can be bound to it even before the TUN device is configured
// (the first session dials before Configure runs).
func DefaultEgress() string {
	_, dev, _ := defaultRoute()
	return dev
}

// defaultRoute returns the current default gateway IP and egress device.
func defaultRoute() (gw, dev string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route: %w", err)
	}
	gw, dev = parseDefaultRoute(string(out))
	return gw, dev, nil
}

// parseDefaultRoute reads the first default line only — parsing all output
// in one Fields() pass can pair a "via" from one line with a "dev" from
// another when several defaults exist (multipath, stale DHCP leases).
func parseDefaultRoute(out string) (gw, dev string) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "via" {
				gw = f[i+1]
			}
			if f[i] == "dev" {
				dev = f[i+1]
			}
		}
		return gw, dev
	}
	return "", ""
}

func ipRun(args ...string) error {
	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *linuxDevice) configure() error {
	addr := d.conf.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	gw, dev, err := defaultRoute()
	if err == nil && dev != "" {
		d.gw, d.dev = gw, dev
		// Carrier sockets bind to the egress device — they bypass the tunnel
		// without FIB entries, so kill -9 leaves no residual routes behind.
		// (main.go also sets this before the first dial; idempotent.)
		if d.conf.Bind != nil {
			d.conf.Bind.Set(dev)
		}
	}
	if err := ipRun("link", "set", "dev", d.name, "mtu", fmt.Sprint(defaultMTU), "up"); err != nil {
		return err
	}
	if err := ipRun("addr", "replace", addr+"/24", "dev", d.name); err != nil {
		return err
	}
	// Split-horizon default: /1 pair beats the ordinary default without
	// touching the original route table entry. Every route we install is
	// dev-scoped so the kernel drops it with the interface.
	if err := ipRun("route", "replace", "0.0.0.0/1", "dev", d.name); err != nil {
		return err
	}
	if err := ipRun("route", "replace", "128.0.0.0/1", "dev", d.name); err != nil {
		return err
	}
	// Same for IPv6 so v6 traffic doesn't leak around the tunnel on
	// dual-stack hosts. Best effort: ignored when v6 is disabled.
	_ = ipRun("-6", "route", "replace", "::/1", "dev", d.name)
	_ = ipRun("-6", "route", "replace", "8000::/1", "dev", d.name)
	return nil
}

func (d *linuxDevice) restore() {
	_ = ipRun("route", "del", "0.0.0.0/1", "dev", d.name)
	_ = ipRun("route", "del", "128.0.0.0/1", "dev", d.name)
	_ = ipRun("-6", "route", "del", "::/1", "dev", d.name)
	_ = ipRun("-6", "route", "del", "8000::/1", "dev", d.name)
	_ = ipRun("link", "del", "dev", d.name)
}
