//go:build linux && !android

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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

// defaultRoute returns the current default gateway IP and egress device.
func defaultRoute() (gw, dev string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route: %w", err)
	}
	// "default via 192.0.2.1 dev eth0 ..."
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "via" {
			gw = f[i+1]
		}
		if f[i] == "dev" && dev == "" {
			dev = f[i+1]
		}
	}
	return gw, dev, nil
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
	if err == nil {
		d.gw, d.dev = gw, dev
	}
	if err := ipRun("link", "set", "dev", d.name, "mtu", fmt.Sprint(defaultMTU), "up"); err != nil {
		return err
	}
	if err := ipRun("addr", "replace", addr+"/24", "dev", d.name); err != nil {
		return err
	}
	// Bypass routes for the tunnel servers themselves — without them the
	// tunnel's own carrier traffic loops back into the tunnel.
	for _, sip := range d.conf.ServerIPs {
		if net.ParseIP(sip) == nil || d.gw == "" {
			continue
		}
		_ = ipRun("route", "replace", sip+"/32", "via", d.gw, "dev", d.dev)
	}
	// Split-horizon default: /1 pair beats the ordinary default without
	// touching the original route table entry.
	if err := ipRun("route", "replace", "0.0.0.0/1", "dev", d.name); err != nil {
		return err
	}
	return ipRun("route", "replace", "128.0.0.0/1", "dev", d.name)
}

func (d *linuxDevice) restore() {
	_ = ipRun("route", "del", "0.0.0.0/1", "dev", d.name)
	_ = ipRun("route", "del", "128.0.0.0/1", "dev", d.name)
	for _, sip := range d.conf.ServerIPs {
		if net.ParseIP(sip) == nil {
			continue
		}
		_ = ipRun("route", "del", sip+"/32")
	}
	_ = ipRun("link", "del", "dev", d.name)
}
