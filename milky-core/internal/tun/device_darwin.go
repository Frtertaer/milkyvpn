//go:build darwin

package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	utunControlName  = "com.apple.net.utun_control"
	utunOptIfname    = 2
	sysProtoControl  = 2
	afSysControl     = 2
	utunHeaderLen    = 4
)

// darwinDevice is a utun adapter (the only unprivileged-by-design tunnel
// device on macOS — still needs root for routes). Each packet carries a
// 4-byte address-family header that fileDevice strips.
type darwinDevice struct {
	*fileDevice
	name string
	conf *Config
	gw   string
	dev  string
}

func openDevice(cfg *Config) (Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysProtoControl)
	if err != nil {
		return nil, fmt.Errorf("utun socket: %w", err)
	}
	var ci unix.CtlInfo
	copy(ci.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &ci); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun CTLIOCGINFO: %w", err)
	}
	sc := &unix.SockaddrCtl{
		ID:   ci.Id,
		Unit: 0, // kernel picks the unit (utunN)
	}
	if err := unix.Connect(fd, sc); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun connect: %w", err)
	}
	ifname, err := getsockoptString(fd, sysProtoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun ifname: %w", err)
	}
	d := &darwinDevice{name: ifname, conf: cfg}
	fd2 := &fileDevice{f: os.NewFile(uintptr(fd), ifname), mtu: defaultMTU, hdr: utunHeaderLen}
	fd2.cfg = d.configure
	fd2.rst = d.restore
	d.fileDevice = fd2
	return d, nil
}

func IsElevated() bool { return os.Geteuid() == 0 }

// getsockoptString reads a string socket option (x/sys lacks the helper on
// darwin for SYSPROTO_CONTROL/UTUN_OPT_IFNAME).
func getsockoptString(fd, level, opt int) (string, error) {
	buf := make([]byte, 64)
	n := uintptr(len(buf))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if errno != 0 {
		return "", errno
	}
	return string(buf[:n]), nil
}

// defaultRoute reads "default: gateway" out of `route -n get default`.
func defaultRoute() (gw, dev string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("route get: %w", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "gateway:" {
			gw = f[1]
		}
		if len(f) == 2 && f[0] == "interface:" {
			dev = f[1]
		}
	}
	return gw, dev, nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *darwinDevice) configure() error {
	addr := d.conf.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	gw, _, err := defaultRoute()
	if err == nil {
		d.gw = gw
	}
	// utun is point-to-point: local addr + destination inside the same /32.
	if err := run("ifconfig", d.name, "inet", addr, addr, "netmask", "255.255.255.0", "up"); err != nil {
		return err
	}
	for _, sip := range d.conf.ServerIPs {
		if net.ParseIP(sip) == nil || d.gw == "" {
			continue
		}
		_ = run("route", "add", "-host", sip, d.gw)
	}
	// /1 split default through the utun interface (BSD `route` needs -net).
	if err := run("route", "add", "-net", "0.0.0.0/1", "-interface", d.name); err != nil {
		return err
	}
	return run("route", "add", "-net", "128.0.0.0/1", "-interface", d.name)
}

func (d *darwinDevice) restore() {
	_ = run("route", "delete", "-net", "0.0.0.0/1", "-interface", d.name)
	_ = run("route", "delete", "-net", "128.0.0.0/1", "-interface", d.name)
	for _, sip := range d.conf.ServerIPs {
		if net.ParseIP(sip) == nil {
			continue
		}
		_ = run("route", "delete", "-host", sip)
	}
	// utun disappears with the fd; no explicit teardown needed.
}
