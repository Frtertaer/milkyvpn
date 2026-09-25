//go:build windows

package tun

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// ERROR_NO_MORE_DATA — wintun rings report this instead of blocking.
const errNoMoreData = syscall.Errno(0x103)

type wintunDevice struct {
	cfg      *Config
	adapter  *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle
	gw       string
	hosts    []string
}

func openDevice(cfg *Config) (Device, error) {
	name := cfg.Name
	if name == "" {
		name = "MilkyVPN-TUN"
	}
	adapter, err := wintun.CreateAdapter(name, "Kal2", nil)
	if err != nil {
		// An orphaned adapter from a crashed client blocks CreateAdapter —
		// reuse it instead of failing the connect.
		if oerr := error(nil); oerr != nil {
			_ = oerr
		}
		if a, oerr := wintun.OpenAdapter(name); oerr == nil {
			adapter = a
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w (need wintun.dll next to the client and administrator rights)", err)
	}
	sess, err := adapter.StartSession(0x400000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}
	addr := cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	cfg.Addr = addr
	return &wintunDevice{
		cfg:      cfg,
		adapter:  adapter,
		session:  sess,
		readWait: sess.ReadWaitEvent(),
	}, nil
}

func (d *wintunDevice) MTU() uint32 { return defaultMTU }

// ReadPacket blocks on the wintun read-wait event between ring polls —
// ReceivePacket itself returns ERROR_NO_MORE_DATA when the ring is empty.
func (d *wintunDevice) ReadPacket() ([]byte, func(), error) {
	for {
		pkt, err := d.session.ReceivePacket()
		if err == nil {
			return pkt, func() { d.session.ReleaseReceivePacket(pkt) }, nil
		}
		if err != errNoMoreData {
			return nil, nil, err
		}
		if _, werr := windows.WaitForSingleObject(d.readWait, windows.INFINITE); werr != nil {
			return nil, nil, werr
		}
	}
}

func (d *wintunDevice) WritePacket(pkt []byte) error {
	buf, err := d.session.AllocateSendPacket(len(pkt))
	if err != nil {
		return err
	}
	copy(buf, pkt)
	d.session.SendPacket(buf)
	return nil
}

func (d *wintunDevice) Configure(serverIPs []string) error {
	ifname := d.cfg.Name
	if ifname == "" {
		ifname = "MilkyVPN-TUN"
	}
	addr := d.cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	gw, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("find default gateway: %w", err)
	}
	d.gw = gw
	if out, err := run("netsh", "interface", "ipv4", "set", "address",
		"name="+ifname, "static", addr, "255.255.255.0"); err != nil {
		return fmt.Errorf("set address: %v (%s)", err, out)
	}
	// Bypass for the tunnel server itself: its traffic must leave via the
	// physical gateway, never the TUN, or the tunnel swallows itself.
	for _, ip := range serverIPs {
		ip = strings.TrimSpace(ip)
		if net4(ip) == "" {
			continue
		}
		_ = runCmd("route", "delete", ip)
		if _, err := run("route", "add", ip, "mask", "255.255.255.255", gw, "metric", "1"); err != nil {
			return fmt.Errorf("server route %s: %w", ip, err)
		}
		d.hosts = append(d.hosts, ip)
	}
	// Two /1 routes override the default without replacing it — clean revert.
	// The IF clause pins them to the wintun adapter; without it Windows binds
	// the route to the physical interface and nothing reaches the tunnel.
	idxOut, err := run("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s').ifIndex", ifname))
	if err != nil {
		return fmt.Errorf("adapter ifindex: %v (%s)", err, idxOut)
	}
	ifIndex := strings.TrimSpace(idxOut)
	for _, r := range [][2]string{{"0.0.0.0", "128.0.0.0"}, {"128.0.0.0", "128.0.0.0"}} {
		if _, err := run("route", "add", r[0], "mask", r[1], addr,
			"metric", "1", "if", ifIndex); err != nil {
			return fmt.Errorf("route %s: %w", r[0], err)
		}
	}
	return nil
}

func (d *wintunDevice) Restore() {
	addr := d.cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	_, _ = run("route", "delete", "0.0.0.0", "mask", "128.0.0.0", addr)
	_, _ = run("route", "delete", "128.0.0.0", "mask", "128.0.0.0", addr)
	for _, ip := range d.hosts {
		_ = runCmd("route", "delete", ip)
	}
	d.hosts = nil
}

func (d *wintunDevice) Close() error {
	d.session.End()
	return d.adapter.Close()
}

// IsElevated reports whether the process runs with administrator rights.
func IsElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func defaultGateway() (string, error) {
	out, err := run("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop")
	if err != nil {
		return "", err
	}
	gw := strings.TrimSpace(out)
	if net4(gw) == "" {
		return "", fmt.Errorf("unexpected gateway %q", gw)
	}
	return gw, nil
}

func net4(s string) string {
	for _, f := range strings.Fields(s) {
		if strings.Count(f, ".") == 3 && !strings.Contains(f, ":") {
			return f
		}
	}
	return s
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func runCmd(name string, args ...string) error {
	_, err := run(name, args...)
	return err
}
