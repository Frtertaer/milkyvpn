//go:build linux || darwin

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// fileDevice adapts a file-descriptor packet device to Device:
// Linux /dev/net/tun (IFF_NO_PI → raw IP), Darwin utun (4-byte AF header),
// Android a VpnService-supplied fd via NewFdDevice.
type fileDevice struct {
	f   *os.File
	mtu uint32
	hdr uint32 // per-packet kernel header to strip/prepend (utun: 4)
	cfg func() error
	rst func()
}

func (d *fileDevice) MTU() uint32 { return d.mtu }

// ReadPacket does a raw blocking read(2) on the fd — not os.File.Read,
// which routes through the runtime poller and fails with "not pollable" on
// kernels/sandboxes that refuse EPOLL_CTL_ADD on character devices. The fd
// stays in blocking mode, so read returns whole packets or an error.
func (d *fileDevice) ReadPacket() (pkt []byte, release func(), err error) {
	b := make([]byte, d.mtu+64)
	for {
		n, rerr := unix.Read(int(d.f.Fd()), b)
		if rerr == unix.EINTR {
			continue
		}
		if rerr != nil {
			return nil, nil, rerr
		}
		if uint32(n) < d.hdr {
			return nil, nil, fmt.Errorf("tun: short read %d", n)
		}
		return b[d.hdr:n], func() {}, nil
	}
}

func (d *fileDevice) WritePacket(pkt []byte) error {
	if d.hdr > 0 {
		var h [4]byte
		// utun's input path reads the family prefix with ntohl — it is
		// big-endian on the fd even though the outbound (kernel→fd) prefix
		// reads as native order in tools.
		binary.BigEndian.PutUint32(h[:], afFamily(pkt))
		pkt = append(h[:], pkt...)
	}
	for {
		n, err := unix.Write(int(d.f.Fd()), pkt)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n != len(pkt) {
			return fmt.Errorf("tun: short write %d/%d", n, len(pkt))
		}
		return nil
	}
}

func afFamily(pkt []byte) uint32 {
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		return 30 // AF_INET6 on Darwin
	}
	return 2 // AF_INET
}

// cstr trims a NUL-terminated kernel string (utun ifname, ifreq names) —
// leaving the trailing NULs in produces exec args the OS rejects.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func (d *fileDevice) Configure(serverIPs []string) error {
	if d.cfg == nil {
		return nil
	}
	return d.cfg()
}

func (d *fileDevice) Restore() {
	if d.rst != nil {
		d.rst()
	}
}

func (d *fileDevice) Close() error { return d.f.Close() }

// NewFdDevice adopts an existing TUN descriptor — on Android the fd comes
// from VpnService.establish() (routing/DNS already handled by the OS); on
// Unix it can wrap an externally opened /dev/net/tun fd. hdr selects the
// per-packet kernel header length (utun: 4, others: 0).
func NewFdDevice(fd uintptr, mtu uint32, hdr uint32) Device {
	if mtu == 0 {
		mtu = defaultMTU
	}
	return &fileDevice{f: os.NewFile(fd, "tun"), mtu: mtu, hdr: hdr}
}
