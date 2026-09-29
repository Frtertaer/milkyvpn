//go:build linux || darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"os"
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

func (d *fileDevice) ReadPacket() (pkt []byte, release func(), err error) {
	b := make([]byte, d.mtu+64)
	n, err := d.f.Read(b)
	if err != nil {
		return nil, nil, err
	}
	if uint32(n) < d.hdr {
		return nil, nil, fmt.Errorf("tun: short read %d", n)
	}
	return b[d.hdr:n], func() {}, nil
}

func (d *fileDevice) WritePacket(pkt []byte) error {
	if d.hdr > 0 {
		var h [4]byte
		binary.LittleEndian.PutUint32(h[:], afFamily(pkt))
		pkt = append(h[:], pkt...)
	}
	_, err := d.f.Write(pkt)
	return err
}

func afFamily(pkt []byte) uint32 {
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		return 30 // AF_INET6 on Darwin
	}
	return 2 // AF_INET
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
