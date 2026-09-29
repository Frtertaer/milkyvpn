//go:build darwin

package tun

// Scratch repro: inject a SYN with src == the NIC address (what macOS puts
// on utun-bound packets) into the same stack config used by runStack, and
// confirm the TCP forwarder fires. Run:
//   go test ./internal/tun -run TestInjectSYN -v
//
// Not a committed regression test for a specific bug — kept because it pins
// down that dst-src == NIC-address SYNs must still reach the forwarder.

import (
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

func TestInjectSYN(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	ep := channel.New(1024, 1500, "")
	if err := s.CreateNIC(tunNICID, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPromiscuousMode(tunNICID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSpoofing(tunNICID, true); err != nil {
		t.Fatal(err)
	}
	_ = s.AddProtocolAddress(tunNICID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4Slice([]byte{10, 85, 0, 1}),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: tunNICID}})

	tcpHit := make(chan stack.TransportEndpointID, 4)
	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		rep, err := r.CreateEndpoint(&wq)
		if err != nil {
			t.Logf("CreateEndpoint: %v", err)
			r.Complete(true)
			return
		}
		r.Complete(false)
		tcpHit <- id
		go func() { gonet.NewTCPConn(&wq, rep).Close() }()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		th := pkt.TransportHeader().Slice()
		nh := pkt.NetworkHeader().Slice()
		var srcA, dstA tcpip.Address
		if len(nh) >= 20 {
			srcA = tcpip.AddrFrom4Slice(nh[12:16])
			dstA = tcpip.AddrFrom4Slice(nh[16:20])
		}
		var thdr header.TCP
		if len(th) > 0 {
			thdr = header.TCP(th)
		}
		csum, csumValid, ok := header.TCPValid(
			thdr,
			func() uint16 { return pkt.Data().Checksum() },
			uint16(pkt.Data().Size()),
			srcA, dstA,
			pkt.RXChecksumValidated)
		t.Logf("TCP handler hit: id=%+v thLen=%d dataSize=%d csum=0x%x csumValid=%v ok=%v flags=%v",
			id, len(th), pkt.Data().Size(), csum, csumValid, ok, thdr.Flags())
		return tcpFwd.HandlePacket(id, pkt)
	})

	// Inject the REAL SYN captured off utun4 (tcpdump-verified checksums):
	// src 10.85.0.1:54168 (== NIC addr) → dst 104.21.5.5:80, flags SEW.
	realSYN := []byte{
		0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xc3, 0x48,
		0x0a, 0x55, 0x00, 0x01, 0x68, 0x15, 0x05, 0x05,
		0xd3, 0x98, 0x00, 0x50, 0x02, 0x25, 0xd2, 0x79, 0x00, 0x00, 0x00, 0x00,
		0xb0, 0xc2, 0xff, 0xff, 0xa0, 0x66, 0x00, 0x00,
		0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01,
		0x08, 0x0a, 0xd4, 0x8f, 0xa1, 0x4e, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x02, 0x00, 0x00,
	}
	ep.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), realSYN...)),
	}))
	// A host SYN must produce a SYN-ACK from the stack — the wiring that
	// BUG-2026-09-29-11's silent-drop made invisible on the host side.
	var gotSynAck bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !gotSynAck {
		op := ep.Read()
		if op == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		b := append([]byte(nil), op.ToView().AsSlice()...)
		op.DecRef()
		if len(b) < 40 || b[0]>>4 != 4 || b[9] != 6 {
			continue
		}
		ihl := int(b[0]&0x0f) * 4
		flags := b[ihl+13]
		sport := int(b[ihl])<<8 | int(b[ihl+1])
		dport := int(b[ihl+2])<<8 | int(b[ihl+3])
		t.Logf("stack reply: %v.%d → %v.%d proto=%d tcpflags=0x%02x",
			b[12:16], sport, b[16:20], dport, b[9], flags)
		if flags&0x12 == 0x12 { // SYN|ACK
			gotSynAck = true
		}
	}
	if !gotSynAck {
		t.Fatalf("no SYN-ACK emitted: TCP %+v", s.Stats().TCP)
	}
	// The endpoint stays half-open — completing the handshake needs a PAWS-
	// valid final ACK (TS echo); that's plumbing, not the behaviour pinned
	// here.
	_ = tcpHit
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func buildTestACK(s0, s1, s2, s3 byte, sport int, d0, d1, d2, d3 byte, dport int, seq, ackNum uint32) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[2], ip[3] = 0, 40
	ip[4], ip[5] = 0, 2
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{s0, s1, s2, s3})
	copy(ip[16:20], []byte{d0, d1, d2, d3})
	c0, c1 := testCksum(ip)
	ip[10], ip[11] = c0, c1

	tcpb := make([]byte, 20)
	tcpb[0], tcpb[1] = byte(sport>>8), byte(sport)
	tcpb[2], tcpb[3] = byte(dport>>8), byte(dport)
	tcpb[4], tcpb[5], tcpb[6], tcpb[7] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	tcpb[8], tcpb[9], tcpb[10], tcpb[11] = byte(ackNum>>24), byte(ackNum>>16), byte(ackNum>>8), byte(ackNum)
	tcpb[12] = 0x50
	tcpb[13] = 0x10 // ACK
	tcpb[14], tcpb[15] = 0xff, 0xff
	pseudo := append(append(append(append([]byte{}, ip[12:20]...), 0, 6), 0, 20), tcpb...)
	tcpb[16], tcpb[17] = testCksum(pseudo)
	return append(ip, tcpb...)
}

func buildTestSYN(s0, s1, s2, s3 byte, sport int, d0, d1, d2, d3 byte, dport int) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[2], ip[3] = 0, 64
	ip[4], ip[5] = 0, 1
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{s0, s1, s2, s3})
	copy(ip[16:20], []byte{d0, d1, d2, d3})
	c0, c1 := testCksum(ip)
	ip[10], ip[11] = c0, c1

	tcpb := make([]byte, 44)
	tcpb[0], tcpb[1] = byte(sport>>8), byte(sport)
	tcpb[2], tcpb[3] = byte(dport>>8), byte(dport)
	tcpb[12] = 0x60
	tcpb[13] = 0x02
	tcpb[14], tcpb[15] = 0xff, 0xff
	tcpb[20], tcpb[21], tcpb[22], tcpb[23] = 2, 4, 0x05, 0xb4
	pseudo := append(append(append(append([]byte{}, ip[12:20]...), 0, 6), 0, 44), tcpb...)
	tcpb[16], tcpb[17] = testCksum(pseudo)
	return append(ip, tcpb...)
}

func testCksum(b []byte) (byte, byte) {
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	c := ^uint16(s)
	return byte(c >> 8), byte(c)
}
