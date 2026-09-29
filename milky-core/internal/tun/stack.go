package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
)

const tunNICID = 1

// runStack bridges the TUN device to kal2 streams via gVisor netstack.
// Blocks until ctx ends or the device fails.
func runStack(ctx context.Context, dev Device, cfg *Config) error {
	logf := cfg.logf()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		// HandleLocal must stay off: with it, the IPv4 layer checks inbound
		// source addresses against the NIC and martian-drops everything the
		// host sources through the tunnel (InvalidSourceAddressesReceived).
		HandleLocal: false,
	})
	ep := channel.New(1024, dev.MTU(), "")
	if err := s.CreateNIC(tunNICID, ep); err != nil {
		return fmt.Errorf("create NIC: %v", err)
	}
	// The NIC owns none of the destinations flowing through it — accept them all.
	if err := s.SetPromiscuousMode(tunNICID, true); err != nil {
		return fmt.Errorf("promiscuous: %v", err)
	}
	if err := s.SetSpoofing(tunNICID, true); err != nil {
		return fmt.Errorf("spoofing: %v", err)
	}
	// Assign the adapter's own address — without it the endpoint has no
	// addressable state and never acquires temp endpoints for foreign dsts.
	if v4 := net.ParseIP(cfg.Addr).To4(); v4 != nil {
		_ = s.AddProtocolAddress(tunNICID, tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4Slice(v4),
				PrefixLen: 24,
			},
		}, stack.AddressProperties{})
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: tunNICID},
		{Destination: header.IPv6EmptySubnet, NIC: tunNICID},
	})

	// TCP flows: one kal2 stream per connection. NewForwarder only builds
	// the forwarder — it must be registered as the transport handler.
	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		rep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		logf("tun: tcp flow → %s:%d", id.LocalAddress, id.LocalPort)
		go serveTCP(gonet.NewTCPConn(&wq, rep), id, cfg, logf)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP flows: one kal2 "udp" relay stream per flow; datagrams carry
	// per-datagram destination headers on the wire.
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		rep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		logf("tun: udp flow → %s:%d", id.LocalAddress, id.LocalPort)
		go serveUDP(gonet.NewUDPConn(&wq, rep), id, cfg, logf)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	done := make(chan error, 2)

	// TUN → netstack
	go func() {
		for {
			pkt, release, err := dev.ReadPacket()
			if err != nil {
				done <- fmt.Errorf("tun read: %w", err)
				return
			}
			if len(pkt) > 0 {
				proto := header.IPv4ProtocolNumber
				if pkt[0]>>4 == 6 {
					proto = header.IPv6ProtocolNumber
				}
				ep.InjectInbound(proto, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
				}))
			}
			release()
		}
	}()

	// netstack → TUN
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				done <- nil
				return
			}
			b := pkt.ToView().AsSlice()
			_ = dev.WritePacket(append([]byte(nil), b...))
			pkt.DecRef()
		}
	}()

	select {
	case <-ctx.Done():
		ep.Close()
		s.Close()
		return ctx.Err()
	case err := <-done:
		ep.Close()
		s.Close()
		return err
	}
}

func serveTCP(local *gonet.TCPConn, id stack.TransportEndpointID, cfg *Config, logf func(string, ...any)) {
	defer local.Close()
	dst := hostPort(id.LocalAddress, id.LocalPort)
	up, err := cfg.OpenTCP(context.Background(), dst)
	if err != nil {
		logf("tun: open tcp %s: %v", dst, err)
		return
	}
	ab, ba := splice(local, up)
	logf("tun: tcp %s done remote→local=%dB local→remote=%dB", dst, ab, ba)
}

func serveUDP(local *gonet.UDPConn, id stack.TransportEndpointID, cfg *Config, logf func(string, ...any)) {
	defer local.Close()
	st, err := cfg.OpenUDP(context.Background())
	if err != nil {
		logf("tun: open udp: %v", err)
		return
	}
	defer st.Close()
	dst := &net.UDPAddr{IP: net.ParseIP(id.LocalAddress.String()), Port: int(id.LocalPort)}
	if dst.IP == nil {
		return
	}

	// netstack → kal2 stream: wrap each datagram with its destination header.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				st.Close()
				return
			}
			frame := core.AppendUDPHeader(nil, dst, buf[:n])
			if frame == nil {
				continue
			}
			if _, err := st.Write(frame); err != nil {
				st.Close()
				return
			}
		}
	}()

	// kal2 stream → netstack: strip the source header, deliver the payload.
	var lb [2]byte
	buf := make([]byte, 64*1024)
	for {
		if _, err := io.ReadFull(st, lb[:]); err != nil {
			return
		}
		n := int(binary.LittleEndian.Uint16(lb[:]))
		if n > len(buf) {
			return
		}
		if _, err := io.ReadFull(st, buf[:n]); err != nil {
			return
		}
		_, payload, err := core.ParseUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		if _, err := local.Write(payload); err != nil {
			return
		}
	}
}
