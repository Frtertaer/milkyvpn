package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// ServeSOCKS5 runs a SOCKS5 (CONNECT + UDP ASSOCIATE, no-auth) listener on
// ln; every CONNECT is opened through the session returned by sessFn —
// resolved per connection so reconnects swap in a live session instead of
// leaving a dead one bound forever.
func ServeSOCKS5(sessFn func() *kal2.Session, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSocks(c, sessFn)
	}
}

func handleSocks(c net.Conn, sessFn func() *kal2.Session) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := socksHandshake(c); err != nil {
		return
	}
	cmd, host, port, err := socksRequest(c)
	if err != nil {
		return
	}
	if cmd == 0x03 {
		socksUDPAssociate(c, sessFn)
		return
	}
	sess := sessFn()
	if sess == nil {
		socksReply(c, 0x05)
		return
	}
	st, err := sess.Open(host, port, 15*time.Second)
	if err != nil {
		socksReply(c, 0x05) // connection refused
		return
	}
	if err := socksReply(c, 0x00); err != nil {
		st.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	errCh := make(chan struct{}, 2)
	go func() { _, _ = io.CopyBuffer(st, c, make([]byte, 1<<16)); errCh <- struct{}{} }()
	go func() { _, _ = io.CopyBuffer(c, st, make([]byte, 1<<16)); errCh <- struct{}{} }()
	<-errCh
	st.Close()
}

// socksUDPAssociate answers a UDP ASSOCIATE request: opens a "udp" stream over
// the tunnel, binds a local UDP relay, and pumps SOCKS5-UDP datagrams in both
// directions. The association ends when the TCP connection closes.
func socksUDPAssociate(c net.Conn, sessFn func() *kal2.Session) {
	sess := sessFn()
	if sess == nil {
		socksReply(c, 0x05)
		return
	}
	st, err := sess.OpenNet("udp", "0.0.0.0", 0, 15*time.Second)
	if err != nil {
		socksReply(c, 0x05)
		return
	}
	defer st.Close()
	// Bind the relay on the same loopback family the TCP client used.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		socksReply(c, 0x01)
		return
	}
	defer pc.Close()
	la := pc.LocalAddr().(*net.UDPAddr)
	if err := socksReplyAddr(c, 0x00, la.IP, uint16(la.Port)); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{})
	// TCP close ends the association (RFC 1928 §6).
	go func() {
		_, _ = io.Copy(io.Discard, c)
		close(done)
	}()

	// Client UDP addr is learned from the first datagram; subsequent datagrams
	// are only accepted from it.
	var clientMu sync.Mutex
	var client *net.UDPAddr

	// wire -> stream -> client: framed datagrams back to the socks client
	go func() {
		var lb [2]byte
		buf := make([]byte, 65535)
		for {
			if _, err := io.ReadFull(st, lb[:]); err != nil {
				pc.Close()
				return
			}
			n := int(binary.LittleEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(st, buf[:n]); err != nil {
				pc.Close()
				return
			}
			pkt := socksUDPPacket(buf[:n])
			if pkt == nil {
				continue
			}
			clientMu.Lock()
			dst := client
			clientMu.Unlock()
			if dst != nil {
				_, _ = pc.WriteTo(pkt, dst)
			}
		}
	}()

	// client -> stream: datagrams to the relay addr get framed through
	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		clientMu.Lock()
		if client == nil {
			client = ua
		}
		clientMu.Unlock()
		if !ua.IP.Equal(client.IP) {
			continue // only the associating client may use the relay
		}
		header, payload, ok := splitSocksUDP(buf[:n])
		if !ok || header[2] != 0x00 { // FRAG reassembly unsupported
			continue
		}
		// frame: [u16 len][ATYP][addr][port][payload]
		inner := header[3 : len(header)-len(payload)] // keep ATYP block only
		frame := make([]byte, 0, 2+len(inner)+len(payload))
		var lb [2]byte
		binary.LittleEndian.PutUint16(lb[:], uint16(len(inner)+len(payload)))
		frame = append(frame, lb[:]...)
		frame = append(frame, inner...)
		frame = append(frame, payload...)
		if _, err := st.Write(frame); err != nil {
			return
		}
	}
}

// splitSocksUDP splits a SOCKS5 UDP request into [RSV FRAG ATYP...PORT] header
// prefix and payload; header is the slice up to and including the port.
func splitSocksUDP(b []byte) (header, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0x00 || b[1] != 0x00 {
		return nil, nil, false
	}
	hl := 0
	switch b[3] {
	case 0x01:
		hl = 4 + 4 + 2
	case 0x04:
		hl = 4 + 16 + 2
	case 0x03:
		if len(b) < 5 {
			return nil, nil, false
		}
		hl = 4 + 1 + int(b[4]) + 2
	default:
		return nil, nil, false
	}
	if len(b) <= hl {
		return nil, nil, false
	}
	return b[:hl], b[hl:], true
}

// socksUDPPacket re-wraps an in-stream frame ([ATYP][addr][port][payload]) into
// a SOCKS5 UDP packet ([RSV FRAG] + frame) for the local client.
func socksUDPPacket(frame []byte) []byte {
	if len(frame) < 7 {
		return nil
	}
	pkt := make([]byte, 0, 3+len(frame))
	pkt = append(pkt, 0x00, 0x00, 0x00)
	return append(pkt, frame...)
}

func socksHandshake(c net.Conn) error {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 0x05 {
		return fmt.Errorf("bad socks greeting")
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	// VER 5, no-auth.
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	return nil
}

func socksRequest(c net.Conn) (cmd byte, host string, port uint16, err error) {
	h := make([]byte, 4)
	if _, err = io.ReadFull(c, h); err != nil {
		return
	}
	cmd = h[1]
	if h[0] != 0x05 || (cmd != 0x01 && cmd != 0x03) { // CONNECT or UDP ASSOCIATE
		socksReply(c, 0x07)
		err = fmt.Errorf("unsupported socks cmd %d", h[1])
		return
	}
	switch h[3] {
	case 0x01: // IPv4
		b := make([]byte, 4+2)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b[:4]).String()
		port = binary.BigEndian.Uint16(b[4:])
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err = io.ReadFull(c, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0])+2)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b[:len(b)-2])
		port = binary.BigEndian.Uint16(b[len(b)-2:])
	case 0x04: // IPv6
		b := make([]byte, 16+2)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = "[" + net.IP(b[:16]).String() + "]"
		port = binary.BigEndian.Uint16(b[16:])
	default:
		socksReply(c, 0x08)
		err = fmt.Errorf("bad atyp")
		return
	}
	return cmd, host, port, nil
}

func socksReply(c net.Conn, rep byte) error {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// socksReplyAddr replies with the real bind address (UDP ASSOCIATE).
func socksReplyAddr(c net.Conn, rep byte, ip net.IP, port uint16) error {
	out := []byte{0x05, rep, 0x00}
	if v4 := ip.To4(); v4 != nil {
		out = append(out, 0x01)
		out = append(out, v4...)
	} else {
		out = append(out, 0x04)
		out = append(out, ip.To16()...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	_, err := c.Write(append(out, p[:]...))
	return err
}

// LocalSocksAddr formats a loopback socks5 addr.
func LocalSocksAddr(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}
