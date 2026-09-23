package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// ServeSOCKS5 runs a minimal SOCKS5 (CONNECT, no-auth) listener on ln; every
// CONNECT is opened through sess. This is the local ingress the app exposes
// to the OS or per-app proxy settings.
func ServeSOCKS5(sess *kal2.Session, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSocks(c, sess)
	}
}

func handleSocks(c net.Conn, sess *kal2.Session) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := socksHandshake(c); err != nil {
		return
	}
	host, port, err := socksRequest(c)
	if err != nil {
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
	go func() { _, _ = io.Copy(st, c); errCh <- struct{}{} }()
	go func() { _, _ = io.Copy(c, st); errCh <- struct{}{} }()
	<-errCh
	st.Close()
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

func socksRequest(c net.Conn) (host string, port uint16, err error) {
	h := make([]byte, 4)
	if _, err = io.ReadFull(c, h); err != nil {
		return
	}
	if h[0] != 0x05 || h[1] != 0x01 { // CONNECT only
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
	return host, port, nil
}

func socksReply(c net.Conn, rep byte) error {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// LocalSocksAddr formats a loopback socks5 addr.
func LocalSocksAddr(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}
