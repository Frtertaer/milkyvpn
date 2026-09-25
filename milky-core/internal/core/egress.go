package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// EgressConfig controls how the server dials upstream targets.
type EgressConfig struct {
	// PreferIPv4 dials tcp4 first and falls back to the dual-stack resolver on
	// failure (IPv6-only hosts still work). Useful when the server's v6 range
	// carries worse reputation than its v4.
	PreferIPv4 bool
	// Upstream chains egress through an upstream SOCKS5 proxy
	// (e.g. "socks5://user:pass@host:port"). Empty = direct egress.
	Upstream *UpstreamSOCKS5
	// UpstreamOnly limits upstream routing to these domain suffixes
	// (e.g. "chatgpt.com" matches host and subdomains). Empty = all traffic
	// goes through Upstream when it is set.
	UpstreamOnly []string
}

// UpstreamSOCKS5 is a chained SOCKS5 proxy for outbound egress.
type UpstreamSOCKS5 struct {
	Addr     string // host:port of the upstream proxy
	User     string
	Pass     string
	Timeout  time.Duration
	preferV4 bool
	dialer   *net.Dialer
}

// ParseUpstream parses "socks5://[user[:pass]@]host:port".
func ParseUpstream(raw string) (*UpstreamSOCKS5, error) {
	s := strings.TrimPrefix(raw, "socks5://")
	var user, pass string
	if at := strings.LastIndex(s, "@"); at >= 0 {
		user, pass, _ = strings.Cut(s[:at], ":")
		s = s[at+1:]
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return nil, fmt.Errorf("upstream: bad addr %q: %w", s, err)
	}
	return &UpstreamSOCKS5{Addr: s, User: user, Pass: pass, Timeout: 15 * time.Second}, nil
}

// Dial connects to host:port through the upstream SOCKS5 proxy (remote DNS).
func (u *UpstreamSOCKS5) Dial(network, host string, port uint16) (net.Conn, error) {
	d := u.dialer
	if d == nil {
		d = &net.Dialer{Timeout: u.Timeout}
	}
	network = strings.ToLower(network)
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("upstream: %s unsupported (UDP chaining is not supported)", network)
	}
	if u.preferV4 && network == "tcp" {
		network = "tcp4"
	}
	c, err := d.Dial(network, u.Addr)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(u.Timeout))
	defer c.SetDeadline(time.Time{})
	if err := u.handshake(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (u *UpstreamSOCKS5) handshake(c net.Conn, host string, port uint16) error {
	// greeting: ver, nmethods, methods
	methods := []byte{0x00} // no-auth
	if u.User != "" {
		methods = append(methods, 0x02)
	}
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	rsp := make([]byte, 2)
	if _, err := io.ReadFull(c, rsp); err != nil {
		return err
	}
	if rsp[0] != 0x05 || rsp[1] == 0xFF {
		return fmt.Errorf("upstream: auth rejected (%02x)", rsp[1])
	}
	if rsp[1] == 0x02 {
		if len(u.User) > 255 || len(u.Pass) > 255 {
			return fmt.Errorf("upstream: credentials too long")
		}
		auth := []byte{0x01, byte(len(u.User))}
		auth = append(auth, u.User...)
		auth = append(auth, byte(len(u.Pass)))
		auth = append(auth, u.Pass...)
		if _, err := c.Write(auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, rsp); err != nil {
			return err
		}
		if rsp[1] != 0x00 {
			return fmt.Errorf("upstream: auth failed")
		}
	}
	// CONNECT host:port
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("upstream: host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	// reply: ver, rep, rsv, atyp, bnd (variable)
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		return fmt.Errorf("upstream: connect failed rep=%02x", hdr[1])
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return err
		}
		skip = int(lb[0])
	default:
		return fmt.Errorf("upstream: bad atyp %02x", hdr[3])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return err
	}
	return nil
}

// routeUpstream reports whether host should egress via the upstream chain.
func (cfg *EgressConfig) routeUpstream(host string) bool {
	if cfg == nil || cfg.Upstream == nil {
		return false
	}
	if len(cfg.UpstreamOnly) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suf := range cfg.UpstreamOnly {
		suf = strings.ToLower(strings.TrimSpace(suf))
		if suf == "" {
			continue
		}
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// dial picks direct vs upstream and applies the family preference.
func (cfg *EgressConfig) dial(dialer *net.Dialer, network, host string, port uint16, logf func(string, ...any)) (net.Conn, error) {
	target := net.JoinHostPort(host, fmt.Sprint(int(port)))
	if cfg != nil && cfg.routeUpstream(host) {
		cfg.Upstream.preferV4 = cfg.PreferIPv4
		c, err := cfg.Upstream.Dial(network, host, port)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", cfg.Upstream.Addr, err)
		}
		logf("egress: %s via upstream %s", target, cfg.Upstream.Addr)
		return c, nil
	}
	netw := strings.ToLower(network)
	if cfg != nil && cfg.PreferIPv4 && netw == "tcp" && net.ParseIP(host) == nil {
		if c, err := dialer.Dial("tcp4", target); err == nil {
			return c, nil
		}
		// dual-stack fallback keeps IPv6-only targets reachable
		return dialer.Dial("tcp", target)
	}
	if cfg != nil && cfg.PreferIPv4 && netw == "tcp" {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			netw = "tcp6" // literal v6 target: only4 keeps it reachable
		}
	}
	return dialer.Dial(netw, target)
}

// ServeEgress accepts KAL streams and proxies each to its requested target
// (server-side exit path). Runs until the session ends.
func ServeEgress(sess *kal2.Session, dialer *net.Dialer, logf func(string, ...any)) error {
	return ServeEgressCfg(sess, dialer, nil, logf)
}

// ServeEgressCfg is ServeEgress with upstream/family egress policy.
func ServeEgressCfg(sess *kal2.Session, dialer *net.Dialer, cfg *EgressConfig, logf func(string, ...any)) error {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 15 * time.Second}
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer st.Close()
			network, host, port, err := st.Target()
			if err != nil {
				logf("egress: bad target: %v", err)
				return
			}
			if strings.EqualFold(network, "udp") {
				if err := st.Ack(0x00); err != nil {
					return
				}
				relayUDP(st, dialer, cfg, logf)
				return
			}
			up, err := cfg.dial(dialer, network, host, port, logf)
			if err != nil {
				logf("egress: dial %s:%d: %v", host, int(port), err)
				_ = st.Ack(0x05)
				return
			}
			if err := st.Ack(0x00); err != nil {
				up.Close()
				return
			}
			defer up.Close()
			errCh := make(chan struct{}, 2)
			go func() { _, _ = io.CopyBuffer(up, st, make([]byte, 1<<16)); errCh <- struct{}{} }()
			go func() { _, _ = io.CopyBuffer(st, up, make([]byte, 1<<16)); errCh <- struct{}{} }()
			<-errCh
		}()
	}
}

// relayUDP pumps framed datagrams between a KAL "udp" stream and a wildcard
// UDP socket. In-stream frame: [u16-LE len][ATYP][addr][port][payload] — the
// inner address block is the SOCKS5-style destination per datagram, and
// replies carry the actual source address back.
func relayUDP(st *kal2.Stream, dialer *net.Dialer, cfg *EgressConfig, logf func(string, ...any)) {
	network := "udp"
	if cfg != nil && cfg.PreferIPv4 {
		network = "udp4"
	}
	pc, err := net.ListenPacket(network, ":0")
	if err != nil {
		logf("egress: udp listen: %v", err)
		return
	}
	defer pc.Close()
	errCh := make(chan struct{}, 2)
	go func() {
		// stream -> wire: parse framed datagram, send to its destination
		var lb [2]byte
		buf := make([]byte, 65535)
		for {
			if _, err := io.ReadFull(st, lb[:]); err != nil {
				errCh <- struct{}{}
				return
			}
			n := int(binary.LittleEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(st, buf[:n]); err != nil {
				errCh <- struct{}{}
				return
			}
			dst, payload, err := parseUDPHeader(buf[:n])
			if err != nil {
				continue
			}
			if _, err := pc.WriteTo(payload, dst); err != nil {
				errCh <- struct{}{}
				return
			}
		}
	}()
	go func() {
		// wire -> stream: one datagram = one frame with source addr
		buf := make([]byte, 65538)
		for {
			n, src, err := pc.ReadFrom(buf[23:]) // reserve room for v6 header
			if err != nil {
				errCh <- struct{}{}
				return
			}
			frame := appendUDPHeader(buf[:0], src, buf[23:23+n])
			if frame == nil {
				continue
			}
			if _, err := st.Write(frame); err != nil {
				errCh <- struct{}{}
				return
			}
		}
	}()
	<-errCh
}

// parseUDPHeader decodes [ATYP][addr][port][payload] into a UDPAddr + payload.
func parseUDPHeader(b []byte) (*net.UDPAddr, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("short udp header")
	}
	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return nil, nil, fmt.Errorf("short v4")
		}
		return &net.UDPAddr{IP: net.IP(b[1:5]), Port: int(binary.BigEndian.Uint16(b[5:7]))}, b[7:], nil
	case 0x04:
		if len(b) < 19 {
			return nil, nil, fmt.Errorf("short v6")
		}
		return &net.UDPAddr{IP: net.IP(b[1:17]), Port: int(binary.BigEndian.Uint16(b[17:19]))}, b[19:], nil
	case 0x03:
		l := int(b[1])
		if len(b) < 2+l+2 {
			return nil, nil, fmt.Errorf("short domain")
		}
		host := string(b[2 : 2+l])
		port := int(binary.BigEndian.Uint16(b[2+l : 2+l+2]))
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			return nil, nil, err
		}
		return addr, b[2+l+2:], nil
	}
	return nil, nil, fmt.Errorf("bad atyp %02x", b[0])
}

// appendUDPHeader encodes [u16 len][ATYP][addr][port][payload].
func appendUDPHeader(dst []byte, addr net.Addr, payload []byte) []byte {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil
	}
	var head []byte
	if v4 := ua.IP.To4(); v4 != nil {
		head = append([]byte{0x01}, v4...)
	} else {
		head = append([]byte{0x04}, ua.IP.To16()...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(ua.Port))
	head = append(head, p[:]...)
	l := len(head) + len(payload)
	if l > 0xFFFF {
		return nil
	}
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(l))
	dst = append(dst, lb[:]...)
	dst = append(dst, head...)
	return append(dst, payload...)
}

// OpenStream is a convenience for clients: open a stream to host:port.
func OpenStream(sess *kal2.Session, host string, port uint16, timeout time.Duration) (*kal2.Stream, error) {
	if sess == nil {
		return nil, fmt.Errorf("nil session")
	}
	return sess.Open(host, port, timeout)
}

// PingSession sends a liveness ping and waits for the pong.
func PingSession(ctx context.Context, sess *kal2.Session) error {
	done := make(chan error, 1)
	go func() { done <- sess.Ping([]byte("ping"), 10*time.Second) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
