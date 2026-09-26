package carrier

// Minimal RFC 6455 WebSocket transport for the CDN-shaped carrier.
// Frames are binary, unfragmented; client-to-server payloads are masked.
// The kal2 byte stream rides inside frame payloads.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsConn adapts a WebSocket connection to BoundConn: a byte stream where each
// Write is one binary frame and Read consumes frame payloads.
type wsConn struct {
	conn     net.Conn
	r        *bufio.Reader
	mask     bool // client side masks outgoing frames
	closed   chan struct{}
	once     sync.Once
	remote   net.Addr
	mu       sync.Mutex // serialize writes
	leftover []byte     // unread payload from the last frame
}

func (c *wsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(b), c.writeFrame(0x2, b)
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	var hdr [14]byte
	n := 0
	hdr[0] = 0x80 | op
	n++
	maskBit := byte(0)
	if c.mask {
		maskBit = 0x80
	}
	switch l := len(payload); {
	case l < 126:
		hdr[n] = maskBit | byte(l)
		n++
	case l < 65536:
		hdr[n] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[n+1:], uint16(l))
		n += 3
	default:
		hdr[n] = maskBit | 127
		binary.BigEndian.PutUint64(hdr[n+1:], uint64(l))
		n += 9
	}
	if c.mask {
		var key [4]byte
		_, _ = rand.Read(key[:])
		copy(hdr[n:], key[:])
		n += 4
		if _, err := c.conn.Write(hdr[:n]); err != nil {
			return err
		}
		masked := make([]byte, len(payload))
		for i, b := range payload {
			masked[i] = b ^ key[i%4]
		}
		_, err := c.conn.Write(masked)
		return err
	}
	if _, err := c.conn.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

// readFrame returns (opcode, payload). Ping is answered with pong here; pong
// frames are skipped; close returns io.EOF.
func (c *wsConn) readFrame() (byte, []byte, error) {
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.r, h[:]); err != nil {
			return 0, nil, err
		}
		op := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		l := int64(h[1] & 0x7f)
		switch l {
		case 126:
			var e [2]byte
			if _, err := io.ReadFull(c.r, e[:]); err != nil {
				return 0, nil, err
			}
			l = int64(binary.BigEndian.Uint16(e[:]))
		case 127:
			var e [8]byte
			if _, err := io.ReadFull(c.r, e[:]); err != nil {
				return 0, nil, err
			}
			l = int64(binary.BigEndian.Uint64(e[:]))
		}
		if l < 0 || l > 1<<24 {
			return 0, nil, fmt.Errorf("ws: frame too large %d", l)
		}
		var key [4]byte
		if masked {
			if _, err := io.ReadFull(c.r, key[:]); err != nil {
				return 0, nil, err
			}
		}
		payload := make([]byte, l)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= key[i%4]
			}
		}
		switch op {
		case 0x8: // close
			return 0, nil, io.EOF
		case 0x9: // ping -> pong
			_ = c.writeFrame(0xA, payload)
			continue
		case 0xA: // pong
			continue
		case 0x0, 0x1, 0x2: // continuation/text/binary — treat as data
			return op, payload, nil
		default:
			continue
		}
	}
}

func (c *wsConn) Read(b []byte) (int, error) {
	if c.leftover == nil {
		_, p, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		c.leftover = p
	}
	n := copy(b, c.leftover)
	c.leftover = c.leftover[n:]
	if len(c.leftover) == 0 {
		c.leftover = nil
	}
	return n, nil
}

func (c *wsConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.writeFrame(0x8, nil)
		_ = c.conn.Close()
	})
	return nil
}

func (c *wsConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.remote }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *wsConn) Binding() kal2.ChannelBinding       { return nil }

// wsAccept validates the upgrade request on the keyed path and hijacks the
// connection. Returns nil (with 404 already written) on any mismatch so
// unauthenticated probes stay indistinguishable. The hijack is registered
// before Hijack() runs — http.Server reports StateHijacked synchronously and
// serveHTTP must find the session's lifecycle channel already there.
func (v *VeilListener) wsAccept(w http.ResponseWriter, r *http.Request) *wsConn {
	if !headerContains(r.Header, "Connection", "upgrade") ||
		!headerContains(r.Header, "Upgrade", "websocket") {
		http.NotFound(w, r)
		return nil
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.NotFound(w, r)
		return nil
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		http.NotFound(w, r)
		return nil
	}
	reg := &hijackReg{closed: make(chan struct{})}
	addrKey := r.RemoteAddr
	v.hijacks.Store(addrKey, reg)
	nc, brw, err := h.Hijack()
	if err != nil {
		v.hijacks.Delete(addrKey)
		return nil
	}
	accept := base64.StdEncoding.EncodeToString(sha1Sum(append([]byte(key), wsGUID...)))
	fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	if err := brw.Flush(); err != nil {
		_ = nc.Close()
		v.hijacks.Delete(addrKey)
		close(reg.closed)
		return nil
	}
	var ra net.Addr
	// Behind a CDN the real client IP rides in CF-Connecting-IP /
	// X-Forwarded-For; the TCP peer is the edge node.
	ipStr := r.Header.Get("CF-Connecting-IP")
	if ipStr == "" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ipStr = strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	if ipStr == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ipStr = host
		}
	}
	if ipStr != "" {
		ra = &net.TCPAddr{IP: net.ParseIP(ipStr)}
	}
	return &wsConn{conn: nc, r: brw.Reader, closed: reg.closed, remote: ra}
}

// wsDial performs the client upgrade on an established TLS conn.
func wsDial(conn net.Conn, host, path string) (*wsConn, error) {
	var key [16]byte
	_, _ = rand.Read(key[:])
	keyB64 := base64.StdEncoding.EncodeToString(key[:])
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: %s\r\n\r\n",
		path, host, keyB64, driftUA())
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, "101") {
		return nil, fmt.Errorf("ws: bad status %q", strings.TrimSpace(status))
	}
	acceptOK := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Sec-WebSocket-Accept") {
			want := base64.StdEncoding.EncodeToString(sha1Sum(append([]byte(keyB64), wsGUID...)))
			acceptOK = strings.TrimSpace(v) == want
		}
	}
	if !acceptOK {
		return nil, fmt.Errorf("ws: bad accept key")
	}
	return &wsConn{conn: conn, r: br, mask: true, closed: make(chan struct{}), remote: conn.RemoteAddr()}, nil
}

func headerContains(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}
