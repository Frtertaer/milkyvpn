package carrier

// Mosaic carrier: one KAL/2 session spread over many short, independent
// HTTPS request/response exchanges ("tiles") instead of a single long-lived
// connection.
//
// It exists because the connection is the unit censors act on. A TSPU-style
// middlebox resets or truncates a flow (foreign hosting connections are cut
// after roughly 16-20 KB in 2026 field reports), blackholes an entry IP, or
// the phone simply changes network — and any carrier that maps a session onto
// one connection dies with it.
//
// Mosaic decouples the two. Every tile carries a slice of the session's byte
// streams addressed by absolute offset and authenticated with the user PSK;
// tiles are idempotent, may be sent over any entry IP, may arrive out of
// order, and a lost tile only means its byte range is re-sent in a later one.
// Underlying TLS connections are retired well below the truncation threshold,
// so no flow ever reaches the size where it gets cut, and losing an entry
// point costs a retransmit instead of the session.
//
// Wire format, inside TLS, in the POST body (client -> server):
//
//	sid[16] | upOff[8] | downAck[8] | upLen[2] | padLen[2] | mac[16] |
//	data[upLen] | pad[padLen]
//
// and in the response body (server -> client):
//
//	downOff[8] | upAck[8] | downLen[2] | padLen[2] | mac[16] |
//	data[downLen] | pad[padLen]
//
// mac is HMAC-SHA256(psk, label || header || data) truncated to 16 bytes, so
// a probe cannot elicit protocol bytes and a tile cannot be forged onto
// someone else's session. Reordering, duplication and replay of tiles are
// harmless: offsets are absolute and the inner KAL/2 records carry their own
// sequence numbers and AEAD tags.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// DefaultMosaicPath is the base path of the tile endpoint.
const DefaultMosaicPath = "/api/v3/tiles"

const (
	mosaicSIDLen  = 16
	mosaicMACLen  = 16
	mosaicHdrLen  = mosaicSIDLen + 8 + 8 + 2 + 2
	mosaicRespHdr = 8 + 8 + 2 + 2

	// MaxMosaicTile bounds the payload carried in one tile in either
	// direction. With padding and HTTP overhead a tile stays a few KiB —
	// the size of an ordinary XHR, far below any observed truncation point.
	MaxMosaicTile = 4 << 10

	// mosaicChunk is the payload both ends actually put in one tile: small
	// enough that a handshake plus one full-duplex tile, and whatever the
	// peer still has in flight at close, fit well inside a 16 KiB flow.
	mosaicChunk = 3 << 10

	// mosaicWindow bounds in-flight unacknowledged bytes per direction, and
	// with it the memory one session can pin on the server.
	mosaicWindow = 1 << 18

	// mosaicConnBudget bounds the wire bytes of one TCP flow in both
	// directions, TLS handshake included: a tile is only admitted onto a
	// connection when measured bytes plus reserved worst cases stay below it,
	// so no flow grows into the ~16 KiB range where middleboxes truncate.
	mosaicConnBudget = 13 << 10

	// mosaicTileOverhead approximates HTTP/2 framing and TLS record bytes a
	// tile exchange adds on the wire.
	mosaicTileOverhead = 384

	// mosaicHandshakeEst stands in for the TLS handshake bytes of a
	// connection that has not finished dialing yet.
	mosaicHandshakeEst = 5 << 10

	// mosaicMaxResp is the largest response body a tile can return.
	mosaicMaxResp = mosaicRespHdr + mosaicMACLen + MaxMosaicTile + 256

	// mosaicHold is how long the server keeps a tile open waiting for
	// downstream bytes — the request looks like a normal polling API call.
	mosaicHold = 4 * time.Second

	// mosaicPollers empty tiles are kept parked on the server for downstream
	// bytes; mosaicSenders more lanes carry upstream bytes as they appear, so
	// a write never waits behind a parked poll.
	mosaicPollers = 2
	mosaicSenders = 2

	// mosaicRTO re-sends bytes the peer has not acknowledged in this long —
	// covers tiles whose response was cut after the peer consumed them.
	mosaicRTO = 3 * time.Second

	// mosaicDead closes the session after this long without any tile
	// completing, handing recovery to the reconnect loop.
	mosaicDead = 45 * time.Second

	mosaicIdle = 90 * time.Second
)

var (
	mosaicTileLabel = []byte("mxs/mosaic-tile")
	mosaicRespLabel = []byte("mxs/mosaic-resp")

	// errMosaicAuth marks an unauthenticated or malformed tile; callers must
	// answer with the decoy site's ordinary 404.
	errMosaicAuth = errors.New("mosaic: tile authentication failed")
)

// MosaicPathToken derives the keyed path suffix of a user's tile endpoint:
// hex(HMAC-SHA256(psk, "mxs/mosaic-path")[:8]).
func MosaicPathToken(psk []byte) string {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte("mxs/mosaic-path"))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

func mosaicMAC(psk, label, hdr, data []byte) []byte {
	m := hmac.New(sha256.New, psk)
	_, _ = m.Write(label)
	_, _ = m.Write(hdr)
	_, _ = m.Write(data)
	return m.Sum(nil)[:mosaicMACLen]
}

// tile is a client -> server exchange unit.
type tile struct {
	sid     [mosaicSIDLen]byte
	upOff   uint64
	downAck uint64
	data    []byte
}

// tileResp is the server -> client half of an exchange.
type tileResp struct {
	downOff uint64
	upAck   uint64
	data    []byte
}

func mosaicPad() []byte {
	n := 16 + mrand.IntN(240)
	p := make([]byte, n)
	_, _ = rand.Read(p)
	return p
}

func (t *tile) encode(psk []byte) []byte {
	pad := mosaicPad()
	hdr := make([]byte, mosaicHdrLen)
	copy(hdr, t.sid[:])
	binary.BigEndian.PutUint64(hdr[mosaicSIDLen:], t.upOff)
	binary.BigEndian.PutUint64(hdr[mosaicSIDLen+8:], t.downAck)
	binary.BigEndian.PutUint16(hdr[mosaicSIDLen+16:], uint16(len(t.data)))
	binary.BigEndian.PutUint16(hdr[mosaicSIDLen+18:], uint16(len(pad)))
	out := make([]byte, 0, mosaicHdrLen+mosaicMACLen+len(t.data)+len(pad))
	out = append(out, hdr...)
	out = append(out, mosaicMAC(psk, mosaicTileLabel, hdr, t.data)...)
	out = append(out, t.data...)
	return append(out, pad...)
}

// parseTileHeader splits the fixed header without authenticating it: the PSK
// is only known after the path token identifies the user.
func parseTileHeader(b []byte) (sid [mosaicSIDLen]byte, upOff, downAck uint64, upLen int, mac []byte, err error) {
	if len(b) < mosaicHdrLen+mosaicMACLen {
		return sid, 0, 0, 0, nil, errMosaicAuth
	}
	copy(sid[:], b[:mosaicSIDLen])
	upOff = binary.BigEndian.Uint64(b[mosaicSIDLen:])
	downAck = binary.BigEndian.Uint64(b[mosaicSIDLen+8:])
	upLen = int(binary.BigEndian.Uint16(b[mosaicSIDLen+16:]))
	padLen := int(binary.BigEndian.Uint16(b[mosaicSIDLen+18:]))
	if upLen > MaxMosaicTile || len(b) < mosaicHdrLen+mosaicMACLen+upLen+padLen {
		return sid, 0, 0, 0, nil, errMosaicAuth
	}
	return sid, upOff, downAck, upLen, b[mosaicHdrLen : mosaicHdrLen+mosaicMACLen], nil
}

// parseTile authenticates a tile body with psk.
func parseTile(b, psk []byte) (*tile, error) {
	sid, upOff, downAck, upLen, mac, err := parseTileHeader(b)
	if err != nil {
		return nil, err
	}
	data := b[mosaicHdrLen+mosaicMACLen : mosaicHdrLen+mosaicMACLen+upLen]
	if !hmac.Equal(mac, mosaicMAC(psk, mosaicTileLabel, b[:mosaicHdrLen], data)) {
		return nil, errMosaicAuth
	}
	return &tile{sid: sid, upOff: upOff, downAck: downAck, data: append([]byte(nil), data...)}, nil
}

func (r *tileResp) encode(psk []byte) []byte {
	pad := mosaicPad()
	hdr := make([]byte, mosaicRespHdr)
	binary.BigEndian.PutUint64(hdr, r.downOff)
	binary.BigEndian.PutUint64(hdr[8:], r.upAck)
	binary.BigEndian.PutUint16(hdr[16:], uint16(len(r.data)))
	binary.BigEndian.PutUint16(hdr[18:], uint16(len(pad)))
	out := make([]byte, 0, mosaicRespHdr+mosaicMACLen+len(r.data)+len(pad))
	out = append(out, hdr...)
	out = append(out, mosaicMAC(psk, mosaicRespLabel, hdr, r.data)...)
	out = append(out, r.data...)
	return append(out, pad...)
}

func parseTileResp(b, psk []byte) (*tileResp, error) {
	if len(b) < mosaicRespHdr+mosaicMACLen {
		return nil, errMosaicAuth
	}
	downOff := binary.BigEndian.Uint64(b)
	upAck := binary.BigEndian.Uint64(b[8:])
	downLen := int(binary.BigEndian.Uint16(b[16:]))
	padLen := int(binary.BigEndian.Uint16(b[18:]))
	if downLen > MaxMosaicTile || len(b) < mosaicRespHdr+mosaicMACLen+downLen+padLen {
		return nil, errMosaicAuth
	}
	mac := b[mosaicRespHdr : mosaicRespHdr+mosaicMACLen]
	data := b[mosaicRespHdr+mosaicMACLen : mosaicRespHdr+mosaicMACLen+downLen]
	if !hmac.Equal(mac, mosaicMAC(psk, mosaicRespLabel, b[:mosaicRespHdr], data)) {
		return nil, errMosaicAuth
	}
	return &tileResp{downOff: downOff, upAck: upAck, data: append([]byte(nil), data...)}, nil
}

// ---------------------------------------------------------------------------
// Reliable offset-addressed stream shared by both ends
// ---------------------------------------------------------------------------

// mosaicStream turns idempotent, offset-addressed tile payloads into the
// ordered reliable byte stream KAL/2 expects. Outbound bytes stay buffered
// until the peer acknowledges the offset, so any tile may be lost, duplicated
// or answered by a different entry point.
type mosaicStream struct {
	mu sync.Mutex
	// Outbound: out holds unacknowledged bytes starting at outBase; sent is
	// the next offset a tile will carry (rewound when a tile fails).
	out     []byte
	outBase uint64
	sent    uint64
	// Inbound: ready holds the contiguous undelivered prefix ending at
	// inNext; seg holds pieces that arrived early.
	ready    []byte
	inNext   uint64
	seg      map[uint64][]byte
	segBytes int

	// lastAck is when outbound acknowledgement last advanced (or a new
	// flight started); see rewindStale.
	lastAck time.Time

	closed bool
	rdl    time.Time

	inSig, outSig, spaceSig chan struct{}
}

func newMosaicStream() *mosaicStream {
	return &mosaicStream{
		seg:      map[uint64][]byte{},
		inSig:    make(chan struct{}, 1),
		outSig:   make(chan struct{}, 1),
		spaceSig: make(chan struct{}, 1),
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// waitSig blocks until ch fires, the deadline passes, or the stream closes.
func (s *mosaicStream) waitSig(ch chan struct{}, dl time.Time) bool {
	var timer *time.Timer
	var tc <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return false
		}
		timer = time.NewTimer(d)
		tc = timer.C
		defer timer.Stop()
	}
	select {
	case <-ch:
		return true
	case <-tc:
		return false
	}
}

func (s *mosaicStream) Write(b []byte) (int, error) {
	total := len(b)
	for len(b) > 0 {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return total - len(b), io.ErrClosedPipe
		}
		space := mosaicWindow - len(s.out)
		if space <= 0 {
			s.mu.Unlock()
			if !s.waitSig(s.spaceSig, time.Now().Add(30*time.Second)) {
				s.mu.Lock()
				closed := s.closed
				s.mu.Unlock()
				if closed {
					return total - len(b), io.ErrClosedPipe
				}
			}
			continue
		}
		n := min(space, len(b))
		s.out = append(s.out, b[:n]...)
		b = b[n:]
		s.mu.Unlock()
		signal(s.outSig)
	}
	return total, nil
}

func (s *mosaicStream) Read(b []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.ready) > 0 {
			n := copy(b, s.ready)
			s.ready = s.ready[n:]
			if len(s.ready) == 0 {
				s.ready = nil
			}
			s.mu.Unlock()
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		dl := s.rdl
		s.mu.Unlock()
		if !s.waitSig(s.inSig, dl) {
			s.mu.Lock()
			closed, pending := s.closed, len(s.ready)
			s.mu.Unlock()
			if closed {
				return 0, io.EOF
			}
			if pending == 0 && !dl.IsZero() {
				return 0, os.ErrDeadlineExceeded
			}
		}
	}
}

// takeOut hands the next unsent outbound range to a tile.
func (s *mosaicStream) takeOut(max int) (uint64, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.outBase + uint64(len(s.out))
	if s.sent < s.outBase {
		s.sent = s.outBase
	}
	if s.sent >= end {
		return s.sent, nil
	}
	if s.sent == s.outBase {
		s.lastAck = time.Now()
	}
	n := min(uint64(max), end-s.sent)
	from := s.sent - s.outBase
	data := append([]byte(nil), s.out[from:from+n]...)
	off := s.sent
	s.sent += n
	return off, data
}

// takeOutWait is takeOut with a bounded wait for bytes to appear.
func (s *mosaicStream) takeOutWait(max int, hold time.Duration) (uint64, []byte) {
	dl := time.Now().Add(hold)
	for {
		if off, data := s.takeOut(max); len(data) > 0 {
			return off, data
		}
		s.mu.Lock()
		closed, sent := s.closed, s.sent
		s.mu.Unlock()
		if closed || !s.waitSig(s.outSig, dl) {
			return sent, nil
		}
	}
}

// rewind returns a failed tile's range to the send queue.
func (s *mosaicStream) rewind(off uint64) {
	s.mu.Lock()
	if off < s.outBase {
		off = s.outBase // already acknowledged meanwhile
	}
	if off < s.sent {
		s.sent = off
	}
	s.mu.Unlock()
	signal(s.outSig)
}

// rewindStale re-queues everything unacknowledged when acknowledgement has
// not advanced for rto: some tile carrying it was lost after being counted
// as sent.
func (s *mosaicStream) rewindStale(rto time.Duration) {
	s.mu.Lock()
	stale := s.sent > s.outBase && time.Since(s.lastAck) > rto
	if stale {
		s.sent = s.outBase
		s.lastAck = time.Now()
	}
	s.mu.Unlock()
	if stale {
		signal(s.outSig)
	}
}

// ackOut drops outbound bytes the peer has received contiguously.
func (s *mosaicStream) ackOut(upto uint64) {
	s.mu.Lock()
	if upto > s.outBase && upto <= s.outBase+uint64(len(s.out)) {
		s.out = append([]byte(nil), s.out[upto-s.outBase:]...)
		s.outBase = upto
		s.lastAck = time.Now()
		if s.sent < upto {
			s.sent = upto
		}
	}
	s.mu.Unlock()
	signal(s.spaceSig)
}

// ingest accepts an offset-addressed inbound range, dropping what is already
// delivered and buffering what arrived early.
func (s *mosaicStream) ingest(off uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		signal(s.inSig)
	}()
	end := off + uint64(len(data))
	if end <= s.inNext {
		return // fully duplicate
	}
	if off > s.inNext+mosaicWindow {
		return // beyond the window; the peer will re-send
	}
	if off < s.inNext {
		data = data[s.inNext-off:]
		off = s.inNext
	}
	if off > s.inNext {
		if prev, dup := s.seg[off]; (!dup || len(prev) < len(data)) && s.segBytes+len(data)-len(prev) <= mosaicWindow {
			s.seg[off] = append([]byte(nil), data...)
			s.segBytes += len(data) - len(prev)
		}
		return
	}
	s.ready = append(s.ready, data...)
	s.inNext = end
	s.drainSegs()
}

// drainSegs moves buffered early pieces that now touch the contiguous
// prefix into ready, trimming overlap.
func (s *mosaicStream) drainSegs() {
	for progressed := true; progressed; {
		progressed = false
		for off, d := range s.seg {
			if off > s.inNext {
				continue
			}
			delete(s.seg, off)
			s.segBytes -= len(d)
			if end := off + uint64(len(d)); end > s.inNext {
				s.ready = append(s.ready, d[s.inNext-off:]...)
				s.inNext = end
				progressed = true
			}
		}
	}
}

// inAck is the contiguous inbound offset to acknowledge to the peer.
func (s *mosaicStream) inAck() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inNext
}

func (s *mosaicStream) setReadDeadline(t time.Time) {
	s.mu.Lock()
	s.rdl = t
	s.mu.Unlock()
	signal(s.inSig)
}

func (s *mosaicStream) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	signal(s.inSig)
	signal(s.outSig)
	signal(s.spaceSig)
}

func (s *mosaicStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ---------------------------------------------------------------------------
// BoundConn over a mosaic stream
// ---------------------------------------------------------------------------

// mosaicConn presents a mosaic stream as the carrier connection KAL/2
// attaches to. It has no channel binding: the session is deliberately not
// bound to any single TLS connection, since it outlives them all.
type mosaicConn struct {
	st     *mosaicStream
	remote net.Addr
	onStop func()
	once   sync.Once
}

func (c *mosaicConn) Read(b []byte) (int, error)  { return c.st.Read(b) }
func (c *mosaicConn) Write(b []byte) (int, error) { return c.st.Write(b) }
func (c *mosaicConn) Close() error {
	c.once.Do(func() {
		c.st.Close()
		if c.onStop != nil {
			c.onStop()
		}
	})
	return nil
}
func (c *mosaicConn) LocalAddr() net.Addr  { return nil }
func (c *mosaicConn) RemoteAddr() net.Addr { return c.remote }
func (c *mosaicConn) SetDeadline(t time.Time) error {
	c.st.setReadDeadline(t)
	return nil
}
func (c *mosaicConn) SetReadDeadline(t time.Time) error {
	c.st.setReadDeadline(t)
	return nil
}
func (c *mosaicConn) SetWriteDeadline(time.Time) error { return nil }
func (c *mosaicConn) Binding() kal2.ChannelBinding     { return nil }

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// mosaicPool holds one short-lived HTTP/2 transport per entry point and
// retires it once its flow would pass mosaicConnBudget, so no TLS flow
// grows into the range where middleboxes truncate connections.
type mosaicPool struct {
	cfg  ClientConfig
	mu   sync.Mutex
	tr   map[string]*pooledTransport
	logf func(string, ...any)
}

type pooledTransport struct {
	tr       *http2.Transport
	wire     *atomic.Int64 // raw TCP bytes both ways, handshake included
	reserved int           // worst-case bytes of tiles still in flight
}

func newMosaicPool(cfg ClientConfig) *mosaicPool {
	return &mosaicPool{cfg: cfg, tr: map[string]*pooledTransport{}}
}

// transport returns a transport for addr with reserve bytes of its budget
// claimed for one exchange, so concurrent tiles cannot jointly overrun the
// budget. A fresh transport always admits its first tile.
func (p *mosaicPool) transport(addr string, reserve int) *http2.Transport {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pt, ok := p.tr[addr]; ok && max(int(pt.wire.Load()), mosaicHandshakeEst)+pt.reserved+reserve <= mosaicConnBudget {
		pt.reserved += reserve
		return pt.tr
	} else if ok {
		go pt.tr.CloseIdleConnections()
	}
	cfg := p.cfg
	cfg.Addr = addr
	wire := new(atomic.Int64)
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			return dialMosaicTLS(ctx, cfg, network, wire)
		},
	}
	p.tr[addr] = &pooledTransport{tr: tr, wire: wire, reserved: reserve}
	return tr
}

// settle drops a finished exchange's reservation; its real bytes are
// already in the transport's wire count.
func (p *mosaicPool) settle(addr string, tr *http2.Transport, reserved int) {
	p.mu.Lock()
	if pt, ok := p.tr[addr]; ok && pt.tr == tr {
		pt.reserved -= reserved
	}
	p.mu.Unlock()
}

// countingConn tallies every byte crossing a raw connection.
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Read(b []byte) (int, error) {
	k, err := c.Conn.Read(b)
	c.n.Add(int64(k))
	return k, err
}

func (c countingConn) Write(b []byte) (int, error) {
	k, err := c.Conn.Write(b)
	c.n.Add(int64(k))
	return k, err
}

// release closes a transport's now-idle connections once it has been
// superseded or has spent its budget; otherwise a connection busy with a
// parked long-poll when the transport was replaced would stay open forever.
func (p *mosaicPool) release(addr string, tr *http2.Transport) {
	p.mu.Lock()
	pt, ok := p.tr[addr]
	stale := !ok || pt.tr != tr
	p.mu.Unlock()
	if stale {
		tr.CloseIdleConnections()
	}
}

// retire drops a transport whose connection failed so the next tile to
// that endpoint dials fresh.
func (p *mosaicPool) retire(addr string, tr *http2.Transport) {
	p.mu.Lock()
	if pt, ok := p.tr[addr]; ok && pt.tr == tr {
		delete(p.tr, addr)
	}
	p.mu.Unlock()
	go tr.CloseIdleConnections()
}

func (p *mosaicPool) close() {
	p.mu.Lock()
	for _, pt := range p.tr {
		pt.tr.CloseIdleConnections()
	}
	p.tr = map[string]*pooledTransport{}
	p.mu.Unlock()
}

func dialMosaicTLS(ctx context.Context, cfg ClientConfig, network string, wire *atomic.Int64) (net.Conn, error) {
	dial := cfg.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: cfg.timeout(), Control: cfg.DialControl}
		dial = d.DialContext
	}
	raw, err := dial(ctx, network, cfg.Addr)
	if err != nil {
		return nil, err
	}
	raw = countingConn{Conn: raw, n: wire}
	spec, _ := utls.UTLSIdToSpec(pickHelloID(cfg.Fingerprint))
	uc := utls.UClient(raw, cfg.utlsConfig("h2"), utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return uc, nil
}

// mosaicClient drives the tile exchange for one session.
type mosaicClient struct {
	cfg     ClientConfig
	st      *mosaicStream
	pool    *mosaicPool
	sid     [mosaicSIDLen]byte
	psk     []byte
	eps     []string
	path    string
	epIdx   atomic.Uint32
	health  mosaicHealth
	lastOK  atomic.Int64 // unix nanos of the last completed tile
	stop    chan struct{}
	once    sync.Once
	logf    func(string, ...any)
	onClose func()
}

// DialMosaic establishes a KAL/2 session carried by mosaic tiles. Every
// endpoint in cfg.Endpoints (or cfg.Addr) is used for the same session, so
// blocking one of them degrades throughput instead of dropping the tunnel.
func DialMosaic(ctx context.Context, cfg ClientConfig, path string) (*kal2.Session, BoundConn, error) {
	if path == "" {
		path = DefaultMosaicPath
	}
	eps := cfg.Endpoints
	if len(eps) == 0 {
		eps = []string{cfg.Addr}
	}
	mc := &mosaicClient{
		cfg:  cfg,
		st:   newMosaicStream(),
		pool: newMosaicPool(cfg),
		psk:  cfg.PSK,
		eps:  eps,
		path: strings.TrimSuffix(path, "/") + "/" + MosaicPathToken(cfg.PSK),
		stop: make(chan struct{}),
		logf: cfg.logger(),
	}
	mc.health.init(len(eps))
	if _, err := rand.Read(mc.sid[:]); err != nil {
		return nil, nil, err
	}
	mc.epIdx.Store(uint32(mrand.IntN(len(eps))))
	ra, _ := net.ResolveTCPAddr("tcp", eps[0])
	conn := &mosaicConn{st: mc.st, remote: ra, onStop: mc.close}

	// One tile must complete before the handshake can: fail the dial fast
	// when no endpoint answers at all instead of retrying forever.
	if err := mc.probe(ctx); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	mc.lastOK.Store(time.Now().UnixNano())
	for i := 0; i < mosaicPollers; i++ {
		go mc.pump(true)
	}
	for i := 0; i < mosaicSenders; i++ {
		go mc.pump(false)
	}
	go mc.watchdog(conn)
	sess, err := runClientHandshake(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, nil, handshakeStageError{err}
	}
	return sess, conn, nil
}

func (m *mosaicClient) close() {
	m.once.Do(func() {
		close(m.stop)
		m.st.Close()
		m.pool.close()
	})
}

// nextEndpoint rotates over the endpoints, skipping ones cooling down
// after failures; when every endpoint is cooling it still returns the next.
func (m *mosaicClient) nextEndpoint() string {
	n := uint32(len(m.eps))
	start := m.epIdx.Add(1)
	now := time.Now()
	for k := uint32(0); k < n; k++ {
		i := int((start + k) % n)
		if m.health.usable(i, now) {
			if k > 0 {
				m.epIdx.Store(start + k)
			}
			return m.eps[i]
		}
	}
	return m.eps[int(start%n)]
}

func (m *mosaicClient) endpointIndex(addr string) int {
	for i, e := range m.eps {
		if e == addr {
			return i
		}
	}
	return -1
}

// mosaicHealth tracks per-endpoint failure streaks so blocked or dead
// endpoints stop absorbing tiles; cooldown doubles per failure up to 30s.
type mosaicHealth struct {
	mu    sync.Mutex
	fails []int
	until []time.Time
}

func (h *mosaicHealth) init(n int) {
	h.fails = make([]int, n)
	h.until = make([]time.Time, n)
}

func (h *mosaicHealth) usable(i int, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !now.Before(h.until[i])
}

func (h *mosaicHealth) failed(i int) {
	if i < 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fails[i]++
	d := time.Second << min(h.fails[i]-1, 5)
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	h.until[i] = time.Now().Add(d)
}

func (h *mosaicHealth) ok(i int) {
	if i < 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fails[i] = 0
	h.until[i] = time.Time{}
}

// healthy reports whether some endpoint is currently outside cooldown.
func (h *mosaicHealth) healthy(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range h.until {
		if !now.Before(u) {
			return true
		}
	}
	return false
}

// probe sends one empty tile to confirm some endpoint accepts the session.
func (m *mosaicClient) probe(ctx context.Context) error {
	var lastErr error
	for range m.eps {
		addr := m.nextEndpoint()
		_, err := m.exchange(ctx, addr, &tile{sid: m.sid})
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("mosaic: no endpoint accepted a tile: %w", lastErr)
}

// watchdog ends the session when no tile has completed for mosaicDead.
func (m *mosaicClient) watchdog(conn *mosaicConn) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
		}
		if time.Since(time.Unix(0, m.lastOK.Load())) > mosaicDead {
			m.logf("kal2: mosaic: no tile completed for %s; closing session", mosaicDead)
			_ = conn.Close()
			return
		}
	}
}

// pump keeps one tile in flight. A poller sends empty tiles the server parks
// until downstream bytes exist; a sender only goes out with upstream bytes.
// Both apply the acknowledgements and data of every response.
func (m *mosaicClient) pump(poller bool) {
	backoff := 200 * time.Millisecond
	for {
		select {
		case <-m.stop:
			return
		default:
		}
		m.st.rewindStale(mosaicRTO + mosaicHold)
		var off uint64
		var data []byte
		if poller {
			off, data = m.st.takeOut(mosaicChunk)
		} else {
			off, data = m.st.takeOutWait(mosaicChunk, time.Second)
			if len(data) == 0 {
				if m.st.isClosed() {
					return
				}
				continue
			}
		}
		t := &tile{sid: m.sid, upOff: off, downAck: m.st.inAck(), data: data}
		addr := m.nextEndpoint()
		ctx, cancel := context.WithTimeout(context.Background(), mosaicHold+m.cfg.timeout())
		resp, err := m.exchange(ctx, addr, t)
		cancel()
		if err != nil {
			if m.st.isClosed() {
				return
			}
			// The tile may never have arrived: queue its bytes again, most
			// likely for a different endpoint (offsets make this idempotent).
			if len(data) > 0 {
				m.st.rewind(off)
			}
			m.logf("kal2: mosaic tile via %s failed: %v", addr, err)
			if m.health.healthy(time.Now()) {
				continue
			}
			select {
			case <-m.stop:
				return
			case <-time.After(backoff + time.Duration(mrand.Int64N(int64(backoff)))):
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 200 * time.Millisecond
		m.lastOK.Store(time.Now().UnixNano())
		m.st.ackOut(resp.upAck)
		m.st.ingest(resp.downOff, resp.data)
	}
}

func (m *mosaicClient) exchange(ctx context.Context, addr string, t *tile) (*tileResp, error) {
	r, err := m.exchangeOnce(ctx, addr, t)
	if err != nil {
		if !m.st.isClosed() {
			m.health.failed(m.endpointIndex(addr))
		}
		return nil, err
	}
	m.health.ok(m.endpointIndex(addr))
	return r, nil
}

func (m *mosaicClient) exchangeOnce(ctx context.Context, addr string, t *tile) (*tileResp, error) {
	body := t.encode(m.psk)
	reserve := len(body) + mosaicRespHdr + mosaicMACLen + mosaicChunk + 256 + mosaicTileOverhead
	tr := m.pool.transport(addr, reserve)
	url := "https://" + m.cfg.SNI + m.path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", driftUA())
	req.Header.Set("Cache-Control", "no-store")
	req.ContentLength = int64(len(body))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		m.pool.retire(addr, tr)
		return nil, err
	}
	defer m.pool.release(addr, tr)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mosaic: status %d", resp.StatusCode)
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, int64(mosaicMaxResp+256)))
	if err != nil {
		m.pool.retire(addr, tr)
		return nil, err
	}
	m.pool.settle(addr, tr, reserve)
	return parseTileResp(out, m.psk)
}
