package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	quic "github.com/quic-go/quic-go"
)

// Quic2 carries a KAL/2 session over real QUIC version 2 (RFC 9369). It is
// the UDP carrier for networks whose censorship parses QUIC specifically:
// TSPU-class QUIC-SNI filters only understand v1 Initials — a v2 handshake
// is never decoded, so no SNI can be extracted and no 4-tuple drop rule is
// installed. Unlike quasar (KCP with a distinctive header), QUICv2 is the
// same protocol family browsers use for HTTP/3, so the flow also blends
// with ordinary web traffic at the transport level.
//
// The QUIC TLS leg authenticates the server certificate exactly like veil
// (CA chain, SPKI pin, or opt-out); the inner KAL/2 flight additionally
// binds to the TLS 1.3 exporter, so a middlebox cannot relay the session.
// QUIC connection migration is inherited for free: the carrier survives
// client IP changes without a redial.

const quic2ALPN = "kal2"

// quic2Bound adapts a QUIC stream (+ its owning conn/socket) to BoundConn.
type quic2Bound struct {
	stream  *quic.Stream
	conn    *quic.Conn
	pc      net.PacketConn
	binding kal2.ChannelBinding
}

func (b *quic2Bound) Read(p []byte) (int, error)         { return b.stream.Read(p) }
func (b *quic2Bound) Write(p []byte) (int, error)        { return b.stream.Write(p) }
func (b *quic2Bound) LocalAddr() net.Addr                { return b.conn.LocalAddr() }
func (b *quic2Bound) RemoteAddr() net.Addr               { return b.conn.RemoteAddr() }
func (b *quic2Bound) SetDeadline(t time.Time) error      { return b.stream.SetDeadline(t) }
func (b *quic2Bound) SetReadDeadline(t time.Time) error  { return b.stream.SetReadDeadline(t) }
func (b *quic2Bound) SetWriteDeadline(t time.Time) error { return b.stream.SetWriteDeadline(t) }
func (b *quic2Bound) Binding() kal2.ChannelBinding       { return b.binding }

func (b *quic2Bound) Close() error {
	_ = b.stream.Close()
	_ = b.conn.CloseWithError(0, "")
	if b.pc != nil {
		_ = b.pc.Close()
	}
	return nil
}

// quic2TLSClient builds the QUIC-layer TLS config — the same auth policy as
// the veil TLS leg: CA chain for the server SNI, SPKI pin when pinned, or
// explicit opt-out.
func quic2TLSClient(cfg ClientConfig) *tls.Config {
	tc := &tls.Config{
		ServerName:         cfg.SNI,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{quic2ALPN},
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if len(cfg.PinSHA256) > 0 {
		pins := cfg.PinSHA256
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifySPKIPin(raw, pins)
		}
	}
	return tc
}

// quic2Exporter pulls the RFC 9266 exporter out of the QUIC TLS state —
// same label as veil so the inner flight binds to this transport leg too.
func quic2Exporter(c *quic.Conn) kal2.ChannelBinding {
	st := c.ConnectionState().TLS
	b, err := st.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil
	}
	return b
}

// DialQuic2 opens a KAL/2 session over QUIC v2: UDP socket → v2-only
// handshake → first bidirectional stream → inner KAL/2 handshake on the
// stream (2-RTT total like quasar, since QUIC needs no extra handshake on
// top of its own).
func DialQuic2(ctx context.Context, cfg ClientConfig) (*kal2.Session, BoundConn, error) {
	to := cfg.timeout()
	udpaddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("quic2 resolve: %w", err)
	}
	var pc net.PacketConn
	if cfg.DialControl != nil {
		lc := net.ListenConfig{Control: cfg.DialControl}
		pc, err = lc.ListenPacket(ctx, "udp", ":0")
	} else {
		pc, err = net.ListenUDP("udp", nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("quic2 socket: %w", err)
	}
	fail := func(err error) (*kal2.Session, BoundConn, error) {
		_ = pc.Close()
		return nil, nil, err
	}

	dctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	conn, err := quic.Dial(dctx, pc, udpaddr, quic2TLSClient(cfg), &quic.Config{
		Versions: []quic.Version{quic.Version2},
	})
	if err != nil {
		return fail(fmt.Errorf("quic2 dial: %w", err))
	}
	stream, err := conn.OpenStreamSync(dctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return fail(fmt.Errorf("quic2 stream: %w", err))
	}
	bc := &quic2Bound{stream: stream, conn: conn, pc: pc, binding: quic2Exporter(conn)}
	_ = bc.SetDeadline(time.Now().Add(to))
	inner, err := runClientHandshake(bc, cfg)
	if err != nil {
		_ = bc.Close()
		return nil, nil, handshakeStageError{err}
	}
	_ = bc.SetDeadline(time.Time{})
	return inner, bc, nil
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

// Quic2Listener accepts QUIC v2 connections, takes the first bidirectional
// stream of each, and runs the same inner-handshake path as the other
// carriers (authFlight + establishKAL on the bound stream).
type Quic2Listener struct {
	v  *VeilListener
	ln *quic.Listener
}

// NewQuic2Listener binds a UDP socket for QUIC v2 only. tlsCfg carries the
// same cert material as the veil listener; the veil v supplies users,
// replay protection and OnSession.
func NewQuic2Listener(v *VeilListener, tlsCfg *tls.Config, laddr string) (*Quic2Listener, error) {
	tc := tlsCfg.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{quic2ALPN}
	ln, err := quic.ListenAddr(laddr, tc, &quic.Config{
		Versions: []quic.Version{quic.Version2},
	})
	if err != nil {
		return nil, err
	}
	return &Quic2Listener{v: v, ln: ln}, nil
}

// Addr returns the bound UDP address.
func (q *Quic2Listener) Addr() net.Addr { return q.ln.Addr() }

// Serve accepts QUIC connections until the listener fails.
func (q *Quic2Listener) Serve() error {
	for {
		conn, err := q.ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go q.serveConn(conn)
	}
}

func (q *Quic2Listener) serveConn(conn *quic.Conn) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return
	}
	bc := &quic2Bound{stream: stream, conn: conn, binding: quic2Exporter(conn)}
	if !q.handle(bc) {
		_ = bc.Close()
	}
}

func (q *Quic2Listener) handle(bc BoundConn) bool {
	to := q.v.cfg.HandshakeTimeout
	if to == 0 {
		to = 10 * time.Second
	}
	_ = bc.SetReadDeadline(time.Now().Add(to))

	magic := make([]byte, len(kal2.Magic))
	if _, err := io.ReadFull(bc, magic); err != nil {
		return false
	}
	if !bytesEqual(magic, kal2.Magic) {
		return false
	}
	rest := make([]byte, kal2.FirstFlightMinSize-len(kal2.Magic))
	if _, err := io.ReadFull(bc, rest); err != nil {
		return false
	}
	flightPrefix := append(magic, rest...)
	eph, totalLen, user, _, err := q.v.authFlight(flightPrefix, bc.Binding())
	if err != nil {
		return false
	}
	if pad := totalLen - kal2.FirstFlightMinSize; pad > 0 {
		if _, err := io.ReadFull(bc, make([]byte, pad)); err != nil {
			return false
		}
	}
	_ = bc.SetReadDeadline(time.Time{})
	if err := q.v.establishKAL(bc, eph, user, bc.Binding(), "quic2"); err != nil {
		q.v.cfg.logf("quic2: handshake fail %s: %v", bc.RemoteAddr(), err)
		return false
	}
	return true
}

// Close stops the listener.
func (q *Quic2Listener) Close() error { return q.ln.Close() }
