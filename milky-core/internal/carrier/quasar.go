package carrier

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"crypto/sha256"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/hkdf"
	"io"
)

// Quasar carries a KAL/2 session over UDP using a KCP reliable stream. It is
// the high-throughput carrier for paths where inbound TCP is strangled:
// retransmissions ride UDP, so the flow inherits UDP's loss profile instead
// of TCP's. Each datagram is salsa20-scrambled (key derived from the user
// PSK) so KCP headers never appear on the wire.
//
// Tuning targets a ~150 ms RTT transcontinental path: aggressive resend,
// no congestion-window throttling (KCP NC off), large windows to cover the
// bandwidth-delay product.

// QuasarConfig tunes the UDP carrier.
type QuasarConfig struct {
	// DataShards/ParityShards enable kcp-go's Reed-Solomon FEC when >0.
	// (0,0) disables it; (10,3) spends 30% overhead to erase most single
	// bursts without retransmit delay.
	DataShards   int
	ParityShards int
	// SndWnd/RcvWnd are KCP window sizes in segments; 0 = tuned default.
	// The receive window also throttles the peer's offered rate to ~wnd*mtu/RTT.
	SndWnd, RcvWnd int
	// Resend is the dup-ack fast-retransmit threshold (KCP resend): 0 =
	// retransmit only on RTO (~RTT+ tail), N = resend after N duplicate
	// ACKs. Ordered delivery makes every byte wait on the oldest lost
	// segment, so >0 cuts head-of-line delay under loss — at the cost of
	// extra wire bytes on reordering-heavy paths.
	Resend int
	// RateLimit caps the packet output rate in bytes/s. Policed links
	// collapse delivery when offered far past their budget — measured
	// ~175 Mbit offered → ~9% delivered vs ~73 Mbit offered → ~62%.
	// Capping near the link's sweet spot beats flooding it. 0 = unlimited.
	RateLimit int
	// WireKey scrambles every datagram (salsa20). nil = plaintext KCP.
	WireKey []byte
}

func (c *QuasarConfig) block() kcp.BlockCrypt {
	if len(c.WireKey) == 0 {
		return nil
	}
	b, err := kcp.NewSalsa20BlockCrypt(c.WireKey)
	if err != nil {
		return nil
	}
	return b
}

// QuasarWireKey derives the datagram scrambling key from the server's public
// identity (known to both ends, identical for every user) so a passive
// observer sees uniform random datagrams.
func QuasarWireKey(serverPub []byte) []byte {
	r := hkdf.New(sha256.New, serverPub, nil, []byte("mxs/quasar-wire"))
	k := make([]byte, 32)
	_, _ = io.ReadFull(r, k)
	return k
}

// tuneKCP applies the fast-loss profile shared by client and listener.
// rcvWnd caps the peer's offered rate: a path whose policer caps inbound UDP
// around ~40 Mbit/s drops everything beyond it, so we advertise a receive
// window just under the cap (~wnd*mtu/RTT) instead of offering 60+ Mbit and
// losing ~40%. Returns the session for chaining.
func tuneKCP(s *kcp.UDPSession, sndWnd, rcvWnd, resend, rateLimit int) {
	if sndWnd <= 0 {
		sndWnd = 16384
	}
	if rcvWnd <= 0 {
		rcvWnd = 16384
	}
	s.SetStreamMode(true) // byte stream, no per-write packetization
	s.SetNoDelay(1, 2, resend, 1) // nodelay, 2ms flush, NC off
	s.SetWindowSize(sndWnd, rcvWnd)
	s.SetMtu(1400)
	s.SetACKNoDelay(true)
	_ = s.SetWriteBuffer(16 << 20)
	_ = s.SetReadBuffer(16 << 20)
	if rateLimit > 0 {
		s.SetRateLimit(uint32(rateLimit))
	}
}

// quasarBound adapts *kcp.UDPSession to BoundConn.
type quasarBound struct {
	*kcp.UDPSession
}

func (q *quasarBound) Binding() kal2.ChannelBinding { return nil }

// DialQuasar opens a KAL/2 session over UDP/KCP. KCP needs no connect
// handshake — the client first flight leaves in the first datagram, so the
// inner handshake costs exactly 2 RTT end to end.
func DialQuasar(ctx context.Context, cfg ClientConfig, qc *QuasarConfig) (*kal2.Session, BoundConn, error) {
	to := cfg.timeout()
	if qc == nil {
		qc = &QuasarConfig{}
	}
	if qc.WireKey == nil && len(cfg.ServerPub) > 0 {
		c2 := *qc
		c2.WireKey = QuasarWireKey(cfg.ServerPub)
		qc = &c2
	}
	type res struct {
		s   *kcp.UDPSession
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := kcp.DialWithOptions(cfg.Addr, qc.block(), qc.DataShards, qc.ParityShards)
		ch <- res{s, err}
	}()
	var sess *kcp.UDPSession
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, nil, fmt.Errorf("quasar dial: %w", r.err)
		}
		sess = r.s
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-time.After(to):
		return nil, nil, fmt.Errorf("quasar dial timeout")
	}
	// Small advertised receive window: paces the server's offered rate to
	// just under the path policer instead of offering 2x and losing ~40%.
	tuneKCP(sess, qc.SndWnd, qc.RcvWnd, qc.Resend, qc.RateLimit)
	_ = sess.SetDeadline(time.Now().Add(to))
	bc := &quasarBound{UDPSession: sess}
	inner, err := runClientHandshake(bc, cfg)
	if err != nil {
		_ = bc.Close()
		return nil, nil, err
	}
	_ = bc.SetDeadline(time.Time{})
	return inner, bc, nil
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

// QuasarListener accepts KCP sessions on a UDP socket and runs the same
// inner-handshake path as the veil listener (shared via the bound
// VeilListener's authFlight/establishKAL).
type QuasarListener struct {
	v     *VeilListener
	qc    *QuasarConfig
	ln    *kcp.Listener
	mu    sync.Mutex
	conns map[*kcp.UDPSession]struct{}
}

// NewQuasarListener binds a UDP socket; v supplies users/replay/OnSession.
func NewQuasarListener(v *VeilListener, qc *QuasarConfig, laddr string) (*QuasarListener, error) {
	if qc == nil {
		qc = &QuasarConfig{}
	}
	ln, err := kcp.ListenWithOptions(laddr, qc.block(), qc.DataShards, qc.ParityShards)
	if err != nil {
		return nil, err
	}
	return &QuasarListener{v: v, qc: qc, ln: ln, conns: map[*kcp.UDPSession]struct{}{}}, nil
}

// Addr returns the bound UDP address.
func (q *QuasarListener) Addr() net.Addr { return q.ln.Addr() }

// Serve accepts KCP sessions until the listener fails.
func (q *QuasarListener) Serve() error {
	for {
		s, err := q.ln.AcceptKCP()
		if err != nil {
			return err
		}
		q.mu.Lock()
		q.conns[s] = struct{}{}
		q.mu.Unlock()
		go func() {
			adopted := q.handle(s)
			q.mu.Lock()
			delete(q.conns, s)
			q.mu.Unlock()
			if !adopted {
				_ = s.Close()
			}
		}()
	}
}

func (q *QuasarListener) handle(s *kcp.UDPSession) bool {
	to := q.v.cfg.HandshakeTimeout
	if to == 0 {
		to = 10 * time.Second
	}
	tuneKCP(s, q.qc.SndWnd, q.qc.RcvWnd, q.qc.Resend, q.qc.RateLimit)
	// Deadline covers only the auth window — it must be cleared before the
	// session is adopted, or every read/write starts failing once it expires.
	_ = s.SetReadDeadline(time.Now().Add(to))
	bc := &quasarBound{UDPSession: s}

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
	eph, totalLen, psk, _, err := q.v.authFlight(flightPrefix, nil)
	if err != nil {
		return false
	}
	if pad := totalLen - kal2.FirstFlightMinSize; pad > 0 {
		if _, err := io.ReadFull(bc, make([]byte, pad)); err != nil {
			return false
		}
	}
	_ = s.SetReadDeadline(time.Time{})
	if err := q.v.establishKAL(bc, eph, psk, nil); err != nil {
		q.v.cfg.logf("quasar: handshake fail %s: %v", s.RemoteAddr(), err)
		return false
	}
	return true
}

// Close stops the listener.
func (q *QuasarListener) Close() error { return q.ln.Close() }
