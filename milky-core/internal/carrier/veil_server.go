package carrier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	"golang.org/x/net/http2"
)

// User is one authorized client credential.
type User struct {
	ID  string
	PSK []byte
}

// VeilConfig configures the real-TLS camouflaged listener.
type VeilConfig struct {
	// Domain is our own SNI served by Cert (e.g. kal.example.com).
	Domain string
	// Cert is a real, publicly trusted certificate for Domain. Ignored when
	// GetCertificate is set.
	Cert tls.Certificate
	// GetCertificate optionally supplies the cert per-ClientHello (ACME).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Identity is the Ed25519 KAL/2 server identity key.
	Identity ed25519.PrivateKey
	// Users lists authorized PSKs (looked up per flight).
	Users []User
	// Mux handles every non-KAL request inside TLS: decoy site + drift path.
	Mux http.Handler
	// StealAddr optionally splices connections whose ClientHello carries a
	// foreign SNI to this host:port (REALITY-style fallback). Empty closes.
	StealAddr string
	// ECHKeys enables Encrypted Client Hello: clients present public_name
	// (taken from each key's Config) as the outer SNI while the real SNI stays
	// encrypted — an observer or blocklist sees only the cover name. Load via
	// LoadECHKeys.
	ECHKeys []tls.EncryptedClientHelloKey
	// OnSession is invoked for each established KAL/2 session.
	OnSession func(*kal2.Session)
	// Logf receives operational messages.
	Logf func(format string, args ...any)
	// FirstFlightDeadline caps time to read+validate the inner flight.
	FirstFlightDeadline time.Duration
	// HandshakeTimeout caps the TLS handshake.
	HandshakeTimeout time.Duration
}

func (c *VeilConfig) logf(f string, a ...any) {
	if c.Logf != nil {
		c.Logf(f, a...)
	}
}

// VeilListener accepts TCP, inspects the ClientHello, terminates real TLS for
// our domain, then demultiplexes the inner protocol: KAL flight → session;
// anything else → the HTTP mux (decoy site / drift).
type VeilListener struct {
	cfg    VeilConfig
	ln     net.Listener
	replay *replayCache

	mu        sync.Mutex
	closed    bool
	conns     map[net.Conn]struct{}
	connsByIP map[string]int
	fails     map[string]int // scanner tarpit: repeated probe-profile failures
	mux       http.Handler
}

// maxConnsPerIP bounds concurrent pre-adoption connections per source —
// scanners fan out; real clients use one or two.
const maxConnsPerIP = 16

// remoteIP returns the bare source address of a conn.
func remoteIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

// penalize counts a probe-profile failure for the source and sleeps before
// the caller closes: repeated scanning gets slower each time while ordinary
// cover traffic (real TLS that reaches the mux) never hits these paths.
func (v *VeilListener) penalize(ip string) {
	v.mu.Lock()
	n := v.fails[ip] + 1
	v.fails[ip] = n
	v.mu.Unlock()
	if n > 1 {
		d := time.Duration(n-1) * 700 * time.Millisecond
		if d > 5*time.Second {
			d = 5 * time.Second
		}
		time.Sleep(d)
	}
}

// clearFails drops the source's penalty score once a session authenticates.
func (v *VeilListener) clearFails(ip string) {
	v.mu.Lock()
	delete(v.fails, ip)
	v.mu.Unlock()
}

// NewVeilListener builds a listener for cfg without serving. The mux may be
// attached later via SetMux (needed when the mux itself routes drift requests
// back into the listener).
func NewVeilListener(cfg VeilConfig) *VeilListener {
	return &VeilListener{
		cfg:       cfg,
		replay:    newReplayCache(10*time.Minute, 8192),
		conns:     map[net.Conn]struct{}{},
		connsByIP: map[string]int{},
		fails:     map[string]int{},
		mux:       cfg.Mux,
	}
}

// SetMux replaces the HTTP mux used for non-KAL inner traffic.
func (v *VeilListener) SetMux(h http.Handler) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.mux = h
}

// Serve runs the accept loop until the listener closes or errors.
func (v *VeilListener) Serve(ln net.Listener) error {
	v.ln = ln
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		v.mu.Lock()
		if v.closed {
			v.mu.Unlock()
			_ = c.Close()
			return errors.New("listener closed")
		}
		ip := remoteIP(c)
		if v.connsByIP[ip] >= maxConnsPerIP {
			v.mu.Unlock()
			_ = c.Close()
			continue
		}
		v.conns[c] = struct{}{}
		v.connsByIP[ip]++
		v.mu.Unlock()
		go func() {
			adopted := v.handle(c)
			v.mu.Lock()
			delete(v.conns, c)
			if v.connsByIP[ip]--; v.connsByIP[ip] <= 0 {
				delete(v.connsByIP, ip)
			}
			v.mu.Unlock()
			if !adopted {
				_ = c.Close()
			}
		}()
	}
}

// handle returns true when the connection was adopted by a KAL session (its
// lifecycle is then owned by the session) — the caller must not close it.
func (v *VeilListener) handle(c net.Conn) bool {
	to := v.cfg.HandshakeTimeout
	if to == 0 {
		to = 10 * time.Second
	}
	_ = c.SetDeadline(time.Now().Add(to))

	ip := remoteIP(c)
	peeked, sni, err := PeekClientHelloSNI(c)
	if err != nil {
		v.cfg.logf("veil: non-TLS client %s: %v", c.RemoteAddr(), err)
		v.penalize(ip)
		return false
	}

	// ECH clients carry the config's public_name as outer SNI.
	echPublic := ""
	for _, k := range v.cfg.ECHKeys {
		if n, err := echPublicName(k.Config); err == nil {
			echPublic = n
			break
		}
	}

	switch {
	case equalSNI(sni, v.cfg.Domain),
		echPublic != "" && equalSNI(sni, echPublic):
		// ours — terminate and demux
	case sni != "" && v.cfg.StealAddr != "":
		v.spliceUpstream(c, peeked, v.cfg.StealAddr)
		return false
	case sni != "" && v.cfg.StealAddr == "":
		// Foreign SNI without a steal target: penalize + close quietly.
		v.penalize(ip)
		return false
	default:
		// Empty SNI: terminate too (many real clients do this; the decoy mux
		// will serve the site).
	}

	tlsCfg := &tls.Config{
		Certificates:             []tls.Certificate{v.cfg.Cert},
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"h2", "http/1.1"},
		EncryptedClientHelloKeys: v.cfg.ECHKeys,
	}
	if v.cfg.GetCertificate != nil {
		tlsCfg.Certificates = nil
		tlsCfg.GetCertificate = v.cfg.GetCertificate
	}
	tconn := tls.Server(WrapPrefix(c, peeked), tlsCfg)
	if err := tconn.Handshake(); err != nil {
		v.cfg.logf("veil: TLS handshake fail %s: %v", c.RemoteAddr(), err)
		v.penalize(ip)
		return false
	}
	_ = tconn.SetDeadline(time.Time{})
	bc := &tlsBoundConn{Conn: tconn}
	bc.binding = tlsExporter(tconn)

	// Demux first inner bytes: KAL magic → veil session; else → HTTP mux.
	magic := make([]byte, len(kal2.Magic))
	_ = bc.SetReadDeadline(time.Now().Add(v.firstFlightDeadline()))
	if _, err := io.ReadFull(bc, magic); err != nil {
		// TLS completed but the peer produced no request/first flight — the
		// masscan profile, not a browser.
		v.penalize(ip)
		return false
	}
	if !bytesEqual(magic, kal2.Magic) {
		_ = bc.SetReadDeadline(time.Time{})
		v.serveHTTP(WrapPrefix2(bc, magic))
		return false
	}
	// Rest of fixed flight prefix.
	rest := make([]byte, kal2.FirstFlightMinSize-len(kal2.Magic))
	if _, err := io.ReadFull(bc, rest); err != nil {
		return false
	}
	flightPrefix := append(magic, rest...)
	eph, totalLen, psk, err := v.authFlight(flightPrefix, bc.binding)
	if err != nil {
		// Cover: rewind and hand to the decoy mux.
		_ = bc.SetReadDeadline(time.Time{})
		v.cfg.logf("veil: bad flight %s: %v", c.RemoteAddr(), err)
		v.serveHTTP(WrapPrefix2(bc, flightPrefix))
		return false
	}
	// Consume declared padding.
	if pad := totalLen - kal2.FirstFlightMinSize; pad > 0 {
		if _, err := io.ReadFull(bc, make([]byte, pad)); err != nil {
			return false
		}
	}
	_ = bc.SetReadDeadline(time.Time{})
	if err := v.establishKAL(bc, eph, psk, flightPrefix); err != nil {
		v.cfg.logf("veil: handshake fail %s: %v", c.RemoteAddr(), err)
		return false
	}
	return true
}

// authFlight validates the fixed flight prefix against all users; returns the
// accepted PSK and client ephemeral. Replay rejection included.
func (v *VeilListener) authFlight(prefix []byte, binding kal2.ChannelBinding) (eph []byte, totalLen int, psk []byte, err error) {
	for _, u := range v.cfg.Users {
		e, tl, err2 := kal2.ParseClientFirstFlight(prefix, u.PSK, binding)
		if err2 == nil {
			h := sha256.Sum256(prefix)
			if v.replay.seen(h[:]) {
				return nil, 0, nil, kal2.ErrReplay
			}
			return e, tl, u.PSK, nil
		}
	}
	return nil, 0, nil, kal2.ErrPreauth
}

// establishKAL completes the inner handshake and hands the session to the
// registered OnSession callback. Shared by veil and drift paths.
func (v *VeilListener) establishKAL(bc BoundConn, eph, psk, flightPrefix []byte) error {
	hs, err := kal2.NewServerHandshake(v.cfg.Identity)
	if err != nil {
		return err
	}
	serverFlight, err := hs.Start(eph, bc.Binding())
	if err != nil {
		return err
	}
	if _, err := bc.Write(serverFlight); err != nil {
		return err
	}
	_ = bc.SetReadDeadline(time.Now().Add(v.firstFlightDeadline()))
	auth := make([]byte, kal2.ClientAuthFlightSize)
	if _, err := io.ReadFull(bc, auth); err != nil {
		return err
	}
	sess, err := hs.Finish()
	if err != nil {
		return err
	}
	if err := sess.VerifyClientAuth(psk, serverFlight, auth); err != nil {
		return err
	}
	// Server finished.
	if _, err := bc.Write(sess.FinishedValue("server")); err != nil {
		return err
	}
	_ = bc.SetReadDeadline(time.Time{})
	sess.Attach(bc)
	v.clearFails(remoteIPConn(bc))
	if v.cfg.OnSession != nil {
		v.cfg.OnSession(sess)
	}
	return nil
}

// remoteIPConn unwraps remote addr through the BoundConn wrappers.
func remoteIPConn(bc BoundConn) string {
	if t, ok := bc.(*tlsBoundConn); ok {
		return remoteIP(t.Conn)
	}
	if p, ok := bc.(*prefixBoundConn); ok {
		return remoteIPConn(p.BoundConn)
	}
	return ""
}

func (v *VeilListener) firstFlightDeadline() time.Duration {
	if v.cfg.FirstFlightDeadline != 0 {
		return v.cfg.FirstFlightDeadline
	}
	return 10 * time.Second
}

// serveHTTP hands an inner byte stream (post-TLS) to the HTTP mux: h2 via
// x/net/http2 ServeConn, http/1.1 via the stdlib one-shot listener.
func (v *VeilListener) serveHTTP(c BoundConn) {
	proto := ""
	if tc, ok := boundTLS(c); ok {
		proto = tc.ConnectionState().NegotiatedProtocol
	}
	v.cfg.logf("veil: serveHTTP proto=%q", proto)
	if proto == "h2" {
		h2 := &http2.Server{}
		h2.ServeConn(c, &http2.ServeConnOpts{
			BaseConfig: &http.Server{
				Handler:           v.mux,
				ReadHeaderTimeout: 10 * time.Second,
			},
		})
		return
	}
	done := make(chan struct{})
	var once sync.Once
	l := &oneShotListener{conn: c}
	srv := &http.Server{
		Handler:           v.mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ConnState: func(nc net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				once.Do(func() { close(done) })
			}
		},
	}
	_ = srv.Serve(l)
	<-done
}

// boundTLS unwraps to the underlying *tls.Conn when the BoundConn carries one
// (directly or under a prefix wrapper).
func boundTLS(c BoundConn) (*tls.Conn, bool) {
	if t, ok := c.(*tlsBoundConn); ok {
		return t.Conn, true
	}
	if p, ok := c.(*prefixBoundConn); ok {
		return boundTLS(p.BoundConn)
	}
	return nil, false
}

// spliceUpstream transparently relays the raw TCP connection to target.
func (v *VeilListener) spliceUpstream(c net.Conn, peeked []byte, target string) {
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := up.Write(peeked); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// tlsBoundConn adapts *tls.Conn to BoundConn.
type tlsBoundConn struct {
	*tls.Conn
	binding kal2.ChannelBinding
}

func (t *tlsBoundConn) Binding() kal2.ChannelBinding { return t.binding }

// tlsExporter extracts the RFC 9266 exporter when the TLS stack exposes it.
func tlsExporter(c *tls.Conn) kal2.ChannelBinding {
	type exporter interface {
		ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
	}
	st := c.ConnectionState()
	if e, ok := any(st).(exporter); ok {
		b, err := e.ExportKeyingMaterial("mxs-bind", nil, 32)
		if err == nil {
			return b
		}
	}
	return nil
}

// WrapPrefix2 wraps a BoundConn with consumed prefix bytes.
func WrapPrefix2(c BoundConn, prefix []byte) *prefixBoundConn {
	return &prefixBoundConn{BoundConn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

type prefixBoundConn struct {
	BoundConn
	r io.Reader
}

func (p *prefixBoundConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// oneShotListener yields one connection then EOF.
type oneShotListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (o *oneShotListener) Accept() (net.Conn, error) {
	var c net.Conn
	o.once.Do(func() { c = o.conn })
	if c != nil {
		return c, nil
	}
	return nil, io.EOF
}

func (o *oneShotListener) Close() error { return nil }

func (o *oneShotListener) Addr() net.Addr { return o.conn.LocalAddr() }

// replayCache bounds first-flight replay detection.
type replayCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	m   map[[32]byte]time.Time
}

func newReplayCache(ttl time.Duration, max int) *replayCache {
	return &replayCache{ttl: ttl, max: max, m: map[[32]byte]time.Time{}}
}

func (r *replayCache) seen(h []byte) bool {
	var k [32]byte
	copy(k[:], h)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if len(r.m) > r.max/2 {
		for kk, t := range r.m {
			if now.Sub(t) > r.ttl {
				delete(r.m, kk)
			}
		}
	}
	if _, ok := r.m[k]; ok {
		return true
	}
	r.m[k] = now
	return false
}

func equalSNI(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
