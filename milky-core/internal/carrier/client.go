package carrier

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	utls "github.com/refraction-networking/utls"
)

// ClientConfig is a KAL/2 client endpoint.
type ClientConfig struct {
	// Addr is host:port of the server.
	Addr string
	// SNI is the TLS server name (our domain).
	SNI string
	// ServerPub is the pinned Ed25519 KAL/2 identity key (raw 32 bytes).
	ServerPub ed25519.PublicKey
	// PSK is the client credential.
	PSK []byte
	// Fingerprint selects the ClientHello shape. "chrome" (default/empty)
	// rotates across modern Chrome builds each dial so successive sessions
	// don't share a byte-identical hello (harder to signature). A fixed
	// utls ID string or "ff"/"safari" pins one shape instead.
	Fingerprint string
	// DialContext overrides TCP dial (e.g. through a proxy CONNECT).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialControl hooks socket creation for the built-in dialers — same
	// signature as net.Dialer.Control / net.ListenConfig.Control. Used by
	// TUN mode to pin carrier sockets to the physical egress device
	// (SO_BINDTODEVICE / IP_BOUND_IF) so they bypass the tunnel without
	// bypass routes in the FIB. Ignored when DialContext is set (that
	// dialer owns its sockets). For UDP carriers it binds the packet
	// socket before the session is created.
	DialControl func(network, address string, c syscall.RawConn) error
	// InsecureSkipVerify disables TLS chain verification (tests only).
	InsecureSkipVerify bool
	// PinSHA256 lists accepted SHA-256 hashes of the server leaf's
	// SubjectPublicKeyInfo. When set it replaces CA-chain verification, so
	// devices with stale root stores still authenticate the outer TLS.
	PinSHA256 [][]byte
	// ECHConfigList enables Encrypted Client Hello (draft-ietf-tls-esni): the
	// real SNI travels encrypted; the outer ClientHello shows only the
	// config's public_name — defeats SNI-based DPI blocking entirely.
	// Serialized ECHConfigList (base64 in links/configs).
	ECHConfigList []byte
	// Deadline for connect+handshake.
	HandshakeTimeout time.Duration
	// FirstFlightPadLen: -1 random, else explicit padding length.
	FirstFlightPadLen int
	// Resume, when non-nil, makes the dialer run a v2.1 resumption flight
	// (KLDO-rs-) on the fresh transport instead of a full handshake — the
	// frozen session keeps its streams across the carrier swap.
	Resume *kal2.ResumeState
	// Endpoints lists every entry point (host:port) serving this server; the
	// mosaic carrier spreads one session across all of them. Empty = Addr.
	Endpoints []string
	// AllowUnboundFallback permits one redial with an empty channel binding
	// when the KAL/2 handshake fails while bound (SPEC: "носитель без
	// binding → binding=∅"). Needed against servers that ignore the TLS
	// exporter. Off by default: a stripping middlebox could otherwise force
	// the session unbound — enable only for compatibility with known peers.
	AllowUnboundFallback bool
	// Front is an optional relay URL ("https://host[:port][/base]") the
	// HTTP-shaped carriers dial INSTEAD of Addr: a dumb proxy (serverless
	// function, CDN worker) that forwards requests to the server's plain
	// front listener. The TLS leg then belongs to the front — its own
	// domain, its own certificate — so SNI is the front host and
	// PinSHA256/ECH are bypassed (they authenticate OUR server leaf, which
	// the front leg never presents); the inner KAL/2 handshake still
	// authenticates the server end-to-end. Carriers that keep a request
	// open in both directions (raw drift POST) only work through fronts
	// that stream bodies; mosaic (short POSTs) and the WS drift shape
	// survive buffering fronts like cloud functions.
	Front string
	// Logf receives carrier diagnostics.
	Logf func(string, ...any)
}

// frontEndpoint is the parsed Front relay: where to dial and what the TLS
// leg and request URLs should look like on the fronted hop.
type frontEndpoint struct {
	addr string // host:port to dial
	sni  string // front domain — TLS server name and URL host
	base string // optional path prefix the relay expects ("/x"), "" = root
}

// front parses cfg.Front; nil when unset. Schemes http/https/wss/ws are
// accepted (ws* are aliases — the transport still negotiates the leg).
func (c *ClientConfig) front() *frontEndpoint {
	if c.Front == "" {
		return nil
	}
	u, err := url.Parse(c.Front)
	if err != nil || u.Host == "" {
		return nil
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	return &frontEndpoint{
		addr: host,
		sni:  u.Hostname(),
		base: strings.TrimSuffix(u.EscapedPath(), "/"),
	}
}

// dialAddr returns where the carrier's TCP leg connects — the front relay
// when Front is set, else the server entry Addr.
func (c *ClientConfig) dialAddr() string {
	if fe := c.front(); fe != nil {
		return fe.addr
	}
	return c.Addr
}

// frontPathHeader carries the logical request path on a fronted leg.
// Invoke gateways (Yandex Functions, some edge setups) reject any path
// after the function id, so the path cannot ride in the URL — relays read
// it from this header instead.
const frontPathHeader = "X-Milky-Path"

// requestURL builds the request URL for an HTTP-shaped carrier. Fronted
// legs stay at the relay root+base — gateways that cannot forward
// arbitrary URL paths would reject anything deeper; the real path rides
// in frontPathHeader (setFrontPath).
func (c *ClientConfig) requestURL(path string) string {
	if fe := c.front(); fe != nil {
		return "https://" + fe.sni + fe.base + "/"
	}
	return "https://" + c.SNI + path
}

// setFrontPath attaches the logical carrier path to a fronted request.
func (c *ClientConfig) setFrontPath(h http.Header, path string) {
	if c.front() != nil {
		h.Set(frontPathHeader, path)
	}
}

// legTLS returns the utls config for the carrier's TLS leg. Fronted legs
// skip PinSHA256/ECH: those authenticate OUR server leaf and would make a
// relay-served certificate fail verification.
func (c *ClientConfig) legTLS(alpn ...string) *utls.Config {
	if fe := c.front(); fe != nil {
		return &utls.Config{
			ServerName:         fe.sni,
			MinVersion:         utls.VersionTLS13,
			InsecureSkipVerify: c.InsecureSkipVerify,
			NextProtos:         alpn,
		}
	}
	return c.utlsConfig(alpn...)
}

func (c *ClientConfig) logger() func(string, ...any) {
	if c.Logf != nil {
		return c.Logf
	}
	return func(string, ...any) {}
}

// utlsConfig is the outer TLS client config shared by every carrier: TLS 1.3
// only, and either CA verification, SPKI pin verification, or (tests / legacy
// opt-in) none.
func (c *ClientConfig) utlsConfig(alpn ...string) *utls.Config {
	uc := &utls.Config{
		ServerName:         c.SNI,
		MinVersion:         utls.VersionTLS13,
		InsecureSkipVerify: c.InsecureSkipVerify,
		NextProtos:         alpn,
	}
	if len(c.PinSHA256) > 0 {
		pins := c.PinSHA256
		uc.InsecureSkipVerify = true
		uc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifySPKIPin(raw, pins)
		}
	}
	return uc
}

// verifySPKIPin accepts the chain when the leaf's SPKI hash is pinned.
func verifySPKIPin(rawCerts [][]byte, pins [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("tls: no server certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	for _, p := range pins {
		if subtle.ConstantTimeCompare(sum[:], p) == 1 {
			return nil
		}
	}
	return errors.New("tls: server key does not match pin")
}

// SPKIPin returns the pin value for a certificate (SHA-256 of its SPKI).
func SPKIPin(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

func (c *ClientConfig) timeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 15 * time.Second
}

// DialVeil connects to a veil listener: real TLS handshake with a Chrome-grade
// ClientHello, then the KAL/2 inner handshake inside.
// helloRotator picks a different real Chrome build per dial: every session's
// outer ClientHello differs in extension order/values, so a DPI signature
// built on one capture doesn't match the next.
var helloRotator = []utls.ClientHelloID{
	utls.HelloChrome_120_PQ,
	utls.HelloChrome_131,
	utls.HelloChrome_133,
	utls.HelloChrome_115_PQ,
	utls.HelloChrome_Auto,
}

var helloRand = func() int { return rand.IntN(len(helloRotator)) }

func pickHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "", "chrome", "auto":
		return helloRotator[helloRand()]
	case "ff", "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	default:
		if id, ok := mapHelloID(fp); ok {
			return id
		}
		return utls.HelloChrome_Auto
	}
}

func mapHelloID(name string) (utls.ClientHelloID, bool) {
	for _, id := range helloRotator {
		if strings.EqualFold(id.Str(), name) || strings.EqualFold(id.Client, name) {
			return id, true
		}
	}
	return utls.HelloCustom, false
}

// handshakeStageError marks a failure after the outer TLS session came up —
// i.e. inside the KAL/2 handshake itself. Only these justify an unbound retry.
type handshakeStageError struct{ err error }

func (e handshakeStageError) Error() string { return e.err.Error() }
func (e handshakeStageError) Unwrap() error { return e.err }

// IsHandshakeStage reports whether err came from after the carrier transport
// was established (inner KAL/2 flight, resume, or a server in-protocol
// reply). Such errors prove the entry point is reachable — a dial sweep that
// never reaches this stage signals a blocked entry, not a bad config.
func IsHandshakeStage(err error) bool {
	var hse handshakeStageError
	return errors.As(err, &hse)
}

// MarkHandshakeStage wraps err as an inner-stage failure — used by tests and
// any future carrier whose transport-established boundary isn't covered by
// the wrappers above.
func MarkHandshakeStage(err error) error { return handshakeStageError{err} }

func DialVeil(ctx context.Context, cfg ClientConfig) (*kal2.Session, BoundConn, error) {
	sess, bc, bound, err := dialVeilOnce(ctx, cfg, false)
	var hse handshakeStageError
	if err != nil && bound && cfg.AllowUnboundFallback && errors.As(err, &hse) {
		cfg.logger()("binding-keyed handshake failed; retrying unbound: %v", err)
		sess, bc, _, err = dialVeilOnce(ctx, cfg, true)
	}
	return sess, bc, err
}

func dialVeilOnce(ctx context.Context, cfg ClientConfig, forceUnbound bool) (*kal2.Session, BoundConn, bool, error) {
	to := cfg.timeout()
	dial := cfg.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: to, Control: cfg.DialControl}
		dial = d.DialContext
	}
	raw, err := dial(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tcp dial: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(to))

	helloID := pickHelloID(cfg.Fingerprint)
	if len(cfg.ECHConfigList) > 0 && helloID == utls.HelloChrome_115_PQ {
		// The 115 preset's pre-standard Kyber share yields an outer hello
		// that ECH servers reject as malformed.
		helloID = utls.HelloChrome_133
	}
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		spec, _ = utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	}
	ucfg := cfg.utlsConfig("h2", "http/1.1")
	ucfg.EncryptedClientHelloConfigList = cfg.ECHConfigList
	uconn := utls.UClient(raw, ucfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return nil, nil, false, fmt.Errorf("utls preset: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, nil, false, fmt.Errorf("tls handshake: %w", err)
	}

	bc := &utlsBoundConn{UConn: uconn}
	if !forceUnbound {
		bc.binding = utlsExporter(uconn, ucfg)
	}
	sess, err := runClientHandshake(bc, cfg)
	if err != nil {
		_ = bc.Close()
		return nil, nil, bc.binding != nil, handshakeStageError{err}
	}
	_ = bc.SetDeadline(time.Time{})
	return sess, bc, bc.binding != nil, nil
}

// runClientHandshake performs the inner KAL/2 handshake over an established
// carrier byte stream — or, when cfg.Resume is set, a resumption flight
// re-attaching the frozen session.
func runClientHandshake(bc BoundConn, cfg ClientConfig) (*kal2.Session, error) {
	if cfg.Resume != nil {
		return runResumeHandshake(bc, cfg)
	}
	hs, err := kal2.NewClientHandshake(cfg.ServerPub, cfg.PSK, bc.Binding())
	if err != nil {
		return nil, err
	}
	flight, err := hs.FirstFlight(cfg.FirstFlightPadLen)
	if err != nil {
		return nil, err
	}
	if _, err := bc.Write(flight); err != nil {
		return nil, err
	}
	serverFlight := make([]byte, kal2.ServerFlightSize)
	if _, err := io.ReadFull(bc, serverFlight); err != nil {
		return nil, fmt.Errorf("server flight: %w", err)
	}
	sess, err := hs.ServerFlight(serverFlight)
	if err != nil {
		return nil, err
	}
	if _, err := bc.Write(sess.ClientAuthFlight(cfg.PSK, serverFlight)); err != nil {
		return nil, err
	}
	fin := make([]byte, kal2.FinishedSize)
	if _, err := io.ReadFull(bc, fin); err != nil {
		return nil, fmt.Errorf("server finished: %w", err)
	}
	if subtleCompare(fin, sess.FinishedValue("server")) != 1 {
		return nil, kal2.ErrHandshake
	}
	sess.Attach(bc)
	return sess, nil
}

// runResumeHandshake drives a v2.1 resumption: KLDO-rs- flight, server
// flight + checkpoint trailer, then ResumeAttach — the frozen session's
// streams migrate onto this transport.
func runResumeHandshake(bc BoundConn, cfg ClientConfig) (*kal2.Session, error) {
	s := cfg.Resume.Session
	cr, err := cfg.Resume.BeginResumeFlight(bc, bc.Binding())
	if err != nil {
		return nil, err
	}
	head := make([]byte, kal2.ServerFlightSize)
	if _, err := io.ReadFull(bc, head); err != nil {
		return nil, fmt.Errorf("resume server flight: %w", err)
	}
	if err := cr.FinishResume(s, cfg.ServerPub, head, bc.Binding()); err != nil {
		return nil, err
	}
	// Server checkpoint trailer: cpLen(2,LE) || checkpoint.
	var clb [2]byte
	if _, err := io.ReadFull(bc, clb[:]); err != nil {
		return nil, fmt.Errorf("resume checkpoint: %w", err)
	}
	cpb := make([]byte, binary.LittleEndian.Uint16(clb[:]))
	if _, err := io.ReadFull(bc, cpb); err != nil {
		return nil, fmt.Errorf("resume checkpoint: %w", err)
	}
	cp, err := kal2.DecodeCheckpoint(cpb)
	if err != nil {
		return nil, err
	}
	if err := s.ResumeAttach(bc, cp); err != nil {
		return nil, err
	}
	return s, nil
}

func subtleCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	if d == 0 {
		return 1
	}
	return 0
}

// utlsBoundConn adapts *utls.UConn to BoundConn.
type utlsBoundConn struct {
	*utls.UConn
	binding kal2.ChannelBinding
}

func (u *utlsBoundConn) Binding() kal2.ChannelBinding { return u.binding }

// exporterLabel is the TLS exporter label both carrier ends bind KAL/2 to.
const exporterLabel = "mxs-bind"

// utlsExporter extracts the RFC 9266 exporter (TLS 1.3). Browser presets
// carry renegotiation_info, which makes uTLS enable renegotiation and refuse
// to export keying material; TLS 1.3 has no renegotiation, so it is switched
// off once the handshake has settled on 1.3 (the hello bytes are unchanged).
func utlsExporter(c *utls.UConn, cfg *utls.Config) kal2.ChannelBinding {
	if c.ConnectionState().Version != utls.VersionTLS13 {
		return nil
	}
	cfg.Renegotiation = utls.RenegotiateNever
	st := c.ConnectionState()
	b, err := st.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil
	}
	return b
}

var _ = tls.VersionTLS13 // keep tls import for dialers that need it
