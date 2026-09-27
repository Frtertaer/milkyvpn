package carrier

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
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
	// Endpoints lists every entry point (host:port) serving this server; the
	// mosaic carrier spreads one session across all of them. Empty = Addr.
	Endpoints []string
	// Logf receives carrier diagnostics.
	Logf func(string, ...any)
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

func DialVeil(ctx context.Context, cfg ClientConfig) (*kal2.Session, BoundConn, error) {
	to := cfg.timeout()
	dial := cfg.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: to}
		dial = d.DialContext
	}
	raw, err := dial(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("tcp dial: %w", err)
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
		return nil, nil, fmt.Errorf("utls preset: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("tls handshake: %w", err)
	}

	bc := &utlsBoundConn{UConn: uconn}
	bc.binding = utlsExporter(uconn, ucfg)
	sess, err := runClientHandshake(bc, cfg)
	if err != nil {
		_ = bc.Close()
		return nil, nil, err
	}
	_ = bc.SetDeadline(time.Time{})
	return sess, bc, nil
}

// runClientHandshake performs the inner KAL/2 handshake over an established
// carrier byte stream.
func runClientHandshake(bc BoundConn, cfg ClientConfig) (*kal2.Session, error) {
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
