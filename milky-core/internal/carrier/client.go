package carrier

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"net"
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
	// Fingerprint selects the ClientHello shape ("chrome" default).
	Fingerprint string
	// DialContext overrides TCP dial (e.g. through a proxy CONNECT).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// InsecureSkipVerify disables TLS chain verification (tests only).
	InsecureSkipVerify bool
	// ECHConfigList enables Encrypted Client Hello (draft-ietf-tls-esni): the
	// real SNI travels encrypted; the outer ClientHello shows only the
	// config's public_name — defeats SNI-based DPI blocking entirely.
	// Serialized ECHConfigList (base64 in links/configs).
	ECHConfigList []byte
	// Deadline for connect+handshake.
	HandshakeTimeout time.Duration
	// FirstFlightPadLen: -1 random, else explicit padding length.
	FirstFlightPadLen int
}

func (c *ClientConfig) timeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 15 * time.Second
}

// DialVeil connects to a veil listener: real TLS handshake with a Chrome-grade
// ClientHello, then the KAL/2 inner handshake inside.
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

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		spec, _ = utls.UTLSIdToSpec(utls.HelloGolang)
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:                     cfg.SNI,
		MinVersion:                     utls.VersionTLS13,
		InsecureSkipVerify:             cfg.InsecureSkipVerify,
		NextProtos:                     []string{"h2", "http/1.1"},
		EncryptedClientHelloConfigList: cfg.ECHConfigList,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("utls preset: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("tls handshake: %w", err)
	}

	bc := &utlsBoundConn{UConn: uconn}
	bc.binding = utlsExporter(uconn)
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

// utlsExporter extracts the RFC 9266 exporter when the stack exposes it.
func utlsExporter(c *utls.UConn) kal2.ChannelBinding {
	st := c.ConnectionState()
	type exporter interface {
		ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
	}
	if e, ok := any(st).(exporter); ok {
		if b, err := e.ExportKeyingMaterial("mxs-bind", nil, 32); err == nil {
			return b
		}
	}
	// Fall back to TLS-Unique (TLS<1.3) if present.
	if len(st.TLSUnique) > 0 {
		return st.TLSUnique
	}
	return nil
}

var _ = tls.VersionTLS13 // keep tls import for dialers that need it
