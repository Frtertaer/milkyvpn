package carrier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// DriftPath is the secret URL path for the HTTP-shaped carrier (config).
const DefaultDriftPath = "/api/v2/stream"

// driftPathToken derives the keyed path suffix for a user's drift endpoint:
// hex(HMAC-SHA256(psk, "mxs/drift-path")[:8]). The endpoint is
// <base>/<token> — anything else is indistinguishable from an unknown URL on
// the decoy site, so the entry point can't be found by path enumeration.
func driftPathToken(psk []byte) string {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte("mxs/drift-path"))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

// DriftHandler returns an http.Handler that authenticates a KAL/2 session
// carried inside the request body stream. It is mounted by the server mux at
// <base> and <base>/; only requests to the HMAC-keyed path proceed — every
// other request gets the decoy's plain 404, byte-identical to an unknown URL.
// The handshake bytes flow inside the POST body (client→server) and the
// streamed response (server→client): to proxies and DPI it is an ordinary
// long-running API stream.
func (v *VeilListener) DriftHandler(base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok := false
		for _, u := range v.cfg.Users {
			want := base + "/" + driftPathToken(u.PSK)
			if subtle.ConstantTimeCompare([]byte(r.URL.Path), []byte(want)) == 1 {
				ok = true
				break
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		var bc BoundConn
		isWS := headerContains(r.Header, "Connection", "upgrade") &&
			headerContains(r.Header, "Upgrade", "websocket")
		if !isWS && (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch) {
			http.NotFound(w, r)
			return
		}
		if isWS {
			// CDN-shaped drift: kal2 stream inside binary WebSocket frames.
			// Survives CDN/proxy request-body buffering that breaks raw POST.
			wc := v.wsAccept(w, r)
			if wc == nil {
				return
			}
			defer wc.Close()
			bc = wc
		} else {
			bc = newDriftServerConn(w, r)
		}
		fail := func(code int) {
			if isWS {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"bad request"}`))
		}
		magic := make([]byte, len(kal2.Magic))
		if _, err := io.ReadFull(bc, magic); err != nil {
			fail(http.StatusNotFound)
			return
		}
		if !bytesEqual(magic, kal2.Magic) {
			// Rewind isn't possible on a consumed request body — respond like
			// an unknown upload endpoint.
			fail(http.StatusBadRequest)
			return
		}
		rest := make([]byte, kal2.FirstFlightMinSize-len(kal2.Magic))
		if _, err := io.ReadFull(bc, rest); err != nil {
			fail(http.StatusNotFound)
			return
		}
		prefix := append(magic, rest...)
		eph, totalLen, psk, err := v.authFlight(prefix, nil)
		if err != nil {
			fail(http.StatusForbidden)
			return
		}
		if pad := totalLen - kal2.FirstFlightMinSize; pad > 0 {
			if _, err := io.ReadFull(bc, make([]byte, pad)); err != nil {
				return
			}
		}
		if !isWS {
			// Authenticated: open the streaming response and finish the handshake.
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			bc.(*driftServerConn).started = true
		}
		if err := v.establishKAL(bc, eph, psk, prefix); err != nil {
			return
		}
		// Keep the handler alive while the session lives: the session's read
		// loop consumes the request body / WS frames; block until it ends.
		if isWS {
			select {
			case <-bc.(*wsConn).closed:
			case <-r.Context().Done():
			}
		} else {
			<-r.Context().Done()
		}
	})
}

// driftServerConn adapts an HTTP request/response pair to BoundConn.
// Read = request body; Write = streaming response; Close = cancels context.
type driftServerConn struct {
	w       http.ResponseWriter
	r       *http.Request
	started bool
	mu      sync.Mutex
	closed  chan struct{}
	once    sync.Once
	remote  net.Addr
}

func newDriftServerConn(w http.ResponseWriter, r *http.Request) *driftServerConn {
	var ra net.Addr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ra = &net.TCPAddr{IP: net.ParseIP(host)}
	}
	d := &driftServerConn{w: w, r: r, closed: make(chan struct{}), remote: ra}
	go func() {
		select {
		case <-r.Context().Done():
			d.Close()
		case <-d.closed:
		}
	}()
	return d
}

func (d *driftServerConn) Read(b []byte) (int, error) { return d.r.Body.Read(b) }
func (d *driftServerConn) Write(b []byte) (n int, err error) {
	// The KAL session can outlive the handler: once the request context ends,
	// the h2 responseWriter panics on Write. Guard with closed + recover.
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, io.ErrClosedPipe
		}
	}()
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n, err = d.w.Write(b)
	if err == nil {
		if f, ok := d.w.(http.Flusher); ok {
			f.Flush()
		}
	}
	return n, err
}
func (d *driftServerConn) Close() error {
	d.once.Do(func() {
		close(d.closed)
		_ = d.r.Body.Close()
	})
	return nil
}
func (d *driftServerConn) LocalAddr() net.Addr                { return nil }
func (d *driftServerConn) RemoteAddr() net.Addr               { return d.remote }
func (d *driftServerConn) SetDeadline(t time.Time) error      { return nil }
func (d *driftServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *driftServerConn) SetWriteDeadline(t time.Time) error { return nil }
func (d *driftServerConn) Binding() kal2.ChannelBinding       { return nil }

// ---------------------------------------------------------------------------
// Drift client: h2 POST with streamed body (up) and streamed response (down).
// ---------------------------------------------------------------------------

// DialDrift connects using the HTTP-shaped carrier: one streaming POST over
// TLS (direct or through a CDN/proxy CONNECT).
func DialDrift(ctx context.Context, cfg ClientConfig, path string) (*kal2.Session, BoundConn, error) {
	if path == "" {
		path = DefaultDriftPath
	}
	to := cfg.timeout()
	dial := cfg.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: to}
		dial = d.DialContext
	}

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, tcfg *tls.Config) (net.Conn, error) {
			raw, err := dial(ctx, network, cfg.Addr)
			if err != nil {
				return nil, err
			}
			spec, _ := utls.UTLSIdToSpec(pickHelloID(cfg.Fingerprint))
			uc := utls.UClient(raw, &utls.Config{
				ServerName:         cfg.SNI,
				MinVersion:         utls.VersionTLS13,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
				NextProtos:         []string{"h2"},
			}, utls.HelloCustom)
			if err := uc.ApplyPreset(&spec); err != nil {
				_ = raw.Close()
				return nil, err
			}
			if err := uc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return uc, nil
		},
	}

	pr, pw := io.Pipe()
	url := "https://" + cfg.SNI + strings.TrimSuffix(path, "/") + "/" + driftPathToken(cfg.PSK)
	// The request IS the session carrier: its lifetime must be the session's,
	// not the dial deadline's — ctx only bounds connect+handshake below (veil
	// parity: there the ctx is dead weight once Attach runs).
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodPost, url, pr)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", driftUA())
	req.ContentLength = -1 // chunked upload

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	conn := &driftClientConn{pr: pr, pw: pw}
	// The KAL flight must be the first bytes of the body: run the handshake
	// manually over the conn's write half, then read the response for the
	// server flight.
	hs, err := kal2.NewClientHandshake(cfg.ServerPub, cfg.PSK, nil)
	if err != nil {
		return nil, nil, err
	}
	flight, err := hs.FirstFlight(cfg.FirstFlightPadLen)
	if err != nil {
		return nil, nil, err
	}
	if _, err := pw.Write(flight); err != nil {
		return nil, nil, err
	}

	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		_ = pw.Close()
		return nil, nil, fmt.Errorf("drift round trip: %w", err)
	case <-ctx.Done():
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, ctx.Err()
	case <-time.After(to):
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, fmt.Errorf("drift response timeout")
	}
	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, nil, fmt.Errorf("drift: server status %d", resp.StatusCode)
	}
	conn.resp = resp
	conn.read = resp.Body

	sess, err := driftHandshakeConn(hs, conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return sess, conn, nil
}

// driftHandshakeConn finishes the kal2 handshake over conn once the first
// flight has been written and the read side is live (shared by the POST-body
// and WebSocket drift transports).
func driftHandshakeConn(hs *kal2.ClientHandshake, conn BoundConn, cfg ClientConfig) (*kal2.Session, error) {
	serverFlight := make([]byte, kal2.ServerFlightSize)
	if _, err := io.ReadFull(conn, serverFlight); err != nil {
		return nil, fmt.Errorf("server flight: %w", err)
	}
	sess, err := hs.ServerFlight(serverFlight)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(sess.ClientAuthFlight(cfg.PSK, serverFlight)); err != nil {
		return nil, err
	}
	fin := make([]byte, kal2.FinishedSize)
	if _, err := io.ReadFull(conn, fin); err != nil {
		return nil, fmt.Errorf("server finished: %w", err)
	}
	if subtleCompare(fin, sess.FinishedValue("server")) != 1 {
		return nil, kal2.ErrHandshake
	}
	sess.Attach(conn)
	return sess, nil
}

// DialDriftWS is drift over a WebSocket: identical kal2 stream inside binary
// frames. WebSocket is the one streaming shape CDNs pass unbuffered — use it
// when the endpoint sits behind a CDN/proxy (proxied DNS name) where raw
// streaming POST bodies get swallowed.
func DialDriftWS(ctx context.Context, cfg ClientConfig, path string) (*kal2.Session, BoundConn, error) {
	if path == "" {
		path = DefaultDriftPath
	}
	to := cfg.timeout()
	dial := cfg.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: to}
		dial = d.DialContext
	}
	raw, err := dial(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, nil, err
	}
	spec, _ := utls.UTLSIdToSpec(pickHelloID(cfg.Fingerprint))
	// WebSocket upgrade needs http/1.1 end-to-end — force the ALPN extension
	// in the picked spec or the server negotiates h2 and the GET never parses.
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = []string{"http/1.1"}
		}
	}
	uc := utls.UClient(raw, &utls.Config{
		ServerName:         cfg.SNI,
		MinVersion:         utls.VersionTLS13,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	wsc, err := wsDial(uc, cfg.SNI, strings.TrimSuffix(path, "/")+"/"+driftPathToken(cfg.PSK))
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}

	hs, err := kal2.NewClientHandshake(cfg.ServerPub, cfg.PSK, nil)
	if err != nil {
		_ = wsc.Close()
		return nil, nil, err
	}
	flight, err := hs.FirstFlight(cfg.FirstFlightPadLen)
	if err != nil {
		_ = wsc.Close()
		return nil, nil, err
	}
	if _, err := wsc.Write(flight); err != nil {
		_ = wsc.Close()
		return nil, nil, err
	}
	type hsRes struct {
		s   *kal2.Session
		err error
	}
	done := make(chan hsRes, 1)
	go func() {
		s, err := driftHandshakeConn(hs, wsc, cfg)
		done <- hsRes{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			_ = wsc.Close()
			return nil, nil, r.err
		}
		return r.s, wsc, nil
	case <-ctx.Done():
		_ = wsc.Close()
		return nil, nil, ctx.Err()
	case <-time.After(to):
		_ = wsc.Close()
		return nil, nil, fmt.Errorf("drift-ws handshake timeout")
	}
}

// driftClientConn adapts the h2 request/response pair to BoundConn.
type driftClientConn struct {
	pr   *io.PipeReader
	pw   *io.PipeWriter
	resp *http.Response
	read io.Reader
}

func (d *driftClientConn) Read(b []byte) (int, error)  { return d.read.Read(b) }
func (d *driftClientConn) Write(b []byte) (int, error) { return d.pw.Write(b) }
func (d *driftClientConn) Close() error {
	_ = d.pw.Close()
	if d.resp != nil {
		_ = d.resp.Body.Close()
	}
	return nil
}
func (d *driftClientConn) LocalAddr() net.Addr                { return nil }
func (d *driftClientConn) RemoteAddr() net.Addr               { return nil }
func (d *driftClientConn) SetDeadline(t time.Time) error      { return nil }
func (d *driftClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *driftClientConn) SetWriteDeadline(t time.Time) error { return nil }
func (d *driftClientConn) Binding() kal2.ChannelBinding       { return nil }

// driftUA returns a browser-grade User-Agent for the shaped requests.
func driftUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
}
