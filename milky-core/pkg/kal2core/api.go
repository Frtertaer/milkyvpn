// Package kal2core is the public API surface of the milky VPN core. The app
// (and the test binaries) consume only this package.
package kal2core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

// ServerConfig configures a kal2 egress/entry server.
type ServerConfig struct {
	Listen   string // ":443"
	Domain   string // our domain, e.g. kal.example.dev
	CertFile string // fullchain PEM
	KeyFile  string // private key PEM
	// AutocertDir enables Let's Encrypt via x/crypto autocert (HTTP-01 on :80)
	// when CertFile/KeyFile are empty; certs cache in this directory.
	AutocertDir string
	// AutocertHTTPAddr is where the ACME challenge listener binds (":80").
	AutocertHTTPAddr string
	Identity         []byte // server ed25519 private key (64B) for KAL/2
	StealAddr        string // optional: decoy upstream for foreign SNI ("host:port")
	// ExtraDomains are additional owned SNIs terminating locally — the decoy
	// pool; a burned primary domain doesn't kill the endpoint. Certificates:
	// with AutocertDir they auto-issue via the host whitelist; with file
	// certs use ExtraCertFiles (or a shared wildcard/SAN cert).
	ExtraDomains   []string
	ExtraCertFiles map[string][2]string // domain -> {certFile, keyFile}
	// StealMap splices specific foreign SNIs to per-SNI upstreams before
	// StealAddr: a scanner probing different cover names reaches the real
	// matching site for each.
	StealMap map[string]string
	DriftPath        string // secret drift path, default carrier.DefaultDriftPath
	DecoyDir         string // directory served for plain HTTP probes
	Users            []User
	// Egress controls upstream dialing: IPv4 preference and an optional
	// chained SOCKS5 upstream (e.g. for reputation-flagged ranges).
	Egress *core.EgressConfig
	// ECHKeyFiles are JSON key files written by `kal2-server -echgen`
	// (carrier.SaveECHKeyFile format). Enables Encrypted Client Hello on the
	// veil listener — the outer ClientHello then shows only the cover name.
	ECHKeyFiles []string
	// Resume enables v2.1 session resumption (KLDO-rs-): the listener keeps
	// frozen sessions for migration and issues one-time tickets. Ticket keys
	// derive from Identity so they survive restarts.
	Resume bool
	// UDPListen enables the quasar (UDP/KCP) listener, e.g. ":20443".
	// Set Listen to "off" to run a UDP-only server without TLS material.
	UDPListen string
	// Quic2Listen enables the quic2 (QUIC v2, RFC 9369) listener on its own
	// UDP port, e.g. ":20444". QUIC-SNI censorship parses only v1 Initials —
	// a v2 handshake yields no SNI to filter. Shares the veil TLS material
	// and KAL/2 handshake path.
	Quic2Listen string
	// FrontListen enables a plain-HTTP listener (e.g. ":8081") serving the
	// same drift/mosaic/decoy mux without TLS — the backend leg of a front
	// relay (serverless function, CDN worker): the front terminates TLS on
	// its own domain and forwards requests here. Only encrypted KAL/2
	// blobs cross it, and the HMAC-keyed paths stay unguessable, but you
	// can still firewall it to the relay's egress ranges. Requests are
	// indistinguishable from probing the decoy site.
	FrontListen string
	// UDPFECData/UDPFECParity enable Reed-Solomon FEC on the quasar
	// listener (e.g. 10,3). 0,0 = off.
	UDPFECData   int
	UDPFECParity int
	// UDPSndWnd caps the KCP send window (segments) the server applies to
	// quasar sessions. It bounds the in-flight backlog — at 16384 segs the
	// tail is ~22 MB (~6 s of added latency for new streams under load),
	// so ~4096 keeps bulk rate near the path cap while control stays fast.
	// 0 = 16384.
	UDPSndWnd int
	// UDPResend is the dup-ack fast-retransmit threshold for quasar sessions.
	UDPResend int
	// UDPRate caps the quasar packet output rate in bytes/s (0 = unlimited).
	UDPRate int
	Logf    func(string, ...any)
}

// User is a provisioned client credential pair.
type User struct {
	ID  string // informational
	PSK []byte // 32 bytes
}

// ClientConfig configures dialing a kal2 server.
type ClientConfig struct {
	Addr      string   // host:port of server or relay
	Addrs     []string // endpoint list — tried in rotating order; overrides Addr
	SNI       string   // TLS SNI (server domain)
	ServerPub []byte   // server Ed25519 public key (32B)
	PSK       []byte   // per-user PSK (32B)
	Carrier   string   // "veil" (default), "drift", "cdn" (WS-shaped drift), "mosaic" (tiled), "auto" (hedged), or "a,b" list
	DriftPath string   // secret path when Carrier=drift
	// InsecureSkipVerify disables chain verification on the carrier TLS layer.
	// The KAL/2 inner handshake still authenticates the server by its Ed25519
	// pubkey and (veil) binds to the TLS exporter, so an interceptor cannot
	// relay the session — but it does see the inner first flight. Prefer
	// PinSHA256 on devices with stale CA stores.
	InsecureSkipVerify bool
	// PinSHA256 pins the outer TLS leaf by SHA-256 of its SPKI instead of
	// CA-chain verification (link param pin=).
	PinSHA256 [][]byte
	// ECHConfigList enables Encrypted Client Hello on the veil carrier
	// (serialized ECHConfigList). On a veil dial failure it is retried once
	// without ECH — availability beats the marginal stealth loss.
	ECHConfigList []byte
	// Cover sends jittered randomized PING records while the session is up so
	// idle periods don't read as a "quiet tunnel" timing signature.
	Cover bool
	// QuasarFEC sets Reed-Solomon FEC shards [data,parity] for the quasar
	// carrier; [0,0] = off.
	QuasarFEC [2]int
	// QuasarRcvWnd caps the KCP receive window the client advertises to the
	// server, throttling its offered rate to ~wnd*mtu/RTT — paths that police
	// inbound UDP to a fixed rate drop everything above the cap, so a window
	// just under it beats a big window that loses ~40%. 0 = 16384.
	QuasarRcvWnd int
	// QuasarResend is the dup-ack fast-retransmit threshold (0 = RTO only).
	QuasarResend int
	// QuasarLanes is the number of parallel quasar sessions (>1 = multi
	// lane). KCP delivers an ordered byte stream, so anything written lands
	// behind every earlier byte — a bulk download makes the tail of its
	// lane's stream seconds deep. Spreading streams round-robin across
	// lanes keeps interactive streams on nearly-empty ordered streams.
	// 0/1 = single session.
	// Lanes pools N parallel sessions over the configured carrier and
	// round-robins new streams across them: a single ordered transport
	// (KCP stream, TCP byte stream) makes every stream wait behind bulk
	// backlogs, so spreading streams over several connections keeps
	// interactive traffic on nearly-empty lanes.
	Lanes int
	// Deprecated: same as Lanes (kept for older CLI flags).
	QuasarLanes int
	// DialContext overrides the base TCP dial (e.g. via HTTP CONNECT proxy).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialControl hooks socket creation in the built-in dialers (signature of
	// net.Dialer.Control): TUN mode pins carrier sockets to the physical
	// egress device so they bypass the tunnel without FIB bypass routes.
	// Ignored when DialContext is set.
	DialControl      func(network, address string, c syscall.RawConn) error
	// Front is an optional front-relay URL ("https://host[:port][/base]", e.g.
	// a serverless function or CDN worker domain) that the HTTP-shaped
	// carriers — drift, cdn, mosaic — dial instead of Addr: the relay
	// forwards to the server's FrontListen port. Use it when the entry IPs
	// are blocked or when only whitelisted domains are reachable; the TLS
	// leg to the front is ordinary browser TLS on the front's own domain.
	// Raw drift needs a streaming relay; mosaic/cdn survive buffering ones.
	Front string
	HandshakeTimeout time.Duration
	Logf             func(string, ...any)
	// Resume, set internally by the migration path, makes dialers run a
	// KLDO-rs- resumption flight on the fresh transport.
	Resume *kal2.ResumeState
}

// Client is an established kal2 tunnel end. When EnableReconnect is running,
// Sess is swapped on each redial — read it through Session().
type Client struct {
	Sess *kal2.Session

	cfg      ClientConfig
	logf     func(string, ...any)
	mu       sync.Mutex
	lanes    []atomic.Pointer[kal2.Session] // quasar lane pool; nil when single
	laneRR   atomic.Uint32
	// laneRTT records the last watchdog pong RTT per lane (ns; 0 = not yet
	// measured). A lane whose pongs crawl is throttled rather than dead —
	// the kill path would never fire on it, so it must be quarantined out of
	// Session() picks instead of attracting every new stream.
	laneRTT  []atomic.Int64
	stop     chan struct{}
	stopOnce sync.Once
	rrIdx    atomic.Int32
	// pingMu serializes Ping callers owned by this client (cover, liveness,
	// Ping method): the session routes each PONG to a single registered
	// channel, so concurrent Pings would steal each other's replies.
	pingMu sync.Mutex
	scores   *core.Scorecard
}

// laneQuarantineRTT is the watchdog pong RTT above which a lane is
// quarantined: it still answers (so it must not be killed), but it is too
// slow to carry new streams. Recovered lanes return to the pool on their
// next healthy pong. Atomic (nanoseconds) for the same test-knob rationale.
var laneQuarantineRTT atomic.Int64

// lanePingEvery / lanePingTimeout / lanePingRetryTimeout pace the per-lane
// watchdog. Two consecutive failures kill the lane; a single lost pong must
// not. Atomics (nanoseconds) so tests can compress the timeline while a
// stray watchdog goroutine is still shutting down.
var (
	lanePingEvery        atomic.Int64 // default 15s
	lanePingTimeout      atomic.Int64 // default 10s
	lanePingRetryTimeout atomic.Int64 // default 5s
)

func init() {
	dialOneFn.Store(dialFunc(dialOne))
	laneQuarantineRTT.Store(int64(3 * time.Second))
	lanePingEvery.Store(int64(15 * time.Second))
	lanePingTimeout.Store(int64(10 * time.Second))
	lanePingRetryTimeout.Store(int64(5 * time.Second))
}

// Session returns a live session, or nil between loss and redial.
// With lanes it picks the session that has emitted the fewest wire bytes:
// a lane deep into a bulk transfer keeps accumulating sent bytes, so new
// streams land on the quiet lanes instead of queueing behind its backlog.
// Lanes quarantined by the watchdog (pong RTT above laneQuarantineRTT) are
// skipped while at least one healthy lane is up; when every lane is
// throttled the least-loaded one still serves rather than failing streams.
func (c *Client) Session() *kal2.Session {
	if len(c.lanes) > 0 {
		var best, fallback *kal2.Session
		var bestSent, fbSent uint64
		start := c.laneRR.Add(1)
		for k := uint32(0); k < uint32(len(c.lanes)); k++ {
			idx := (start + k) % uint32(len(c.lanes))
			s := c.lanes[idx].Load()
			if s == nil {
				continue
			}
			if fallback == nil || s.SentBytes() < fbSent {
				fallback, fbSent = s, s.SentBytes()
			}
			if rtt := c.laneRTT[idx].Load(); rtt > laneQuarantineRTT.Load() {
				continue
			}
			if best == nil || s.SentBytes() < bestSent {
				best, bestSent = s, s.SentBytes()
			}
		}
		if best != nil {
			return best
		}
		return fallback
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Sess
}

// DecodeBase64 accepts standard or URL-safe base64, padded or raw.
// Share links carry whatever encoding the generator produced — a padded
// URL-safe string fails both StdEncoding (rejects -_) and RawURLEncoding
// (rejects =), so all four variants must be tried.
func DecodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("key must decode as base64 (std|url, padded|raw)")
}

// DecodeKey accepts hex or base64 key material.
func DecodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("key must decode to 32 bytes (hex or base64)")
}

// Serve runs a kal2 server until the listener fails.
func Serve(cfg ServerConfig) error {
	var echKeys []tls.EncryptedClientHelloKey
	var echNames []string
	if len(cfg.ECHKeyFiles) > 0 {
		k, err := carrier.LoadECHKeys(cfg.ECHKeyFiles)
		if err != nil {
			return fmt.Errorf("ech keys: %w", err)
		}
		echKeys = k
		for _, kk := range k {
			if n, err := carrier.ECHPublicName(kk.Config); err == nil && n != "" {
				echNames = append(echNames, n)
			}
		}
	}
	udpOnly := cfg.Listen == "off"
	var cert *tls.Certificate
	var autocertMgr *autocert.Manager
	if !udpOnly && cfg.CertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load cert: %w", err)
		}
		cert = &c
	} else if !udpOnly && cfg.AutocertDir != "" {
		autocertMgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			// Whitelist the real domain plus ECH cover names so autocert
			// issues fallback certs for outer hellos too.
			// Whitelist the real domain plus decoy-pool domains plus ECH cover
			// names so autocert issues certs for outer hellos too.
			HostPolicy: autocert.HostWhitelist(append(append([]string{cfg.Domain}, cfg.ExtraDomains...), echNames...)...),
			Cache:      autocert.DirCache(cfg.AutocertDir),
		}
		httpAddr := cfg.AutocertHTTPAddr
		if httpAddr == "" {
			httpAddr = ":80"
		}
		go func() {
			// HTTP-01 challenge endpoint; non-ACME requests get the decoy page.
			h := autocertMgr.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(defaultDecoyPage))
			}))
			_ = http.ListenAndServe(httpAddr, h)
		}()
	} else if !udpOnly {
		return fmt.Errorf("need CertFile/KeyFile or AutocertDir")
	}
	driftPath := cfg.DriftPath
	if driftPath == "" {
		driftPath = carrier.DefaultDriftPath
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	var ln net.Listener
	if !udpOnly {
		var lerr error
		ln, lerr = net.Listen("tcp", cfg.Listen)
		if lerr != nil {
			return lerr
		}
	}

	vc := carrier.VeilConfig{
		Domain:     cfg.Domain,
		AltDomains: cfg.ExtraDomains,
		Identity:   ed25519.PrivateKey(cfg.Identity),
		Users:      toCarrierUsers(cfg.Users),
		StealAddr:  cfg.StealAddr,
		StealMap:   cfg.StealMap,
		Logf:       logf,
		ECHKeys:    echKeys,
		OnSession: func(s *kal2.Session) {
			go func() {
				_ = core.ServeEgressCfg(s, nil, cfg.Egress, logf)
			}()
		},
	}
	if cfg.Resume {
		// Ticket AEAD keys derive from the server identity — resumable
		// sessions survive process restarts without extra state.
		tk, _ := kal2.HKDFDerive([]byte("kal2-ticket-key"), cfg.Identity, []byte("v1"), 32)
		var k1 [32]byte
		copy(k1[:], tk)
		codec := kal2.NewTicketCodec(k1)
		vc.Resumer = kal2.NewSessionRegistry(codec, 0)
	}
	// Per-domain file certs + optional shared fallback, or pure ACME.
	var extraCerts map[string]tls.Certificate
	if len(cfg.ExtraCertFiles) > 0 {
		extraCerts = map[string]tls.Certificate{}
		for d, pair := range cfg.ExtraCertFiles {
			c, err := tls.LoadX509KeyPair(pair[0], pair[1])
			if err != nil {
				return fmt.Errorf("load extra cert %s: %w", d, err)
			}
			extraCerts[strings.ToLower(d)] = c
		}
	}
	if len(extraCerts) > 0 || (autocertMgr != nil && cert != nil) {
		base := autocertMgr.GetCertificate
		if base == nil && cert != nil {
			b := cert
			base = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return b, nil }
		}
		vc.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := extraCerts[strings.ToLower(h.ServerName)]; ok {
				return &c, nil
			}
			return base(h)
		}
	} else if cert != nil {
		vc.Cert = *cert
	} else if autocertMgr != nil {
		vc.GetCertificate = autocertMgr.GetCertificate
	}
	v := carrier.NewVeilListener(vc)

	mux := http.NewServeMux()
	mux.Handle(driftPath, v.DriftHandler(driftPath))
	mux.Handle(driftPath+"/", v.DriftHandler(driftPath))
	mux.Handle(carrier.DefaultMosaicPath, v.MosaicHandler(carrier.DefaultMosaicPath))
	mux.Handle(carrier.DefaultMosaicPath+"/", v.MosaicHandler(carrier.DefaultMosaicPath))
	if cfg.DecoyDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(cfg.DecoyDir)))
	} else {
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(defaultDecoyPage))
		}))
	}
	v.SetMux(mux)

	if cfg.FrontListen != "" {
		fsrv := &http.Server{Addr: cfg.FrontListen, Handler: mux}
		go func() {
			if err := fsrv.ListenAndServe(); err != nil {
				logf("core: front listener %s stopped: %v", cfg.FrontListen, err)
			}
		}()
		logf("core: front relay listener on %s", cfg.FrontListen)
	}

	if cfg.UDPListen != "" {
		wireKey := carrier.QuasarWireKey(ed25519.PrivateKey(cfg.Identity).Public().(ed25519.PublicKey))
		ql, err := carrier.NewQuasarListener(v, &carrier.QuasarConfig{
			WireKey:      wireKey,
			DataShards:   cfg.UDPFECData,
			ParityShards: cfg.UDPFECParity,
			SndWnd:       cfg.UDPSndWnd,
			Resend:       cfg.UDPResend,
			RateLimit:    cfg.UDPRate,
		}, cfg.UDPListen)
		if err != nil {
			return fmt.Errorf("quasar listen: %w", err)
		}
		go func() {
			if err := ql.Serve(); err != nil {
				logf("core: quasar listener %s stopped: %v", cfg.UDPListen, err)
			}
		}()
		logf("core: quasar udp on %s (fec %d,%d)", ql.Addr(), cfg.UDPFECData, cfg.UDPFECParity)
	}

	if cfg.Quic2Listen != "" {
		qtls := &tls.Config{MinVersion: tls.VersionTLS13}
		if vc.GetCertificate != nil {
			qtls.GetCertificate = vc.GetCertificate
		} else {
			qtls.Certificates = []tls.Certificate{vc.Cert}
		}
		q2, err := carrier.NewQuic2Listener(v, qtls, cfg.Quic2Listen)
		if err != nil {
			return fmt.Errorf("quic2 listen: %w", err)
		}
		go func() {
			if err := q2.Serve(); err != nil {
				logf("core: quic2 listener %s stopped: %v", cfg.Quic2Listen, err)
			}
		}()
		logf("core: quic2 udp on %s", q2.Addr())
	}

	if udpOnly {
		logf("core: udp-only server on %s", cfg.UDPListen)
		select {}
	}
	logf("core: serving %s on %s", cfg.Domain, cfg.Listen)
	return v.Serve(ln)
}

// Dial establishes a kal2 session using the configured carrier, trying each
// endpoint in Addrs (or Addr) in order.
func Dial(ctx context.Context, cfg ClientConfig) (*Client, error) {
	scores := core.NewScorecard()
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	cli := &Client{cfg: cfg, logf: logf, stop: make(chan struct{}), scores: scores}
	n := cfg.Lanes
	if n <= 0 {
		n = cfg.QuasarLanes
	}
	if n > 1 {
		cli.lanes = make([]atomic.Pointer[kal2.Session], n)
		cli.laneRTT = make([]atomic.Int64, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s, err := dialAny(ctx, cfg, i, scores)
				if err == nil {
					cli.lanes[i].Store(s)
				}
				errs[i] = err
			}(i)
		}
		wg.Wait()
		var firstErr error
		up := 0
		for i := 0; i < n; i++ {
			if cli.lanes[i].Load() != nil {
				up++
			} else if firstErr == nil {
				firstErr = errs[i]
			}
		}
		if up == 0 {
			return nil, firstErr
		}
		if up < n {
			logf("core: %d/%d carrier lanes up at dial", up, n)
		}
	} else {
		sess, err := dialAny(ctx, cfg, 0, scores)
		if err != nil {
			return nil, err
		}
		cli.Sess = sess
	}
	if cfg.Cover {
		go cli.coverLoop()
	}
	return cli, nil
}

// coverLoop emits jittered random-payload PINGs while the session is up so an
// idle tunnel doesn't read as a quiet, fixed-timing signature to DPI.
func (c *Client) coverLoop() {
	for {
		// 6–18s jittered interval; payload size varies too.
		d := 6*time.Second + time.Duration(rand.IntN(13))*time.Second
		select {
		case <-c.stop:
			return
		case <-time.After(d):
		}
		s := c.Session()
		if s == nil {
			continue
		}
		pad := make([]byte, 8+rand.IntN(80))
		for i := range pad {
			pad[i] = byte(rand.IntN(256))
		}
		c.pingMu.Lock()
		_ = s.Ping(pad, 10*time.Second)
		c.pingMu.Unlock()
	}
}

func endpoints(cfg ClientConfig) []string {
	if len(cfg.Addrs) > 0 {
		return cfg.Addrs
	}
	return []string{cfg.Addr}
}

// splitCommaList splits a comma list into trimmed non-empty parts.
func splitCommaList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// carriers expands the Carrier field into the concrete carriers to try.
// "auto" (or empty) hedges across every carrier: all are dialed in parallel
// and the first session that completes wins — during throttling windows one
// carrier usually still squeezes through (observed live: veil dials timed
// out while drift completed). Mosaic completes last on a clean path, so it
// wins exactly when the connection-shaped carriers are being cut.
func carriers(cfg ClientConfig) []string {
	c := strings.TrimSpace(cfg.Carrier)
	if c == "" || c == "auto" {
		return []string{"veil", "drift", "cdn", "mosaic"}
	}
	parts := strings.Split(c, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return []string{"veil"}
	}
	return out
}

// dialHedged races the candidate carriers for one endpoint and returns the
// first successful session; losing sessions are closed when they finish.
// Candidate order comes from the scorecard (failover ordering); the race
// starts staggered so the healthiest carrier usually wins.
func dialHedged(ctx context.Context, cfg ClientConfig, scores *core.Scorecard) (*kal2.Session, error) {
	cs := carriers(cfg)
	if scores != nil {
		cs = scores.Order(cs)
	}
	if len(cs) == 1 {
		c2 := cfg
		c2.Carrier = cs[0]
		t0 := time.Now()
		s, err := dialOneFn.Load().(dialFunc)(ctx, c2)
		if scores != nil {
			scores.ReportDial(cs[0], err == nil, time.Since(t0).Seconds())
		}
		return s, err
	}
	type result struct {
		name string
		s    *kal2.Session
		err  error
		secs float64
	}
	ch := make(chan result, len(cs))
	sub, cancel := context.WithCancel(ctx)
	for i, name := range cs {
		go func(name string, delay time.Duration) {
			if delay > 0 {
				select {
				case <-sub.Done():
					ch <- result{name: name, err: sub.Err()}
					return
				case <-time.After(delay):
				}
			}
			c2 := cfg
			c2.Carrier = name
			t0 := time.Now()
			s, err := dialOneFn.Load().(dialFunc)(sub, c2)
			ch <- result{name: name, s: s, err: err, secs: time.Since(t0).Seconds()}
		}(name, time.Duration(i)*150*time.Millisecond)
	}
	var lastErr, stageErr error
	pending := len(cs)
	for pending > 0 {
		select {
		case r := <-ch:
			pending--
			if scores != nil && r.err != context.Canceled {
				scores.ReportDial(r.name, r.err == nil, r.secs)
			}
			if r.err == nil {
				cancel()
				// Drain late completions so a slow winner's session is closed.
				go func() {
					for i := 0; i < pending; i++ {
						if r := <-ch; r.s != nil {
							_ = r.s.Close()
						}
					}
				}()
				return r.s, nil
			}
			if carrier.IsHandshakeStage(r.err) {
				stageErr = r.err
			}
			lastErr = r.err
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	}
	cancel()
	// A lane that reached the inner handshake proves the entry is alive —
	// surface that error over a sibling lane's transport failure so the
	// entry-block canary never fires on a reachable server.
	if stageErr != nil {
		return nil, stageErr
	}
	return nil, lastErr
}

// EntriesBlockedError reports that every entry point (addr x sni, all
// carriers in the hedge) failed before reaching the KAL/2 handshake — the
// signature of a provider/TSPU block on the entry (IP block, RST
// injection, UDP cutoff), not of a bad config or auth failure. The app
// maps it to "entry blocked — refresh your link/subscription".
type EntriesBlockedError struct {
	Attempts int   // addr x sni sweep size
	Err      error // last transport-stage error
}

func (e *EntriesBlockedError) Error() string {
	return fmt.Sprintf("entries_blocked: all %d endpoints unreachable (%v)", e.Attempts, e.Err)
}

func (e *EntriesBlockedError) Unwrap() error { return e.Err }

// IsEntriesBlocked reports whether err is an EntriesBlockedError.
func IsEntriesBlocked(err error) bool {
	var eb *EntriesBlockedError
	return errors.As(err, &eb)
}

// dialAny walks the endpoint list starting at index start, returning the
// first session that completes the handshake (hedged across carriers).
// SNI also accepts a comma list (decoy pool): the attempt index rotates
// through endpoints AND cover names, so over retries the client sweeps the
// addr×sni cross-product — a single SNI block can't kill the link.
func dialAny(ctx context.Context, cfg ClientConfig, start int, scores *core.Scorecard) (*kal2.Session, error) {
	addrs := endpoints(cfg)
	snis := splitCommaList(cfg.SNI)
	var lastErr error
	sawInner := false
	for i := range addrs {
		c2 := cfg
		attempt := start + i
		c2.Addr = addrs[attempt%len(addrs)]
		if len(snis) > 1 {
			c2.SNI = snis[attempt%len(snis)]
		}
		s, err := dialHedged(ctx, c2, scores)
		if err == nil {
			return s, nil
		}
		if carrier.IsHandshakeStage(err) {
			sawInner = true
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if !sawInner {
		attempts := len(addrs)
		if len(snis) > 1 {
			attempts *= len(snis)
		}
		return nil, &EntriesBlockedError{Attempts: attempts, Err: lastErr}
	}
	return nil, lastErr
}

// dialOneFn is the per-carrier dialer (a knob for tests). Atomic value:
// tests swap it while hedged-dial goroutines may still be in flight.
type dialFunc func(context.Context, ClientConfig) (*kal2.Session, error)

var dialOneFn atomic.Value // dialFunc

func dialOne(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
	cc := carrier.ClientConfig{
		Addr:               cfg.Addr,
		SNI:                cfg.SNI,
		ServerPub:          cfg.ServerPub,
		PSK:                cfg.PSK,
		DialContext:        cfg.DialContext,
		DialControl:        cfg.DialControl,
		HandshakeTimeout:   cfg.HandshakeTimeout,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		PinSHA256:          cfg.PinSHA256,
		ECHConfigList:      cfg.ECHConfigList,
		Resume:             cfg.Resume,
		Front:              cfg.Front,
	}
	switch cfg.Carrier {
	case "", "veil":
		s, _, err := carrier.DialVeil(ctx, cc)
		if err != nil && len(cc.ECHConfigList) > 0 {
			cc.ECHConfigList = nil
			if cfg.Logf != nil {
				cfg.Logf("kal2: veil+ech failed (%v) — retrying plain veil", err)
			}
			s, _, err = carrier.DialVeil(ctx, cc)
		}
		return s, err
	case "drift":
		s, _, err := carrier.DialDrift(ctx, cc, cfg.DriftPath)
		return s, err
	case "cdn":
		s, _, err := carrier.DialDriftWS(ctx, cc, cfg.DriftPath)
		return s, err
	case "quasar":
		s, _, err := carrier.DialQuasar(ctx, cc, &carrier.QuasarConfig{
			DataShards:   cfg.QuasarFEC[0],
			ParityShards: cfg.QuasarFEC[1],
			RcvWnd:       cfg.QuasarRcvWnd,
			Resend:       cfg.QuasarResend,
		})
		return s, err
	case "quic2":
		s, _, err := carrier.DialQuic2(ctx, cc)
		return s, err
	case "mosaic":
		cc.Endpoints = endpoints(cfg)
		cc.Logf = cfg.Logf
		s, _, err := carrier.DialMosaic(ctx, cc, "")
		return s, err
	default:
		return nil, fmt.Errorf("unknown carrier %q", cfg.Carrier)
	}
}

// EnableReconnect starts the session watchdog: when the carrier connection
// dies (TSPU reset, idle kill, mobile roaming), the client re-dials over the
// endpoint list with backoff+jitter and swaps in the new session; SOCKS
// connections opened during the gap are refused fast, ones after see a live
// session again.
func (c *Client) EnableReconnect() {
	go c.reconnectLoop()
}

func (c *Client) reconnectLoop() {
	if len(c.lanes) > 0 {
		for i := range c.lanes {
			go c.reconnectLane(i)
		}
		<-c.stop
		return
	}
	for {
		sess := c.Session()
		if sess == nil {
			return
		}
		migrated := false
		select {
		case <-sess.WaitClosed():
		case <-sess.NeedsMigrate():
			migrated = true
		case <-c.stop:
			return
		}
		if migrated {
			c.logf("core: transport lost; migrating session")
			if c.tryMigrate(sess) {
				c.scores.ReportMigrate(true)
				continue // same session object, new transport — re-watch
			}
			c.scores.ReportMigrate(false)
			c.logf("core: migration failed; falling back to redial")
		}
		c.mu.Lock()
		if c.Sess == sess {
			c.Sess = nil
		}
		c.mu.Unlock()
		_ = sess.Close() // frozen remnants die now; streams are lost
		c.logf("core: session lost; redialing")
		backoff := time.Second
		blockedRounds := 0
		for {
			select {
			case <-c.stop:
				return
			case <-time.After(backoff + time.Duration(rand.Int64N(int64(backoff/4)+1))):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			s, err := dialAny(ctx, c.cfg, int(c.rrIdx.Add(1)), c.scores)
			cancel()
			if err == nil {
				c.mu.Lock()
				if c.Sess == nil {
					c.Sess = s
				} else {
					_ = s.Close() // concurrent swap won; keep it
				}
				c.mu.Unlock()
				c.logf("core: session restored")
				break
			}
			if IsEntriesBlocked(err) {
				blockedRounds++
				// Canary: 3 consecutive all-dead sweeps = sustained entry
				// block, not a transient cut. One structured log line per
				// incident; retries continue — a block may lift.
				if blockedRounds == 3 {
					var eb *EntriesBlockedError
					if errors.As(err, &eb) {
						c.logf("core: ENTRIES_BLOCKED addrs=%d sweeps=%d — all entry points unreachable; likely provider/TSPU block", eb.Attempts, blockedRounds)
					}
				}
			} else {
				blockedRounds = 0
			}
			c.logf("core: redial failed: %v", err)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

// errLivenessKill is the cause attached to a session the liveness watchdog
// retires after too many unanswered probes.
var errLivenessKill = errors.New("kal2: liveness probe failures")

// EnableLiveness starts a watchdog that probes the live session every `every`
// and kills it after `misses` consecutive failed probes, letting the
// EnableReconnect redialer take over. Needed because a blackholed carrier
// (packets silently dropped, no RST) leaves WaitClosed silent forever: the
// read loop blocks on a socket that never errors and writes just back up in
// the kernel. The probe runs inside an outer deadline so a Ping stuck behind
// a full outbound queue still counts as a miss instead of stalling the loop.
func (c *Client) EnableLiveness(every, pongTimeout time.Duration, misses int) {
	if every <= 0 {
		every = 4 * time.Second
	}
	if pongTimeout <= 0 {
		pongTimeout = 4 * time.Second
	}
	if misses <= 0 {
		misses = 2
	}
	go c.livenessLoop(every, pongTimeout, misses)
}

func (c *Client) livenessLoop(every, pongTimeout time.Duration, maxMisses int) {
	t := time.NewTicker(every)
	defer t.Stop()
	misses := 0
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		s := c.Session()
		if s == nil { // between loss and redial — the reconnect loop owns the gap
			misses = 0
			continue
		}
		if err := c.probe(s, pongTimeout, every); err == nil {
			misses = 0
			continue
		}
		misses++
		if misses >= maxMisses {
			c.logf("core: liveness: %d failed probes — killing session for redial", misses)
			misses = 0
			s.Kill(errLivenessKill)
		}
	}
}

// probe pings s with an outer deadline past Ping's own pong timeout: a Ping
// that cannot even enqueue (outbound lanes backed up behind a wedged carrier)
// reports as a miss rather than hanging the watchdog.
func (c *Client) probe(s *kal2.Session, pongTimeout, slack time.Duration) error {
	done := make(chan error, 1)
	c.pingMu.Lock()
	go func() {
		defer c.pingMu.Unlock()
		done <- s.Ping(nil, pongTimeout)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(pongTimeout + slack):
		return errLivenessKill
	}
}

// tryMigrate attempts one resumption of the frozen session over a fresh
// carrier (hedged race across the carrier list — the server's single-use
// ticket makes exactly one attempt stick). False means fall back to redial.
func (c *Client) tryMigrate(sess *kal2.Session) bool {
	rs, ok := sess.TicketState()
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cfg := c.cfg
	cfg.Resume = rs
	s, err := dialAny(ctx, cfg, int(c.rrIdx.Add(1)), c.scores)
	return err == nil && s == sess
}

// Scores exposes the live carrier scorecard for reporting.
func (c *Client) Scores() *core.Scorecard { return c.scores }

// reconnectLane watches one quasar lane, keeps it warm with pings, and
// redials into its slot when it dies. Contract with failover scoring (PR #7
// scorecard, when merged): this watchdog only kills *dead* lanes — a ping
// must actually error twice; a merely slow pong keeps the lane alive and the
// least-loaded stream picker simply starves it. Degradation is handled by
// score/quarantine logic, never by the kill path, so a throttled lane is
// backed off rather than destroyed.
func (c *Client) reconnectLane(i int) {
	for {
		sess := c.lanes[i].Load()
		if sess != nil {
			go func(s *kal2.Session) {
				t := time.NewTicker(time.Duration(lanePingEvery.Load()))
				defer t.Stop()
				for {
					select {
					case <-t.C:
						// A ping failure means the session is silently dead
						// (e.g. the server forgot it): close so WaitClosed
						// fires and this lane gets redialed. Two strikes —
						// a single lost pong must not kill a live session.
						// A slow-but-arriving pong is a throttle signal, not
						// death: it quarantines the lane via laneRTT.
						t0 := time.Now()
						if err := s.Ping([]byte("k"), time.Duration(lanePingTimeout.Load())); err != nil {
							t0 = time.Now()
							if err2 := s.Ping([]byte("k"), time.Duration(lanePingRetryTimeout.Load())); err2 != nil {
								_ = s.Close()
								return
							}
						}
						c.laneRTT[i].Store(int64(time.Since(t0)))
					case <-s.WaitClosed():
						return
					case <-c.stop:
						return
					}
				}
			}(sess)
			select {
			case <-sess.WaitClosed():
				c.lanes[i].CompareAndSwap(sess, nil)
			case <-c.stop:
				return
			}
		}
		c.logf("core: lane %d lost; redialing", i)
		backoff := time.Second
		for {
			select {
			case <-c.stop:
				return
			case <-time.After(backoff + time.Duration(rand.Int64N(int64(backoff/4)+1))):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			s, err := dialAny(ctx, c.cfg, int(c.rrIdx.Add(1)), c.scores)
			cancel()
			if err == nil {
				c.laneRTT[i].Store(0) // fresh session, unmeasured = healthy
				c.lanes[i].Store(s)
				c.logf("core: lane %d restored", i)
				break
			}
			c.logf("core: lane %d redial failed: %v", i, err)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

// ServeSocks exposes a local SOCKS5 proxy that forwards through whichever
// session is live — survives reconnects.
func (c *Client) ServeSocks(laddr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	go func() { _ = core.ServeSOCKS5(c.Session, ln) }()
	return ln, nil
}

// Ping checks liveness.
func (c *Client) Ping(ctx context.Context) error {
	s := c.Session()
	if s == nil {
		return fmt.Errorf("core: no live session")
	}
	c.pingMu.Lock()
	defer c.pingMu.Unlock()
	return core.PingSession(ctx, s)
}

// Close ends the session(s) and stops the reconnect watchdog.
func (c *Client) Close() error {
	var err error
	c.stopOnce.Do(func() {
		if c.stop != nil {
			close(c.stop)
		}
		if len(c.lanes) > 0 {
			for i := range c.lanes {
				if s := c.lanes[i].Swap(nil); s != nil {
					if e := s.Close(); e != nil {
						err = e
					}
				}
			}
			return
		}
		if s := c.Session(); s != nil {
			err = s.Close()
		}
	})
	return err
}

func toCarrierUsers(in []User) []carrier.User {
	out := make([]carrier.User, len(in))
	for i, u := range in {
		out[i] = carrier.User{ID: u.ID, PSK: u.PSK}
	}
	return out
}

var _ = http2.ErrCodeNo // keep http2 linked for drift

const defaultDecoyPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>It works</h1></body></html>`
