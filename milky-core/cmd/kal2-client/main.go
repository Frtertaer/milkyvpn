// kal2-client: local client — establishes a kal2 session and exposes a local
// SOCKS5 proxy. Also supports -fetch to pull a URL through the tunnel for
// testing.
//
//	kal2-client -addr kal.example.dev:443 -sni kal.example.dev \
//	  -pub <hex> -psk <hex|b64> [-carrier drift] [-socks 127.0.0.1:10808] \
//	  [-fetch https://ifconfig.me]
//
// -addr accepts a comma-separated endpoint list (e.g. direct IP, domestic
// relay, CDN edge): dial tries them in rotating order and the reconnect
// watchdog rotates through them after a drop.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/tun"
	"github.com/Frtertaer/milkyvpn/milky-core/pkg/kal2core"
)

func main() {
	// Internal mode: crash watchdog child for Darwin bypass routes
	// (kal2-client -route-janitor <ledger>). Not a user-facing flag.
	if len(os.Args) >= 3 && os.Args[1] == "-route-janitor" {
		runRouteJanitor(os.Args[2])
		return
	}
	addr := flag.String("addr", "", "server host:port (comma list for failover)")
	sni := flag.String("sni", "", "TLS SNI")
	pub := flag.String("pub", "", "server ed25519 pub (hex)")
	psk := flag.String("psk", "", "user PSK (hex|b64)")
	carrier := flag.String("carrier", "auto", "auto|veil|drift")
	driftPath := flag.String("drift", "", "drift path")
	socks := flag.String("socks", "127.0.0.1:10808", "local socks listen")
	tunName := flag.String("tun", "", "create a TUN adapter with this name and tunnel all device traffic (needs root/admin)")
	ctlAddr := flag.String("ctl", "", "control socket: log lines are mirrored here and 'stop' exits (used when spawned elevated)")
	logPath := flag.String("log", "", "append logs to this file as well (rolls to .1 past ~1MB; parent dirs are created)")
	fetch := flag.String("fetch", "", "fetch URL through tunnel and exit")
	fetchMax := flag.Int64("fetchmax", 32<<20, "max bytes to read for -fetch")
	proxyURL := flag.String("proxy", "", "base-dial proxy (http://user:pass@host:port)")
	insecure := flag.Bool("insecure", false, "skip carrier TLS chain verify (inner handshake still authenticates the server pubkey)")
	ech := flag.String("ech", "", "base64 ECHConfigList — Encrypted Client Hello on veil (outer SNI shows only the cover name)")
	pin := flag.String("pin", "", "comma list of sha256(SPKI) pins (hex|b64) replacing CA verification")
	cover := flag.Bool("cover", true, "jittered chaff traffic against timing/size DPI heuristics")
	front := flag.String("front", "", "front relay URL(s), comma-separated (https://host[:port][/base]) — one = front-only; several = universal sweep: direct first, then each front in order")
	qfec := flag.String("qfec", "0,0", "quasar carrier Reed-Solomon FEC shards data,parity (e.g. 10,3)")
	qres := flag.Int("qresend", 0, "quasar client KCP dup-ack fast-retransmit threshold (0 = RTO only)")
	lanes := flag.Int("lanes", 0, "number of parallel carrier sessions (multi-lane stream spreading)")
	qlanes := flag.Int("qlanes", 1, "quasar parallel sessions; streams round-robin across lanes")
	qwnd := flag.Int("qwnd", 0, "quasar receive window in segments; paces the server's offered rate to ~wnd*mtu/RTT (0 = 16384)")
	flag.Parse()

	var logFile *os.File
	if *logPath != "" {
		f, err := openLogFile(*logPath, 1<<20)
		if err != nil {
			log.Printf("kal2: cannot open -log %s: %v", *logPath, err)
		} else {
			logFile = f
			defer logFile.Close()
			log.SetOutput(io.MultiWriter(failsoft{os.Stderr}, failsoft{logFile}))
			log.Printf("kal2: logging to %s", *logPath)
		}
	}

	serverPub, err := kal2core.DecodeKey(*pub)
	if err != nil {
		log.Fatalf("bad -pub: %v", err)
	}
	userPSK, err := kal2core.DecodeKey(*psk)
	if err != nil {
		log.Fatalf("bad -psk: %v", err)
	}
	if *addr == "" {
		log.Fatal("need -addr")
	}
	if *sni == "" {
		*sni, _, _ = net.SplitHostPort(strings.TrimSpace(strings.Split(*addr, ",")[0]))
	}

	var addrs []string
	for _, a := range strings.Split(*addr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		log.Fatal("need -addr")
	}
	fecD, fecP := 0, 0
	if *qfec != "0,0" {
		if _, err := fmt.Sscanf(*qfec, "%d,%d", &fecD, &fecP); err != nil || fecD < 0 || fecP < 0 {
			log.Fatalf("bad -qfec %q (want data,parity)", *qfec)
		}
	}
	// bindGuard pins carrier sockets to the physical egress device once the
	// TUN device is configured. On Darwin it also maintains the /32 bypass
	// routes bound sockets require — the route janitor removes those after
	// a crash since they are not device-scoped.
	bindGuard := tun.NewBindGuard()
	if *tunName != "" {
		// The first session dials before tun.Configure can publish the
		// device — seed it now or the socket's next dst revalidation loops
		// carrier traffic into the tunnel.
		bindGuard.Set(tun.DefaultEgress())
		armRouteJanitor(bindGuard)
	}
	cfg := kal2core.ClientConfig{
		Addr:               addrs[0],
		Addrs:              addrs,
		SNI:                *sni,
		ServerPub:          serverPub,
		PSK:                userPSK,
		Carrier:            *carrier,
		DriftPath:          *driftPath,
		Logf:               log.Printf,
		InsecureSkipVerify: *insecure,
		Cover:              *cover,
		QuasarFEC:          [2]int{fecD, fecP},
		QuasarRcvWnd:       *qwnd,
		QuasarResend:       *qres,
		Lanes:              *lanes,
		QuasarLanes:        *qlanes,
		DialControl:        bindGuard.Control,
		Fronts:             frontURLs(*front),
	}
	for _, p := range strings.Split(*pin, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		b, err := kal2core.DecodeKey(p)
		if err != nil {
			log.Fatalf("bad -pin: %v", err)
		}
		cfg.PinSHA256 = append(cfg.PinSHA256, b)
	}
	if *ech != "" {
		list, err := kal2core.DecodeBase64(*ech)
		if err != nil {
			log.Fatalf("bad -ech: %v", err)
		}
		cfg.ECHConfigList = list
	}
	if *proxyURL != "" {
		d, err := httpConnectDialer(*proxyURL, bindGuard.Control)
		if err != nil {
			log.Fatal(err)
		}
		cfg.DialContext = d
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cli, err := kal2core.Dial(ctx, cfg)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	log.Printf("kal2: session up via %s", *carrier)

	if *fetch != "" {
		st, err := openURL(cli, *fetch)
		if err != nil {
			log.Fatalf("fetch: %v", err)
		}
		defer st.Close()
		out, err := io.ReadAll(io.LimitReader(st, *fetchMax))
		if err != nil {
			log.Printf("fetch: read error after %d bytes: %v", len(out), err)
		}
		fmt.Println(string(out))
		return
	}

	ln, err := cli.ServeSocks(*socks)
	if err != nil {
		log.Fatal(err)
	}
	cli.EnableReconnect()
	log.Printf("kal2: socks5 on %s (reconnect watchdog on)", ln.Addr())

	var ctl *ctlServer
	if *ctlAddr != "" {
		ctl, err = startCtl(*ctlAddr)
		if err != nil {
			log.Fatalf("ctl: %v", err)
		}
		defer ctl.close()
		outs := []io.Writer{failsoft{os.Stderr}, failsoft{ctl}}
		if logFile != nil {
			outs = append(outs, failsoft{logFile})
		}
		log.SetOutput(io.MultiWriter(outs...))
		ctl.echo("kal2: session up via " + *carrier)
	}

	sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()

	var tunDone chan struct{}
	if *tunName != "" {
		// Full-device mode: the TUN adapter routes all traffic into kal2
		// streams. Still serves SOCKS5 alongside — both paths stay live
		// across reconnects via cli.Session().
		tcfg := &tun.Config{
			Name:      *tunName,
			Addr:      tun.DefaultAddr,
			Bind:      bindGuard,
			ServerIPs: resolveServerIPs(addrs),
			Logf:      log.Printf,
			OpenTCP: func(ctx context.Context, target string) (tun.Stream, error) {
				sess := cli.Session()
				if sess == nil {
					return nil, fmt.Errorf("no live session")
				}
				host, ps, err := net.SplitHostPort(target)
				if err != nil {
					return nil, err
				}
				var port int
				if _, err := fmt.Sscanf(ps, "%d", &port); err != nil {
					return nil, err
				}
				return sess.Open(host, uint16(port), 15*time.Second)
			},
			OpenUDP: func(ctx context.Context) (tun.Stream, error) {
				sess := cli.Session()
				if sess == nil {
					return nil, fmt.Errorf("no live session")
				}
				return sess.OpenNet("udp", "0.0.0.0", 0, 15*time.Second)
			},
		}
		tunDone = make(chan struct{})
		go func() {
			defer close(tunDone)
			if err := tun.Run(sigCtx, tcfg); err != nil {
				log.Printf("kal2: tun stopped: %v", err)
			}
		}()
		log.Printf("kal2: tun requested (%s)", *tunName)
	}
	if ctl != nil {
		// 'stop' on the control channel exits cleanly: the tun goroutine owns
		// route/adapter teardown — returning early would kill it mid-flight
		// and orphan the /32 server-bypass routes.
		select {
		case <-ctl.stopCh:
		case <-sigCtx.Done():
		}
	} else {
		<-sigCtx.Done()
	}
	stopSig()
	// Give the TUN goroutine a moment to tear routes down before exit.
	if tunDone != nil {
		select {
		case <-tunDone:
		case <-time.After(4 * time.Second):
		}
	}
}

// failsoft swallows Write errors so a dead sink cannot starve the rest of
// the MultiWriter chain — an elevated GUI-subsystem spawn has an invalid
// stderr handle, and without this every line died on the first Write.
type failsoft struct{ io.Writer }

func (f failsoft) Write(p []byte) (int, error) {
	_, _ = f.Writer.Write(p)
	return len(p), nil
}


// ctlServer is a TCP control channel: the client mirrors its log lines to
// the connected peer and exits when a peer sends "stop". Accepts repeatedly —
// an orphaned elevated helper must still answer a later peer's 'stop' (a new
// client respawns cannot bind :11909 while the orphan holds it).
type ctlServer struct {
	ln       net.Listener
	conn     net.Conn
	mu       sync.Mutex
	stopCh   chan struct{}
	stopOnce sync.Once
	echoed   []string
}

func startCtl(addr string) (*ctlServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	c := &ctlServer{ln: ln, stopCh: make(chan struct{})}
	go c.accept()
	return c, nil
}

func (c *ctlServer) accept() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return
		}
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
		}
		c.conn = conn
		for _, l := range c.echoed {
			_, _ = fmt.Fprintln(conn, l)
		}
		c.echoed = nil
		c.mu.Unlock()
		go func() {
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				if strings.TrimSpace(sc.Text()) == "stop" {
					c.stopOnce.Do(func() { close(c.stopCh) })
					return
				}
			}
			// Peer vanished — keep running; the tunnel is still up.
		}()
	}
}

// Write mirrors log lines to the control peer (io.Writer for log output).
func (c *ctlServer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_, _ = c.conn.Write(p)
		return len(p), nil
	}
	c.echoed = append(c.echoed, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (c *ctlServer) echo(line string) { _, _ = c.Write([]byte(line + "\n")) }

func (c *ctlServer) close() { c.ln.Close() }

// openLogFile rolls path to path.1 once it exceeds maxBytes — one backlog
// generation is kept, enough for field diagnostics without unbounded growth
// on long soaks — then opens it for appending with a start banner.
func openLogFile(path string, maxBytes int64) (*os.File, error) {
	if st, err := os.Stat(path); err == nil && st.Size() > maxBytes {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(f, "=== kal2-client started %s ===\n", time.Now().Format(time.RFC3339))
	return f, nil
}

func openURL(cli *kal2core.Client, raw string) (io.ReadCloser, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := uint16(443)
	if u.Scheme == "http" {
		port = 80
	}
	if p := u.Port(); p != "" {
		var pp int
		if _, err := fmt.Sscanf(p, "%d", &pp); err == nil {
			port = uint16(pp)
		}
	}
	st, err := core.OpenStream(cli.Sess, host, port, 15*time.Second)
	if err != nil {
		return nil, err
	}
	reqHeaders := "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	if u.Scheme == "https" {
		tc := tls.Client(st, &tls.Config{
			ServerName: host,
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err := tc.Handshake(); err != nil {
			st.Close()
			return nil, fmt.Errorf("inner TLS to %s: %w", host, err)
		}
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			return fetchH2(tc, u, reqHeaders)
		}
		// plain http/1.1 over the negotiated TLS stream
		fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Host, reqHeaders)
		return tc, nil
	}
	fmt.Fprintf(st, "GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Host, reqHeaders)
	return st, nil
}

// fetchH2 issues the GET over an h2 connection already established on c.
// Cloudflare-fronted sites that close HTTP/1.1 connections (e.g. chatgpt.com)
// answer normally over h2.
func fetchH2(c net.Conn, u *url.URL, ua string) (io.ReadCloser, error) {
	cc, err := (&http2.Transport{}).NewClientConn(c)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Host:   u.Host,
		Header: http.Header{
			"User-Agent":      {ua},
			"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language": {"en-US,en;q=0.9"},
		},
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return &h2Body{ReadCloser: resp.Body, status: resp.StatusCode}, nil
}

type h2Body struct {
	io.ReadCloser
	status int
}

func (b *h2Body) Close() error { return b.ReadCloser.Close() }

// httpConnectDialer builds a DialContext that tunnels through an HTTP CONNECT
// proxy (http://[user:pass@]host:port). control, when non-nil, hooks socket
// creation (TUN mode egress-device binding).
func httpConnectDialer(raw string, control func(network, address string, c syscall.RawConn) error) (func(context.Context, string, string) (net.Conn, error), error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy scheme %q unsupported (use http://)", u.Scheme)
	}
	proxyAddr := u.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":8080"
	}
	var auth string
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw))
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Control: control}
		c, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if auth != "" {
			req += "Proxy-Authorization: " + auth + "\r\n"
		}
		req += "\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			c.Close()
			return nil, err
		}
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return nil, err
		}
		parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(parts) < 2 || parts[1] != "200" {
			c.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(line))
		}
		// Drain remaining headers.
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				c.Close()
				return nil, err
			}
			if l == "\r\n" || l == "\n" {
				break
			}
		}
		_ = c.SetDeadline(time.Time{})
		// Preserve any buffered bytes past the headers.
		if br.Buffered() > 0 {
			return &prefixReaderConn{Conn: c, r: br}, nil
		}
		return c, nil
	}, nil
}

// resolveServerIPs flattens the endpoint list to literal v4 addresses for the
// Darwin /32 bypasses — hostnames resolve once here and again lazily per-dial
// inside BindGuard.Control when a carrier reconnects.
func resolveServerIPs(addrs []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(ip net.IP) {
		if ip == nil || ip.To4() == nil {
			return
		}
		s := ip.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			host = a
		}
		if ip := net.ParseIP(host); ip != nil {
			add(ip)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			add(ip)
		}
	}
	return out
}

// prefixReaderConn reads buffered bytes before the underlying conn.
type prefixReaderConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixReaderConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// waitForTun cancels the tun goroutine and waits for its deferred teardown
// (route restore + adapter close); false on timeout.
func waitForTun(cancel context.CancelFunc, done <-chan struct{}, d time.Duration) bool {
	if cancel == nil || done == nil {
		return true
	}
	cancel()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// frontURLs splits the -front comma list into separate relay URLs.
func frontURLs(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
