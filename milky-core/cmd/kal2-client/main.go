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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/tun"
	"github.com/Frtertaer/milkyvpn/milky-core/pkg/kal2core"
)

func main() {
	addr := flag.String("addr", "", "server host:port (comma list for failover)")
	sni := flag.String("sni", "", "TLS SNI")
	pub := flag.String("pub", "", "server ed25519 pub (hex)")
	psk := flag.String("psk", "", "user PSK (hex|b64)")
	carrier := flag.String("carrier", "auto", "auto|veil|drift")
	driftPath := flag.String("drift", "", "drift path")
	socks := flag.String("socks", "127.0.0.1:10808", "local socks listen")
	tunName := flag.String("tun", "", "create a wintun adapter with this name and tunnel all device traffic (Windows, needs admin)")
	ctlAddr := flag.String("ctl", "", "control socket: log lines are mirrored here and 'stop' exits (used when spawned elevated)")
	fetch := flag.String("fetch", "", "fetch URL through tunnel and exit")
	fetchMax := flag.Int64("fetchmax", 32<<20, "max bytes to read for -fetch")
	proxyURL := flag.String("proxy", "", "base-dial proxy (http://user:pass@host:port)")
	insecure := flag.Bool("insecure", false, "skip carrier TLS chain verify (inner handshake still authenticates the server pubkey)")
	ech := flag.String("ech", "", "base64 ECHConfigList — Encrypted Client Hello on veil (outer SNI shows only the cover name)")
	cover := flag.Bool("cover", true, "jittered chaff traffic against timing/size DPI heuristics")
	flag.Parse()

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
	}
	if *ech != "" {
		list, err := base64.StdEncoding.DecodeString(*ech)
		if err != nil {
			list, err = base64.RawURLEncoding.DecodeString(*ech)
		}
		if err != nil {
			log.Fatalf("bad -ech: %v", err)
		}
		cfg.ECHConfigList = list
	}
	if *proxyURL != "" {
		d, err := httpConnectDialer(*proxyURL)
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
		log.SetOutput(io.MultiWriter(os.Stderr, ctl))
		ctl.echo("kal2: session up via " + *carrier)
	}

	if *tunName != "" {
		// Full-device mode: the TUN adapter routes all traffic into kal2
		// streams. Still serves SOCKS5 alongside — both paths stay live
		// across reconnects via cli.Session().
		var serverIPs []string
		for _, a := range addrs {
			host, _, _ := net.SplitHostPort(a)
			if net.ParseIP(host) != nil {
				serverIPs = append(serverIPs, host)
				continue
			}
			if ips, err := net.LookupIP(host); err == nil {
				for _, ip := range ips {
					if ip4 := ip.To4(); ip4 != nil {
						serverIPs = append(serverIPs, ip4.String())
					}
				}
			}
		}
		tcfg := &tun.Config{
			Name:      *tunName,
			Addr:      tun.DefaultAddr,
			ServerIPs: serverIPs,
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
		go func() {
			if err := tun.Run(context.Background(), tcfg); err != nil {
				log.Printf("kal2: tun stopped: %v", err)
			}
		}()
		log.Printf("kal2: tun requested (%s)", *tunName)
	}
	if ctl != nil {
		// 'stop' on the control channel exits cleanly (defers restore routes).
		select {
		case <-ctl.stopCh:
			return
		}
	}
	select {}
}

// ctlServer is a one-shot TCP control channel: the client mirrors its log
// lines to the peer and exits when the peer sends "stop".
type ctlServer struct {
	ln     net.Listener
	conn   net.Conn
	mu     sync.Mutex
	stopCh chan struct{}
	echoed []string
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
	conn, err := c.ln.Accept()
	if err != nil {
		return
	}
	c.mu.Lock()
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
				close(c.stopCh)
				return
			}
		}
		// Peer vanished — keep running; the tunnel is still up.
	}()
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
// proxy (http://[user:pass@]host:port).
func httpConnectDialer(raw string) (func(context.Context, string, string) (net.Conn, error), error) {
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
		var d net.Dialer
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

// prefixReaderConn reads buffered bytes before the underlying conn.
type prefixReaderConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixReaderConn) Read(b []byte) (int, error) { return p.r.Read(b) }
