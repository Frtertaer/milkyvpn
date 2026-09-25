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
	"net/url"
	"strings"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/core"
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
	fetch := flag.String("fetch", "", "fetch URL through tunnel and exit")
	fetchMax := flag.Int64("fetchmax", 32<<20, "max bytes to read for -fetch")
	proxyURL := flag.String("proxy", "", "base-dial proxy (http://user:pass@host:port)")
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
		Addr:      addrs[0],
		Addrs:     addrs,
		SNI:       *sni,
		ServerPub: serverPub,
		PSK:       userPSK,
		Carrier:   *carrier,
		DriftPath: *driftPath,
		Logf:      log.Printf,
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
	select {}
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
	var rwc io.ReadWriteCloser = st
	if u.Scheme == "https" {
		tc := tls.Client(st, &tls.Config{ServerName: host})
		if err := tc.Handshake(); err != nil {
			st.Close()
			return nil, fmt.Errorf("inner TLS to %s: %w", host, err)
		}
		rwc = tc
	}
	path := u.RequestURI()
	fmt.Fprintf(rwc, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n", path, u.Host)
	return &readCloser{rwc}, nil
}

type readCloser struct{ io.ReadWriteCloser }

func (r *readCloser) Read(b []byte) (int, error) {
	n, err := r.ReadWriteCloser.Read(b)
	return n, err
}

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
		// Preserve any buffered bytes past the headers.
		if br.Buffered() > 0 {
			return &prefixReaderConn{Conn: c, r: br}, nil
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}, nil
}

// prefixReaderConn reads buffered bytes before the underlying conn.
type prefixReaderConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixReaderConn) Read(b []byte) (int, error) { return p.r.Read(b) }
