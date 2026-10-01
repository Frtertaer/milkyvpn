package carrier

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

// frontRelay stands up the serverless/CDN relay: a TLS endpoint that blindly
// forwards every request to the server's plain front listener (backend).
// Like the real gateways it only accepts HTTP/1.1 and reads the logical
// path from frontPathHeader — invoke URLs cannot carry arbitrary paths.
func frontRelay(t *testing.T, backend http.Handler, base string) *httptest.Server {
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bl.Close() })
	go func() { _ = http.Serve(bl, backend) }()

	target := &url.URL{Scheme: "http", Host: bl.Addr().String(), Path: base}
	rp := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get(frontPathHeader); p != "" {
			r.URL.Path = p
			r.Header.Del(frontPathHeader)
		}
		rp.ServeHTTP(w, r)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// frontMux builds the plain-HTTP mux kal2core.Serve exposes on FrontListen.
func frontMux(v *VeilListener) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(DefaultDriftPath, v.DriftHandler(DefaultDriftPath))
	mux.Handle(DefaultDriftPath+"/", v.DriftHandler(DefaultDriftPath))
	mux.Handle(DefaultMosaicPath, v.MosaicHandler(DefaultMosaicPath))
	mux.Handle(DefaultMosaicPath+"/", v.MosaicHandler(DefaultMosaicPath))
	return mux
}

func frontCfg(ts *testServer, relay *httptest.Server) ClientConfig {
	return ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
		Front:              relay.URL,
	}
}

// Mosaic tiles are request/response — the one carrier guaranteed to survive
// a buffering relay (cloud functions buffer the whole request).
func TestMosaicFronted(t *testing.T) {
	ts := newTestServer(t)
	relay := frontRelay(t, frontMux(ts.v), "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, _, err := DialMosaic(ctx, frontCfg(ts, relay), "")
	if err != nil {
		t.Fatalf("dial mosaic via front: %v", err)
	}
	defer sess.Close()
	streamEchoTest(t, sess)
}

// A relay mounted under a path prefix must still reach the keyed endpoint:
// the client prepends the front's base path to the carrier path.
func TestMosaicFrontedBasePath(t *testing.T) {
	ts := newTestServer(t)
	// StripPrefix-shaped relay: mount everything under /fn, forward the
	// remainder — mirrors a cloud function URL like …/d5x123/mosaic.
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bl.Close() })
	go func() { _ = http.Serve(bl, frontMux(ts.v)) }()
	target := &url.URL{Scheme: "http", Host: bl.Addr().String()}
	rp := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewUnstartedServer(http.StripPrefix("/fn", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get(frontPathHeader); p != "" {
			r.URL.Path = p
			r.Header.Del(frontPathHeader)
		}
		rp.ServeHTTP(w, r)
	})))
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cfg := frontCfg(ts, srv)
	cfg.Front = srv.URL + "/fn"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, _, err := DialMosaic(ctx, cfg, "")
	if err != nil {
		t.Fatalf("dial mosaic via front /fn: %v", err)
	}
	defer sess.Close()
	streamEchoTest(t, sess)
}

// WebSocket drift (cdn carrier) is transparently proxied by relays that
// pass Upgrade — e.g. Cloudflare Workers.
func TestDriftWSFronted(t *testing.T) {
	ts := newTestServer(t)
	relay := frontRelay(t, frontMux(ts.v), "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _, err := DialDriftWS(ctx, frontCfg(ts, relay), "")
	if err != nil {
		t.Fatalf("dial cdn via front: %v", err)
	}
	defer sess.Close()
	streamEchoTest(t, sess)
}

// NOTE: raw drift (one request open in both directions) deadlocks through
// buffering relays — the front finishes reading the request body only when
// it closes, while the client waits for the streamed response. Through a
// reverse proxy it can still work (httputil pipes the body), but the fronts
// this feature targets — serverless functions — buffer, so drift stays a
// direct/WS-capable-front carrier and is not tested here.
// Front parsing: default port, path prefixes, ws-scheme aliases.
func TestFrontParse(t *testing.T) {
	mk := func(raw string) *frontEndpoint {
		c := ClientConfig{Front: raw}
		return c.front()
	}
	cases := []struct {
		raw, addr, sni, base string
	}{
		{"https://d5x.apigw.yandexcloud.net", "d5x.apigw.yandexcloud.net:443", "d5x.apigw.yandexcloud.net", ""},
		{"https://w.workers.dev/mosaic", "w.workers.dev:443", "w.workers.dev", "/mosaic"},
		{"wss://gw.example.net:8443/x/", "gw.example.net:8443", "gw.example.net", "/x"},
		{"https://127.0.0.1:9443", "127.0.0.1:9443", "127.0.0.1", ""},
	}
	for _, c := range cases {
		fe := mk(c.raw)
		if fe == nil || fe.addr != c.addr || fe.sni != c.sni || fe.base != c.base {
			t.Fatalf("front %q: got %+v", c.raw, fe)
		}
	}
	if mk("") != nil || mk("::bad url::") != nil {
		t.Fatal("bad front should parse to nil")
	}
	c := ClientConfig{Front: "https://w.workers.dev/x", Addr: "1.2.3.4:443", SNI: "ours.dev"}
	if a := c.dialAddr(); a != "w.workers.dev:443" {
		t.Fatalf("dialAddr %q", a)
	}
	if u := c.requestURL("/api/v3/tiles/tok"); u != "https://w.workers.dev/x/" {
		t.Fatalf("requestURL %q", u)
	}
	h := make(http.Header)
	c.setFrontPath(h, "/api/v3/tiles/tok")
	if h.Get(frontPathHeader) != "/api/v3/tiles/tok" {
		t.Fatal("fronted request must carry the path in the header")
	}
	if c.legTLS("h2").ServerName != "w.workers.dev" {
		t.Fatal("fronted leg must use the front's own SNI")
	}
}
