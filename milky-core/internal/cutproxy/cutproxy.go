// Package cutproxy is a TCP proxy that truncates every flow once a byte
// budget has passed in both directions combined — the per-flow truncation
// observed on hostile networks (TSPU per-flow kill toward foreign hosting,
// long-lived TLS timeouts, idle NAT reaping). Test-only infrastructure;
// shared by carrier failover/migration tests.
package cutproxy

import (
	"net"
	"sync/atomic"
	"testing"
)

// Proxy counts flows it truncated and the largest flow it saw.
type Proxy struct {
	addr    string
	limit   int64
	maxFlow atomic.Int64
	flows   atomic.Int64
	cuts    atomic.Int64
}

// Start listens on 127.0.0.1:0 and forwards to upstream. limit == 0 forwards
// forever; otherwise every flow is cut once its combined byte count exceeds
// limit (TLS handshake bytes included).
func Start(t testing.TB, upstream string, limit int64) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{addr: ln.Addr().String(), limit: limit}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.flows.Add(1)
			go p.handle(c, upstream)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *Proxy) Addr() string      { return p.addr }
func (p *Proxy) Flows() int64      { return p.flows.Load() }
func (p *Proxy) Cuts() int64       { return p.cuts.Load() }
func (p *Proxy) MaxFlow() int64    { return p.maxFlow.Load() }

func (p *Proxy) handle(c net.Conn, upstream string) {
	defer c.Close()
	up, err := net.Dial("tcp", upstream)
	if err != nil {
		return
	}
	defer up.Close()
	var n atomic.Int64
	pipe := func(dst, src net.Conn) {
		defer dst.Close()
		defer src.Close()
		buf := make([]byte, 4096)
		for {
			k, err := src.Read(buf)
			if k > 0 {
				total := n.Add(int64(k))
				if p.limit > 0 && total > p.limit {
					p.cuts.Add(1)
					return
				}
				if _, werr := dst.Write(buf[:k]); werr != nil {
					return
				}
				for {
					old := p.maxFlow.Load()
					if total <= old || p.maxFlow.CompareAndSwap(old, total) {
						break
					}
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(up, c)
	pipe(c, up)
}
