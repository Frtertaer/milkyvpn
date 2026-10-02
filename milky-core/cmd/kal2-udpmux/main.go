// kal2-udpmux demultiplexes UDP/443 between the QUIC-shaped services on the
// box: Hysteria2 (sing-box, QUIC v1) and the KAL/2 UDP carriers (quic2 =
// QUIC v2, quasar = opaque AEAD datagrams). It owns the public socket and
// forwards each client flow to the right loopback backend, classified on the
// first datagram of the flow:
//
//	long-header + version 0x6b3343cf (QUIC v2, RFC 9369) → quic2
//	long-header + any other version (v1, drafts, version-negotiation) → hy2
//	everything else (opaque datagrams, short headers) → quasar
//
// Port-443-only networks then reach the UDP carriers too — whitelists and
// DPI rules that kill nonstandard ports see ordinary UDP/443.
package main

import (
	
	"encoding/binary"
	"flag"

	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	flowIdle     = 120 * time.Second
	dgramMax     = 64 * 1024
	reapInterval = 30 * time.Second
)

// classify picks the backend for a flow's first datagram. The backend keys
// are fixed: "quic2", "hy2", "quasar" — see backendAddrs.
func classify(pkt []byte) string {
	// QUIC long header: bit0 (0x80) set, fixed bit (0x40) set, version at
	// bytes 1..4. QUIC v2's version differs from every v1/draft version,
	// which is the whole reason quic2 is a separate backend.
	if len(pkt) >= 5 && pkt[0]&0xC0 == 0xC0 {
		if binary.BigEndian.Uint32(pkt[1:5]) == 0x6b3343cf {
			return "quic2"
		}
		return "hy2"
	}
	// quasar sends opaque AEAD datagrams (no plaintext header); anything
	// not a QUIC long header — random UDP, garbage — lands there and is
	// dropped unforgeably if it isn't ours.
	return "quasar"
}

// flow is one client→backend pair of sockets.
type flow struct {
	toBackend *net.UDPConn
	last      time.Time
}

var backends = map[string]string{
	"quic2":  "127.0.0.1:20444",
	"hy2":    "127.0.0.1:23443",
	"quasar": "127.0.0.1:20443",
}

func main() {
	listen := flag.String("listen", ":443", "public UDP listen address")
	hy2 := flag.String("hy2", backends["hy2"], "backend for QUIC v1 / hysteria2 traffic")
	quic2 := flag.String("quic2", backends["quic2"], "backend for QUIC v2 (kal2 quic2) traffic")
	quasar := flag.String("quasar", backends["quasar"], "backend for non-QUIC datagrams (kal2 quasar)")
	flag.Parse()
	backends["hy2"], backends["quic2"], backends["quasar"] = *hy2, *quic2, *quasar

	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("udpmux: bad -listen: %v", err)
	}
	in, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("udpmux: listen %s: %v", *listen, err)
	}
	defer in.Close()
	log.Printf("udpmux: %s → quicv2=%s quicv1/hy2=%s other=%s", *listen, backends["quic2"], backends["hy2"], backends["quasar"])

	var mu sync.Mutex
	flows := map[string]*flow{}

	bkey := map[string]*net.UDPAddr{}
	for name, a := range backends {
		ua, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			log.Fatalf("udpmux: bad %s backend %q: %v", name, a, err)
		}
		bkey[name] = ua
	}

	// Idle-flow reaper: client NATs die silently, so flows must expire or
	// the table grows without bound.
	go func() {
		t := time.NewTicker(reapInterval)
		defer t.Stop()
		for range t.C {
			mu.Lock()
			now := time.Now()
			for k, f := range flows {
				if now.Sub(f.last) > flowIdle {
					_ = f.toBackend.Close()
					delete(flows, k)
				}
			}
			mu.Unlock()
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = in.Close()
	}()

	buf := make([]byte, dgramMax)
	for {
		n, src, err := in.ReadFromUDP(buf)
		if err != nil {
			return // socket closed on shutdown
		}
		key := src.String()
		mu.Lock()
		f := flows[key]
		if f == nil {
			backend := classify(buf[:n])
			dst := bkey[backend]
			conn, derr := net.DialUDP("udp", nil, dst)
			if derr != nil {
				mu.Unlock()
				continue
			}
			f = &flow{toBackend: conn, last: time.Now()}
			flows[key] = f
			// Reply path: backend → this client flow.
			go func(client *net.UDPAddr, c *net.UDPConn, k string) {
				rb := make([]byte, dgramMax)
				for {
					rn, rerr := c.Read(rb)
					if rerr != nil {
						return
					}
					mu.Lock()
					if ff := flows[k]; ff != nil {
						ff.last = time.Now()
					}
					mu.Unlock()
					_, _ = in.WriteToUDP(rb[:rn], client)
				}
			}(src, conn, key)
		}
		f.last = time.Now()
		mu.Unlock()
		// Best-effort: a dead backend write just drops the datagram (UDP
		// semantics); the flow itself is reaped when idle.
		_, _ = f.toBackend.Write(buf[:n])
	}
}
