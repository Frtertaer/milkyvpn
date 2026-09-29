package kal2

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent Pings used to corrupt the pong registry: registerPong blindly
// overwrote s.pongReg, so the second caller hijacked the first's pong and the
// first timed out — a spurious failure the lanes watchdog reads as lane death
// (kill-vs-quarantine contract). Unsynchronized access also trips -race.
func TestMuxConcurrentPings(t *testing.T) {
	client, _ := pipeSessions(t) // server auto-pongs in dispatch

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("ping-%d", i))
			if err := client.Ping(payload, 5*time.Second); err != nil {
				errs <- fmt.Errorf("ping %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// SFQ: a bulk stream deep into a multi-MB backlog must not pin an interactive
// stream's first bytes — the least-emitted stream wins the next batch.
func TestMuxSFQInteractiveUnderBulk(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	bulk, err := client.Open("bulk.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open bulk: %v", err)
	}
	<-accepted

	// Push several MB — far beyond the wire capacity of the test pipe, so a
	// deep data-lane backlog accumulates while the writer blocks on slots.
	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		chunk := make([]byte, 16*1024)
		for i := 0; i < 256; i++ { // 4 MiB
			if _, err := bulk.Write(chunk); err != nil {
				return
			}
		}
	}()
	// Let the backlog build.
	time.Sleep(200 * time.Millisecond)

	interactive, err := client.Open("interactive.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open interactive: %v", err)
	}
	srvInteractive := <-accepted

	start := time.Now()
	msg := []byte("ping-pong-interactive")
	if _, err := interactive.Write(msg); err != nil {
		t.Fatalf("interactive write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = srvInteractive.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(srvInteractive, got); err != nil {
		t.Fatalf("interactive starved behind bulk: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("payload mismatch %q", got)
	}
	t.Logf("interactive delivered under bulk in %s", time.Since(start))
	_ = interactive.Close()
	_ = bulk.Close()
	<-bulkDone
}

// A remotely-closed stream must be evicted from the session's stream map:
// before the fix, MsgClose/MsgRst never deleted the entry, so a long-lived
// session accumulated a zombie per client-closed stream.
func TestMuxRemoteCloseEvicts(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	const n = 50
	for i := 0; i < n; i++ {
		st, err := client.Open("evict.example", 443, 3*time.Second)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		<-accepted
		if err := st.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		server.smu.RLock()
		left := len(server.streams)
		server.smu.RUnlock()
		if left == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d zombie streams left on the server after remote close", left)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Long-run mux soak under -race: churn opens, reads, writes, closes, and
// pings across sessions while a bulk writer saturates the data lane. Gated —
// runs only when KAL2_SOAK=1 (the carrier-track 15-minute soak gate).
func TestMuxSoak(t *testing.T) {
	if os.Getenv("KAL2_SOAK") == "" {
		t.Skip("set KAL2_SOAK=1 to run the 15-minute mux soak")
	}
	duration := 15 * time.Minute
	if v := os.Getenv("KAL2_SOAK_MINUTES"); v != "" {
		if d, err := time.ParseDuration(v + "m"); err == nil {
			duration = d
		}
	}
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	deadline := time.Now().Add(duration)
	var ops atomic.Int64
	stop := make(chan struct{})

	// Memory watch: a leak in either direction shows as rising heap or a
	// growing stream map between samples.
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				server.smu.RLock()
				srvStreams := len(server.streams)
				server.smu.RUnlock()
				client.smu.RLock()
				cliStreams := len(client.streams)
				client.smu.RUnlock()
				t.Logf("soak: heap=%dMB streams cli=%d srv=%d ops=%d",
					m.HeapAlloc>>20, cliStreams, srvStreams, ops.Load())
			case <-stop:
				return
			}
		}
	}()

	// Bulk writer saturating the data lane for the whole soak.
	go func() {
		st, err := client.Open("soak-bulk", 443, 10*time.Second)
		if err != nil {
			return
		}
		chunk := make([]byte, 16*1024)
		for {
			select {
			case <-stop:
				_ = st.Close()
				return
			default:
				if _, err := st.Write(chunk); err != nil {
					return
				}
			}
		}
	}()

	// Interactive churn: open, write, read-echo (server echoes via serveLoop
	// ack only — write on the server side for the round trip), close.
	var churnWG sync.WaitGroup
	for w := 0; w < 4; w++ {
		churnWG.Add(1)
		go func(w int) {
			defer churnWG.Done()
			payload := []byte(fmt.Sprintf("churn-%d", w))
			for time.Now().Before(deadline) {
				st, err := client.Open("soak.example", 443, 10*time.Second)
				if err != nil {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				srv := <-accepted
				if _, err := st.Write(payload); err == nil {
					go func(s *Stream) {
						defer s.Close()
						buf := make([]byte, len(payload))
						_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
						if _, err := io.ReadFull(s, buf); err == nil {
							_, _ = s.Write(buf) // echo back
						}
					}(srv)
					buf := make([]byte, len(payload))
					_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
					_, _ = io.ReadFull(st, buf)
				}
				_ = st.Close()
				ops.Add(1)
			}
		}(w)
	}

	// Concurrent pings for the whole soak (the registry stress path).
	go func() {
		for time.Now().Before(deadline) {
			if err := client.Ping([]byte("soak"), 10*time.Second); err != nil {
				t.Errorf("soak ping: %v", err)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	time.Sleep(time.Until(deadline))
	close(stop)
	churnWG.Wait()
	if ops.Load() < 10 {
		t.Fatalf("soak stalled: only %d stream cycles in %s", ops.Load(), duration)
	}
	t.Logf("soak done: %d stream cycles", ops.Load())
}


