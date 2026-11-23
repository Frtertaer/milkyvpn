package kal2

// Reliability contract of a stream: it either delivers every byte in order
// and ends with io.EOF, or it ends with an error BOTH ends can see. Each test
// here failed on the v2.1 session layer in a way that looked like success.

import (
	"errors"
	"io"
	"runtime"
	"testing"
	"time"
)

// A stream reset by the peer must read as an abort. It used to read as a
// clean EOF — an application relaying an HTTP body would hand the user a
// truncated file and call it complete.
func TestStreamResetIsNotEOF(t *testing.T) {
	client, server := pipeSessions(t)
	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			_, _ = st.Write([]byte("partial"))
			_ = st.Reset()
		}
	}()
	st, err := client.OpenOpt("reset.example", 443)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	n, rerr := io.Copy(io.Discard, st)
	if rerr == nil {
		t.Fatalf("RST surfaced as a clean EOF after %d bytes", n)
	}
	if !IsAbort(rerr) {
		t.Fatalf("want an abort, got %v", rerr)
	}
}

// A refused dial under optimistic open (OPEN_ACK != 0) is an abort too.
func TestRefusedDialIsNotEOF(t *testing.T) {
	client, server := pipeSessions(t)
	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			_ = st.Ack(0x05)
			_ = st.Close()
		}
	}()
	st, err := client.OpenOpt("refused.example", 443)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, rerr := io.Copy(io.Discard, st); !IsAbort(rerr) {
		t.Fatalf("refused dial: want an abort, got %v", rerr)
	}
}

// The session dies mid-transfer (no resumption possible): the reader gets
// what arrived, then an abort — not EOF.
func TestSessionDeathIsNotEOF(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)
	st, err := client.Open("death.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv := <-accepted
	go func() {
		chunk := make([]byte, 16<<10)
		for i := 0; i < 64; i++ {
			if _, err := srv.Write(chunk); err != nil {
				return
			}
		}
		_ = server.rw.Close() // the transport dies abruptly: no CLOSE record
	}()
	n, rerr := io.Copy(io.Discard, st)
	if rerr == nil {
		t.Fatalf("session death surfaced as a clean EOF after %d bytes", n)
	}
	if !IsAbort(rerr) {
		t.Fatalf("want an abort, got %v", rerr)
	}
}

// A graceful close still reads as io.EOF after every byte.
func TestGracefulCloseIsEOF(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)
	st, err := client.Open("eof.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv := <-accepted
	const total = 3 << 20
	go func() {
		if err := pump(srv, 'S', total, 32<<10); err != nil {
			t.Errorf("pump: %v", err)
		}
		_ = srv.Close()
	}()
	got, n, err := drain(st, total)
	if err != nil || got != wantHash('S', total) {
		t.Fatalf("read %d/%d err=%v", n, total, err)
	}
	if _, err := st.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after a graceful close: want io.EOF, got %v", err)
	}
}

// Closing a session must fail its streams at once. A migratable session used
// to freeze instead, leaving every reader hung for the two-minute resumption
// TTL — after a failed migration the user's connections stalled instead of
// failing over to the fresh session.
func TestSessionCloseFailsStreamsPromptly(t *testing.T) {
	p, _ := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("close.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	<-accepted
	p.waitTicket(t)

	done := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = p.client.Close()
	select {
	case err := <-done:
		if err == nil || err == io.EOF {
			t.Fatalf("closed session: want an error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream reader still blocked 3s after its session was closed")
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("write on a closed session succeeded")
	}
}

// Once the peer has closed or reset a stream, writing to it must fail: the
// peer is gone. Writes used to succeed forever into the void, so a relay
// kept pumping a source nobody was reading.
func TestWriteAfterPeerGoneFails(t *testing.T) {
	for _, mode := range []string{"close", "reset"} {
		t.Run(mode, func(t *testing.T) {
			client, server := pipeSessions(t)
			accepted := serveLoop(t, server)
			st, err := client.Open("gone.example", 443, 3*time.Second)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			srv := <-accepted
			if mode == "close" {
				_ = st.Close()
			} else {
				_ = st.Reset()
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				_, werr := srv.Write(make([]byte, 1024))
				if werr != nil {
					if mode == "reset" && !IsAbort(werr) {
						t.Fatalf("write after peer reset: want an abort, got %v", werr)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("writes still succeed 3s after the peer's %s", mode)
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

// A consumer slower than the tunnel. The record channel has no per-stream
// credit, so the stream cannot be slowed down and is aborted once its
// receive buffer is full — but BOTH ends must learn that. Before, the reader
// saw a clean EOF at ~50 MiB of a 96 MiB transfer and the writer was told
// all 96 MiB had been delivered.
func TestSlowConsumerOverflowIsVisibleToBothEnds(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)
	st, err := client.Open("slow.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv := <-accepted

	const total = 96 << 20
	werr := make(chan error, 1)
	go func() {
		err := pump(srv, 'S', total, 64<<10)
		if err == nil {
			err = srv.Close()
		}
		werr <- err
	}()

	time.Sleep(1500 * time.Millisecond) // the consumer stalls...
	_, n, rerr := drain(st, total)      // ...then tries to take everything
	if rerr == nil {
		// The whole payload fitting is fine too — it must then be intact,
		// which drain's caller would check; here the buffer is smaller.
		t.Fatalf("reader got all %d bytes: the receive cap did not engage", n)
	}
	if rerr == io.EOF || errors.Is(rerr, io.ErrUnexpectedEOF) {
		t.Fatalf("overflow surfaced as a clean end of stream after %d/%d bytes", n, total)
	}
	if !IsAbort(rerr) {
		t.Fatalf("reader: want an abort, got %v after %d bytes", rerr, n)
	}
	select {
	case err := <-werr:
		if err == nil {
			t.Fatal("writer was told the transfer succeeded although the stream was aborted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer never learned the stream was aborted")
	}
}

// A stalled stream must not take the session with it: its siblings keep
// working while it overflows.
func TestSlowConsumerDoesNotStallSiblings(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)
	stuck, err := client.Open("stuck.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srvStuck := <-accepted
	go func() { _ = pump(srvStuck, 'X', 64<<20, 64<<10) }() // never read

	for i := 0; i < 5; i++ {
		st, err := client.Open("live.example", 443, 5*time.Second)
		if err != nil {
			t.Fatalf("sibling open %d: %v", i, err)
		}
		srv := <-accepted
		errc := make(chan error, 1)
		go func() { errc <- exchange(srv, 'S', 'C', 1<<20, 16<<10) }()
		if err := exchange(st, 'C', 'S', 1<<20, 16<<10); err != nil {
			t.Fatalf("sibling %d: %v", i, err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("sibling %d (server side): %v", i, err)
		}
		_ = st.Close()
	}
	_ = stuck.Close()
}

// heapInUse returns the live heap after a forced collection.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

// The replay window is bounded by bytes. A session used to pin its last 2048
// stream records whatever their size: 64 MiB for as long as it lived after
// any bulk transfer — per user on a server, per upload on a phone.
func TestReplayWindowIsByteBounded(t *testing.T) {
	var w sentWindow
	for i := 0; i < 4096; i++ {
		w.push(sentRec{seq: uint64(i), t: MsgData, id: 1, p: make([]byte, 32<<10)})
		if w.bytes > sentWinMaxBytes {
			t.Fatalf("window holds %d bytes after %d records (cap %d)", w.bytes, i+1, sentWinMaxBytes)
		}
	}
	if got := len(w.recs) * (32 << 10); got != w.bytes {
		t.Fatalf("byte accounting drifted: %d records, %d bytes", len(w.recs), w.bytes)
	}
	// Evicted records are remembered as lost: a peer still needing them is
	// an unrecoverable gap, not a silent hole in a stream.
	if w.lost == 0 || w.recs[0].seq != w.lost {
		t.Fatalf("lost=%d does not abut the oldest retained seq %d", w.lost, w.recs[0].seq)
	}
	w.ack(4000)
	if len(w.recs) != 96 || w.recs[0].seq != 4000 {
		t.Fatalf("ack(4000): %d records left, oldest seq %d", len(w.recs), w.recs[0].seq)
	}
	w.ack(1 << 40)
	if len(w.recs) != 0 || w.bytes != 0 || w.recs != nil {
		t.Fatalf("a full ack must release the window: %d records, %d bytes", len(w.recs), w.bytes)
	}
}

// End to end: after a bulk transfer between two v2.2 peers, acknowledgements
// have emptied the sender's replay window down to the last unacknowledged
// stretch — an idle session pins next to nothing.
func TestIdleSessionReleasesReplayMemory(t *testing.T) {
	p, _ := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("mem.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv := <-accepted
	const total = 256 << 20
	go func() { _ = pump(srv, 'S', total, 32<<10) }()
	if got, n, err := drain(st, total); err != nil || got != wantHash('S', total) {
		t.Fatalf("read %d/%d err=%v", n, total, err)
	}
	// The last ACK trails the last record by at most ackEvery wire bytes.
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.server.migMu.Lock()
		held, recs := p.server.sent.bytes, len(p.server.sent.recs)
		p.server.migMu.Unlock()
		if held <= 2*ackEvery {
			t.Logf("sender retains %d records / %d KiB after %d MiB", recs, held>>10, total>>20)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sender still retains %d records / %d MiB of sent payload", recs, held>>20)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h := heapInUse(); h > 48<<20 {
		t.Fatalf("heap in use with one idle session pair: %d MiB", h>>20)
	}
	runtime.KeepAlive(p)
}

// A server that cannot resume sessions keeps no replay window at all.
func TestNonMigratableServerRetainsNothing(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)
	st, err := client.Open("noretain.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv := <-accepted
	const total = 8 << 20
	go func() { _ = pump(srv, 'S', total, 32<<10) }()
	if _, n, err := drain(st, total); err != nil {
		t.Fatalf("read %d/%d err=%v", n, total, err)
	}
	server.migMu.Lock()
	recs := len(server.sent.recs)
	server.migMu.Unlock()
	if recs != 0 {
		t.Fatalf("non-migratable server retains %d records", recs)
	}
}
