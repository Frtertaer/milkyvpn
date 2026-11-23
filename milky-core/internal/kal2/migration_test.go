package kal2

// Session migration under load. The v2.1 tests only ever cut the transport
// of an idle session; every test here cuts it while data is moving, which is
// when a real transport dies — and when the v2.1 session layer lost, repeated
// or stalled records.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resumablePair is a client/server session pair joined by memLinks, with a
// server-side registry so the session can be resumed on a fresh link.
type resumablePair struct {
	pub            ed25519.PublicKey
	priv           ed25519.PrivateKey
	reg            *SessionRegistry
	client, server *Session
	linkBuf        int

	// errs collects failures from goroutines that may outlive the test body.
	emu  sync.Mutex
	errs []string
	// flightLen, if set, observes the size of each server resumption flight.
	flightLen func(int)
}

// errorf records a failure from a helper goroutine; check reports them.
func (p *resumablePair) errorf(format string, args ...any) {
	p.emu.Lock()
	p.errs = append(p.errs, fmt.Sprintf(format, args...))
	p.emu.Unlock()
}

func (p *resumablePair) check(t *testing.T) {
	t.Helper()
	p.emu.Lock()
	defer p.emu.Unlock()
	for _, e := range p.errs {
		t.Error(e)
	}
}

func newResumablePair(t *testing.T, linkBuf int) (*resumablePair, *memEnd) {
	return newResumablePairPad(t, linkBuf, PadMimicMode)
}

// newResumablePairPad builds the pair with an explicit padding mode. Bucket
// padding keeps control records small, which the tests that kill a transport
// within its first kilobytes need to make any progress at all.
func newResumablePairPad(t *testing.T, linkBuf int, pad PadMode) (*resumablePair, *memEnd) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := NewServerHandshake(priv)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewClientHandshake(pub, []byte("test-psk"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatal(err)
	}
	eph := ff[len(Magic)+1 : len(Magic)+1+ephemeralKeySize]
	srvFlight, err := sh.Start(eph, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ch.ServerFlight(srvFlight)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := sh.Finish()
	if err != nil {
		t.Fatal(err)
	}
	cs.SetPadMode(pad)
	ss.SetPadMode(pad)
	a, b := memLink(linkBuf)
	cs.Attach(a)
	ss.Attach(b)
	reg := NewSessionRegistry(NewTicketCodec(), 0)
	var uid [16]byte
	if err := reg.Adopt(ss, uid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return &resumablePair{pub: pub, priv: priv, reg: reg, client: cs, server: ss, linkBuf: linkBuf}, a
}

func (p *resumablePair) tickets() int {
	p.client.migMu.Lock()
	defer p.client.migMu.Unlock()
	return len(p.client.tickets)
}

func (p *resumablePair) waitTicket(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for p.tickets() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no resumption ticket arrived within 3s")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitFrozen blocks until the client noticed its transport died.
func (p *resumablePair) waitFrozen(t *testing.T) {
	t.Helper()
	select {
	case <-p.client.NeedsMigrate():
	case <-p.client.WaitClosed():
		t.Fatal("client session died instead of freezing for resumption")
	case <-time.After(5 * time.Second):
		t.Fatal("client did not notice its transport died")
	}
}

// serverResume is the server half of a resumption over b — the same sequence
// the carriers run (veil acceptResume, drift acceptResumeDrift).
func (p *resumablePair) serverResume(b io.ReadWriteCloser) error {
	head := make([]byte, ResumeFixedSize)
	if _, err := io.ReadFull(b, head); err != nil {
		return fmt.Errorf("resume head: %w", err)
	}
	res, err := p.reg.Accept(head, b, nil)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	flight, _, err := res.ServerResume(p.priv, nil)
	if err != nil {
		return err
	}
	out := append(flight, res.ServerTrailer()...)
	if p.flightLen != nil {
		p.flightLen(len(out))
	}
	if _, err := b.Write(out); err != nil {
		return fmt.Errorf("server flight: %w", err)
	}
	if err := res.Attach(b); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	return nil
}

// clientResume is the client half (carrier runResumeHandshake).
func (p *resumablePair) clientResume(a io.ReadWriteCloser) error {
	rs, ok := p.client.TicketState()
	if !ok {
		return errors.New("client holds no resumption ticket")
	}
	cr, err := rs.BeginResumeFlight(a, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	head := make([]byte, ServerFlightSize)
	if _, err := io.ReadFull(a, head); err != nil {
		return fmt.Errorf("server flight: %w", err)
	}
	if err := cr.FinishResume(p.client, p.pub, head, nil); err != nil {
		return err
	}
	cp, err := cr.ReadTrailer(p.client, a)
	if err != nil {
		return err
	}
	return cr.Attach(p.client, a, cp)
}

// resume moves the session onto a fresh link and returns the client end.
// prep, if set, runs on the new link before any byte crosses it.
func (p *resumablePair) resume(prep func(clientEnd, serverEnd *memEnd)) (*memEnd, error) {
	a, b := memLink(p.linkBuf)
	if prep != nil {
		prep(a, b)
	}
	srvErr := make(chan error, 1)
	go func() { srvErr <- p.serverResume(b) }()
	if err := p.clientResume(a); err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("client: %w (server: %v)", err, <-srvErr)
	}
	if err := <-srvErr; err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("server: %w", err)
	}
	return a, nil
}

// serveExchange accepts streams on the server session and runs the server
// half of exchange on each; failures are collected for check.
func (p *resumablePair) serveExchange(total, chunk int) {
	go func() {
		for {
			st, err := p.server.Accept()
			if err != nil {
				return
			}
			if err := st.Ack(0); err != nil {
				return
			}
			go func() {
				if err := exchange(st, 'S', 'C', total, chunk); err != nil {
					p.errorf("server side of stream %d: %v", st.id, err)
				}
				_ = st.Close()
			}()
		}
	}()
}

// One transport loss in the middle of a full-duplex bulk transfer. The dying
// transport is seen by the writer here (it is mid-write) — the case that
// used to latch a write error into the session for good: the resumption
// "succeeded" and the session never sent another record.
func TestMigrationUnderLoad(t *testing.T) {
	const total = 24 << 20
	p, link := newResumablePair(t, 256<<10)
	p.serveExchange(total, 16<<10)
	st, err := p.client.Open("load.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- exchange(st, 'C', 'S', total, 16<<10) }()

	p.waitTicket(t)
	time.Sleep(20 * time.Millisecond)
	link.kill()
	p.waitFrozen(t)
	if _, err := p.resume(nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transfer across one migration: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("transfer stalled after the migration")
	}
	p.check(t)
	// The session is fully usable afterwards, in both directions.
	if err := p.client.Ping([]byte("after"), 3*time.Second); err != nil {
		t.Fatalf("ping after migration: %v", err)
	}
	if err := p.server.Ping([]byte("after"), 3*time.Second); err != nil {
		t.Fatalf("server ping after migration: %v", err)
	}
}

// A control record written while the session is frozen (liveness and cover
// pings do this every few seconds) hits the dead transport. That, too, used
// to poison the session for every later send.
func TestMigrationAfterControlWriteWhileFrozen(t *testing.T) {
	p, link := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("frozen.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	p.waitTicket(t)

	link.kill()
	p.waitFrozen(t)
	// Watchdog pings while frozen: they fail (no transport), nothing more.
	for i := 0; i < 3; i++ {
		if err := p.client.Ping([]byte("frozen"), 50*time.Millisecond); err == nil {
			t.Fatal("ping succeeded on a frozen session")
		}
	}
	if _, err := p.resume(nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if err := p.client.Ping([]byte("thawed"), 3*time.Second); err != nil {
		t.Fatalf("ping after resume: %v", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- exchange(srv, 'S', 'C', 1<<20, 16<<10) }()
	if err := exchange(st, 'C', 'S', 1<<20, 16<<10); err != nil {
		t.Fatalf("stream after resume: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("stream after resume (server side): %v", err)
	}
}

// chaos keeps killing the link of a resumable pair while `busy` reports
// transfers in progress: every fresh link is given a random byte budget after
// which it dies mid-write — mid-record, and for small budgets mid-replay.
// It returns the number of migrations performed.
func chaos(t *testing.T, p *resumablePair, first *memEnd, cuts int, minBudget, maxBudget int, finished <-chan struct{}) int {
	t.Helper()
	rng := mrand.New(mrand.NewPCG(1, uint64(cuts)))
	budget := func() int { return minBudget + rng.IntN(maxBudget-minBudget+1) }
	arm := func(clientEnd, serverEnd *memEnd) {
		// Kill it from either direction: the side that is writing notices
		// through its writer, the other through its reader.
		if rng.IntN(2) == 0 {
			clientEnd.cutAfter(budget())
		} else {
			serverEnd.cutAfter(budget())
		}
	}
	first.cutAfter(budget())
	n := 0
	for n < cuts {
		select {
		case <-finished:
			return n
		case <-p.client.WaitClosed():
			t.Fatalf("client session died after %d migrations", n)
		case <-p.client.NeedsMigrate():
		}
		// A ticket is single-use; the replacement rides the new transport.
		// With traffic flowing it is there within a record or two.
		p.waitTicket(t)
		prep := arm
		if n == cuts-1 {
			prep = nil // the last link lives, so the transfers can finish
		}
		if _, err := p.resume(prep); err != nil {
			t.Fatalf("migration %d: %v", n, err)
		}
		n++
	}
	return n
}

// Many transport losses during one long full-duplex transfer, each at an
// arbitrary byte. Every byte must still arrive exactly once and in order.
// On v2.1 the second loss already lost a record (a stalled stream) or
// replayed one twice (a corrupted stream).
func TestMigrationChaosSingleStream(t *testing.T) {
	const total = 48 << 20
	p, link := newResumablePair(t, 256<<10)
	p.serveExchange(total, 16<<10)
	st, err := p.client.Open("chaos.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	var xerr error
	go func() {
		defer close(finished)
		xerr = exchange(st, 'C', 'S', total, 16<<10)
	}()
	n := chaos(t, p, link, 40, 64<<10, 3<<20, finished)
	select {
	case <-finished:
	case <-time.After(60 * time.Second):
		t.Fatalf("transfer stalled after %d migrations", n)
	}
	if xerr != nil {
		t.Fatalf("after %d migrations: %v", n, xerr)
	}
	p.check(t)
	if n < 10 {
		t.Fatalf("only %d migrations happened — the test did not exercise what it claims", n)
	}
	t.Logf("%d MiB each way intact across %d migrations", total>>20, n)
}

// The transport dies within the first few kilobytes after every resumption,
// i.e. while the replay of the previous loss is still going out. This is the
// pattern a censor that cuts each new flow early produces, and it is the one
// that made v2.1 drop the records an interrupted replay had not emitted yet.
func TestMigrationChaosCutDuringReplay(t *testing.T) {
	const total = 6 << 20
	p, link := newResumablePairPad(t, 256<<10, PadBucketMode)
	p.serveExchange(total, 4<<10)
	st, err := p.client.Open("replay.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	var xerr error
	go func() {
		defer close(finished)
		xerr = exchange(st, 'C', 'S', total, 4<<10)
	}()
	n := chaos(t, p, link, 120, 6<<10, 48<<10, finished)
	select {
	case <-finished:
	case <-time.After(60 * time.Second):
		t.Fatalf("transfer stalled after %d migrations", n)
	}
	if xerr != nil {
		t.Fatalf("after %d migrations: %v", n, xerr)
	}
	p.check(t)
	if n < 40 {
		t.Fatalf("only %d migrations happened", n)
	}
	t.Logf("%d MiB each way intact across %d migrations cut mid-replay", total>>20, n)
}

// Streams opening, transferring and closing while the transport keeps dying:
// an OPEN or a CLOSE in flight at the moment of a loss must not cost the
// stream. v2.1 reconciled stream tables by set difference on every resume
// and reset exactly those streams.
func TestMigrationChaosStreamChurn(t *testing.T) {
	const (
		workers = 6
		cycles  = 12
		chunk   = 8 << 10
	)
	p, link := newResumablePair(t, 256<<10)
	sizes := func(w, c int) int { return (64 + (w*37+c*101)%448) << 10 } // 64..512 KiB

	// The server learns each stream's size from its OPEN target port.
	go func() {
		for {
			st, err := p.server.Accept()
			if err != nil {
				return
			}
			_, _, port, err := st.Target()
			if err != nil {
				p.errorf("target: %v", err)
				return
			}
			if err := st.Ack(0); err != nil {
				return
			}
			go func() {
				total := int(port) << 10
				if err := exchange(st, 'S', 'C', total, chunk); err != nil {
					p.errorf("server side of stream %d (%d KiB): %v", st.id, port, err)
				}
				_ = st.Close()
			}()
		}
	}()

	finished := make(chan struct{})
	var failures atomic.Int32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for c := 0; c < cycles; c++ {
				total := sizes(w, c)
				st, err := p.client.Open("churn.example", uint16(total>>10), 30*time.Second)
				if err != nil {
					failures.Add(1)
					p.errorf("worker %d cycle %d: open: %v", w, c, err)
					return
				}
				if err := exchange(st, 'C', 'S', total, chunk); err != nil {
					failures.Add(1)
					p.errorf("worker %d cycle %d (stream %d): %v", w, c, st.id, err)
					return
				}
				_ = st.Close()
			}
		}(w)
	}
	go func() { wg.Wait(); close(finished) }()

	n := chaos(t, p, link, 60, 24<<10, 512<<10, finished)
	select {
	case <-finished:
	case <-time.After(90 * time.Second):
		t.Fatalf("stream churn stalled after %d migrations", n)
	}
	p.check(t)
	if f := failures.Load(); f != 0 {
		t.Fatalf("%d streams failed across %d migrations", f, n)
	}
	// No stream may outlive its transfer on either side.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.client.smu.RLock()
		cl := len(p.client.streams)
		p.client.smu.RUnlock()
		p.server.smu.RLock()
		sl := len(p.server.streams)
		p.server.smu.RUnlock()
		if cl == 0 && sl == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("streams leaked after the churn: client %d, server %d", cl, sl)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("%d streams intact across %d migrations", workers*cycles, n)
}

// Transport after transport completes the resumption handshake and then
// carries nothing — the signature of a path that lets a small handshake
// through and drops the payload behind it. Every completed handshake must
// leave the client holding a ticket for the next attempt, however long that
// goes on; before, the replacement ticket travelled behind the replay, and
// two such transports in a row ended the session.
func TestMigrationSurvivesHandshakeOnlyTransports(t *testing.T) {
	p, link := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("ticket.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	p.waitTicket(t)
	deadline := time.Now().Add(3 * time.Second)
	for p.tickets() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("client holds %d tickets; a v2.2 server issues a spare", p.tickets())
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Wait until the client knows its peer speaks v2.2 (SETTINGS arrived).
	for p.client.peerFeat.Load()&FeatReplay == 0 {
		if time.Now().After(deadline) {
			t.Fatal("client never saw the server's SETTINGS")
		}
		time.Sleep(2 * time.Millisecond)
	}

	for round := 0; round < 4; round++ {
		link.kill()
		p.waitFrozen(t)
		for dud := 0; dud < 6; dud++ {
			before := p.tickets()
			a, b := memLink(p.linkBuf)
			srvErr := make(chan error, 1)
			// The server writes its flight and trailer in one piece; a link
			// budgeted for exactly that many bytes delivers the handshake
			// and nothing else. The budget is armed the moment the size is
			// known — just before the server writes it.
			p.flightLen = func(n int) { b.cutAfter(n) }
			go func() { srvErr <- p.serverResume(b) }()
			if err := p.clientResume(a); err != nil {
				t.Fatalf("round %d dud %d: client: %v (server: %v)", round, dud, err, <-srvErr)
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("round %d dud %d: server: %v", round, dud, err)
			}
			p.waitFrozen(t)
			if got := p.tickets(); got < before {
				t.Fatalf("round %d dud %d: ticket pool shrank %d → %d on a handshake-only transport", round, dud, before, got)
			}
		}
		p.flightLen = nil
		if link, err = p.resume(nil); err != nil {
			t.Fatalf("round %d: resume onto a good link: %v", round, err)
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- exchange(srv, 'S', 'C', 1<<20, 16<<10) }()
	if err := exchange(st, 'C', 'S', 1<<20, 16<<10); err != nil {
		t.Fatalf("stream after the handshake-only transports: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// A resumption attempt that fails (here: an unknown session id) must leave
// the session frozen and resumable, never half-moved: a retry with a good
// ticket picks every stream up again.
func TestFailedResumeLeavesSessionResumable(t *testing.T) {
	const total = 4 << 20
	p, link := newResumablePair(t, 256<<10)
	p.serveExchange(total, 16<<10)
	st, err := p.client.Open("retry.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- exchange(st, 'C', 'S', total, 16<<10) }()
	p.waitTicket(t)
	_ = link

	// A proactive resumption under a forged session id, while data flows.
	rs, ok := p.client.TicketState()
	if !ok {
		t.Fatal("no ticket")
	}
	rs.SessionID[0] ^= 0xff
	a, b := memLink(p.linkBuf)
	srvErr := make(chan error, 1)
	go func() { srvErr <- p.serverResume(b) }()
	if _, err := rs.BeginResumeFlight(a, nil); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := <-srvErr; err == nil {
		t.Fatal("server accepted a resumption for an unknown session")
	}
	a.kill()
	if !p.client.Frozen() {
		t.Fatal("a resumption attempt must freeze the session before its checkpoint goes out")
	}
	if _, err := p.resume(nil); err != nil {
		t.Fatalf("retry with a valid ticket: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("transfer across the failed attempt and the retry: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("transfer stalled")
	}
}

// Two resumption flights for one session overlap on the server. Only the
// later one may attach; the earlier must be refused rather than re-key the
// session under the feet of the transport that won.
func TestSupersededResumeIsRefused(t *testing.T) {
	p, link := newResumablePair(t, 256<<10)
	p.waitTicket(t)
	deadline := time.Now().Add(3 * time.Second)
	for p.tickets() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("need two tickets")
		}
		time.Sleep(2 * time.Millisecond)
	}
	link.kill()
	p.waitFrozen(t)

	accept := func() (*ResumeResult, *memEnd, *ClientResume, *memEnd) {
		rs, ok := p.client.TicketState()
		if !ok {
			t.Fatal("no ticket")
		}
		a, b := memLink(p.linkBuf)
		crc := make(chan *ClientResume, 1)
		go func() {
			cr, err := rs.BeginResumeFlight(a, nil)
			if err != nil {
				t.Errorf("begin: %v", err)
			}
			crc <- cr
		}()
		head := make([]byte, ResumeFixedSize)
		if _, err := io.ReadFull(b, head); err != nil {
			t.Fatal(err)
		}
		res, err := p.reg.Accept(head, b, nil)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		return res, b, <-crc, a
	}
	res1, b1, _, _ := accept()
	res2, b2, cr2, a2 := accept()

	if _, _, err := res1.ServerResume(p.priv, nil); err != nil {
		t.Fatal(err)
	}
	if err := res1.Attach(b1); err == nil {
		t.Fatal("a superseded resumption attached")
	}
	flight, _, err := res2.ServerResume(p.priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	cp := res2.ServerCheckpoint()
	if err := res2.Attach(b2); err != nil {
		t.Fatalf("the latest resumption must attach: %v", err)
	}
	if err := cr2.FinishResume(p.client, p.pub, flight, nil); err != nil {
		t.Fatal(err)
	}
	if err := cr2.Attach(p.client, a2, cp); err != nil {
		t.Fatal(err)
	}
	if err := p.client.Ping([]byte("x"), 3*time.Second); err != nil {
		t.Fatalf("session unusable after overlapping resumptions: %v", err)
	}
}

// The replay window no longer holds what the peer is missing: the streams
// cannot be made whole, so both ends must see them abort — and the session
// itself must stay usable for new streams.
func TestMigrationGapAbortsStreamsNotSession(t *testing.T) {
	p, link := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("gap.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	p.waitTicket(t)
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(srv, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}

	link.kill()
	p.waitFrozen(t)
	// Pretend the client's window had to evict records the server never got.
	p.client.migMu.Lock()
	p.client.sent.forget(p.client.sendSeq + 100)
	p.client.sendSeq += 101
	p.client.migMu.Unlock()
	// (The server would normally report a counter below that; force it.)
	p.server.recvSeq.Store(p.server.recvSeq.Load())

	if _, err := p.resume(nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := io.ReadAll(srv); !IsAbort(err) {
		t.Fatalf("server side of a gapped stream: want an abort, got %v", err)
	}
	if _, err := io.ReadAll(st); !IsAbort(err) {
		t.Fatalf("client side of a gapped stream: want an abort, got %v", err)
	}
	st2, err := p.client.Open("after-gap.example", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("open after a gap: %v", err)
	}
	srv2 := <-accepted
	errc := make(chan error, 1)
	go func() { errc <- exchange(srv2, 'S', 'C', 1<<20, 16<<10) }()
	if err := exchange(st2, 'C', 'S', 1<<20, 16<<10); err != nil {
		t.Fatalf("new stream after a gap: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// A hedged dial races carriers with one ResumeState. An attempt that gets
// going after a sibling already re-attached the session must be refused —
// not freeze the fresh transport (which would cost another resumption, or
// with an unlucky ticket the session).
func TestResumeLoserDoesNotRefreeze(t *testing.T) {
	p, link := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("hedge.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	p.waitTicket(t)
	link.kill()
	p.waitFrozen(t)

	rs, ok := p.client.TicketState()
	if !ok {
		t.Fatal("no ticket")
	}
	// The winner resumes with the shared state...
	a, b := memLink(p.linkBuf)
	srvErr := make(chan error, 1)
	go func() { srvErr <- p.serverResume(b) }()
	cr, err := rs.BeginResumeFlight(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, ServerFlightSize)
	if _, err := io.ReadFull(a, head); err != nil {
		t.Fatal(err)
	}
	if err := cr.FinishResume(p.client, p.pub, head, nil); err != nil {
		t.Fatal(err)
	}
	cp, err := cr.ReadTrailer(p.client, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.Attach(p.client, a, cp); err != nil {
		t.Fatal(err)
	}
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
	// ...then a slow sibling reaches its resumption step with the same state.
	loser, _ := memLink(p.linkBuf)
	if _, err := rs.BeginResumeFlight(loser, nil); err == nil {
		t.Fatal("a stale resumption attempt went ahead on a re-attached session")
	}
	if p.client.Frozen() {
		t.Fatal("a stale resumption attempt froze the healthy session")
	}
	errc := make(chan error, 1)
	go func() { errc <- exchange(srv, 'S', 'C', 1<<20, 16<<10) }()
	if err := exchange(st, 'C', 'S', 1<<20, 16<<10); err != nil {
		t.Fatalf("stream after the stale attempt: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// Two attempts with the same ticket run at once over two transports. The
// server accepts the ticket once; exactly one attempt attaches, the other
// fails cleanly, and the session carries on.
func TestConcurrentResumeAttemptsOneWins(t *testing.T) {
	p, link := newResumablePair(t, 256<<10)
	accepted := serveLoop(t, p.server)
	st, err := p.client.Open("race.example", 443, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	p.waitTicket(t)
	link.kill()
	p.waitFrozen(t)
	rs, ok := p.client.TicketState()
	if !ok {
		t.Fatal("no ticket")
	}

	attempt := func() error {
		a, b := memLink(p.linkBuf)
		srvErr := make(chan error, 1)
		go func() {
			err := p.serverResume(b)
			if err != nil {
				_ = b.Close() // a refused flight gets the connection closed
			}
			srvErr <- err
		}()
		cr, err := rs.BeginResumeFlight(a, nil)
		if err != nil {
			_ = a.Close()
			return err
		}
		head := make([]byte, ServerFlightSize)
		if _, err := io.ReadFull(a, head); err != nil {
			<-srvErr
			return err
		}
		if err := cr.FinishResume(p.client, p.pub, head, nil); err != nil {
			<-srvErr
			return err
		}
		cp, err := cr.ReadTrailer(p.client, a)
		if err != nil {
			<-srvErr
			return err
		}
		if err := cr.Attach(p.client, a, cp); err != nil {
			<-srvErr
			_ = a.Close()
			return err
		}
		return <-srvErr
	}
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { errs <- attempt() }()
	}
	won := 0
	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d of 2 concurrent resumption attempts attached; want exactly 1", won)
	}
	if p.client.Frozen() {
		t.Fatal("session still frozen after the winning attempt")
	}
	errc := make(chan error, 1)
	go func() { errc <- exchange(srv, 'S', 'C', 1<<20, 16<<10) }()
	if err := exchange(st, 'C', 'S', 1<<20, 16<<10); err != nil {
		t.Fatalf("stream after the race: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// A writer whose transport generation was retired while it held a record
// dequeued from the priority lane must put it back at the head of the lane.
// It used to append it at the tail — behind later records of the same
// stream — and the next resumption replayed them out of order (a stream
// whose bytes all arrived, in the wrong order).
func TestRetiredWriterReturnsRecordToLaneHead(t *testing.T) {
	client, _ := pipeSessions(t)
	client.freeze() // the live writer stops draining the lane
	stale := newLoopSet()
	client.migMu.Lock()
	client.replayQ = []outRec{{t: MsgData, id: 1, p: []byte("B")}, {t: MsgData, id: 1, p: []byte("C")}}
	client.migMu.Unlock()
	if _, ok := client.appendFrame(nil, outRec{t: MsgData, id: 1, p: []byte("A")}, stale); ok {
		t.Fatal("a retired generation emitted a frame")
	}
	client.migMu.Lock()
	defer client.migMu.Unlock()
	var got string
	for _, r := range client.replayQ {
		got += string(r.p)
	}
	if got != "ABC" {
		t.Fatalf("priority lane after a retired writer handed its record back: %q, want \"ABC\"", got)
	}
}
