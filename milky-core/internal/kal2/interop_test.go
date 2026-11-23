package kal2

// Wire interoperability with the v2.1 session layer that shipped in releases
// v1.0.0–v1.2.2 (frozen in internal/v21ref). Servers and apps update on their
// own schedules, so every v2.2 change must leave a mixed pair working: the
// new records (SETTINGS, ACK) must be skipped by old peers, and the new
// resumption behaviour must still resume old peers' sessions — streams intact.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	old "github.com/Frtertaer/milkyvpn/milky-core/internal/kal2/internal/v21ref"
)

var interopPSK = []byte("interop-psk")

// errSink collects failures from goroutines that may outlive the test body.
type errSink struct {
	mu   sync.Mutex
	errs []string
}

func (e *errSink) errorf(format string, args ...any) {
	e.mu.Lock()
	e.errs = append(e.errs, fmt.Sprintf(format, args...))
	e.mu.Unlock()
}

func (e *errSink) check(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.errs {
		t.Error(s)
	}
}

// --- pairings ----------------------------------------------------------------

// newClientOldServer runs the full handshake — first flight, server flight,
// client auth flight, server Finished — between a v2.2 client and a v2.1
// server, then attaches both to a fresh link.
func newClientOldServer(t *testing.T) (cs *Session, ss *old.Session, pub ed25519.PublicKey, priv ed25519.PrivateKey, link *memEnd) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewClientHandshake(pub, interopPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	ff, err := ch.FirstFlight(-1)
	if err != nil {
		t.Fatal(err)
	}
	eph, flightLen, err := old.ParseClientFirstFlight(ff, interopPSK, nil)
	if err != nil {
		t.Fatalf("v2.1 server rejects the v2.2 first flight: %v", err)
	}
	if flightLen != len(ff) {
		t.Fatalf("v2.1 server reads %d bytes of a %d-byte first flight", flightLen, len(ff))
	}
	sh, err := old.NewServerHandshake(priv)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := sh.Start(eph, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err = ch.ServerFlight(sf)
	if err != nil {
		t.Fatalf("v2.2 client rejects the v2.1 server flight: %v", err)
	}
	ss, err = sh.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.VerifyClientAuth(interopPSK, sf, cs.ClientAuthFlight(interopPSK, sf)); err != nil {
		t.Fatalf("v2.1 server rejects the v2.2 client auth flight: %v", err)
	}
	if string(ss.FinishedValue("server")) != string(cs.FinishedValue("server")) {
		t.Fatal("server Finished differs between v2.1 and v2.2")
	}
	a, b := memLink(256 << 10)
	cs.Attach(a)
	ss.Attach(b)
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs, ss, pub, priv, a
}

// oldClientNewServer is the mirror pairing.
func oldClientNewServer(t *testing.T) (cs *old.Session, ss *Session, pub ed25519.PublicKey, priv ed25519.PrivateKey, link *memEnd) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := old.NewClientHandshake(pub, interopPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	ff, err := ch.FirstFlight(-1)
	if err != nil {
		t.Fatal(err)
	}
	eph, flightLen, err := ParseClientFirstFlight(ff, interopPSK, nil)
	if err != nil {
		t.Fatalf("v2.2 server rejects the v2.1 first flight: %v", err)
	}
	if flightLen != len(ff) {
		t.Fatalf("v2.2 server reads %d bytes of a %d-byte first flight", flightLen, len(ff))
	}
	sh, err := NewServerHandshake(priv)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := sh.Start(eph, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err = ch.ServerFlight(sf)
	if err != nil {
		t.Fatalf("v2.1 client rejects the v2.2 server flight: %v", err)
	}
	ss, err = sh.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.VerifyClientAuth(interopPSK, sf, cs.ClientAuthFlight(interopPSK, sf)); err != nil {
		t.Fatalf("v2.2 server rejects the v2.1 client auth flight: %v", err)
	}
	if string(ss.FinishedValue("server")) != string(cs.FinishedValue("server")) {
		t.Fatal("server Finished differs between v2.1 and v2.2")
	}
	a, b := memLink(256 << 10)
	cs.Attach(a)
	ss.Attach(b)
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs, ss, pub, priv, a
}

// --- stream traffic ------------------------------------------------------------

// acceptor is the server side of either implementation.
type acceptor[S io.ReadWriteCloser] interface {
	Accept() (S, error)
}

// serveEach accepts streams and runs fn on each until the session ends.
func serveEach[S io.ReadWriteCloser](s acceptor[S], ack func(S) error, fn func(S)) {
	go func() {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			if err := ack(st); err != nil {
				return
			}
			go fn(st)
		}
	}()
}

// trafficCheck opens n streams in parallel through open and runs a full-duplex
// exchange on each.
func trafficCheck(t *testing.T, n, total int, open func() (io.ReadWriteCloser, error)) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := open()
			if err != nil {
				errs <- fmt.Errorf("open: %w", err)
				return
			}
			defer st.Close()
			if err := exchange(st, 'C', 'S', total, 16<<10); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// --- tests ---------------------------------------------------------------------

// A v2.2 client talks to a v2.1 server: streams in both directions, the new
// SETTINGS record silently skipped by the old server, no ACKs sent to a peer
// that never announced it reads them.
func TestInteropNewClientOldServerStreams(t *testing.T) {
	cs, ss, _, _, _ := newClientOldServer(t)
	var sink errSink
	serveEach[*old.Stream](ss, func(st *old.Stream) error { return st.Ack(0) }, func(st *old.Stream) {
		if err := exchange(st, 'S', 'C', 4<<20, 16<<10); err != nil {
			sink.errorf("v2.1 server side: %v", err)
		}
		_ = st.Close()
	})
	trafficCheck(t, 6, 4<<20, func() (io.ReadWriteCloser, error) { return cs.Open("interop.example", 443, 5*time.Second) })
	if err := cs.Ping([]byte("x"), 3*time.Second); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := ss.Ping([]byte("x"), 3*time.Second); err != nil {
		t.Fatalf("ping from the v2.1 side: %v", err)
	}
	if cs.peerFeat.Load() != 0 {
		t.Fatalf("a v2.1 server announced features %#x", cs.peerFeat.Load())
	}
	sink.check(t)
}

// A v2.1 client talks to a v2.2 server.
func TestInteropOldClientNewServerStreams(t *testing.T) {
	cs, ss, _, _, _ := oldClientNewServer(t)
	var sink errSink
	serveEach[*Stream](ss, func(st *Stream) error { return st.Ack(0) }, func(st *Stream) {
		if err := exchange(st, 'S', 'C', 4<<20, 16<<10); err != nil {
			sink.errorf("v2.2 server side: %v", err)
		}
		_ = st.Close()
	})
	trafficCheck(t, 6, 4<<20, func() (io.ReadWriteCloser, error) { return cs.Open("interop.example", 443, 5*time.Second) })
	if err := cs.Ping([]byte("x"), 3*time.Second); err != nil {
		t.Fatalf("ping from the v2.1 side: %v", err)
	}
	if err := ss.Ping([]byte("x"), 3*time.Second); err != nil {
		t.Fatalf("ping: %v", err)
	}
	sink.check(t)
}

// A v2.1 peer never acknowledges, so the v2.2 side cannot release its replay
// window by ACKs: it must stay byte-bounded through a long transfer anyway.
func TestInteropLegacyPeerWindowStaysBounded(t *testing.T) {
	cs, ss, _, _, _ := oldClientNewServer(t)
	reg := NewSessionRegistry(NewTicketCodec(), 0)
	var uid [16]byte
	if err := reg.Adopt(ss, uid); err != nil {
		t.Fatal(err)
	}
	// 48 MiB each way in 1 MiB request/response rounds. (One unpaced 48 MiB
	// burst would overflow the v2.1 client's 512-record stream queue — its
	// own slow-consumer limit, which it reports as a clean EOF.)
	const round, rounds = 1 << 20, 48
	var sink errSink
	serveEach[*Stream](ss, func(st *Stream) error { return st.Ack(0) }, func(st *Stream) {
		if err := roundServer(st, round); err != nil {
			sink.errorf("v2.2 server side: %v", err)
		}
	})
	st, err := cs.Open("bulk.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rounds; i++ {
		if err := roundClient(st, round); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	sink.check(t)
	ss.migMu.Lock()
	held := ss.sent.bytes
	ss.migMu.Unlock()
	if held > sentWinMaxBytes {
		t.Fatalf("v2.2 server holds %d MiB of replay for an ACK-less peer", held>>20)
	}
}

// roundClient runs one request/response round: send size bytes, then read
// size bytes back. Between rounds both ends are idle — the only state in
// which a v2.1 peer survives a transport loss: its writer latches the error
// of a write that hits a dying transport and never sends again (the defect
// v2.2 fixes). Interop tests that cut a link therefore cut it between rounds.
func roundClient(st io.ReadWriter, size int) error {
	if err := pump(st, 'C', size, 16<<10); err != nil {
		return err
	}
	got, n, err := drain(st, size)
	if err != nil {
		return fmt.Errorf("read %d/%d: %w", n, size, err)
	}
	if got != wantHash('S', size) {
		return fmt.Errorf("response corrupted")
	}
	return nil
}

// roundServer answers rounds until the client goes away between them.
func roundServer(st io.ReadWriter, size int) error {
	for {
		got, n, err := drain(st, size)
		if n == 0 && err != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %d/%d: %w", n, size, err)
		}
		if got != wantHash('C', size) {
			return fmt.Errorf("request corrupted")
		}
		if err := pump(st, 'S', size, 16<<10); err != nil {
			return err
		}
	}
}

// oldServerResume is the v2.1 server half of a resumption — what a server
// running v1.2.x does (carrier acceptResume at 48f8a76).
func oldServerResume(reg *old.SessionRegistry, priv ed25519.PrivateKey, b io.ReadWriteCloser) error {
	head := make([]byte, old.ResumeFixedSize)
	if _, err := io.ReadFull(b, head); err != nil {
		return err
	}
	res, err := reg.Accept(head, b, nil)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	flight, _, err := res.ServerResume(priv, nil)
	if err != nil {
		return err
	}
	cp := res.Session.Checkpoint().Encode()
	out := append(flight, byte(len(cp)), byte(len(cp)>>8))
	out = append(out, cp...)
	if _, err := b.Write(out); err != nil {
		return err
	}
	if err := res.Finish(); err != nil {
		return err
	}
	if err := res.Session.ResumeAttach(b, res.Checkpoint); err != nil {
		return err
	}
	return reg.Refresh(res.Session)
}

// oldClientResume is the v2.1 client half (carrier runResumeHandshake at
// 48f8a76).
func oldClientResume(cs *old.Session, pub ed25519.PublicKey, a io.ReadWriteCloser) error {
	rs, ok := cs.TicketState()
	if !ok {
		return fmt.Errorf("v2.1 client holds no ticket")
	}
	cr, err := rs.BeginResumeFlight(a, nil)
	if err != nil {
		return err
	}
	head := make([]byte, old.ServerFlightSize)
	if _, err := io.ReadFull(a, head); err != nil {
		return fmt.Errorf("server flight: %w", err)
	}
	if err := cr.FinishResume(cs, pub, head, nil); err != nil {
		return err
	}
	var lb [2]byte
	if _, err := io.ReadFull(a, lb[:]); err != nil {
		return err
	}
	cpb := make([]byte, binary.LittleEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(a, cpb); err != nil {
		return err
	}
	cp, err := old.DecodeCheckpoint(cpb)
	if err != nil {
		return err
	}
	return cs.ResumeAttach(a, cp)
}

// newClientResume is the v2.2 client half (carrier runResumeHandshake).
func newClientResume(cs *Session, pub ed25519.PublicKey, a io.ReadWriteCloser) error {
	rs, ok := cs.TicketState()
	if !ok {
		return fmt.Errorf("v2.2 client holds no ticket")
	}
	cr, err := rs.BeginResumeFlight(a, nil)
	if err != nil {
		return err
	}
	head := make([]byte, ServerFlightSize)
	if _, err := io.ReadFull(a, head); err != nil {
		return fmt.Errorf("server flight: %w", err)
	}
	if err := cr.FinishResume(cs, pub, head, nil); err != nil {
		return err
	}
	cp, err := cr.ReadTrailer(cs, a)
	if err != nil {
		return err
	}
	return cr.Attach(cs, a, cp)
}

// newServerResume is the v2.2 server half (carrier acceptResume).
func newServerResume(reg *SessionRegistry, priv ed25519.PrivateKey, b io.ReadWriteCloser) error {
	head := make([]byte, ResumeFixedSize)
	if _, err := io.ReadFull(b, head); err != nil {
		return err
	}
	res, err := reg.Accept(head, b, nil)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	flight, _, err := res.ServerResume(priv, nil)
	if err != nil {
		return err
	}
	if _, err := b.Write(append(flight, res.ServerTrailer()...)); err != nil {
		return err
	}
	return res.Attach(b)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A v2.2 client resumes its session on a v2.1 server — twice, with a stream
// that was open across both losses carrying data before and after.
func TestInteropNewClientResumesOnOldServer(t *testing.T) {
	cs, ss, pub, priv, link := newClientOldServer(t)
	reg := old.NewSessionRegistry(old.NewTicketCodec(), 0)
	var uid [16]byte
	if err := reg.Adopt(ss, uid); err != nil {
		t.Fatal(err)
	}
	var sink errSink
	serveEach[*old.Stream](ss, func(st *old.Stream) error { return st.Ack(0) }, func(st *old.Stream) {
		if err := roundServer(st, 256<<10); err != nil {
			sink.errorf("v2.1 server side: %v", err)
		}
	})
	st, err := cs.Open("resume.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundClient(st, 256<<10); err != nil {
		t.Fatalf("before migrating: %v", err)
	}
	for cycle := 0; cycle < 2; cycle++ {
		waitUntil(t, "a ticket from the v2.1 server", func() bool { _, ok := cs.TicketState(); return ok })
		link.kill()
		select {
		case <-cs.NeedsMigrate():
		case <-time.After(3 * time.Second):
			t.Fatal("v2.2 client did not freeze")
		}
		a, b := memLink(256 << 10)
		srvErr := make(chan error, 1)
		go func() { srvErr <- oldServerResume(reg, priv, b) }()
		if err := newClientResume(cs, pub, a); err != nil {
			t.Fatalf("cycle %d: v2.2 client resuming on a v2.1 server: %v (server: %v)", cycle, err, <-srvErr)
		}
		if err := <-srvErr; err != nil {
			t.Fatalf("cycle %d: v2.1 server: %v", cycle, err)
		}
		link = a
		if err := roundClient(st, 256<<10); err != nil {
			t.Fatalf("cycle %d: stream after resuming: %v", cycle, err)
		}
	}
	sink.check(t)
}

// A v2.1 client resumes its session on a v2.2 server — twice. The v2.2
// server must hand the replacement ticket to a client that reads only the
// classic trailer, and must not make the old client's set-difference
// reconcile reset a live stream.
func TestInteropOldClientResumesOnNewServer(t *testing.T) {
	cs, ss, pub, priv, link := oldClientNewServer(t)
	reg := NewSessionRegistry(NewTicketCodec(), 0)
	var uid [16]byte
	if err := reg.Adopt(ss, uid); err != nil {
		t.Fatal(err)
	}
	var sink errSink
	serveEach[*Stream](ss, func(st *Stream) error { return st.Ack(0) }, func(st *Stream) {
		if err := roundServer(st, 256<<10); err != nil {
			sink.errorf("v2.2 server side: %v", err)
		}
	})
	st, err := cs.Open("resume.example", 443, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundClient(st, 256<<10); err != nil {
		t.Fatalf("before migrating: %v", err)
	}
	for cycle := 0; cycle < 2; cycle++ {
		waitUntil(t, "a ticket from the v2.2 server", func() bool { _, ok := cs.TicketState(); return ok })
		link.kill()
		select {
		case <-cs.NeedsMigrate():
		case <-time.After(3 * time.Second):
			t.Fatal("v2.1 client did not freeze")
		}
		a, b := memLink(256 << 10)
		srvErr := make(chan error, 1)
		go func() { srvErr <- newServerResume(reg, priv, b) }()
		if err := oldClientResume(cs, pub, a); err != nil {
			t.Fatalf("cycle %d: v2.1 client resuming on a v2.2 server: %v (server: %v)", cycle, err, <-srvErr)
		}
		if err := <-srvErr; err != nil {
			t.Fatalf("cycle %d: v2.2 server: %v", cycle, err)
		}
		link = a
		if err := roundClient(st, 256<<10); err != nil {
			t.Fatalf("cycle %d: stream after resuming: %v", cycle, err)
		}
	}
	sink.check(t)
}

// A stream the v2.1 client opens right before its transport dies — the OPEN
// still in flight — must survive the resumption on a v2.2 server. A v2.1
// server reset exactly such streams (its reconcile saw the client list a
// stream it had not created yet).
func TestInteropOldClientInFlightOpenSurvives(t *testing.T) {
	cs, ss, pub, priv, link := oldClientNewServer(t)
	reg := NewSessionRegistry(NewTicketCodec(), 0)
	var uid [16]byte
	if err := reg.Adopt(ss, uid); err != nil {
		t.Fatal(err)
	}
	var sink errSink
	serveEach[*Stream](ss, func(st *Stream) error { return st.Ack(0) }, func(st *Stream) {
		if err := exchange(st, 'S', 'C', 512<<10, 16<<10); err != nil {
			sink.errorf("v2.2 server side: %v", err)
		}
		_ = st.Close()
	})
	waitUntil(t, "a ticket", func() bool { _, ok := cs.TicketState(); return ok })

	// Hold the client→server direction: the OPEN leaves the client (its
	// write succeeds) but stays in flight — then the link dies with it.
	link.wr.setHold(true)
	opened := make(chan *old.Stream, 1)
	go func() {
		st, err := cs.OpenOpt("inflight.example", 443)
		if err != nil {
			sink.errorf("open: %v", err)
			close(opened)
			return
		}
		opened <- st
	}()
	time.Sleep(50 * time.Millisecond)
	link.kill()
	select {
	case <-cs.NeedsMigrate():
	case <-time.After(3 * time.Second):
		t.Fatal("v2.1 client did not freeze")
	}
	a, b := memLink(256 << 10)
	srvErr := make(chan error, 1)
	go func() { srvErr <- newServerResume(reg, priv, b) }()
	if err := oldClientResume(cs, pub, a); err != nil {
		t.Fatalf("resume: %v (server: %v)", err, <-srvErr)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("v2.2 server: %v", err)
	}
	st, ok := <-opened
	if !ok {
		t.FailNow()
	}
	if err := exchange(st, 'C', 'S', 512<<10, 16<<10); err != nil {
		t.Fatalf("stream whose OPEN was in flight at the loss: %v", err)
	}
	sink.check(t)
}
