package kal2

import (
	"container/heap"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session is a completed KAL/2 handshake: bidirectional AEAD record channel
// plus a stream multiplexer. It is not safe for concurrent Send on a single
// direction except through the serialized internal writer; use Open/Stream
// APIs for application traffic.
//
// Reliability contract: the record channel is an ordered, exactly-once
// sequence of stream-affecting records (OPEN, DATA, CLOSE, RST, OPEN_ACK,
// TICKET). A transport may die at any point; a resumed session replays
// precisely the records the peer has not received, in their original order,
// and nothing else. A stream therefore either delivers every byte in order or
// ends with an error both applications can see — never a silent gap.
type Session struct {
	transcript []byte
	sendKey    []byte
	recvKey    []byte
	nonceBase  []byte
	verify     []byte
	isClient   bool

	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	// sendSeq is the next record sequence to emit (guarded by migMu).
	sendSeq uint64
	// recvSeq is the next sequence expected from the peer. Only the read loop
	// of the live generation advances it (ResumeAttach runs while no loop
	// does); atomic so checkpoints can read it from any goroutine.
	recvSeq atomic.Uint64
	// ended remembers the peer-opened streams that finished most recently
	// (read loop and stream teardown; guarded by smu). A pre-2.2 peer can
	// replay an OPEN twice across back-to-back migrations; without this the
	// second copy would dial the target again and replay a request into it.
	ended endedSet

	rw io.ReadWriteCloser

	// padBucket is this direction's padding multiple (default PadBucketSize);
	// randomized per session so wire packet-size histograms differ run to run.
	// Used only when padMode == PadBucketMode.
	padBucket int

	// padMode selects the record padding strategy (PadMimicMode by default).
	// The peer needs no matching mode — padding is self-delimiting.
	padMode PadMode

	// --- resumption & migration (v2.1) -----------------------------------
	// resumeSecret proves ownership of this session on a new transport
	// without being a traffic key (PFS preserved).
	resumeSecret []byte
	sessionID    [8]byte
	userID       [16]byte
	migratable   atomic.Bool // ticket issued (server) / received (client)
	registry     *SessionRegistry

	// migMu guards everything below up to the blank line: the transport
	// binding, the send sequence and the replay bookkeeping.
	migMu       sync.Mutex
	tickets     [][]byte            // client: unused resumption tickets, oldest first
	resumeEpoch uint64              // server: bumped per accepted resumption flight
	sent        sentWindow          // emitted records the peer has not acknowledged
	replayQ     []outRec            // priority lane: replays, requeued and overflow records
	replayOpen  map[uint32]struct{} // streams whose OPEN the current replay carries
	migrateCh   chan struct{}       // closed when the transport froze (migration wanted)
	loops       *loopSet            // record loops of the live transport generation
	attachGen   uint64              // bumped by every successful (re)attach
	frozen      bool                // transport dead, session awaits resumption
	freezeT     *time.Timer
	migrateTTL  time.Duration // frozen-session lifetime, default 2m
	onCloseFns  []func()      // listeners (registry unregister) run on real Close

	// peerFeat holds the feature bits the peer announced in SETTINGS; zero
	// until it arrives, which is also what a pre-2.2 peer looks like forever.
	peerFeat atomic.Uint32

	// Outbound scheduler: control records (OPEN/ACK/CLOSE/RST/PING/PONG)
	// go out ahead of queued DATA so stream control never starves behind
	// bulk transfer. DATA records queue per stream and the writer emits
	// from the stream that has sent the fewest bytes so far (start-time
	// fair queueing): a fresh stream's first records leave in the next
	// batch even while bulk streams hold deep queues — on lossy carriers
	// the queue tail is seconds of wire time, so a plain FIFO would pin
	// interactive TTFB to it. DATA senders block when the lane cap fills.
	ctrlCh chan outRec
	data   *dataLane
	wake   chan struct{} // nudges an idle writer when replayQ gains a record

	smu       sync.RWMutex // guards streams, nextID, writeErr
	streams   map[uint32]*stream
	acceptCh  chan *stream
	nextID    uint32
	writeErr  error
	sentBytes atomic.Uint64 // wire bytes emitted; lane picker reads it
	recvBytes atomic.Uint64 // wire bytes received; stats accounting
	closed    chan struct{}
	closeOnce sync.Once
	// pongMu guards pongQ: the FIFO queue of outstanding Ping waiters.
	// Concurrent Pings used to overwrite a single shared channel, so pongs
	// were misdelivered and callers timed out on a live session (a spurious
	// failure the lanes watchdog reads as lane death).
	pongMu sync.Mutex
	pongQ  []chan []byte
}

type outRec struct {
	t  byte
	id uint32
	p  []byte
}

// loopSet is one transport generation's pair of record loops. A generation
// is retired exactly once (freeze, resume or close); resumption waits for
// both loops to exit before it touches sequence numbers, so a checkpoint is
// never read while a loop could still move it.
type loopSet struct {
	stop      chan struct{}
	stopOnce  sync.Once
	readDone  chan struct{}
	writeDone chan struct{}
}

func newLoopSet() *loopSet {
	return &loopSet{
		stop:      make(chan struct{}),
		readDone:  make(chan struct{}),
		writeDone: make(chan struct{}),
	}
}

func (l *loopSet) retire() { l.stopOnce.Do(func() { close(l.stop) }) }

// wait blocks until both loops have exited; false if they did not within d.
func (l *loopSet) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	for _, ch := range []chan struct{}{l.readDone, l.writeDone} {
		select {
		case <-ch:
		case <-t.C:
			return false
		}
	}
	return true
}

// quiesceTimeout bounds the wait for a retired generation's loops. Closing
// the carrier unblocks both of them, so in practice this is microseconds.
const quiesceTimeout = 5 * time.Second

// dataLane is the per-stream fair queue behind the writer's DATA lane:
// each stream's records stay FIFO, streams interleave by least emitted
// bytes. slots bounds total pending records (senders block), wake
// signals the writer when work arrives.
type dataLane struct {
	mu      sync.Mutex
	heap    dataHeap
	queues  map[uint32][]outRec
	emitted map[uint32]uint64
	slots   chan struct{}
	wake    chan struct{}
}

// dataLaneCap bounds records pending in the data lane across streams.
const dataLaneCap = 1024

func newDataLane() *dataLane {
	return &dataLane{
		queues:  map[uint32][]outRec{},
		emitted: map[uint32]uint64{},
		slots:   make(chan struct{}, dataLaneCap),
		wake:    make(chan struct{}, 1),
	}
}

// enqueue appends rec to its stream's FIFO. The caller must already
// hold a slot token; pop releases it when the record is emitted.
func (l *dataLane) enqueue(rec outRec) {
	l.mu.Lock()
	if len(l.queues[rec.id]) == 0 {
		heap.Push(&l.heap, dataItem{id: rec.id, emitted: l.emitted[rec.id]})
	}
	l.queues[rec.id] = append(l.queues[rec.id], rec)
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// pop removes the head record of the stream that has emitted the fewest
// bytes so far and releases its slot token.
func (l *dataLane) pop() (outRec, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for l.heap.Len() > 0 {
		it := heap.Pop(&l.heap).(dataItem)
		q := l.queues[it.id]
		if len(q) == 0 {
			continue // the heap only holds non-empty queues
		}
		rec := q[0]
		l.emitted[it.id] += uint64(len(rec.p))
		if len(q) > 1 {
			l.queues[it.id] = q[1:]
			heap.Push(&l.heap, dataItem{id: it.id, emitted: l.emitted[it.id]})
		} else {
			delete(l.queues, it.id)
			delete(l.emitted, it.id)
		}
		<-l.slots
		return rec, true
	}
	return outRec{}, false
}

// dataItem is a ready (non-empty) stream in the fair queue, ordered by
// total bytes the stream has emitted.
type dataItem struct {
	id      uint32
	emitted uint64
}

type dataHeap []dataItem

func (h dataHeap) Len() int           { return len(h) }
func (h dataHeap) Less(i, j int) bool { return h[i].emitted < h[j].emitted }
func (h dataHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *dataHeap) Push(x any)        { *h = append(*h, x.(dataItem)) }
func (h *dataHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// Transcript returns the handshake transcript (for PSK proofs).
func (s *Session) Transcript() []byte { return s.transcript }

// Attach binds the session to the carrier byte stream and starts the reader.
func (s *Session) Attach(rw io.ReadWriteCloser) {
	s.rw = rw
	s.acceptCh = make(chan *stream, 64)
	s.closed = make(chan struct{})
	s.ctrlCh = make(chan outRec, 512)
	s.data = newDataLane()
	s.wake = make(chan struct{}, 1)
	s.migrateCh = make(chan struct{})
	if s.isClient {
		s.nextID = 1 // clients use odd stream ids
	} else {
		s.nextID = 2 // servers (only for server-initiated streams; unused now)
	}
	s.initAEAD()
	ls := newLoopSet()
	s.loops = ls
	s.attachGen = 1
	go s.readLoop(ls, rw)
	go s.writeLoop(ls, rw)
	s.announce()
}

func (s *Session) initAEAD() {
	var err error
	s.sendAEAD, err = chacha20poly1305.New(s.sendKey)
	if err != nil {
		panic(err)
	}
	s.recvAEAD, err = chacha20poly1305.New(s.recvKey)
	if err != nil {
		panic(err)
	}
}

// WaitClosed returns a channel closed when the session ends.
func (s *Session) WaitClosed() <-chan struct{} { return s.closed }

// Close terminates the session and its carrier. Every stream still open
// fails at once: their readers and writers see an abort instead of hanging
// on a session nobody serves any more.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.closed != nil {
			close(s.closed)
		}
		s.migMu.Lock()
		rw := s.rw
		ls := s.loops
		if s.freezeT != nil {
			s.freezeT.Stop()
		}
		s.migMu.Unlock()
		if ls != nil {
			ls.retire()
		}
		if rw != nil {
			err = rw.Close()
		}
		s.failStreams(ErrClosed)
		for _, fn := range s.onCloseFns {
			fn()
		}
	})
	return err
}

// failStreams latches the session's terminal error and aborts every stream.
func (s *Session) failStreams(cause error) {
	s.smu.Lock()
	if s.writeErr == nil {
		s.writeErr = cause
	}
	sts := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		sts = append(sts, st)
	}
	s.smu.Unlock()
	for _, st := range sts {
		st.fail(abortf("session lost: %v", cause))
	}
}

// Kill fails the session with err: every open stream learns the cause and the
// carrier freezes or closes per the migration rules. Close alone only stops
// the carrier — stream readers would hang waiting on queues nobody drains,
// so watchdogs use Kill.
func (s *Session) Kill(err error) { s.fail(err, nil) }

// isDead reports whether the session was finally closed (vs merely frozen).
func (s *Session) isDead() bool {
	if s.closed == nil {
		return false
	}
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Session) nonce(seq uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	copy(n, s.nonceBase)
	var sq [8]byte
	binary.BigEndian.PutUint64(sq[:], seq)
	for i := 0; i < 8; i++ {
		n[4+i] ^= sq[i]
	}
	return n
}

// sendRecord queues one record for emission. Control records go to the
// priority lane; DATA senders block on the bounded data lane (write
// backpressure). Actual write failures surface via s.fail.
func (s *Session) sendRecord(t byte, streamID uint32, payload []byte) error {
	return s.sendRecordDeadline(t, streamID, payload, nil)
}

// sendRecordDeadline is sendRecord with a caller-supplied timeout channel
// for the blocking queue points (the net.Conn write deadline path).
//
// A frozen session keeps accepting records: they wait in the lanes (senders
// block once those fill) and leave after the replay when a resumed transport
// attaches — the writer drains the replay lane first, so nothing new can
// overtake a record the peer is still missing.
func (s *Session) sendRecordDeadline(t byte, streamID uint32, payload []byte, timeout <-chan time.Time) error {
	if len(payload) > MaxPayload {
		return ErrFraming
	}
	s.smu.RLock()
	err := s.writeErr
	s.smu.RUnlock()
	if err != nil {
		return err
	}
	// Copy the payload before queueing: callers may reuse the buffer (e.g.
	// io.CopyBuffer) before the writer goroutine encrypts it.
	rec := outRec{t: t, id: streamID, p: append([]byte(nil), payload...)}
	// MsgClose rides the data lane so it stays ordered behind this stream's
	// queued DATA on the wire (ctrl lane can otherwise overtake it and the
	// peer sees close before trailing data).
	if t == MsgData || t == MsgClose {
		select {
		case s.data.slots <- struct{}{}:
		case <-s.closed:
			return ErrClosed
		case <-timeout:
			return os.ErrDeadlineExceeded
		}
		s.data.enqueue(rec)
		return nil
	}
	select {
	case s.ctrlCh <- rec:
		return nil
	case <-s.closed:
		return ErrClosed
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}

// maxPriorityBacklog bounds records parked in the priority lane by the
// record dispatcher. It only grows when the peer keeps demanding replies
// (PINGs, opens to refuse) while not reading ours — past this the peer is
// broken or hostile and the session ends rather than buffer without limit.
const maxPriorityBacklog = 8192

// sendFromDispatch queues a record on behalf of the read loop. It never
// blocks: a read loop parked on a full lane could not notice its transport
// dying, and a resumption has to wait for that loop before it may read the
// receive counter. Overflow goes to the priority lane, which the writer
// drains first.
func (s *Session) sendFromDispatch(t byte, streamID uint32, payload []byte) {
	rec := outRec{t: t, id: streamID, p: append([]byte(nil), payload...)}
	select {
	case s.ctrlCh <- rec:
		return
	default:
	}
	s.migMu.Lock()
	s.replayQ = append(s.replayQ, rec)
	backlog := len(s.replayQ)
	s.migMu.Unlock()
	s.nudge()
	if backlog > maxPriorityBacklog {
		s.die(ErrFraming)
	}
}

// nudge wakes an idle writer after the priority lane gained a record.
func (s *Session) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// writeBatchBytes bounds the frames coalesced into one carrier write: larger
// writes mean larger TLS records — fewer segments (throughput) and a packet
// rate closer to ordinary bulk HTTP rather than a chattery tunnel.
const writeBatchBytes = 1 << 14

// writeLoop is the single serialized emitter of one transport generation. It
// blocks for the first queued record, then greedily drains whatever else is
// queued — priority lane, control lane, then DATA — into one carrier write,
// so opens/acks/rsts/pongs never queue behind bulk transfer and busy links
// emit few large writes.
func (s *Session) writeLoop(ls *loopSet, rw io.Writer) {
	defer close(ls.writeDone)
	var buf []byte
	for {
		r, ok := s.nextOut(ls, true)
		if !ok {
			return
		}
		buf = buf[:0]
		target := s.batchTarget()
		for {
			var live bool
			if buf, live = s.appendFrame(buf, r, ls); !live {
				return
			}
			if len(buf) >= target {
				break
			}
			if r, ok = s.nextOut(ls, false); !ok {
				break
			}
		}
		if !s.flushBuf(buf, ls, rw) {
			return
		}
	}
}

// nextOut picks the next record to emit: priority lane, then control, then
// the fair DATA queue. With block set it waits for work; ok is false when the
// generation is retired or nothing is queued (non-blocking).
func (s *Session) nextOut(ls *loopSet, block bool) (outRec, bool) {
	for {
		s.migMu.Lock()
		if s.loops != ls || s.frozen {
			s.migMu.Unlock()
			return outRec{}, false
		}
		if len(s.replayQ) > 0 {
			r := s.replayQ[0]
			s.replayQ[0] = outRec{}
			s.replayQ = s.replayQ[1:]
			if len(s.replayQ) == 0 {
				s.replayQ = nil
			}
			s.migMu.Unlock()
			return r, true
		}
		s.migMu.Unlock()
		select {
		case r := <-s.ctrlCh:
			return r, true
		default:
		}
		if r, ok := s.data.pop(); ok {
			return r, true
		}
		if !block {
			return outRec{}, false
		}
		select {
		case r := <-s.ctrlCh:
			return r, true
		case <-s.data.wake:
		case <-s.wake:
		case <-s.closed:
			return outRec{}, false
		case <-ls.stop:
			return outRec{}, false
		}
	}
}

// appendFrame assigns the next sequence number to r and seals it into buf.
// The generation check, the sequence consume and the replay bookkeeping
// share migMu, so a resumption's sequence rewind can never interleave with a
// retiring writer. A record a retired writer still holds is handed back to
// the HEAD of the priority lane: it was dequeued before everything queued
// there now (the lane drains first, and anything added since came later),
// and must neither vanish nor slip behind later records of its stream.
func (s *Session) appendFrame(buf []byte, r outRec, ls *loopSet) ([]byte, bool) {
	s.migMu.Lock()
	if s.loops != ls || s.frozen {
		s.replayQ = append([]outRec{r}, s.replayQ...)
		s.migMu.Unlock()
		return buf, false
	}
	seq := s.sendSeq
	s.sendSeq++
	if retainedType(r.t) {
		if s.retains() {
			s.sent.push(sentRec{seq: seq, t: r.t, id: r.id, p: r.p})
		} else {
			s.sent.forget(seq)
		}
	}
	aead := s.sendAEAD
	s.migMu.Unlock()

	var padded []byte
	var err error
	if s.padMode == PadMimicMode {
		padded, err = PadMimic(r.p)
	} else {
		bucket := s.padBucket
		if bucket < MinPadBytes {
			bucket = PadBucketSize
		}
		padded, err = PadBucket(r.p, bucket)
	}
	if err != nil {
		// The sequence number is spent; a hole would desynchronise the peer.
		s.die(err)
		return buf, false
	}
	header := encodeHeader(r.t, seq, r.id, len(padded)+aeadTagSize)
	buf = append(buf, header...)
	buf = aead.Seal(buf, s.nonce(seq), padded, header)
	return buf, true
}

// SentBytes reports total wire bytes this session has emitted.
func (s *Session) SentBytes() uint64 { return s.sentBytes.Load() }

// ReceivedBytes reports total wire bytes this session has consumed.
func (s *Session) ReceivedBytes() uint64 { return s.recvBytes.Load() }

// SetPadMode selects the padding strategy for records this session emits.
// Set it before Attach so the writer goroutine sees the final choice.
func (s *Session) SetPadMode(m PadMode) { s.padMode = m }

// flushBuf writes one coalesced batch. A failed write is a transport fault,
// not a session fault: fail() decides whether the session freezes for
// resumption or dies, and only a real death latches an error for senders.
func (s *Session) flushBuf(buf []byte, ls *loopSet, rw io.Writer) bool {
	s.sentBytes.Add(uint64(len(buf)))
	if _, err := rw.Write(buf); err != nil {
		s.fail(err, ls)
		return false
	}
	return true
}

// readRecord reads and authenticates the next record from rw — the conn
// captured by this generation's readLoop, immune to a resume swap.
func (s *Session) readRecord(rw io.Reader) (*Record, error) {
	rec, _, err := s.readRecordN(rw)
	return rec, err
}

// readRecordN is readRecord that also reports the record's wire size.
func (s *Session) readRecordN(rw io.Reader) (*Record, int, error) {
	header := make([]byte, RecordHeaderSize)
	if _, err := io.ReadFull(rw, header); err != nil {
		return nil, 0, err
	}
	t, seq, streamID, ctLen, err := decodeHeader(header)
	if err != nil {
		return nil, 0, err
	}
	// Forward-compat (SPEC §12): unknown record types below 0x80 are
	// authenticated, decrypted, and skipped; types ≥0x80 are mandatory —
	// an unknown one tears the session down.
	if !validMsgType(t) && t >= 0x80 {
		return nil, 0, ErrFraming
	}
	if ctLen < aeadTagSize+2 || ctLen > MaxRecordCiphertext {
		return nil, 0, ErrFraming
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(rw, ct); err != nil {
		return nil, 0, err
	}
	wire := RecordHeaderSize + ctLen
	s.recvBytes.Add(uint64(wire))
	// Ordered profile: sequence must equal expected counter.
	if seq != s.recvSeq.Load() {
		return nil, 0, ErrReplay
	}
	padded, err := s.recvAEAD.Open(nil, s.nonce(seq), ct, header)
	if err != nil {
		return nil, 0, ErrTag
	}
	s.recvSeq.Store(seq + 1)
	payload, err := Unpad(padded)
	if err != nil {
		return nil, 0, err
	}
	return &Record{Type: t, Seq: seq, StreamID: streamID, Payload: payload}, wire, nil
}

// ackEvery is how many received wire bytes may go unacknowledged before the
// read loop tells the peer its receive counter. The peer keeps every
// stream-affecting record until it is acknowledged, so this is also the
// replay memory an idle session pins.
const ackEvery = 256 << 10

func (s *Session) readLoop(ls *loopSet, rw io.Reader) {
	defer close(ls.readDone)
	unacked := 0
	for {
		rec, n, err := s.readRecordN(rw)
		if err != nil {
			s.fail(err, ls)
			return
		}
		s.dispatch(rec)
		if unacked += n; unacked >= ackEvery {
			unacked = 0
			if s.peerFeat.Load()&FeatReplay != 0 {
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], s.recvSeq.Load())
				s.sendFromDispatch(MsgAck, 0, b[:])
			}
		}
	}
}

func (s *Session) getStream(id uint32) (*stream, bool) {
	s.smu.RLock()
	st, ok := s.streams[id]
	s.smu.RUnlock()
	return st, ok
}

func (s *Session) dropStream(id uint32) {
	s.smu.Lock()
	if _, ok := s.streams[id]; ok {
		delete(s.streams, id)
		// Stream ids are odd when the client opened them, even otherwise.
		if peerOpened := (id&1 == 1) != s.isClient; peerOpened {
			s.ended.add(id)
		}
	}
	s.smu.Unlock()
}

// endedSet is a fixed-size memory of recently finished stream ids.
type endedSet struct {
	ring [endedSetSize]uint32
	n    int // ids ever added
	set  map[uint32]struct{}
}

const endedSetSize = 1024

func (e *endedSet) add(id uint32) {
	if e.set == nil {
		e.set = make(map[uint32]struct{}, endedSetSize)
	}
	slot := e.n % endedSetSize
	if e.n >= endedSetSize {
		delete(e.set, e.ring[slot])
	}
	e.ring[slot] = id
	e.set[id] = struct{}{}
	e.n++
}

func (e *endedSet) has(id uint32) bool {
	_, ok := e.set[id]
	return ok
}

// dispatch applies one inbound record. It runs on the read loop and must
// never block: everything it emits goes through sendFromDispatch.
func (s *Session) dispatch(rec *Record) {
	switch rec.Type {
	case MsgOpen:
		if _, ok := s.getStream(rec.StreamID); ok {
			// Replayed OPEN after migration — the stream exists already;
			// re-acknowledge it instead of redialing the target.
			s.sendFromDispatch(MsgOpenAck, rec.StreamID, []byte{0x00})
			return
		}
		st := newStream(s, rec.StreamID)
		st.openPayload = rec.Payload
		s.smu.Lock()
		if s.ended.has(rec.StreamID) {
			// A second copy of an OPEN whose stream already ran its course.
			s.smu.Unlock()
			return
		}
		s.streams[rec.StreamID] = st
		s.smu.Unlock()
		select {
		case s.acceptCh <- st:
		default:
			s.dropStream(rec.StreamID)
			st.fail(abortf("accept backlog full"))
			s.sendFromDispatch(MsgRst, rec.StreamID, []byte("backpressure"))
		}
	case MsgOpenAck:
		if st, ok := s.getStream(rec.StreamID); ok {
			st.setDialResult(rec.Payload)
			if !(len(rec.Payload) == 1 && rec.Payload[0] == 0x00) {
				st.fail(abortf("remote dial failed: %v", rec.Payload))
			}
		}
	case MsgData:
		if st, ok := s.getStream(rec.StreamID); ok {
			st.feed(rec.Payload)
		}
	case MsgClose:
		if st, ok := s.getStream(rec.StreamID); ok {
			st.remoteClose()
		}
	case MsgRst:
		if s.spuriousMigrateRst(rec) {
			return
		}
		if st, ok := s.getStream(rec.StreamID); ok {
			st.reset(abortf("reset by peer"))
		}
	case MsgPing:
		s.sendFromDispatch(MsgPong, rec.StreamID, rec.Payload)
	case MsgPong:
		// liveness replies are consumed by PingWait
		if ch := s.pongCh(); ch != nil {
			select {
			case ch <- rec.Payload:
			default:
			}
		}
	case MsgTicket:
		// Server-issued resumption ticket: sessionID(8) || ticket.
		if s.isClient && len(rec.Payload) > 8 {
			s.storeTicket(rec.Payload)
		}
	case MsgMigrate:
		// First record after a resumption. Its checkpoint repeats what the
		// resumption flight already carried; the replay is driven by that.
	case MsgSettings:
		s.applySettings(rec.Payload)
	case MsgAck:
		if len(rec.Payload) >= 8 {
			s.acked(binary.BigEndian.Uint64(rec.Payload))
		}
	}
}

// spuriousMigrateRst reports whether rec is a reconcile reset that must be
// ignored. A pre-2.2 peer compares stream tables by set difference when a
// session resumes and resets every stream it does not hold yet — including
// one whose OPEN was simply still in flight when the transport died. That
// OPEN is in our replay, the peer is about to create the stream after all,
// and honouring the reset would kill a healthy connection.
func (s *Session) spuriousMigrateRst(rec *Record) bool {
	if p := string(rec.Payload); p != "migrate" && p != "migrate-gap" {
		return false
	}
	s.migMu.Lock()
	defer s.migMu.Unlock()
	if _, ok := s.replayOpen[rec.StreamID]; !ok {
		return false
	}
	delete(s.replayOpen, rec.StreamID)
	return true
}

// fail handles a terminal read/write error raised by the loops of generation
// ls (nil = raised from outside the loops, e.g. a watchdog). Protocol
// violations are always fatal; transport errors freeze a migratable session
// so a resumption can re-attach it without losing its streams.
func (s *Session) fail(err error, ls *loopSet) {
	if ls != nil {
		s.migMu.Lock()
		stale := s.loops != ls
		s.migMu.Unlock()
		if stale {
			return // dead transport's error — a newer attach owns the session
		}
	}
	if _, proto := err.(Error); !proto && s.migratable.Load() && !s.isDead() {
		s.freeze()
		return
	}
	s.die(err)
}

// die ends the session for good: every stream is aborted with the cause.
func (s *Session) die(err error) {
	s.failStreams(err)
	s.Close()
}

// NeedsMigrate is closed when a migratable session's transport died: the
// caller should re-dial a carrier and resume instead of losing the streams.
func (s *Session) NeedsMigrate() <-chan struct{} {
	s.migMu.Lock()
	defer s.migMu.Unlock()
	return s.migrateCh
}

// Frozen reports whether the session lost its transport but still holds
// its streams awaiting resumption.
func (s *Session) Frozen() bool {
	s.migMu.Lock()
	defer s.migMu.Unlock()
	return s.frozen
}

// freeze parks a transport-dead session: the record loops are retired,
// streams keep their state, writers backpressure into the queues, and a TTL
// bounds the wait for resumption.
func (s *Session) freeze() {
	s.migMu.Lock()
	rw, ls := s.freezeLocked()
	s.migMu.Unlock()
	retireTransport(rw, ls)
}

// freezeLocked marks the session frozen (caller holds migMu) and returns the
// transport and loops the caller must retire once the lock is released.
// Nil results mean there was nothing to do.
func (s *Session) freezeLocked() (io.Closer, *loopSet) {
	if s.frozen || s.isDead() {
		return nil, nil
	}
	s.frozen = true
	ttl := s.migrateTTL
	if ttl == 0 {
		ttl = 120 * time.Second
	}
	s.freezeT = time.AfterFunc(ttl, s.expireMigration)
	select {
	case <-s.migrateCh:
	default:
		close(s.migrateCh)
	}
	return s.rw, s.loops
}

func retireTransport(rw io.Closer, ls *loopSet) {
	if ls != nil {
		ls.retire()
	}
	if rw != nil {
		_ = rw.Close()
	}
}

// quiesce freezes the session if it still runs and waits until the retired
// generation's loops are gone. After it returns nil, the receive counter and
// the replay window cannot move until a resumption attaches a new transport.
func (s *Session) quiesce() error {
	return s.quiesceAt(0)
}

// quiesceAt is quiesce for a resumption attempt that was prepared against
// transport generation gen (0 = any): if the session has been re-attached
// since — a sibling attempt of a hedged dial won the race — it refuses
// instead of freezing a session that is healthy again.
func (s *Session) quiesceAt(gen uint64) error {
	s.migMu.Lock()
	if s.isDead() {
		s.migMu.Unlock()
		return ErrClosed
	}
	if gen != 0 && s.attachGen != gen {
		s.migMu.Unlock()
		return ErrMigrate
	}
	rw, ls := s.freezeLocked()
	cur := s.loops
	s.migMu.Unlock()
	retireTransport(rw, ls)
	if cur != nil && !cur.wait(quiesceTimeout) {
		return ErrMigrate
	}
	return nil
}

// expireMigration is the TTL shot: resumption never arrived — fail for real.
func (s *Session) expireMigration() {
	s.migMu.Lock()
	frozen := s.frozen
	s.migMu.Unlock()
	if !frozen {
		return
	}
	s.die(ErrMigrate)
}

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------

// sentRec is an emitted record retained until the peer acknowledges it.
type sentRec struct {
	seq uint64
	t   byte
	id  uint32
	p   []byte
}

// retainedType reports whether a record must survive a transport loss.
// Everything that changes stream state does, and so does TICKET: a lost
// ticket would otherwise leave the client unable to resume a second time.
// PING/PONG/ACK/SETTINGS/MIGRATE are either idempotent or re-announced.
func retainedType(t byte) bool {
	switch t {
	case MsgOpen, MsgData, MsgClose, MsgRst, MsgOpenAck, MsgTicket:
		return true
	}
	return false
}

// sentWindow holds the records emitted but not yet acknowledged, in sequence
// order. It is bounded: when acknowledgements stop arriving (a pre-2.2 peer
// never sends any, a dead path cannot) the oldest records are evicted and
// remembered as lost, and a resumption that would need them is refused as an
// unrecoverable gap instead of replaying a stream with a hole in it.
type sentWindow struct {
	recs  []sentRec
	bytes int
	// lost is one past the highest sequence evicted or never retained while
	// unacknowledged; 0 = nothing lost.
	lost uint64
}

const (
	// sentWinMaxRecs / sentWinMaxBytes bound the replay window. The byte cap
	// is the one that matters for memory: a session used to pin its last
	// 2048 records regardless of size — 64 MiB after any bulk transfer.
	sentWinMaxRecs  = 2048
	sentWinMaxBytes = 8 << 20
)

func (w *sentWindow) push(r sentRec) {
	w.recs = append(w.recs, r)
	w.bytes += len(r.p)
	// Evict from the head until both caps hold; the newest record always
	// stays, however large.
	bytes, over := w.bytes, 0
	for len(w.recs)-over > sentWinMaxRecs || (bytes > sentWinMaxBytes && len(w.recs)-over > 1) {
		bytes -= len(w.recs[over].p)
		over++
	}
	if over > 0 {
		w.dropHead(over, true)
	}
}

// forget records that seq was emitted without being retained.
func (w *sentWindow) forget(seq uint64) {
	if seq+1 > w.lost {
		w.lost = seq + 1
	}
}

// dropHead releases the n oldest records; lost marks them as evicted while
// unacknowledged (as opposed to acknowledged).
func (w *sentWindow) dropHead(n int, lost bool) {
	for i := 0; i < n; i++ {
		w.bytes -= len(w.recs[i].p)
		if lost {
			w.forget(w.recs[i].seq)
		}
		w.recs[i] = sentRec{} // drop the payload reference
	}
	w.recs = w.recs[n:]
	if len(w.recs) == 0 {
		w.recs = nil // release the backing array
	}
}

// ack releases every record the peer has received (seq < next).
func (w *sentWindow) ack(next uint64) {
	n := 0
	for n < len(w.recs) && w.recs[n].seq < next {
		n++
	}
	if n > 0 {
		w.dropHead(n, false)
	}
}

func (w *sentWindow) reset() { *w = sentWindow{} }

// retains reports whether this session keeps a replay window at all: a
// client always may be handed a ticket, a server only resumes sessions its
// registry adopted. Caller holds migMu or tolerates a stale answer.
func (s *Session) retains() bool { return s.isClient || s.migratable.Load() }

// acked applies a cumulative acknowledgement from the peer.
func (s *Session) acked(next uint64) {
	s.migMu.Lock()
	if next <= s.sendSeq { // a peer cannot have received what was never sent
		s.sent.ack(next)
	}
	s.migMu.Unlock()
}

// ---------------------------------------------------------------------------
// Settings (v2.2 capability announcement)
// ---------------------------------------------------------------------------

// Feature bits carried in SETTINGS. A feature is in effect only when both
// ends announce it; a peer that never sends SETTINGS announces none.
const (
	// FeatReplay: the peer acknowledges received records (ACK) and resumes
	// by exact replay — it does not reconcile stream tables by set
	// difference, so the stream list in a checkpoint is advisory.
	FeatReplay uint32 = 1 << 0
)

// localFeatures is what this implementation announces.
const localFeatures = FeatReplay

// settingsVersion is the SETTINGS payload layout: version(1) || features(4,BE)
// followed by optional TLVs a newer peer may append (ignored here).
const settingsVersion byte = 1

// announce sends the idempotent session state a peer needs after an attach:
// our SETTINGS. It is repeated after every resumption because control
// records are not replayed — one lost with the previous transport would
// otherwise leave the peer treating us as a pre-2.2 implementation forever.
func (s *Session) announce() {
	var p [5]byte
	p[0] = settingsVersion
	binary.BigEndian.PutUint32(p[1:], localFeatures)
	s.sendFromDispatch(MsgSettings, 0, p[:])
}

func (s *Session) applySettings(p []byte) {
	if len(p) < 5 || p[0] < settingsVersion {
		return
	}
	s.peerFeat.Store(binary.BigEndian.Uint32(p[1:5]) & localFeatures)
}

// ---------------------------------------------------------------------------
// Streams (minimal reliable mux over the ordered carrier)
// ---------------------------------------------------------------------------

// OpenTarget encodes a CONNECT-style open payload (implies "tcp").
func OpenTarget(network, host string, port uint16) []byte {
	return OpenTargetNet(network, host, port)
}

// OpenTargetNet encodes an open payload with an explicit network tag.
// Wire format (v2): [0x80|atyp][netTag][host...][port] — the 0x80 marker lets
// old servers reject cleanly (unknown atyp) instead of mis-parsing. "tcp"
// targets may also use the legacy v1 encoding from OpenTarget.
func OpenTargetNet(network, host string, port uint16) []byte {
	var atyp byte
	ip := net.ParseIP(host)
	var hostBytes []byte
	if ip == nil {
		atyp = 0x03
		hostBytes = []byte(host)
	} else if v4 := ip.To4(); v4 != nil {
		atyp = 0x01
		hostBytes = v4
	} else {
		atyp = 0x04
		hostBytes = ip.To16()
	}
	netTag := byte('t')
	if strings.EqualFold(network, "udp") {
		netTag = 'u'
	}
	explicit := netTag != 't'
	out := make([]byte, 0, 5+len(hostBytes)+2)
	if explicit {
		out = append(out, atyp|0x80, netTag)
	} else {
		out = append(out, atyp)
	}
	if atyp == 0x03 {
		out = append(out, byte(len(hostBytes)))
	}
	out = append(out, hostBytes...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(out, p[:]...)
}

// ParseOpenTarget decodes an OPEN payload (v1 implies tcp; v2 carries the
// network tag after the 0x80|atyp marker).
func ParseOpenTarget(b []byte) (network, host string, port uint16, err error) {
	if len(b) < 4 {
		return "", "", 0, ErrFraming
	}
	network = "tcp"
	atyp := b[0]
	if atyp&0x80 != 0 {
		atyp &^= 0x80
		if len(b) < 5 {
			return "", "", 0, ErrFraming
		}
		switch b[1] {
		case 't':
			network = "tcp"
		case 'u':
			network = "udp"
		default:
			return "", "", 0, ErrFraming
		}
		b = b[1:] // fall through with the tag consumed
	}
	switch atyp {
	case 0x01:
		if len(b) < 7 {
			return "", "", 0, ErrFraming
		}
		host = net.IP(b[1:5]).String()
		port = binary.BigEndian.Uint16(b[5:7])
	case 0x03:
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", "", 0, ErrFraming
		}
		host = string(b[2 : 2+l])
		port = binary.BigEndian.Uint16(b[2+l : 2+l+2])
	case 0x04:
		if len(b) < 19 {
			return "", "", 0, ErrFraming
		}
		host = net.IP(b[1:17]).String()
		port = binary.BigEndian.Uint16(b[17:19])
	default:
		return "", "", 0, ErrFraming
	}
	return network, host, port, nil
}

// Open opens a TCP stream to target on the server and returns it after OPEN_ACK.
func (s *Session) Open(host string, port uint16, timeout time.Duration) (*Stream, error) {
	return s.OpenNet("tcp", host, port, timeout)
}

// OpenOpt returns the stream as soon as OPEN is on the wire — the caller may
// start writing immediately (the server buffers data until its target dial
// completes), so request+open travel in the same flight and first byte costs
// ~1 RTT instead of ~2. A refused dial arrives later as a stream abort;
// callers needing the synchronous dial result use OpenNet.
func (s *Session) OpenOpt(host string, port uint16) (*Stream, error) {
	st, err := s.openStream("tcp", host, port)
	if err != nil {
		return nil, err
	}
	return &Stream{stream: st}, nil
}

// openStream allocates and registers a stream and puts OPEN on the wire. It
// does not wait for OPEN_ACK.
func (s *Session) openStream(network, host string, port uint16) (*stream, error) {
	id := s.allocID()
	st := newStream(s, id)
	s.smu.Lock()
	s.streams[id] = st
	s.smu.Unlock()
	if err := s.sendRecord(MsgOpen, id, OpenTargetNet(network, host, port)); err != nil {
		s.dropStream(id)
		st.fail(abortf("open: %v", err))
		return nil, err
	}
	return st, nil
}

func (s *Session) allocID() uint32 {
	s.smu.Lock()
	defer s.smu.Unlock()
	id := s.nextID
	s.nextID += 2
	return id
}

// OpenNet opens a stream with an explicit network ("tcp" or "udp").
func (s *Session) OpenNet(network, host string, port uint16, timeout time.Duration) (*Stream, error) {
	st, err := s.openStream(network, host, port)
	if err != nil {
		return nil, err
	}
	if !st.waitDial(timeout) {
		s.dropStream(st.id)
		st.fail(abortf("open timeout"))
		_ = s.sendRecord(MsgRst, st.id, []byte("open timeout"))
		return nil, fmt.Errorf("session: open timeout or refused")
	}
	if st.dialErr != nil {
		s.dropStream(st.id)
		st.fail(abortf("open: %v", st.dialErr))
		return nil, st.dialErr
	}
	return &Stream{stream: st}, nil
}

// Ping sends PING and waits for the echo. Multiple callers are supported:
// waiters queue FIFO and each incoming PONG satisfies the oldest one — the
// ordered carrier returns echoes in request order, and a PONG from any peer
// activity answers exactly one outstanding ping.
func (s *Session) Ping(payload []byte, timeout time.Duration) error {
	ch := s.registerPong()
	defer s.unregisterPong(ch)
	if err := s.sendRecord(MsgPing, 0, payload); err != nil {
		return err
	}
	select {
	case <-ch:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("session: pong timeout")
	case <-s.closed:
		return ErrClosed
	}
}

// --- stream internals --------------------------------------------------------

// streamRecvMax bounds what one stream may hold for a consumer that is not
// reading. The record channel carries no per-stream credit yet, so a sender
// faster than the consumer cannot be slowed down — past this the stream is
// aborted (both ends see the abort) rather than stall the demux for every
// other stream or buffer without limit. Each queued chunk is charged a fixed
// overhead so a flood of tiny records cannot hide behind a small byte count.
const (
	streamRecvMax      = 32 << 20
	streamChunkCharged = 64
)

type stream struct {
	s  *Session
	id uint32

	mu     sync.Mutex
	rq     [][]byte // received chunks the consumer has not taken yet
	rhead  []byte   // unread remainder of the chunk being consumed
	rqCost int      // bytes charged against streamRecvMax
	// Terminal state. eof: the peer closed after delivering everything —
	// readers see io.EOF once the queue drains. err: the stream ended
	// abnormally — readers see it once the queue drains, or at once when
	// dropped is set (a reset discards what was not consumed, as TCP does).
	eof     bool
	err     error
	dropped bool
	lclosed bool // the local application closed or reset the stream
	wclosed bool // nothing more may be written (any terminal state)

	rsig chan struct{} // wakes the reader on any state change

	dialCh      chan []byte
	dialErr     error
	openPayload []byte
	// net.Conn deadline contract (unix ns, 0 = none). These were no-op
	// placeholders: callers relying on them (SOCKS idle timeouts, the mux
	// soak churn) blocked forever.
	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
}

func newStream(s *Session, id uint32) *stream {
	return &stream{
		s:      s,
		id:     id,
		rsig:   make(chan struct{}, 1),
		dialCh: make(chan []byte, 1),
	}
}

func (st *stream) wakeReader() {
	select {
	case st.rsig <- struct{}{}:
	default:
	}
}

// feed queues a DATA payload for the consumer. Called on the demux goroutine,
// so it must never block: a consumer that stalled past the cap gets its
// stream aborted, the session and its other streams carry on.
func (st *stream) feed(b []byte) {
	if len(b) == 0 {
		return
	}
	st.mu.Lock()
	if st.eof || st.err != nil || st.lclosed {
		st.mu.Unlock()
		return // terminal: late records for a finished stream are dropped
	}
	cost := len(b) + streamChunkCharged
	if st.rqCost+cost > streamRecvMax {
		st.mu.Unlock()
		st.s.dropStream(st.id)
		st.reset(abortf("receive buffer overflow: consumer too slow"))
		st.s.sendFromDispatch(MsgRst, st.id, []byte("buffer full"))
		return
	}
	st.rq = append(st.rq, b)
	st.rqCost += cost
	st.mu.Unlock()
	st.wakeReader()
}

func (st *stream) setDialResult(payload []byte) {
	select {
	case st.dialCh <- payload:
	default:
	}
}

func (st *stream) waitDial(timeout time.Duration) bool {
	select {
	case code := <-st.dialCh:
		if len(code) == 1 && code[0] == 0x00 {
			return true
		}
		st.dialErr = fmt.Errorf("session: remote dial failed: %v", code)
		return true
	case <-time.After(timeout):
		return false
	case <-st.s.closed:
		st.dialErr = ErrClosed
		return true
	}
}

// remoteClose handles the peer's CLOSE: it is gone for good (a CLOSE is a
// full close on the wire), so the consumer gets what is queued and then a
// clean end, and nothing more can be written. The stream leaves the session
// table at once — no later record can belong to it.
func (st *stream) remoteClose() {
	st.mu.Lock()
	if !st.eof && st.err == nil {
		st.eof = true
	}
	st.wclosed = true
	st.mu.Unlock()
	st.s.dropStream(st.id)
	st.wakeReader()
}

// reset aborts the stream: the consumer sees err immediately and unread data
// is discarded. A reset that arrives after the peer's clean CLOSE is ignored —
// the stream already ended well and its tail is still owed to the consumer.
func (st *stream) reset(err error) {
	st.mu.Lock()
	if !st.eof && st.err == nil {
		st.err = err
		st.dropped = true
		st.rq, st.rhead, st.rqCost = nil, nil, 0
	}
	st.wclosed = true
	st.mu.Unlock()
	st.s.dropStream(st.id)
	st.wakeReader()
}

// fail ends the stream abnormally without discarding what already arrived:
// the consumer drains the queue, then sees err instead of a clean end.
func (st *stream) fail(err error) {
	st.mu.Lock()
	if !st.eof && st.err == nil {
		st.err = err
	}
	st.wclosed = true
	st.mu.Unlock()
	st.wakeReader()
}

// closeLocal marks the stream closed by the local application. It reports
// whether this call made the transition and whether the peer still holds the
// stream (it has neither closed nor reset it), i.e. whether it needs telling.
func (st *stream) closeLocal() (first, tellPeer bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.lclosed {
		return false, false
	}
	tellPeer = !st.eof && st.err == nil
	st.lclosed = true
	st.wclosed = true
	st.dropped = true
	if st.err == nil {
		st.err = io.ErrClosedPipe
	}
	st.rq, st.rhead, st.rqCost = nil, nil, 0
	return true, tellPeer
}

// writable returns nil while the stream accepts data, else why it does not.
func (st *stream) writable() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.wclosed {
		return nil
	}
	if st.err != nil && !st.lclosed {
		return st.err
	}
	return io.ErrClosedPipe
}

// Stream is a net.Conn facade over a muxed stream.
type Stream struct {
	*stream
}

// Read implements net.Conn. It returns io.EOF only when the peer closed the
// stream after delivering everything; any other end of the stream is an
// error (see IsAbort) so truncation is never mistaken for completion.
func (st *Stream) Read(b []byte) (int, error) {
	for {
		st.mu.Lock()
		if st.dropped {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		if len(st.rhead) == 0 && len(st.rq) > 0 {
			st.rhead = st.rq[0]
			st.rq[0] = nil
			st.rq = st.rq[1:]
			if len(st.rq) == 0 {
				st.rq = nil
			}
			st.rqCost -= streamChunkCharged
		}
		if len(st.rhead) > 0 {
			n := copy(b, st.rhead)
			st.rhead = st.rhead[n:]
			st.rqCost -= n
			more := len(st.rhead) > 0 || len(st.rq) > 0
			st.mu.Unlock()
			if more {
				st.wakeReader() // a second reader must not sleep on queued data
			}
			return n, nil
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		if st.eof {
			st.mu.Unlock()
			return 0, io.EOF
		}
		st.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if dl := st.readDeadline.Load(); dl != 0 {
			rem := time.Until(time.Unix(0, dl))
			if rem <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(rem)
			timeout = timer.C
		}
		select {
		case <-st.rsig:
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// Write implements net.Conn. The write deadline covers the whole call
// across chunks (a deadline is a point in time, not a per-chunk budget).
func (st *Stream) Write(b []byte) (int, error) {
	var timer *time.Timer
	var timeout <-chan time.Time
	if dl := st.writeDeadline.Load(); dl != 0 {
		if rem := time.Until(time.Unix(0, dl)); rem > 0 {
			timer = time.NewTimer(rem)
			timeout = timer.C
			defer timer.Stop()
		} else {
			return 0, os.ErrDeadlineExceeded
		}
	}
	total := 0
	for total < len(b) {
		if err := st.writable(); err != nil {
			return total, err
		}
		n := len(b) - total
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := st.s.sendRecordDeadline(MsgData, st.id, b[total:total+n], timeout); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Close ends the stream gracefully: data already written is delivered, then
// the peer's reader sees a clean end. Further reads and writes fail.
func (st *Stream) Close() error {
	first, tellPeer := st.closeLocal()
	if !first {
		return nil
	}
	st.s.dropStream(st.id)
	st.wakeReader()
	if !tellPeer {
		return nil // the peer already dropped the stream
	}
	return st.s.sendRecord(MsgClose, st.id, nil)
}

// Reset aborts the stream: the peer's reader sees an abort instead of a clean
// end, and data still queued for it may be discarded. Use it when the local
// side of a relayed connection failed, so the failure is not mistaken for
// completion at the far end.
func (st *Stream) Reset() error {
	first, tellPeer := st.closeLocal()
	if !first {
		return nil
	}
	st.s.dropStream(st.id)
	st.wakeReader()
	if !tellPeer {
		return nil
	}
	return st.s.sendRecord(MsgRst, st.id, []byte("abort"))
}

// LocalAddr / RemoteAddr are placeholders (carrier-level).
func (st *Stream) LocalAddr() net.Addr  { return nil }
func (st *Stream) RemoteAddr() net.Addr { return nil }

// SetDeadline implements net.Conn: real read/write deadline semantics —
// the previous placeholders returned nil and silently discarded deadlines,
// so any caller relying on them blocked indefinitely.
func (st *Stream) SetDeadline(t time.Time) error {
	st.readDeadline.Store(deadlineNanos(t))
	st.writeDeadline.Store(deadlineNanos(t))
	st.wakeReader()
	return nil
}
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.readDeadline.Store(deadlineNanos(t))
	st.wakeReader() // a blocked Read re-evaluates against the new deadline
	return nil
}
func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.writeDeadline.Store(deadlineNanos(t))
	return nil
}

// deadlineNanos maps the zero time (no deadline) to 0.
func deadlineNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// Accept returns the next inbound stream (server side).
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return &Stream{stream: st}, nil
	case <-s.closed:
		return nil, ErrClosed
	}
}

// Ack tells the opener the dial result: 0x00 ok, anything else = refused.
// The acceptor must call it after resolving/dialing the target.
func (st *Stream) Ack(code byte) error {
	return st.s.sendRecord(MsgOpenAck, st.id, []byte{code})
}

// OpenPayload returns the raw OPEN payload (server side).
func (st *Stream) OpenPayload() []byte { return st.openPayload }

// Target decodes the OPEN payload (server side).
func (st *Stream) Target() (network, host string, port uint16, err error) {
	return ParseOpenTarget(st.openPayload)
}

// pong registry ---------------------------------------------------------------

func (s *Session) pongCh() chan []byte {
	s.pongMu.Lock()
	defer s.pongMu.Unlock()
	if len(s.pongQ) == 0 {
		return nil
	}
	ch := s.pongQ[0]
	s.pongQ = s.pongQ[1:]
	return ch
}

func (s *Session) registerPong() chan []byte {
	ch := make(chan []byte, 1)
	s.pongMu.Lock()
	s.pongQ = append(s.pongQ, ch)
	s.pongMu.Unlock()
	return ch
}

func (s *Session) unregisterPong(ch chan []byte) {
	s.pongMu.Lock()
	defer s.pongMu.Unlock()
	for i, w := range s.pongQ {
		if w == ch {
			s.pongQ = append(s.pongQ[:i], s.pongQ[i+1:]...)
			return
		}
	}
}
