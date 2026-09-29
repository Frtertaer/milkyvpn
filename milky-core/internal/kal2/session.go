package kal2

import (
	"container/heap"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
type Session struct {
	transcript []byte
	sendKey    []byte
	recvKey    []byte
	nonceBase  []byte
	verify     []byte
	isClient   bool

	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	sendSeq uint64
	recvSeq uint64

	rw io.ReadWriteCloser

	// padBucket is this direction's padding multiple (default PadBucketSize);
	// randomized per session so wire packet-size histograms differ run to run.
	// Used only when padMode == PadBucketMode.
	padBucket int

	// padMode selects the record padding strategy (PadMimicMode by default).
	// The peer needs no matching mode — padding is self-delimiting.
	padMode PadMode

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

	smu       sync.RWMutex // guards streams
	streams   map[uint32]*stream
	acceptCh  chan *stream
	nextID    uint32
	writeErr  error
	sentBytes atomic.Uint64 // wire bytes emitted; lane picker reads it
	closed    chan struct{}
	closeOnce sync.Once
	readDone  chan struct{}
	// pongMu guards pongQ: the FIFO queue of outstanding Ping waiters.
	// Concurrent Pings used to overwrite a single shared channel, so pongs
	// were misdelivered and callers timed out on a live session (a spurious
	// failure the lanes watchdog reads as lane death).
	pongMu    sync.Mutex
	pongQ     []chan []byte
}

type outRec struct {
	t  byte
	id uint32
	p  []byte
}

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
	s.readDone = make(chan struct{})
	s.ctrlCh = make(chan outRec, 512)
	s.data = newDataLane()
	if s.isClient {
		s.nextID = 1 // clients use odd stream ids
	} else {
		s.nextID = 2 // servers (only for server-initiated streams; unused now)
	}
	s.initAEAD()
	go s.readLoop()
	go s.writeLoop()
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

// Close terminates the session and its carrier.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.closed != nil {
			close(s.closed)
		}
		if s.rw != nil {
			err = s.rw.Close()
		}
	})
	return err
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
		}
		s.data.enqueue(rec)
		return nil
	}
	select {
	case s.ctrlCh <- rec:
		return nil
	case <-s.closed:
		return ErrClosed
	}
}

// writeBatchBytes bounds the frames coalesced into one carrier write: larger
// writes mean larger TLS records — fewer segments (throughput) and a packet
// rate closer to ordinary bulk HTTP rather than a chattery tunnel.
const writeBatchBytes = 1 << 14

// writeLoop is the single serialized emitter. It blocks for the first queued
// record, then greedily drains whatever else is queued — control lane first,
// then DATA — into one carrier write, so opens/acks/rsts/pongs never queue
// behind bulk transfer and busy links emit few large writes.
func (s *Session) writeLoop() {
	for {
		var first outRec
		haveFirst := false
		select {
		case first = <-s.ctrlCh:
			haveFirst = true
		default:
			if r, ok := s.data.pop(); ok {
				first = r
				haveFirst = true
			}
		}
		if !haveFirst {
			select {
			case first = <-s.ctrlCh:
				haveFirst = true
			case <-s.data.wake:
				if r, ok := s.data.pop(); ok {
					first = r
					haveFirst = true
				}
			case <-s.closed:
				return
			}
		}
		var buf []byte
		if haveFirst {
			buf = s.appendFrame(buf, first)
		}
		target := s.batchTarget()
	batch:
		for len(buf) < target {
			select {
			case r := <-s.ctrlCh:
				buf = s.appendFrame(buf, r)
				continue
			default:
			}
			select {
			case r := <-s.ctrlCh:
				buf = s.appendFrame(buf, r)
			default:
				if r, ok := s.data.pop(); ok {
					buf = s.appendFrame(buf, r)
					continue
				}
				break batch
			}
		}
		if len(buf) == 0 {
			continue // spurious wake
		}
		if !s.flushBuf(buf) {
			return
		}
	}
}

// appendFrame encrypts one record into buf. Runs only on the writer goroutine;
// an undeliverable payload is dropped (the session continues).
func (s *Session) appendFrame(buf []byte, r outRec) []byte {
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
		return buf
	}
	seq := s.sendSeq
	header := encodeHeader(r.t, seq, r.id, len(padded)+aeadTagSize)
	ct := s.sendAEAD.Seal(nil, s.nonce(seq), padded, header)
	buf = append(buf, header...)
	buf = append(buf, ct...)
	s.sendSeq++
	return buf
}

// SentBytes reports total wire bytes this session has emitted.
func (s *Session) SentBytes() uint64 { return s.sentBytes.Load() }

// SetPadMode selects the padding strategy for records this session emits.
// Set it before Attach so the writer goroutine sees the final choice.
func (s *Session) SetPadMode(m PadMode) { s.padMode = m }

// flushBuf writes one coalesced batch; failure marks the session dead.
func (s *Session) flushBuf(buf []byte) bool {
	s.sentBytes.Add(uint64(len(buf)))
	if _, err := s.rw.Write(buf); err != nil {
		s.smu.Lock()
		s.writeErr = err
		s.smu.Unlock()
		s.fail(err)
		return false
	}
	return true
}

// readRecord reads and authenticates the next record.
func (s *Session) readRecord() (*Record, error) {
	header := make([]byte, RecordHeaderSize)
	if _, err := io.ReadFull(s.rw, header); err != nil {
		return nil, err
	}
	t, seq, streamID, ctLen, err := decodeHeader(header)
	if err != nil {
		return nil, err
	}
	if !validMsgType(t) {
		return nil, ErrFraming
	}
	if ctLen < aeadTagSize+2 || ctLen > MaxRecordCiphertext {
		return nil, ErrFraming
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(s.rw, ct); err != nil {
		return nil, err
	}
	// Ordered profile: sequence must equal expected counter.
	if seq != s.recvSeq {
		return nil, ErrReplay
	}
	padded, err := s.recvAEAD.Open(nil, s.nonce(seq), ct, header)
	if err != nil {
		return nil, ErrTag
	}
	s.recvSeq = seq + 1
	payload, err := Unpad(padded)
	if err != nil {
		return nil, err
	}
	return &Record{Type: t, Seq: seq, StreamID: streamID, Payload: payload}, nil
}

func (s *Session) readLoop() {
	defer close(s.readDone)
	for {
		rec, err := s.readRecord()
		if err != nil {
			s.fail(err)
			return
		}
		s.dispatch(rec)
	}
}

func (s *Session) getStream(id uint32) (*stream, bool) {
	s.smu.RLock()
	st, ok := s.streams[id]
	s.smu.RUnlock()
	return st, ok
}

func (s *Session) dispatch(rec *Record) {
	switch rec.Type {
	case MsgOpen:
		st := newStream(s, rec.StreamID)
		st.openPayload = rec.Payload
		s.smu.Lock()
		s.streams[rec.StreamID] = st
		s.smu.Unlock()
		select {
		case s.acceptCh <- st:
		default:
			_ = s.sendRecord(MsgRst, rec.StreamID, []byte("backpressure"))
			s.smu.Lock()
			delete(s.streams, rec.StreamID)
			s.smu.Unlock()
		}
	case MsgOpenAck:
		if st, ok := s.getStream(rec.StreamID); ok {
			st.setDialResult(rec.Payload)
			if !(len(rec.Payload) == 1 && rec.Payload[0] == 0x00) {
				st.fail(fmt.Errorf("session: remote dial failed: %v", rec.Payload))
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
		if st, ok := s.getStream(rec.StreamID); ok {
			st.reset()
		}
	case MsgPing:
		_ = s.sendRecord(MsgPong, rec.StreamID, rec.Payload)
	case MsgPong:
		// liveness replies are consumed by PingWait
		if ch := s.pongCh(); ch != nil {
			select {
			case ch <- rec.Payload:
			default:
			}
		}
	}
}

func (s *Session) fail(err error) {
	s.smu.Lock()
	s.writeErr = err
	for _, st := range s.streams {
		st.fail(err)
	}
	s.smu.Unlock()
	s.Close()
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
// ~1 RTT instead of ~2. A refused dial arrives later as RST/reset; callers
// needing the synchronous dial result use OpenNet.
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
		s.smu.Lock()
		delete(s.streams, id)
		s.smu.Unlock()
		st.remoteClose()
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
		s.smu.Lock()
		delete(s.streams, st.id)
		s.smu.Unlock()
		st.remoteClose()
		_ = s.sendRecord(MsgRst, st.id, []byte("open timeout"))
		return nil, fmt.Errorf("session: open timeout or refused")
	}
	if st.dialErr != nil {
		s.smu.Lock()
		delete(s.streams, st.id)
		s.smu.Unlock()
		st.remoteClose()
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

var errStreamClosed = fmt.Errorf("session: stream closed")

// --- stream internals --------------------------------------------------------

// streamQueueMax bounds records buffered while the consumer stalls; beyond
// it the stream is reset (its peer gets RST) instead of stalling the demux.
const streamQueueMax = 512

type stream struct {
	s  *Session
	id uint32

	mu   sync.Mutex // guards rawQ
	rawQ [][]byte   // records waiting for the pump; feed() never blocks
	kick chan struct{}

	recvCh      chan []byte
	dialCh      chan []byte
	dialErr     error
	closedCh    chan struct{}
	closed      bool // guards the once-only close transition (mu)
	recvBuf     []byte
	openPayload []byte
}

func newStream(s *Session, id uint32) *stream {
	st := &stream{
		s:        s,
		id:       id,
		kick:     make(chan struct{}, 1),
		recvCh:   make(chan []byte, 256),
		dialCh:   make(chan []byte, 1),
		closedCh: make(chan struct{}),
	}
	go st.pump()
	return st
}

// feed appends to the stream's raw queue. Called on the demux goroutine, so
// it must never block: a full queue resets this stream, not the session.
func (st *stream) feed(b []byte) {
	st.mu.Lock()
	if len(st.rawQ) >= streamQueueMax {
		st.mu.Unlock()
		st.remoteClose()
		_ = st.s.sendRecord(MsgRst, st.id, []byte("buffer full"))
		return
	}
	st.rawQ = append(st.rawQ, b)
	st.mu.Unlock()
	select {
	case st.kick <- struct{}{}:
	default:
	}
}

// markClosed flips the closed flag once; false if already closed (mu).
func (st *stream) markClosed() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return false
	}
	st.closed = true
	return true
}

// queueEOF appends the nil sentinel behind any queued data, preserving order.
func (st *stream) queueEOF() {
	st.mu.Lock()
	st.rawQ = append(st.rawQ, nil)
	st.mu.Unlock()
	select {
	case st.kick <- struct{}{}:
	default:
	}
}

// pump moves rawQ into recvCh in order. It may block on recvCh — that only
// backpressures this stream, not the demux.
func (st *stream) pump() {
	for {
		st.mu.Lock()
		if len(st.rawQ) > 0 {
			b := st.rawQ[0]
			st.rawQ[0] = nil
			st.rawQ = st.rawQ[1:]
			st.mu.Unlock()
			if b == nil {
				// EOF sentinel: report close only after all queued data
				st.sendEOF()
				return
			}
			select {
			case st.recvCh <- b:
				continue
			case <-st.closedCh:
				return
			}
		}
		st.mu.Unlock()
		select {
		case <-st.kick:
		case <-st.closedCh:
			return
		}
	}
}

// sendEOF closes recvCh so readers drain rbuf then see io.EOF.
func (st *stream) sendEOF() {
	close(st.recvCh)
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

func (st *stream) remoteClose() {
	// Graceful close: keep ordering — the peer may still have sent data before
	// its close frame; enqueue EOF behind it instead of aborting reads.
	if st.markClosed() {
		st.queueEOF()
	}
}

func (st *stream) reset() {
	// Abrupt close (RST or session death): abort reads immediately.
	if st.markClosed() {
		close(st.closedCh)
	}
}

func (st *stream) fail(err error) {
	st.dialErr = err
	st.remoteClose()
}

func (st *stream) write(b []byte) error {
	return st.s.sendRecord(MsgData, st.id, b)
}

func (st *stream) close() error {
	st.remoteClose()
	return st.s.sendRecord(MsgClose, st.id, nil)
}

// Stream is a net.Conn facade over a muxed stream.
type Stream struct {
	*stream
	rbuf []byte
}

// Read implements net.Conn.
func (st *Stream) Read(b []byte) (int, error) {
	for len(st.rbuf) == 0 {
		select {
		case chunk, ok := <-st.recvCh:
			if !ok {
				return 0, io.EOF
			}
			st.rbuf = chunk
		case <-st.closedCh:
			return 0, io.EOF
		}
	}
	n := copy(b, st.rbuf)
	st.rbuf = st.rbuf[n:]
	return n, nil
}

// Write implements net.Conn.
func (st *Stream) Write(b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n := len(b) - total
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := st.write(b[total : total+n]); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Close half-closes the stream.
func (st *Stream) Close() error {
	st.s.smu.Lock()
	delete(st.s.streams, st.id)
	st.s.smu.Unlock()
	return st.close()
}

// LocalAddr / RemoteAddr / deadlines are placeholders (carrier-level).
func (st *Stream) LocalAddr() net.Addr                { return nil }
func (st *Stream) RemoteAddr() net.Addr               { return nil }
func (st *Stream) SetDeadline(t time.Time) error      { return nil }
func (st *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (st *Stream) SetWriteDeadline(t time.Time) error { return nil }

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
