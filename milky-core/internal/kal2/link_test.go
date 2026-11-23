package kal2

// Test transport and data helpers shared by the reliability, migration and
// interop tests.

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
)

// memHalf is one direction of an in-memory, buffered, cuttable byte link.
type memHalf struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
	max  int
	// dead: the direction is gone and whatever was in flight with it.
	// fin: nothing more can be written, but what was written is delivered
	// before the reader sees the failure.
	dead, fin bool
	// hold: written bytes stay in flight — the reader does not get them
	// until the hold is lifted (or the link dies and they are lost).
	hold bool
	// budget, when >0, ends the link once exactly that many more bytes were
	// written into this direction — a transport that dies mid-record,
	// mid-replay.
	budget int
	onCut  func()
}

func newMemHalf(max int) *memHalf {
	h := &memHalf{max: max}
	h.cond = sync.NewCond(&h.mu)
	return h
}

func (h *memHalf) write(p []byte) (int, error) {
	total := 0
	h.mu.Lock()
	for len(p) > 0 {
		for !h.dead && !h.fin && len(h.buf) >= h.max {
			h.cond.Wait()
		}
		if h.dead || h.fin {
			h.mu.Unlock()
			return total, io.ErrClosedPipe
		}
		n := h.max - len(h.buf)
		if n > len(p) {
			n = len(p)
		}
		if h.budget > 0 && n >= h.budget {
			// The budget runs out inside this write: the prefix is
			// delivered, the rest never leaves.
			n = h.budget
			whole := n == len(p)
			h.buf = append(h.buf, p[:n]...)
			h.budget = 0
			h.fin = true
			cut := h.onCut
			h.cond.Broadcast()
			h.mu.Unlock()
			if cut != nil {
				cut()
			}
			if whole {
				return total + n, nil // this write made it; the next one fails
			}
			return total + n, io.ErrClosedPipe
		}
		if h.budget > 0 {
			h.budget -= n
		}
		h.buf = append(h.buf, p[:n]...)
		p = p[n:]
		total += n
		h.cond.Broadcast()
	}
	h.mu.Unlock()
	return total, nil
}

func (h *memHalf) read(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for !h.dead && !h.fin && (len(h.buf) == 0 || h.hold) {
		h.cond.Wait()
	}
	if h.dead || len(h.buf) == 0 || h.hold {
		return 0, io.ErrUnexpectedEOF // the link died; nothing more arrives
	}
	n := copy(p, h.buf)
	h.buf = h.buf[n:]
	h.cond.Broadcast()
	return n, nil
}

// cut kills the direction and drops what was in flight.
func (h *memHalf) cut() {
	h.mu.Lock()
	h.dead = true
	h.buf = nil
	h.cond.Broadcast()
	h.mu.Unlock()
}

// setHold keeps (or releases) written bytes in flight.
func (h *memHalf) setHold(on bool) {
	h.mu.Lock()
	h.hold = on
	h.cond.Broadcast()
	h.mu.Unlock()
}

// finish ends the direction for the writer; what it wrote is still delivered.
func (h *memHalf) finish() {
	h.mu.Lock()
	h.fin = true
	h.cond.Broadcast()
	h.mu.Unlock()
}

// memEnd is one end of a memLink.
type memEnd struct{ rd, wr *memHalf }

func (e *memEnd) Read(p []byte) (int, error)  { return e.rd.read(p) }
func (e *memEnd) Write(p []byte) (int, error) { return e.wr.write(p) }

// Close is what an endpoint closing its socket does: bytes it already wrote
// still reach the peer (they left the application), nothing more is read.
func (e *memEnd) Close() error { e.wr.finish(); e.rd.cut(); return nil }

// kill is the network dying under both endpoints: both directions go at
// once, with everything that was in flight.
func (e *memEnd) kill() { e.rd.cut(); e.wr.cut() }

// cutAfter ends the link once n more bytes have been written from this end:
// exactly those n bytes still reach the peer, nothing after them does, and
// the opposite direction dies on the spot with whatever it had in flight.
func (e *memEnd) cutAfter(n int) {
	e.wr.mu.Lock()
	e.wr.budget = n
	e.wr.onCut = e.rd.cut
	e.wr.mu.Unlock()
}

// memLink returns the two ends of a TCP-like link with buf bytes of in-flight
// capacity per direction.
func memLink(buf int) (a, b *memEnd) {
	x, y := newMemHalf(buf), newMemHalf(buf)
	return &memEnd{rd: x, wr: y}, &memEnd{rd: y, wr: x}
}

// pattern fills b with a deterministic stream identified by tag, starting at
// absolute offset off — any duplicated, dropped or reordered byte range
// changes the hash.
func pattern(b []byte, tag byte, off int) {
	for i := range b {
		x := uint32(off+i) * 2654435761
		b[i] = byte(x>>24) ^ byte(x>>9) ^ tag
	}
}

// pump writes total pattern bytes to w in chunk-sized writes.
func pump(w io.Writer, tag byte, total, chunk int) error {
	buf := make([]byte, chunk)
	for off := 0; off < total; {
		n := chunk
		if total-off < n {
			n = total - off
		}
		pattern(buf[:n], tag, off)
		if _, err := w.Write(buf[:n]); err != nil {
			return fmt.Errorf("write at %d: %w", off, err)
		}
		off += n
	}
	return nil
}

func wantHash(tag byte, total int) [32]byte {
	buf := make([]byte, total)
	pattern(buf, tag, 0)
	return sha256.Sum256(buf)
}

// drain reads exactly total bytes and returns their hash.
func drain(r io.Reader, total int) ([32]byte, int, error) {
	h := sha256.New()
	n, err := io.CopyN(h, r, int64(total))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, int(n), err
}

// exchange runs a full-duplex transfer on st: it sends `total` bytes tagged
// send and expects `total` bytes tagged recv. Any truncation, duplication,
// reordering or stream error is returned.
func exchange(st io.ReadWriter, send, recv byte, total, chunk int) error {
	werr := make(chan error, 1)
	go func() { werr <- pump(st, send, total, chunk) }()
	got, n, err := drain(st, total)
	if err != nil {
		return fmt.Errorf("read %d/%d: %w", n, total, err)
	}
	if got != wantHash(recv, total) {
		return fmt.Errorf("read %d bytes but the content is corrupted", n)
	}
	if err := <-werr; err != nil {
		return err
	}
	return nil
}
