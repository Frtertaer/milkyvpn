package core

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// relayBufs recycles copy buffers: two per relayed connection, for as long as
// it lives. They used to be allocated fresh (64 KiB each) for every stream.
var relayBufs = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// Relay copies bytes both ways between a and b until either direction ends,
// and carries the manner of that ending across:
//
//   - a clean end of stream (EOF) closes both sides cleanly;
//   - an abnormal end — a tunnel stream that was reset or lost its session, a
//     socket that was reset — aborts the other side (TCP RST on a socket, RST
//     on a tunnel stream).
//
// The distinction is the whole point. A relay that answers every ending with
// a clean close tells the application "the transfer completed" when it was
// cut short: a truncated download looks finished, a failed upload looks
// delivered. An abort is what the application would have seen without a
// tunnel in between.
//
// It returns the bytes moved a←b and b←a. Relay returns once the first
// direction has ended and both sides were told; it waits for the second
// direction only briefly, so a stream parked behind a frozen session cannot
// hold the caller.
func Relay(a, b io.ReadWriteCloser) (ab, ba int64) {
	var nab, nba atomic.Int64
	type end struct {
		src, dst   io.ReadWriteCloser
		rerr, werr error
	}
	done := make(chan end, 2)
	pump := func(dst, src io.ReadWriteCloser, n *atomic.Int64) {
		rerr, werr := copyCounted(dst, src, n)
		done <- end{src: src, dst: dst, rerr: rerr, werr: werr}
	}
	go pump(a, b, &nab)
	go pump(b, a, &nba)

	first := <-done
	switch {
	case first.rerr != nil:
		// The source ended abnormally: the destination must not read this
		// as a completed stream.
		abortEnd(first.dst)
		_ = first.src.Close()
	case first.werr != nil && peerClosedGracefully(first.werr):
		// The destination is a tunnel stream whose peer closed it while we
		// still had data for it. That data is undeliverable, but the peer's
		// own data may still be queued for the other direction — let that
		// direction run to its clean end instead of cutting it off.
		second := <-done
		closeAfter(second.rerr != nil, a, b)
		return nab.Load(), nba.Load()
	case first.werr != nil:
		// The destination failed (socket reset, stream aborted): the source
		// is told its data went nowhere.
		abortEnd(first.src)
		_ = first.dst.Close()
	default:
		// Clean end of the source. A CLOSE on the wire is a full close, so
		// the relay ends here for both directions.
		_ = first.dst.Close()
		_ = first.src.Close()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return nab.Load(), nba.Load()
}

// closeAfter ends both sides once the second direction has finished, as an
// abort if that direction itself ended abnormally.
func closeAfter(abnormal bool, a, b io.ReadWriteCloser) {
	if abnormal {
		abortEnd(a)
		abortEnd(b)
		return
	}
	_ = a.Close()
	_ = b.Close()
}

// copyCounted is io.Copy that reports which side failed: rerr is a read
// error on src other than io.EOF, werr a write error on dst.
func copyCounted(dst io.Writer, src io.Reader, n *atomic.Int64) (rerr, werr error) {
	bp := relayBufs.Get().(*[]byte)
	defer relayBufs.Put(bp)
	buf := *bp
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n.Add(int64(nw))
			if ew != nil {
				return nil, ew
			}
			if nw != nr {
				return nil, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return nil, nil
			}
			return er, nil
		}
	}
}

// peerClosedGracefully reports a write refused because the tunnel peer has
// closed the stream cleanly (as opposed to the stream being aborted).
func peerClosedGracefully(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) && !kal2.IsAbort(err)
}

// abortEnd ends c abnormally, in whatever way its type allows, so that its
// reader sees an error rather than a clean end of stream.
func abortEnd(c io.Closer) {
	switch x := c.(type) {
	case interface{ Reset() error }: // tunnel stream: RST record
		_ = x.Reset()
		return
	case interface{ Abort() }: // userspace TCP endpoint
		x.Abort()
		return
	case interface{ SetLinger(int) error }: // kernel TCP socket: RST on close
		_ = x.SetLinger(0)
	}
	_ = c.Close()
}

// Aborter wraps a connection together with the function that aborts it —
// for endpoint types that cannot abort through the connection value itself
// (a gVisor TCP conn hides its endpoint).
type Aborter struct {
	io.ReadWriteCloser
	AbortFn func()
}

// Abort implements the abort hook Relay looks for.
func (a Aborter) Abort() {
	if a.AbortFn != nil {
		a.AbortFn()
	}
	_ = a.ReadWriteCloser.Close()
}
