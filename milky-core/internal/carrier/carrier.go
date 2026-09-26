// Package carrier holds the outer transports that carry a KAL/2 session.
// A carrier presents an ordered byte stream plus an optional channel binding
// (TLS exporter) consumed by the inner handshake.
package carrier

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// BoundConn is an established carrier connection. Binding may return nil when
// the carrier provides no channel binding (e.g. drift over CDN).
type BoundConn interface {
	io.ReadWriteCloser
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Binding() kal2.ChannelBinding
}

// PrefixConn replays already-read bytes before the underlying conn, used to
// push a peeked ClientHello / flight back onto the stream for TLS or demux.
type PrefixConn struct {
	net.Conn
	r      io.Reader
	bind   kal2.ChannelBinding
	closed sync.Once
}

// WrapPrefix returns conn wrapped so reads first drain prefix.
func WrapPrefix(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
}

func (p *PrefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// BoundConn implementation
func (p *PrefixConn) Binding() kal2.ChannelBinding { return p.bind }

// SetBinding stores a channel binding (set after TLS termination).
func (p *PrefixConn) SetBinding(b kal2.ChannelBinding) { p.bind = b }
