package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
	kcp "github.com/xtaci/kcp-go/v5"
)

// rtc ("WebRTC-shaped") is quasar in a video-call costume: every datagram on
// the wire is a valid RTP packet. Deep-packet analysis that classifies flows
// by header structure and packet-size distribution sees a WebRTC media
// stream — a class of UDP traffic censors throttle much more gently than
// "unknown UDP".
//
// Envelope: standard RTP fixed header (V=2, payload type 96 — the dynamic
// range WebRTC uses for video, 90 kHz timestamp, per-session SSRC); the
// media payload frames the KAL/2 datagram and random padding brings short
// control datagrams up to video-frame sizes (~1 KB). Periodic RTCP Sender
// Reports make the flow read as a reporting media source. Payload content is
// unchanged — the inner AEAD + session crypto is untouched, and forged
// RTP-looking packets still fail authentication at the KCP layer.

const (
	rtpHdrLen    = 12
	rtpPT        = 96    // dynamic-range video payload type
	rtpClockRate = 90000 // 90 kHz RTP timestamp (video convention)
	rtcpEvery    = 5 * time.Second
	rtcpSR       = 200 // Sender Report packet type

	// Short datagrams get RTP-padded into this range — the ballpark packet
	// size of a one-frame media burst.
	rtpPadMin = 900
	rtpPadMax = 1250
)

// rtpConn wraps a UDP PacketConn so every datagram on the wire carries a
// valid RTP header. Peer demuxing (listener accepts many remotes) is left to
// the wrapped conn — this type is a pure codec.
type rtpConn struct {
	net.PacketConn
	ssrc uint32
	seq  uint16
	ts   uint32
	base time.Time

	sentPkts  uint32
	sentBytes uint64
	lastSR    time.Time

	// remote, when set, filters inbound datagrams (client side).
	remote net.Addr
}

func newRTPConn(inner net.PacketConn, remote net.Addr) *rtpConn {
	c := &rtpConn{PacketConn: inner, remote: remote, base: time.Now()}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	c.ssrc = binary.BigEndian.Uint32(rnd[:])
	_, _ = rand.Read(rnd[:])
	c.seq = uint16(binary.BigEndian.Uint32(rnd[:]) & 0xffff)
	return c
}

func (c *rtpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.writeRTP(b, addr)
	if err == nil {
		c.maybeRTCP(addr)
	}
	return n, err
}

// mediaLenLen is the size prefix inside the RTP payload. RTP padding proper
// tops out at 255 bytes — too small to reach video-frame sizes — so the
// envelope frames the datagram itself and pads inside the payload: the wire
// still shows an ordinary RTP packet of any size.
const mediaLenLen = 2

func (c *rtpConn) writeRTP(b []byte, addr net.Addr) (int, error) {
	pad := 0
	if len(b) > 0 && len(b) < rtpPadMin {
		pad = rtpPadMin + int(b[0])%(rtpPadMax-rtpPadMin) - len(b)
		if len(b)+rtpHdrLen+mediaLenLen+pad > 1500 {
			pad = 0 // keep the datagram under a media-path MTU
		}
	}
	out := make([]byte, rtpHdrLen+mediaLenLen+len(b)+pad)
	out[0] = 0x80 // V=2
	out[1] = rtpPT
	binary.BigEndian.PutUint16(out[2:], c.seq)
	c.seq++
	binary.BigEndian.PutUint32(out[4:], c.rtpTS())
	binary.BigEndian.PutUint32(out[8:], c.ssrc)
	binary.LittleEndian.PutUint16(out[rtpHdrLen:], uint16(len(b)))
	copy(out[rtpHdrLen+mediaLenLen:], b)
	if pad > 0 {
		// Random filler — entropy looks like media payload to a sniffer.
		_, _ = rand.Read(out[rtpHdrLen+mediaLenLen+len(b):])
	}
	n, err := c.PacketConn.WriteTo(out, addr)
	c.sentPkts++
	c.sentBytes += uint64(len(out))
	if n == len(out) {
		// report caller-payload bytes written — the envelope is ours alone
		return len(b), nil
	}
	return 0, err
}

func (c *rtpConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		tmp := make([]byte, 2048)
		n, addr, err := c.PacketConn.ReadFrom(tmp)
		if err != nil {
			return 0, addr, err
		}
		if c.remote != nil && addr.String() != c.remote.String() {
			continue
		}
		if n < rtpHdrLen+mediaLenLen || tmp[0]>>6 != 2 {
			continue // not an RTP datagram
		}
		pt := tmp[1] & 0x7f
		if pt >= 72 && pt <= 76 {
			continue // RTCP — consumed by the envelope, not the stream
		}
		l := int(binary.LittleEndian.Uint16(tmp[rtpHdrLen:]))
		if l > n-rtpHdrLen-mediaLenLen {
			continue // length prefix outside the datagram — forged or corrupt
		}
		if l > len(buf) {
			l = len(buf)
		}
		copy(buf, tmp[rtpHdrLen+mediaLenLen:rtpHdrLen+mediaLenLen+l])
		return l, addr, nil
	}
}

// rtpTS returns a 90 kHz timestamp — the convention a sniffing middlebox
// expects from an RTP video source.
func (c *rtpConn) rtpTS() uint32 {
	return uint32(time.Since(c.base).Seconds() * rtpClockRate)
}

// maybeRTCP emits a Sender Report roughly every rtcpEvery — receivers in a
// real call see regular reports, and some classifiers check for them.
func (c *rtpConn) maybeRTCP(addr net.Addr) {
	if time.Since(c.lastSR) < rtcpEvery {
		return
	}
	c.lastSR = time.Now()
	var sr [28]byte
	sr[0], sr[1] = 0x80, rtcpSR
	binary.BigEndian.PutUint16(sr[2:], 7) // length in 32-bit words - 1
	binary.BigEndian.PutUint32(sr[4:], c.ssrc)
	now := time.Now()
	ntp := now.Unix() + 2208988800
	binary.BigEndian.PutUint32(sr[8:], uint32(ntp))
	binary.BigEndian.PutUint32(sr[12:], uint32(now.Nanosecond()))
	binary.BigEndian.PutUint32(sr[16:], c.rtpTS())
	binary.BigEndian.PutUint32(sr[20:], c.sentPkts)
	binary.BigEndian.PutUint32(sr[24:], uint32(c.sentBytes))
	_, _ = c.PacketConn.WriteTo(sr[:], addr)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// DialRTC opens a KAL/2 session over RTP-shaped UDP — quasar semantics,
// video-call wire format.
func DialRTC(ctx context.Context, cfg ClientConfig, qc *QuasarConfig) (*kal2.Session, BoundConn, error) {
	to := cfg.timeout()
	if qc == nil {
		qc = &QuasarConfig{}
	}
	if qc.WireKey == nil && len(cfg.ServerPub) > 0 {
		c2 := *qc
		c2.WireKey = QuasarWireKey(cfg.ServerPub)
		qc = &c2
	}
	udpaddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	var lc net.ListenConfig
	if cfg.DialControl != nil {
		lc.Control = cfg.DialControl
	}
	rawPC, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, nil, err
	}
	pc := newRTPConn(rawPC, udpaddr)

	type res struct {
		s   *kcp.UDPSession
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var convid uint32
		_ = binary.Read(rand.Reader, binary.LittleEndian, &convid)
		s, err := kcp.NewConn4(convid, udpaddr, qc.block(), qc.DataShards, qc.ParityShards, true, pc)
		ch <- res{s, err}
	}()
	var sess *kcp.UDPSession
	select {
	case r := <-ch:
		if r.err != nil {
			_ = pc.Close()
			return nil, nil, fmt.Errorf("rtc dial: %w", r.err)
		}
		sess = r.s
	case <-ctx.Done():
		_ = pc.Close()
		return nil, nil, ctx.Err()
	case <-time.After(to):
		_ = pc.Close()
		return nil, nil, fmt.Errorf("rtc dial timeout")
	}
	tuneKCP(sess, qc.SndWnd, qc.RcvWnd, qc.Resend, qc.RateLimit)
	_ = sess.SetDeadline(time.Now().Add(to))
	bc := &quasarBound{UDPSession: sess}
	inner, err := runClientHandshake(bc, cfg)
	if err != nil {
		_ = bc.Close()
		return nil, nil, handshakeStageError{err}
	}
	_ = bc.SetDeadline(time.Time{})
	return inner, bc, nil
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// NewRTCListener is NewQuasarListener over an RTP-shaped PacketConn: the
// accepted KCP sessions see unwrapped datagrams while the wire shows a
// WebRTC media flow.
func NewRTCListener(v *VeilListener, qc *QuasarConfig, laddr string) (*QuasarListener, error) {
	if qc == nil {
		qc = &QuasarConfig{}
	}
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, err
	}
	ln, err := kcp.ServeConn(qc.block(), qc.DataShards, qc.ParityShards, newRTPConn(pc, nil))
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return &QuasarListener{v: v, qc: qc, ln: ln, conns: map[*kcp.UDPSession]struct{}{}, name: "rtc"}, nil
}
