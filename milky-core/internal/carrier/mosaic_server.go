package carrier

import (
	"crypto/subtle"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

const (
	// maxMosaicSessions bounds concurrent mosaic sessions per listener.
	maxMosaicSessions = 4096
	// maxMosaicBody bounds a tile request body read from the network.
	maxMosaicBody = mosaicHdrLen + mosaicMACLen + MaxMosaicTile + 1024
	// mosaicTombstone keeps ended session ids so a replayed tile cannot
	// resurrect them.
	mosaicTombstone = 10 * time.Minute
)

type mosaicSession struct {
	st       *mosaicStream
	conn     *mosaicConn
	psk      []byte
	lastSeen atomic.Int64
}

func (s *mosaicSession) touch() { s.lastSeen.Store(time.Now().UnixNano()) }

type mosaicTable struct {
	mu    sync.Mutex
	live  map[[mosaicSIDLen]byte]*mosaicSession
	tomb  map[[mosaicSIDLen]byte]time.Time
	sweep sync.Once
}

// MosaicHandler serves the tile endpoint mounted at <base>/. Only POSTs to a
// user's HMAC-keyed path carrying a tile authenticated with that user's PSK
// reach the session table; everything else gets the decoy's plain 404.
func (v *VeilListener) MosaicHandler(base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var psk []byte
		for _, u := range v.cfg.users() {
			want := base + "/" + MosaicPathToken(u.PSK)
			if subtle.ConstantTimeCompare([]byte(r.URL.Path), []byte(want)) == 1 {
				psk = u.PSK
				break
			}
		}
		if psk == nil || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxMosaicBody))
		if err != nil {
			return
		}
		t, err := parseTile(body, psk)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		sess, created := v.mosaicLookup(t.sid, psk, r)
		if sess == nil {
			http.NotFound(w, r)
			return
		}
		sess.touch()
		sess.st.ackOut(t.downAck)
		sess.st.ingest(t.upOff, t.data)
		sess.st.rewindStale(mosaicRTO + mosaicHold)

		// A tile with upstream bytes is answered almost at once (after a
		// short grace for the reply they provoke); an empty tile on a live
		// session is a poll and parks until downstream bytes exist.
		hold := 40 * time.Millisecond
		if !created && len(t.data) == 0 {
			hold = mosaicHold - time.Duration(mrand.Int64N(int64(mosaicHold/4)))
		}
		off, data := sess.st.takeOutWait(mosaicChunk, hold)
		resp := (&tileResp{downOff: off, upAck: sess.st.inAck(), data: data}).encode(psk)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write(resp); err != nil && len(data) > 0 {
			sess.st.rewind(off)
		}
	})
}

// mosaicLookup returns the live session for sid, creating it (and starting
// its KAL/2 handshake) on first sight. Ended ids and ids owned by another
// user return nil.
func (v *VeilListener) mosaicLookup(sid [mosaicSIDLen]byte, psk []byte, r *http.Request) (*mosaicSession, bool) {
	tb := &v.mosaics
	tb.sweep.Do(func() { go v.mosaicSweep() })
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.live == nil {
		tb.live = map[[mosaicSIDLen]byte]*mosaicSession{}
		tb.tomb = map[[mosaicSIDLen]byte]time.Time{}
	}
	if s, ok := tb.live[sid]; ok {
		if subtle.ConstantTimeCompare(s.psk, psk) != 1 {
			return nil, false
		}
		return s, false
	}
	if _, dead := tb.tomb[sid]; dead || len(tb.live) >= maxMosaicSessions {
		return nil, false
	}
	var ra net.Addr
	if ip := requestClientIP(r); ip != "" {
		ra = &net.TCPAddr{IP: net.ParseIP(ip)}
	}
	st := newMosaicStream()
	s := &mosaicSession{st: st, psk: psk}
	s.conn = &mosaicConn{st: st, remote: ra, onStop: func() { v.mosaicEnd(sid) }}
	s.touch()
	tb.live[sid] = s
	go v.serveMosaic(s)
	return s, true
}

func (v *VeilListener) mosaicEnd(sid [mosaicSIDLen]byte) {
	tb := &v.mosaics
	tb.mu.Lock()
	delete(tb.live, sid)
	tb.tomb[sid] = time.Now()
	tb.mu.Unlock()
}

// mosaicSweep closes idle sessions and forgets old tombstones.
func (v *VeilListener) mosaicSweep() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var idle []*mosaicSession
		tb := &v.mosaics
		tb.mu.Lock()
		for _, s := range tb.live {
			if now.Sub(time.Unix(0, s.lastSeen.Load())) > mosaicIdle {
				idle = append(idle, s)
			}
		}
		for sid, at := range tb.tomb {
			if now.Sub(at) > mosaicTombstone {
				delete(tb.tomb, sid)
			}
		}
		tb.mu.Unlock()
		for _, s := range idle {
			_ = s.conn.Close()
		}
	}
}

// serveMosaic runs the server side of the KAL/2 handshake over the tiles of
// a new session. The session is not bound to a TLS exporter: it spans many
// TLS connections (and possibly CDN edges) by design; the Ed25519 identity
// signature and PSK proof still authenticate both ends.
func (v *VeilListener) serveMosaic(s *mosaicSession) {
	bc := s.conn
	_ = bc.SetReadDeadline(time.Now().Add(v.firstFlightDeadline()))
	prefix := make([]byte, kal2.FirstFlightMinSize)
	if _, err := io.ReadFull(bc, prefix); err != nil {
		_ = bc.Close()
		return
	}
	eph, totalLen, user, _, err := v.authFlight(prefix, nil)
	if err != nil || subtle.ConstantTimeCompare(user.PSK, s.psk) != 1 {
		v.cfg.logf("mosaic: bad flight: %v", err)
		_ = bc.Close()
		return
	}
	if pad := totalLen - kal2.FirstFlightMinSize; pad > 0 {
		if _, err := io.ReadFull(bc, make([]byte, pad)); err != nil {
			_ = bc.Close()
			return
		}
	}
	if err := v.establishKAL(bc, eph, user, nil, "mosaic"); err != nil {
		v.cfg.logf("mosaic: handshake fail: %v", err)
		_ = bc.Close()
	}
}
