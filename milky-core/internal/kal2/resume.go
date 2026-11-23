package kal2

// resume.go — KAL/2 v2.1 session resumption & carrier migration.
//
// Wire summary (SPEC.md §9):
//   - server issues TICKET records (stream 0): AEAD-sealed resumption ticket
//     carrying sessionID + userID + expiry + resumeSecret;
//   - on transport loss a migratable session freezes (streams survive);
//   - the client re-dials (any carrier/endpoint) and sends the KLDO-rs-
//     resumption flight instead of KLDO-in-;
//   - both sides rekey from transcript2/salt2 (fresh X25519), then exchange
//     MIGRATE checkpoints and replay unacked stream records.
//
// Invariants the implementation keeps (v2.2 — each one is a defect the v2.1
// code had under load or back-to-back transport losses):
//   - a checkpoint is only read after the record loops of the dead
//     transport have exited, so the receive counter cannot move under it;
//   - the replay is exactly the records the peer has not received, in their
//     original order: acknowledged records leave the window, replayed ones
//     re-enter it under their new sequence numbers, and records a previous
//     replay never got to emit are carried over, never dropped;
//   - a transport fault never latches an error into a session that resumes;
//   - stream tables are not reconciled by set difference — the exact replay
//     converges them, and a difference only means a record is still in
//     flight.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

var (
	labelResumeSecret  = []byte("mxs-in-v2/resume-secret")
	labelResumePreauth = []byte("mxs-in-v2/resume-preauth")
)

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

// TicketVersion is the current ticket wire format.
const TicketVersion byte = 0x01

// TicketFlagMigrate marks tickets allowing carrier changes on resumption.
const TicketFlagMigrate byte = 0x01

// TicketPlain is the unsealed resumption ticket body.
type TicketPlain struct {
	SessionID    [8]byte
	UserID       [16]byte
	Expires      uint32 // unix seconds
	Flags        byte
	ResumeSecret [32]byte
}

func (t *TicketPlain) encode() []byte {
	b := make([]byte, 0, 61)
	b = append(b, TicketVersion)
	b = append(b, t.SessionID[:]...)
	b = append(b, t.UserID[:]...)
	b = binary.BigEndian.AppendUint32(b, t.Expires)
	b = append(b, t.Flags)
	return append(b, t.ResumeSecret[:]...)
}

func decodeTicketPlain(b []byte) (*TicketPlain, error) {
	if len(b) != 1+8+16+4+1+32 || b[0] != TicketVersion {
		return nil, ErrTicket
	}
	t := &TicketPlain{}
	copy(t.SessionID[:], b[1:9])
	copy(t.UserID[:], b[9:25])
	t.Expires = binary.BigEndian.Uint32(b[25:29])
	t.Flags = b[29]
	copy(t.ResumeSecret[:], b[30:62])
	return t, nil
}

// TicketCodec seals and opens resumption tickets under rotating server keys.
// Two key generations are accepted: a rotation does not invalidate
// in-flight tickets issued minutes before.
type TicketCodec struct {
	mu   sync.Mutex
	keys [][32]byte // newest first; at most 2 retained
}

// NewTicketCodec creates a codec: with no arguments it seeds a random key;
// explicit keys make tickets verifiable across process restarts (e.g.
// derived from the server identity).
func NewTicketCodec(keys ...[32]byte) *TicketCodec {
	tc := &TicketCodec{}
	if len(keys) > 0 {
		tc.keys = append([][32]byte(nil), keys...)
		if len(tc.keys) > 2 {
			tc.keys = tc.keys[:2]
		}
		return tc
	}
	_ = tc.Rotate()
	return tc
}

// Rotate installs a fresh sealing key (call e.g. every 12-24h).
func (tc *TicketCodec) Rotate() error {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return err
	}
	tc.mu.Lock()
	tc.keys = append([][32]byte{k}, tc.keys...)
	if len(tc.keys) > 2 {
		tc.keys = tc.keys[:2]
	}
	tc.mu.Unlock()
	return nil
}

// Issue seals a ticket: nonce(12) || AEAD(plain).
func (tc *TicketCodec) Issue(t *TicketPlain) ([]byte, error) {
	tc.mu.Lock()
	key := tc.keys[0]
	tc.mu.Unlock()
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, t.encode(), nil), nil
}

// Open unseals a ticket, trying the current and previous key generation.
// Expiry is checked by the caller against its own clock.
func (tc *TicketCodec) Open(b []byte) (*TicketPlain, error) {
	if len(b) < 12+62 {
		return nil, ErrTicket
	}
	tc.mu.Lock()
	keys := append([][32]byte(nil), tc.keys...)
	tc.mu.Unlock()
	for i := range keys {
		aead, err := chacha20poly1305.New(keys[i][:])
		if err != nil {
			return nil, err
		}
		if pt, err := aead.Open(nil, b[:12], b[12:], nil); err == nil {
			return decodeTicketPlain(pt)
		}
	}
	return nil, ErrTicket
}

// ticketID identifies a presented ticket for single-use enforcement.
func ticketID(b []byte) (id [16]byte) {
	h := sha256.Sum256(b)
	copy(id[:], h[:16])
	return
}

// ---------------------------------------------------------------------------
// Resume flights (KLDO-rs-)
// ---------------------------------------------------------------------------

// ResumeFixedSize is the unframed head of the resumption flight:
// magic || version || sessionID || clientEph || ticketLen(2).
const ResumeFixedSize = MagicLen + 1 + 8 + ephemeralKeySize + 2

// ResumeCheckpoint is the client's stream-state checkpoint echoed into the
// resumption flight and re-announced inside the MIGRATE record.
type ResumeCheckpoint struct {
	LastRecvSeq uint64
	Streams     []ResumeStreamState
}

// ResumeStreamState is one stream's state in a checkpoint/snapshot.
type ResumeStreamState struct {
	ID       uint32
	WriteEnd bool // our write side is closed (CLOSE already emitted)
	// Ext (flags bit 1) is only meaningful on the entry for stream id 0,
	// which never names a stream: a v2.2 client lists it to tell a v2.2
	// server that it reads the extended resumption trailer (see
	// ResumeResult.ServerTrailer). v2.1 ignores the bit and the entry.
	Ext bool
}

func (cp *ResumeCheckpoint) Encode() []byte {
	b := binary.BigEndian.AppendUint64(nil, cp.LastRecvSeq)
	b = binary.BigEndian.AppendUint16(b, uint16(len(cp.Streams)))
	for _, st := range cp.Streams {
		b = binary.BigEndian.AppendUint32(b, st.ID)
		var f byte
		if st.WriteEnd {
			f |= 1
		}
		if st.Ext {
			f |= 2
		}
		b = append(b, f)
	}
	return b
}

// wantsExt reports whether the checkpoint carries the extended-trailer marker.
func (cp *ResumeCheckpoint) wantsExt() bool {
	for _, st := range cp.Streams {
		if st.ID == 0 && st.Ext {
			return true
		}
	}
	return false
}

func DecodeCheckpoint(b []byte) (*ResumeCheckpoint, error) {
	if len(b) < 10 {
		return nil, ErrFraming
	}
	cp := &ResumeCheckpoint{LastRecvSeq: binary.BigEndian.Uint64(b[:8])}
	n := int(binary.BigEndian.Uint16(b[8:10]))
	if len(b[10:]) != n*5 {
		return nil, ErrFraming
	}
	for i := 0; i < n; i++ {
		o := 10 + i*5
		cp.Streams = append(cp.Streams, ResumeStreamState{
			ID:       binary.BigEndian.Uint32(b[o : o+4]),
			WriteEnd: b[o+4]&1 != 0,
			Ext:      b[o+4]&2 != 0,
		})
	}
	return cp, nil
}

// resumePreauth proves possession of the resumption secret over the
// presented flight material (checkpoint excluded — it changes per attempt).
func resumePreauth(secret []byte, sessionID [8]byte, clientEph, ticket []byte, binding ChannelBinding) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(labelResumePreauth)
	m.Write(ResumeMagic)
	m.Write([]byte{Version})
	m.Write(sessionID[:])
	m.Write(clientEph)
	m.Write(ticket)
	if len(binding) > 0 {
		m.Write(binding)
	}
	return m.Sum(nil)
}

// ResumeFlight builds the KLDO-rs- client resumption flight for the
// session's own sessionID and its oldest unused ticket. Use
// ResumeState.BeginResumeFlight to resume under a specific (e.g. forged in
// tests) session id or ticket.
func (s *Session) ResumeFlight(clientEph []byte, cp *ResumeCheckpoint, binding ChannelBinding) []byte {
	s.migMu.Lock()
	sid := s.sessionID
	var ticket []byte
	if len(s.tickets) > 0 {
		ticket = s.tickets[0]
	}
	s.migMu.Unlock()
	return s.resumeFlight(sid, ticket, clientEph, cp, binding)
}

func (s *Session) resumeFlight(sessionID [8]byte, ticket, clientEph []byte, cp *ResumeCheckpoint, binding ChannelBinding) []byte {
	out := append(append([]byte{}, ResumeMagic...), Version)
	out = append(out, sessionID[:]...)
	out = append(out, clientEph...)
	var tb [2]byte
	binary.LittleEndian.PutUint16(tb[:], uint16(len(ticket)))
	out = append(out, tb[:]...)
	out = append(out, ticket...)
	out = append(out, resumePreauth(s.resumeSecret, sessionID, clientEph, ticket, binding)...)
	return append(out, cp.Encode()...)
}

// ResumeFlightHead is the fixed-size resume flight prefix the server reads
// first (through ticketLen).
// ParseResumeHead returns sessionID, clientEph, ticketLen.
func ParseResumeHead(head []byte) (sessionID [8]byte, clientEph []byte, ticketLen int, err error) {
	if len(head) < ResumeFixedSize {
		return sessionID, nil, 0, ErrHandshake
	}
	if !bytes.Equal(head[:MagicLen], ResumeMagic) {
		return sessionID, nil, 0, ErrMagic
	}
	if head[MagicLen] != Version {
		return sessionID, nil, 0, ErrVersion
	}
	copy(sessionID[:], head[MagicLen+1:MagicLen+9])
	clientEph = append([]byte(nil), head[MagicLen+9:MagicLen+41]...)
	ticketLen = int(binary.LittleEndian.Uint16(head[MagicLen+41:]))
	if ticketLen <= 0 || ticketLen > 4096 {
		return sessionID, nil, 0, ErrHandshake
	}
	return sessionID, clientEph, ticketLen, nil
}

// resumeTranscript computes transcript2 for a resumed session.
func resumeTranscript(sessionID [8]byte, clientEph, serverEph []byte) []byte {
	t := make([]byte, 0, MagicLen+1+8+64)
	t = append(t, ResumeMagic...)
	t = append(t, Version)
	t = append(t, sessionID[:]...)
	t = append(t, clientEph...)
	return append(t, serverEph...)
}

// resumeSalt computes salt2 = HMAC(label, shared || binding || resumeSecret).
func resumeSalt(shared, binding, resumeSecret []byte) []byte {
	m := hmac.New(sha256.New, labelExporterBind)
	m.Write(shared)
	m.Write(binding)
	m.Write(resumeSecret)
	return m.Sum(nil)
}

// ---------------------------------------------------------------------------
// Client-side resumption handshake
// ---------------------------------------------------------------------------

// ClientResume drives the client side of a resumption handshake on a fresh
// carrier connection. On success the session is re-keyed; the caller then
// hands the server's checkpoint to ResumeAttach.
type ClientResume struct {
	ephPriv   []byte
	ephPub    []byte
	sessionID [8]byte
	ticket    []byte
	// ext: the flight announced the extended trailer, so the server's
	// trailer carries one (the server is known to be v2.2).
	ext bool
	// gen is the transport generation this attempt replaces; it may only
	// attach while the session is still in it.
	gen uint64
	// salt / tr are the re-key inputs, set once FinishResume verified the
	// server flight.
	salt, tr []byte
}

// BeginResumeFlight writes the resumption flight on rw and returns the
// handshake state needed to consume the server flight. It resumes under the
// session's own id with its oldest unused ticket.
func (s *Session) BeginResumeFlight(rw io.Writer, binding ChannelBinding) (*ClientResume, error) {
	rs, ok := s.TicketState()
	if !ok {
		return nil, ErrTicket
	}
	return rs.BeginResumeFlight(rw, binding)
}

// BeginResumeFlight drives the exchange through a ResumeState: the flight
// announces rs.SessionID and presents rs.Ticket, which may differ from the
// session's own (server-side ticket rebinding, or a forged id in tests).
//
// The session is frozen first, and its record loops are waited out, before
// the checkpoint is taken: the flight tells the server "replay from here",
// so nothing may be received on the old transport after that number is on
// the wire. A proactive resumption (carrier rotation) therefore gives up its
// working transport at this point — if the attempt then fails, the session
// stays frozen and resumable rather than half-moved.
//
// Several attempts may run at once (a hedged dial races carriers with one
// ResumeState): the first to attach wins, and an attempt that reaches this
// point after a sibling already re-attached the session is refused rather
// than freezing the fresh transport.
func (rs *ResumeState) BeginResumeFlight(rw io.Writer, binding ChannelBinding) (*ClientResume, error) {
	s := rs.Session
	if err := s.quiesceAt(rs.gen); err != nil {
		return nil, err
	}
	priv, pub, err := genX25519()
	if err != nil {
		return nil, err
	}
	cp := s.Checkpoint()
	// Only a server that announced v2.2 itself is asked for the extended
	// trailer: a v2.1 server would send the plain one, and the client would
	// then mistake the first record for the extension.
	ext := s.peerFeat.Load()&FeatReplay != 0
	if ext {
		cp.Streams = append(cp.Streams, ResumeStreamState{ID: 0, Ext: true})
	}
	flight := s.resumeFlight(rs.SessionID, rs.Ticket, pub, cp, binding)
	if _, err := rw.Write(flight); err != nil {
		return nil, err
	}
	return &ClientResume{ephPriv: priv, ephPub: pub, sessionID: rs.SessionID, ticket: rs.Ticket, ext: ext, gen: rs.gen}, nil
}

// Trailer extension TLV types (ResumeResult.ServerTrailer).
const trailerExtTicket byte = 0x01

// maxTrailerExt bounds the extension a client will read.
const maxTrailerExt = 8192

// ReadTrailer consumes what follows the server flight: cpLen(2,LE) ||
// checkpoint and, when this resumption asked for it, extLen(2,LE) ||
// extension. Call it after FinishResume; pass the result to ResumeAttach.
//
// The extension hands the client its next resumption ticket inside the
// handshake itself, so completing a resumption always leaves it able to
// resume again — even if this transport then fails to carry a single record.
func (cr *ClientResume) ReadTrailer(s *Session, r io.Reader) (*ResumeCheckpoint, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, fmt.Errorf("resume checkpoint: %w", err)
	}
	cpb := make([]byte, binary.LittleEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, cpb); err != nil {
		return nil, fmt.Errorf("resume checkpoint: %w", err)
	}
	cp, err := DecodeCheckpoint(cpb)
	if err != nil {
		return nil, err
	}
	if !cr.ext {
		return cp, nil
	}
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, fmt.Errorf("resume trailer: %w", err)
	}
	n := int(binary.LittleEndian.Uint16(lb[:]))
	if n > maxTrailerExt {
		return nil, ErrFraming
	}
	ext := make([]byte, n)
	if _, err := io.ReadFull(r, ext); err != nil {
		return nil, fmt.Errorf("resume trailer: %w", err)
	}
	for len(ext) >= 3 {
		t, l := ext[0], int(binary.LittleEndian.Uint16(ext[1:3]))
		if l > len(ext)-3 {
			return nil, ErrFraming
		}
		if v := ext[3 : 3+l]; t == trailerExtTicket && l > 0 {
			s.poolTicket(v)
		}
		ext = ext[3+l:] // unknown types are skipped
	}
	return cp, nil
}

// FinishResume consumes the server flight (eph||sig) and verifies the
// Ed25519 signature over transcript2. serverPub is the pinned identity key.
// A valid server flight proves the server accepted — and thereby spent —
// the ticket, so it leaves the client's pool here. The session itself is
// not touched until Attach.
func (cr *ClientResume) FinishResume(s *Session, serverPub ed25519.PublicKey, msg []byte, binding ChannelBinding) error {
	if len(msg) != ServerFlightSize {
		return ErrHandshake
	}
	serverEph := msg[:ephemeralKeySize]
	sig := msg[ephemeralKeySize:]
	shared, err := curve25519.X25519(cr.ephPriv, serverEph)
	if err != nil {
		return ErrHandshake
	}
	if isLowOrder(shared) {
		return ErrHandshake
	}
	tr := resumeTranscript(cr.sessionID, cr.ephPub, serverEph)
	salt := resumeSalt(shared, binding, s.resumeSecret)
	sigInput, err := hkdfDerive(labelServerSig, salt, tr, 32)
	if err != nil {
		return err
	}
	if !ed25519.Verify(serverPub, sigInput, sig) {
		return ErrSignature
	}
	s.spendTicket(cr.ticket)
	cr.salt, cr.tr = salt, tr
	return nil
}

// Attach completes the resumption: it re-keys the session and binds it to
// rw, with peerCP the checkpoint from the server's trailer (ReadTrailer).
// Re-keying and binding are one step, taken only if the session is still in
// the transport generation this attempt was prepared for — of attempts racing
// for one session, exactly one attaches.
func (cr *ClientResume) Attach(s *Session, rw io.ReadWriteCloser, peerCP *ResumeCheckpoint) error {
	if cr.salt == nil || cr.tr == nil {
		return ErrHandshake // FinishResume did not verify a server flight
	}
	return s.resumeAttach(rw, peerCP, nil, func() error {
		if cr.gen != 0 && s.attachGen != cr.gen {
			return ErrMigrate
		}
		return s.rekeyLocked(cr.salt, cr.tr)
	})
}

// ---------------------------------------------------------------------------
// Server-side resumption
// ---------------------------------------------------------------------------

// SessionRegistry keeps frozen sessions indexable by sessionID so a
// resumption flight can find and re-attach them. Entries expire if the
// client never returns.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[[8]byte]*registeredSession
	ttl      time.Duration
	codec    *TicketCodec
	used     map[[16]byte]time.Time // presented ticketIDs → expiry
}

type registeredSession struct {
	sess   *Session
	userID [16]byte
}

// NewSessionRegistry creates a registry; ttl overrides the per-session
// frozen-retention window on adopted sessions (0 keeps the session default,
// 2m). Live sessions stay registered indefinitely — a frozen session's wait
// is bounded by its own migrate TTL, after which it dies and is swept.
func NewSessionRegistry(codec *TicketCodec, ttl time.Duration) *SessionRegistry {
	r := &SessionRegistry{
		sessions: make(map[[8]byte]*registeredSession),
		used:     make(map[[16]byte]time.Time),
		ttl:      ttl,
		codec:    codec,
	}
	go r.sweep()
	return r
}

func (r *SessionRegistry) sweep() {
	for range time.Tick(time.Minute) {
		r.mu.Lock()
		now := time.Now()
		for id, rs := range r.sessions {
			if rs.sess.isDead() {
				delete(r.sessions, id)
			}
		}
		for id, exp := range r.used {
			if now.After(exp) {
				delete(r.used, id)
			}
		}
		r.mu.Unlock()
	}
}

// adopt makes a fresh session resumable: assigns sessionID, issues the first
// ticket and registers it. Called by the listener right after Attach.
func (r *SessionRegistry) Adopt(s *Session, userID [16]byte) error {
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return err
	}
	expires := uint32(time.Now().Add(24 * time.Hour).Unix())
	tp := &TicketPlain{
		SessionID:    sid,
		UserID:       userID,
		Expires:      expires,
		Flags:        TicketFlagMigrate,
		ResumeSecret: [32]byte{},
	}
	copy(tp.ResumeSecret[:], s.resumeSecret)
	t, err := r.codec.Issue(tp)
	if err != nil {
		return err
	}
	s.migMu.Lock()
	s.sessionID = sid
	s.userID = userID
	s.registry = r
	if r.ttl > 0 {
		s.migrateTTL = r.ttl
	}
	s.onCloseFns = append(s.onCloseFns, func() { r.remove(sid) })
	s.migMu.Unlock()
	s.migratable.Store(true)
	r.mu.Lock()
	r.sessions[sid] = &registeredSession{sess: s, userID: userID}
	r.mu.Unlock()
	// TICKET is a control record; queued safely post-Attach.
	if err := s.sendTicket(t); err != nil {
		return err
	}
	// A spare, so a client is never one lost record away from being unable
	// to resume: a ticket is single-use, and the replacement issued after a
	// resumption can itself die with the next transport. (A pre-2.2 client
	// keeps only the latest ticket it was sent; the spare is harmless.)
	t2, err := r.codec.Issue(tp)
	if err != nil {
		return err
	}
	return s.sendTicket(t2)
}

// remove unregisters a closed session.
func (r *SessionRegistry) remove(sid [8]byte) {
	r.mu.Lock()
	delete(r.sessions, sid)
	r.mu.Unlock()
}

// issueFor seals a fresh ticket for an already-registered session.
func (r *SessionRegistry) issueFor(s *Session) ([]byte, error) {
	if s.registry != r {
		return nil, ErrTicket
	}
	tp := &TicketPlain{
		SessionID: s.sessionID,
		UserID:    s.userID,
		Expires:   uint32(time.Now().Add(24 * time.Hour).Unix()),
		Flags:     TicketFlagMigrate,
	}
	copy(tp.ResumeSecret[:], s.resumeSecret)
	return r.codec.Issue(tp)
}

// Refresh issues one more ticket on an already-registered session.
// ResumeResult.Attach already replaces the ticket a resumption spent; callers
// that attach through Finish + ResumeAttach use this to re-arm the client.
func (r *SessionRegistry) Refresh(s *Session) error {
	t, err := r.issueFor(s)
	if err != nil {
		return err
	}
	return s.sendTicket(t)
}

// ResumeResult is a validated resumption request.
type ResumeResult struct {
	Session     *Session
	ClientEph   []byte
	Checkpoint  *ResumeCheckpoint
	TicketPlain *TicketPlain

	// epoch identifies this resumption among overlapping ones for the same
	// session; only the latest accepted flight may attach.
	epoch uint64
	// resumeTr / resumeSalt are the re-key inputs derived by ServerResume.
	resumeTr   []byte
	resumeSalt []byte
	// ticketSent: the replacement ticket already went out in the trailer.
	ticketSent bool
}

// Accept validates a resumption flight: opens the ticket, checks expiry,
// single-use and user binding, finds the frozen session and verifies the
// resumePreauth. Reads exactly ticket + preauth + checkpoint from rw after
// the caller consumed the fixed head.
func (r *SessionRegistry) Accept(head []byte, rest io.Reader, binding ChannelBinding) (*ResumeResult, error) {
	sessionID, clientEph, ticketLen, err := ParseResumeHead(head)
	if err != nil {
		return nil, err
	}
	body := make([]byte, ticketLen+preauthSize)
	if _, err := io.ReadFull(rest, body); err != nil {
		return nil, err
	}
	ticket := body[:ticketLen]
	pa := body[ticketLen:]
	tp, err := r.codec.Open(ticket)
	if err != nil {
		return nil, err
	}
	if int64(tp.Expires) < time.Now().Unix() {
		return nil, ErrTicket
	}
	r.mu.Lock()
	if _, seen := r.used[ticketID(ticket)]; seen {
		r.mu.Unlock()
		return nil, ErrReplay
	}
	r.used[ticketID(ticket)] = time.Unix(int64(tp.Expires), 0)
	rs, ok := r.sessions[sessionID]
	if ok && rs.sess.isDead() {
		ok = false
	}
	r.mu.Unlock()
	if !ok {
		return nil, Error("session: resumption ticket unknown session")
	}
	if tp.SessionID != sessionID {
		return nil, Error("session: resumption ticket sid mismatch")
	}
	if tp.UserID != rs.userID {
		return nil, Error("session: resumption ticket uid mismatch")
	}
	s := rs.sess
	if subtle.ConstantTimeCompare(pa, resumePreauth(s.resumeSecret, sessionID, clientEph, ticket, binding)) != 1 {
		return nil, ErrPreauth
	}
	// Migration may be proactive: the old transport can linger server-side
	// (client switched networks) — freeze the session ourselves so the
	// re-attach replaces it, and wait its record loops out. The caller reads
	// the receive counter next (the checkpoint in the server flight tells the
	// client where to replay from); a loop still running could move that
	// counter after it was read, and the client would then replay a record
	// this side had already consumed.
	if err := s.quiesce(); err != nil {
		return nil, err
	}
	s.migMu.Lock()
	s.resumeEpoch++
	epoch := s.resumeEpoch
	s.migMu.Unlock()
	// Client checkpoint trailer: lastRecv(8) || nStreams(2) || {id,flags}*.
	cph := make([]byte, 10)
	if _, err := io.ReadFull(rest, cph); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(cph[8:10]))
	if n > 8192 {
		return nil, ErrFraming
	}
	cpb := append(cph, make([]byte, n*5)...)
	if _, err := io.ReadFull(rest, cpb[10:]); err != nil {
		return nil, err
	}
	cp, err := DecodeCheckpoint(cpb)
	if err != nil {
		return nil, err
	}
	return &ResumeResult{Session: s, ClientEph: clientEph, Checkpoint: cp, TicketPlain: tp, epoch: epoch}, nil
}

// ServerResume completes the server side: Start equivalent — returns the
// server flight bytes to write.
func (res *ResumeResult) ServerResume(identity ed25519.PrivateKey, binding ChannelBinding) (serverFlight []byte, hs *ServerHandshake, err error) {
	h, err := NewServerHandshake(identity)
	if err != nil {
		return nil, nil, err
	}
	shared, err := curve25519.X25519(h.ephPriv, res.ClientEph)
	if err != nil {
		return nil, nil, ErrHandshake
	}
	if isLowOrder(shared) {
		return nil, nil, ErrHandshake
	}
	tr := resumeTranscript(res.Session.sessionID, res.ClientEph, h.ephPub)
	h.salt = resumeSalt(shared, binding, res.Session.resumeSecret)
	h.transcript = tr
	sigInput, err := hkdfDerive(labelServerSig, h.salt, tr, 32)
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(h.identity, sigInput)
	flight := append(append([]byte{}, h.ephPub...), sig...)
	res.resumeTr = tr
	res.resumeSalt = h.salt
	return flight, h, nil
}

// current reports whether res is still the latest resumption accepted for
// its session. A newer flight supersedes it: only one transport may attach.
func (res *ResumeResult) current() bool {
	s := res.Session
	s.migMu.Lock()
	defer s.migMu.Unlock()
	return s.resumeEpoch == res.epoch
}

// ServerCheckpoint is the checkpoint the server announces in its resumption
// flight: its receive counter (where the client must replay from) and a
// stream list.
//
// For a pre-2.2 client the list is the client's own, echoed back. Such a
// client compares the two lists by set difference and resets every stream on
// one side only — which kills streams whose OPEN or CLOSE was merely still in
// flight when the transport died. An empty difference makes that step a
// no-op; the exact replay then brings both tables into agreement.
func (res *ResumeResult) ServerCheckpoint() *ResumeCheckpoint {
	cp := res.Session.Checkpoint()
	if res.Session.peerFeat.Load()&FeatReplay == 0 && res.Checkpoint != nil && !res.Checkpoint.wantsExt() {
		cp.Streams = append([]ResumeStreamState(nil), res.Checkpoint.Streams...)
	}
	return cp
}

// ServerTrailer is what the server writes right behind its resumption
// flight: cpLen(2,LE) || checkpoint, and for a client that announced it can
// read one, extLen(2,LE) || extension — a TLV list (type(1) || len(2,LE) ||
// value) currently holding the ticket that replaces the one just spent.
func (res *ResumeResult) ServerTrailer() []byte {
	cp := res.ServerCheckpoint().Encode()
	out := binary.LittleEndian.AppendUint16(nil, uint16(len(cp)))
	out = append(out, cp...)
	if res.Checkpoint == nil || !res.Checkpoint.wantsExt() {
		return out
	}
	var ext []byte
	if r := res.Session.registry; r != nil {
		if t, err := r.issueFor(res.Session); err == nil {
			ext = append(ext, trailerExtTicket)
			ext = binary.LittleEndian.AppendUint16(ext, uint16(len(t)))
			ext = append(ext, t...)
			res.ticketSent = true
		}
	}
	out = binary.LittleEndian.AppendUint16(out, uint16(len(ext)))
	return append(out, ext...)
}

// Attach re-keys the frozen session and binds it to rw. It refuses a
// resumption that a newer flight for the same session has superseded; the
// check and the re-key happen in one step with the binding.
//
// Unless ServerTrailer already delivered it, Attach also issues the ticket
// that replaces the one this resumption spent and places it at the very head
// of the replay: a transport that dies again a few kilobytes in must still
// have handed the client the means to resume once more. (Queued behind the
// replay, the ticket was lost with every short-lived transport, and two such
// losses in a row ended the session.)
func (res *ResumeResult) Attach(rw io.ReadWriteCloser) error {
	if res.resumeTr == nil || res.resumeSalt == nil {
		return ErrHandshake // ServerResume did not run
	}
	s := res.Session
	var head []outRec
	if r := s.registry; r != nil && !res.ticketSent {
		if t, err := r.issueFor(s); err == nil {
			head = append(head, outRec{t: MsgTicket, p: append(append([]byte{}, s.sessionID[:]...), t...)})
		}
	}
	return s.resumeAttach(rw, res.Checkpoint, head, func() error {
		if s.resumeEpoch != res.epoch {
			return ErrMigrate
		}
		return s.rekeyLocked(res.resumeSalt, res.resumeTr)
	})
}

// checkpointMaxStreams bounds the stream list of a checkpoint. A v2.1 peer
// rejects a resumption flight listing more than 8192.
const checkpointMaxStreams = 4096

// Checkpoint snapshots the receive counter and live stream table for the
// resumption flight / MIGRATE record. LastRecvSeq is the receiver's
// next-expected sequence (== recvSeq) — the seq the peer's next record must
// carry.
//
// The number is only meaningful for a resumption once the session is
// quiesced; BeginResumeFlight and SessionRegistry.Accept see to that.
func (s *Session) Checkpoint() *ResumeCheckpoint {
	cp := &ResumeCheckpoint{LastRecvSeq: s.recvSeq.Load()}
	s.smu.RLock()
	live := make(map[uint32]struct{}, len(s.streams))
	for id, st := range s.streams {
		if len(cp.Streams) >= checkpointMaxStreams {
			break
		}
		live[id] = struct{}{}
		cp.Streams = append(cp.Streams, ResumeStreamState{ID: id, WriteEnd: st.writable() != nil})
	}
	s.smu.RUnlock()
	if s.peerFeat.Load()&FeatReplay != 0 {
		return cp
	}
	// A pre-2.2 peer resets every stream it holds that this list lacks. A
	// stream we closed is absent from our table — but if its CLOSE is still
	// unacknowledged, the peer may not have seen it and is still owed the
	// data queued ahead of it. List such streams as alive so the peer keeps
	// them until the replayed CLOSE arrives.
	s.migMu.Lock()
	for _, r := range s.sent.recs {
		if r.t != MsgClose || len(cp.Streams) >= checkpointMaxStreams {
			continue
		}
		if _, ok := live[r.id]; ok {
			continue
		}
		live[r.id] = struct{}{}
		cp.Streams = append(cp.Streams, ResumeStreamState{ID: r.id, WriteEnd: true})
	}
	s.migMu.Unlock()
	return cp
}

// resumeAttach binds a frozen session to a fresh authenticated transport
// after a successful resumption handshake. peerCP is the checkpoint the
// peer announced in its flight (client) or flight trailer (server); head are
// extra records to emit right behind the MIGRATE marker, ahead of the
// replay; commit runs under migMu once the dead transport's loops are gone,
// right before the session changes — it installs the new keys, and an error
// from it aborts the attach with the session still frozen.
//
// It rewinds the send counter to the peer's checkpoint and queues — ahead of
// everything else — our MIGRATE marker followed by exactly the records the
// peer is missing. New records keep waiting in the lanes until that replay
// has gone out.
func (s *Session) resumeAttach(rw io.ReadWriteCloser, peerCP *ResumeCheckpoint, head []outRec, commit func() error) error {
	if peerCP == nil {
		return ErrHandshake
	}
	s.migMu.Lock()
	if !s.frozen || s.isDead() {
		s.migMu.Unlock()
		return ErrHandshake
	}
	old := s.loops
	s.migMu.Unlock()
	// The previous generation must be gone before the counters are touched:
	// a writer still running could consume a sequence number or emit into
	// the replay, a reader could advance the counter the peer was told.
	if old != nil {
		old.retire()
		if !old.wait(quiesceTimeout) {
			return ErrMigrate
		}
	}
	ours := s.Checkpoint()

	s.migMu.Lock()
	if !s.frozen || s.isDead() || s.loops != old {
		s.migMu.Unlock()
		return ErrHandshake // lost a race with another attach, or closed
	}
	if commit != nil {
		if err := commit(); err != nil {
			s.migMu.Unlock()
			return err
		}
	}
	from := peerCP.LastRecvSeq
	if from > s.sendSeq {
		// The peer claims records that were never sent.
		s.migMu.Unlock()
		return ErrMigrate
	}
	gap := from < s.sent.lost

	// The replay, in emission order: records emitted but unacknowledged,
	// then what an earlier replay or a retiring writer never got to emit
	// (control records in there are stale — re-announced or idempotent).
	pending := make([]outRec, 0, len(s.sent.recs)+len(s.replayQ))
	for _, r := range s.sent.recs {
		if r.seq >= from {
			pending = append(pending, outRec{t: r.t, id: r.id, p: r.p})
		}
	}
	for _, r := range s.replayQ {
		if retainedType(r.t) {
			pending = append(pending, r)
		}
	}
	replay := make([]outRec, 0, 1+len(head)+len(pending))
	replay = append(replay, outRec{t: MsgMigrate, id: 0, p: ours.Encode()})
	// Tickets lead: they are tiny, order-independent, and the one thing the
	// peer must hold before this transport is allowed to die as well.
	replay = append(replay, head...)
	for _, r := range pending {
		if r.t == MsgTicket {
			replay = append(replay, r)
		}
	}
	opens := map[uint32]struct{}{}
	for _, r := range pending {
		// After an unrecoverable gap every stream is reset below; replaying
		// fragments of them would only feed the peer data it must discard.
		if r.t == MsgTicket || gap {
			continue
		}
		replay = append(replay, r)
		if r.t == MsgOpen {
			opens[r.id] = struct{}{}
		}
	}
	s.sent.reset() // acknowledged records are done; the rest re-enter on emission
	s.sendSeq = from
	s.replayQ = replay
	s.replayOpen = opens
	s.frozen = false
	s.rw = rw
	if s.freezeT != nil {
		s.freezeT.Stop()
		s.freezeT = nil
	}
	ls := newLoopSet()
	s.loops = ls
	s.attachGen++
	s.migrateCh = make(chan struct{}) // arm NeedsMigrate for the next loss
	s.migMu.Unlock()

	if gap {
		s.resetForGap(peerCP)
	}
	go s.readLoop(ls, rw)
	go s.writeLoop(ls, rw)
	s.announce()
	return nil
}

// resetForGap handles a resumption whose replay window no longer holds what
// the peer is missing: no stream can be trusted to be intact, so all of them
// are aborted on both sides. Called before the new loops start, so the resets
// leave right behind the MIGRATE marker.
func (s *Session) resetForGap(peer *ResumeCheckpoint) {
	ids := map[uint32]struct{}{}
	s.smu.RLock()
	sts := make([]*stream, 0, len(s.streams))
	for id, st := range s.streams {
		ids[id] = struct{}{}
		sts = append(sts, st)
	}
	s.smu.RUnlock()
	for _, st := range sts {
		st.reset(abortf("records lost in migration"))
	}
	for _, st := range peer.Streams {
		if st.ID != 0 { // id 0 is the extended-trailer marker, not a stream
			ids[st.ID] = struct{}{}
		}
	}
	s.migMu.Lock()
	for id := range ids {
		s.replayQ = append(s.replayQ, outRec{t: MsgRst, id: id, p: []byte("migrate-gap")})
	}
	s.migMu.Unlock()
}

// sendTicket queues a TICKET record with the sealed ticket.
func (s *Session) sendTicket(ticket []byte) error {
	payload := append(append([]byte{}, s.sessionID[:]...), ticket...)
	return s.sendRecord(MsgTicket, 0, payload)
}

// ticketPoolMax bounds the unused tickets a client keeps.
const ticketPoolMax = 4

// storeTicket handles a TICKET record (payload = sessionID || ticket).
func (s *Session) storeTicket(payload []byte) {
	s.migMu.Lock()
	copy(s.sessionID[:], payload[:8])
	s.migMu.Unlock()
	s.poolTicket(payload[8:])
}

// poolTicket adds a server-issued ticket to the client's pool.
func (s *Session) poolTicket(ticket []byte) {
	s.migMu.Lock()
	s.tickets = append(s.tickets, append([]byte(nil), ticket...))
	if n := len(s.tickets) - ticketPoolMax; n > 0 {
		s.tickets = append(s.tickets[:0], s.tickets[n:]...)
	}
	s.migMu.Unlock()
	s.migratable.Store(true)
}

// spendTicket removes a ticket the server has accepted.
func (s *Session) spendTicket(ticket []byte) {
	s.migMu.Lock()
	defer s.migMu.Unlock()
	for i, t := range s.tickets {
		if bytes.Equal(t, ticket) {
			s.tickets = append(s.tickets[:i], s.tickets[i+1:]...)
			return
		}
	}
}

// ResumeState is the client-held resumption material for a frozen session.
type ResumeState struct {
	SessionID [8]byte
	Ticket    []byte
	Session   *Session
	// gen is the transport generation the state was taken in (see
	// ResumeState.BeginResumeFlight).
	gen uint64
}

// TicketState returns resumption material for this session, if an unused
// ticket is held. Each call hands out the oldest ticket and moves it to the
// back of the pool: an attempt that never reached the server leaves its
// ticket valid for a later try, while one that did reach it has spent the
// ticket — the next attempt must not present the same one first.
func (s *Session) TicketState() (*ResumeState, bool) {
	s.migMu.Lock()
	defer s.migMu.Unlock()
	if len(s.tickets) == 0 {
		return nil, false
	}
	t := s.tickets[0]
	s.tickets = append(s.tickets[1:], t)
	return &ResumeState{SessionID: s.sessionID, Ticket: append([]byte(nil), t...), Session: s, gen: s.attachGen}, true
}

var _ = fmt.Sprintf // silence unused in some build configs
