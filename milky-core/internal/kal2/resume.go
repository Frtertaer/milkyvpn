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
}

func (cp *ResumeCheckpoint) Encode() []byte {
	b := binary.BigEndian.AppendUint64(nil, cp.LastRecvSeq)
	b = binary.BigEndian.AppendUint16(b, uint16(len(cp.Streams)))
	for _, st := range cp.Streams {
		b = binary.BigEndian.AppendUint32(b, st.ID)
		var f byte
		if st.WriteEnd {
			f = 1
		}
		b = append(b, f)
	}
	return b
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
// session's own sessionID. Use ResumeState.ResumeFlight to resume under a
// specific (e.g. forged in tests) session id.
func (s *Session) ResumeFlight(clientEph []byte, cp *ResumeCheckpoint, binding ChannelBinding) []byte {
	return s.resumeFlight(s.sessionID, clientEph, cp, binding)
}

func (s *Session) resumeFlight(sessionID [8]byte, clientEph []byte, cp *ResumeCheckpoint, binding ChannelBinding) []byte {
	out := append(append([]byte{}, ResumeMagic...), Version)
	out = append(out, sessionID[:]...)
	out = append(out, clientEph...)
	var tb [2]byte
	binary.LittleEndian.PutUint16(tb[:], uint16(len(s.ticket)))
	out = append(out, tb[:]...)
	out = append(out, s.ticket...)
	out = append(out, resumePreauth(s.resumeSecret, sessionID, clientEph, s.ticket, binding)...)
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
// carrier connection. On success the session is re-keyed and re-attached;
// the caller then exchanges MIGRATE checkpoints via s.Migratate.
type ClientResume struct {
	ephPriv   []byte
	ephPub    []byte
	sessionID [8]byte
}

// BeginResumeFlight writes the resumption flight on rw and returns the
// handshake state needed to consume the server flight.
func (s *Session) BeginResumeFlight(rw io.Writer, binding ChannelBinding) (*ClientResume, error) {
	priv, pub, err := genX25519()
	if err != nil {
		return nil, err
	}
	cp := s.Checkpoint()
	flight := s.ResumeFlight(pub, cp, binding)
	if _, err := rw.Write(flight); err != nil {
		return nil, err
	}
	return &ClientResume{ephPriv: priv, ephPub: pub, sessionID: s.sessionID}, nil
}

// BeginResumeFlight drives the same exchange through a ResumeState: the
// flight announces rs.SessionID, which may differ from the session's own id
// (server-side ticket rebinding, or a forged id in tests).
func (rs *ResumeState) BeginResumeFlight(rw io.Writer, binding ChannelBinding) (*ClientResume, error) {
	s := rs.Session
	priv, pub, err := genX25519()
	if err != nil {
		return nil, err
	}
	flight := s.resumeFlight(rs.SessionID, pub, s.Checkpoint(), binding)
	if _, err := rw.Write(flight); err != nil {
		return nil, err
	}
	return &ClientResume{ephPriv: priv, ephPub: pub, sessionID: rs.SessionID}, nil
}

// FinishResume consumes the server flight (eph||sig), verifies the Ed25519
// signature over transcript2, re-keys the session and returns the server
// Finished value the caller must verify after the server writes it.
// serverPub is the pinned identity key.
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
	return s.rekey(salt, tr)
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
	s.sessionID = sid
	s.userID = userID
	s.migratable = true
	s.registry = r
	if r.ttl > 0 {
		s.migrateTTL = r.ttl
	}
	s.onCloseFns = append(s.onCloseFns, func() { r.remove(sid) })
	r.mu.Lock()
	r.sessions[sid] = &registeredSession{sess: s, userID: userID}
	r.mu.Unlock()
	// TICKET is a control record; queued safely post-Attach.
	return s.sendTicket(t)
}

// remove unregisters a closed session.
func (r *SessionRegistry) remove(sid [8]byte) {
	r.mu.Lock()
	delete(r.sessions, sid)
	r.mu.Unlock()
}

// Refresh issues a fresh ticket on an already-registered session — the
// resumption path re-arms the client for the next migration.
func (r *SessionRegistry) Refresh(s *Session) error {
	if s.registry != r {
		return ErrTicket
	}
	tp := &TicketPlain{
		SessionID: s.sessionID,
		UserID:    s.userID,
		Expires:   uint32(time.Now().Add(24 * time.Hour).Unix()),
		Flags:     TicketFlagMigrate,
	}
	copy(tp.ResumeSecret[:], s.resumeSecret)
	t, err := r.codec.Issue(tp)
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
	// re-attach replaces it. freeze() is idempotent.
	if !s.Frozen() {
		s.freeze()
	}
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
	return &ResumeResult{Session: s, ClientEph: clientEph, Checkpoint: cp, TicketPlain: tp}, nil
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
	res.Session.resumeTr = tr
	res.Session.resumeSalt = h.salt
	return flight, h, nil
}

// finishResume re-keys the frozen session after the server flight is sent.
func (res *ResumeResult) Finish() error {
	return res.Session.rekey(res.Session.resumeSalt, res.Session.resumeTr)
}

// ---------------------------------------------------------------------------
// Migration (MIGRATE exchange + stream reconcile + replay)
// ---------------------------------------------------------------------------

// Checkpoint snapshots the receive counter and live stream table for the
// resumption flight / MIGRATE record. LastRecvSeq is the receiver's
// next-expected sequence (== recvSeq) — the seq the peer's next record must
// carry.
func (s *Session) Checkpoint() *ResumeCheckpoint {
	s.smu.RLock()
	cp := &ResumeCheckpoint{LastRecvSeq: s.recvSeq, Streams: make([]ResumeStreamState, 0, len(s.streams))}
	for id, st := range s.streams {
		cp.Streams = append(cp.Streams, ResumeStreamState{ID: id, WriteEnd: st.closed})
	}
	s.smu.RUnlock()
	return cp
}

// ResumeAttach binds a frozen session to a fresh authenticated transport
// after a successful resumption handshake. peerCP is the checkpoint the
// peer announced in its flight (client) or flight trailer (server). It
// rewinds the send counter, queues our MIGRATE marker followed by the
// retained unacked records, reconciles stream tables, and restarts the
// record loops — stream writes held during the freeze flow after replays.
func (s *Session) ResumeAttach(rw io.ReadWriteCloser, peerCP *ResumeCheckpoint) error {
	s.migMu.Lock()
	if !s.frozen {
		s.migMu.Unlock()
		return ErrHandshake
	}
	s.frozen = false
	s.rw = rw
	s.ticket = nil // the consumed ticket is dead; the peer re-issues via TICKET
	s.loopGen++    // retire the previous generation's record loops
	prevStop, prevDone := s.loopStop, s.writeDone
	s.loopStop = make(chan struct{})
	s.writeDone = make(chan struct{})
	if s.freezeT != nil {
		s.freezeT.Stop()
		s.freezeT = nil
	}
	s.migMu.Unlock()

	// Retire the old writer before rewinding sendSeq: it must not consume
	// sequence numbers or interleave frames into the replay lane. The wait
	// is bounded — a stuck writer can only die at its next generation check.
	if prevStop != nil {
		close(prevStop)
	}
	if prevDone != nil {
		select {
		case <-prevDone:
		case <-time.After(5 * time.Second):
		}
	}

	s.migMu.Lock()
	ours := s.Checkpoint()
	s.sendSeq = peerCP.LastRecvSeq
	oldest := s.sentWinOldest()
	gap := len(s.sentWin) > 0 && peerCP.LastRecvSeq < oldest
	replay := []outRec{{t: MsgMigrate, id: 0, p: ours.Encode()}}
	for _, r := range s.sentWin {
		if r.seq >= peerCP.LastRecvSeq {
			replay = append(replay, outRec{t: r.t, id: r.id, p: r.p})
		}
	}
	s.replayQ = replay
	s.gapLost = gap
	s.migMu.Unlock()

	// Reconcile stream tables before loops restart so RSTs for dead streams
	// land after their replays on the wire.
	s.reconcile(peerCP)

	s.migMu.Lock()
	close(s.migGate)
	s.migrateCh = make(chan struct{}) // arm NeedsMigrate for the next loss
	s.readDone = make(chan struct{})  // old readLoop closed the previous one
	gen := s.loopGen
	stop := s.loopStop
	done := s.writeDone
	s.migMu.Unlock()
	go s.readLoop(gen)
	go s.writeLoop(gen, stop, done)
	return nil
}

// reconcile resets streams the peer no longer has and queues RSTs for
// peer-unknown or gap-lost streams (into the replay tail, preserving order).
func (s *Session) reconcile(peer *ResumeCheckpoint) {
	peerIDs := make(map[uint32]bool, len(peer.Streams))
	for _, st := range peer.Streams {
		peerIDs[st.ID] = true
	}
	s.smu.Lock()
	var oursGone []uint32
	for id := range s.streams {
		if !peerIDs[id] {
			oursGone = append(oursGone, id)
		}
	}
	for _, id := range oursGone {
		st := s.streams[id]
		delete(s.streams, id)
		st.reset()
	}
	s.smu.Unlock()
	for _, id := range oursGone {
		s.migMu.Lock()
		s.replayQ = append(s.replayQ, outRec{t: MsgRst, id: id, p: []byte("migrate")})
		s.migMu.Unlock()
	}
	for _, st := range peer.Streams {
		if _, ok := s.getStream(st.ID); !ok {
			s.migMu.Lock()
			s.replayQ = append(s.replayQ, outRec{t: MsgRst, id: st.ID, p: []byte("migrate")})
			s.migMu.Unlock()
		}
	}
	if s.gapLost {
		// Records vanished in the unrecoverable gap: any surviving stream may
		// have lost data — abort them rather than corrupt state.
		s.smu.Lock()
		var ids []uint32
		for id, st := range s.streams {
			st.reset()
			delete(s.streams, id)
			ids = append(ids, id)
		}
		s.smu.Unlock()
		s.migMu.Lock()
		for _, id := range ids {
			s.replayQ = append(s.replayQ, outRec{t: MsgRst, id: id, p: []byte("migrate-gap")})
		}
		s.migMu.Unlock()
	}
}

// sendTicket queues a TICKET record with the sealed ticket.
func (s *Session) sendTicket(ticket []byte) error {
	payload := append(append([]byte{}, s.sessionID[:]...), ticket...)
	return s.sendRecord(MsgTicket, 0, payload)
}

// ResumeState is the client-held resumption material for a frozen session.
type ResumeState struct {
	SessionID [8]byte
	Ticket    []byte
	Session   *Session
}

// TicketState returns the resumption material for this session, if a
// TICKET has been received.
func (s *Session) TicketState() (*ResumeState, bool) {
	s.migMu.Lock()
	defer s.migMu.Unlock()
	if len(s.ticket) == 0 {
		return nil, false
	}
	return &ResumeState{SessionID: s.sessionID, Ticket: append([]byte(nil), s.ticket...), Session: s}, true
}

var _ = fmt.Sprintf // silence unused in some build configs
