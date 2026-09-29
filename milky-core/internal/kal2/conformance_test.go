package kal2

// Conformance tests for KAL/2 v2.1 (kaleido/SPEC.md + testdata/vectors.json).
// Expected values are derived here from spec formulas in test code —
// independent of the production KDF — and then compared against both the
// implementation and the checked-in vectors file.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type vectors map[string]map[string]string

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("vectors json: %v", err)
	}
	return v
}

func vhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// specInfo builds the §2 HKDF info string: mxs-in-v2/transcript/<label>/<tr>.
func specInfo(label, tr []byte) []byte {
	out := append([]byte("mxs-in-v2/transcript/"), label...)
	out = append(out, '/')
	return append(out, tr...)
}

// specHKDF is the §2 KDF: HKDF-SHA256(ikm=salt, salt=SHA256(transcript), info).
func specHKDF(t *testing.T, ikm, tr, label []byte, n int) []byte {
	t.Helper()
	th := sha256.Sum256(tr)
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, th[:], specInfo(label, tr)), out); err != nil {
		t.Fatal(err)
	}
	return out
}

func specSalt(t *testing.T, shared, binding []byte) []byte {
	t.Helper()
	if len(binding) == 0 {
		return shared
	}
	m := hmac.New(sha256.New, []byte("mxs-in-v2/exporter-bind"))
	m.Write(shared)
	m.Write(binding)
	return m.Sum(nil)
}

func specConcatTranscript(magic []byte, ver byte, ce, se []byte) []byte {
	out := append([]byte{}, magic...)
	out = append(out, ver)
	out = append(out, ce...)
	return append(out, se...)
}

// TestVectorHandshakeKeys: every §2-derived secret, client and server side,
// via the spec formulas vs the vectors file vs the production key schedule.
func TestVectorHandshakeKeys(t *testing.T) {
	v := loadVectors(t)
	shared := vhex(t, v["input"]["shared"])
	tr := vhex(t, v["handshake"]["transcript"])

	// Transcript assembly itself (§2): magic || version || ephs.
	if want := specConcatTranscript(Magic, Version, vhex(t, v["input"]["clientEph"]), vhex(t, v["input"]["serverEph"])); !bytes.Equal(want, tr) {
		t.Fatalf("vector transcript != spec assembly:\nwant %x\ngot  %x", want, tr)
	}

	salt := specSalt(t, shared, nil)
	checks := map[string]struct {
		label []byte
		n     int
	}{
		"clientRecordKey": {[]byte("mxs-in-v2/record/client"), 32},
		"serverRecordKey": {[]byte("mxs-in-v2/record/server"), 32},
		"nonceBase":       {[]byte("mxs-in-v2/nonce-base"), 8},
		"handshakeVerify": {[]byte("mxs-in-v2/handshake-verify"), 32},
		"resumeSecret":    {[]byte("mxs-in-v2/resume-secret"), 32},
	}
	for field, c := range checks {
		exp := specHKDF(t, salt, tr, c.label, c.n)
		if got := vhex(t, v["keys"][field]); !bytes.Equal(exp, got) {
			t.Errorf("keys.%s mismatch\nspec   %x\nvector %x", field, exp, got)
		}
	}

	// The production key schedule must equal the spec derivation.
	mk, err := deriveSessionKeys(tr, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mk.sendKey, specHKDF(t, salt, tr, []byte("mxs-in-v2/record/client"), 32)) {
		t.Error("impl clientRecordKey != spec")
	}
	if !bytes.Equal(mk.recvKey, specHKDF(t, salt, tr, []byte("mxs-in-v2/record/server"), 32)) {
		t.Error("impl serverRecordKey != spec")
	}
	if !bytes.Equal(mk.nonceBase, specHKDF(t, salt, tr, []byte("mxs-in-v2/nonce-base"), 8)) {
		t.Error("impl nonceBase != spec")
	}
	if !bytes.Equal(mk.verify, specHKDF(t, salt, tr, []byte("mxs-in-v2/handshake-verify"), 32)) {
		t.Error("impl handshakeVerify != spec")
	}
}

// TestVectorFlights: client flight prefix, server flight, signature and
// preauth as byte-for-byte spec checks.
func TestVectorFlights(t *testing.T) {
	v := loadVectors(t)
	psk := vhex(t, v["input"]["psk"])
	clientEph := vhex(t, v["input"]["clientEph"])
	serverEph := vhex(t, v["input"]["serverEph"])
	shared := vhex(t, v["input"]["shared"])
	tr := vhex(t, v["handshake"]["transcript"])

	// Client preauth: HMAC(psk, label || magic || version || clientEph).
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("mxs-in-v2/client-preauth"))
	m.Write(Magic)
	m.Write([]byte{Version})
	m.Write(clientEph)
	preauth := m.Sum(nil)
	if !bytes.Equal(preauth, vhex(t, v["handshake"]["preauth"])) {
		t.Errorf("preauth mismatch\nspec   %x\nvector %x", preauth, vhex(t, v["handshake"]["preauth"]))
	}

	// Client flight = magic || ver || eph || preauth || padLen(2,LE) || pad.
	cf := vhex(t, v["handshake"]["clientFlight"])
	head := append(append(append(append([]byte{}, Magic...), Version), clientEph...), preauth...)
	if !bytes.Equal(cf[:len(head)], head) {
		t.Errorf("clientFlight head mismatch\nspec   %x\nvector %x", head, cf[:len(head)])
	}
	padLen := int(binary.LittleEndian.Uint16(cf[len(head):]))
	if padLen != len(cf)-len(head)-2 {
		t.Errorf("clientFlight padLen %d, trailing %d", padLen, len(cf)-len(head)-2)
	}
	// And it must parse through the production reader.
	eph, tl, err := ParseClientFirstFlight(cf, psk, nil)
	if err != nil {
		t.Fatalf("ParseClientFirstFlight: %v", err)
	}
	if !bytes.Equal(eph, clientEph) || tl != len(cf) {
		t.Errorf("flight parse: eph=%x totalLen=%d want %d", eph, tl, len(cf))
	}

	// Server flight = serverEph || Ed25519(sigInput); sigInput = HKDF of the
	// server-sig-input label.
	salt := specSalt(t, shared, nil)
	sigInput := specHKDF(t, salt, tr, []byte("mxs-in-v2/server-sig-input"), 32)
	sf := vhex(t, v["handshake"]["serverFlight"])
	if !bytes.Equal(sf[:32], serverEph) {
		t.Error("serverFlight ephemeral != input.serverEph")
	}
	if !ed25519.Verify(ed25519.PublicKey(vhex(t, v["input"]["serverPub"])), sigInput, sf[32:]) {
		t.Error("server signature does not verify under spec sigInput")
	}
	if !bytes.Equal(sf[32:], vhex(t, v["handshake"]["signature"])) {
		t.Error("handshake.signature != serverFlight signature")
	}
}

// TestVectorRecord: impl decrypts the vector OPEN record; write path
// round-trips through the spec key.
func TestVectorRecord(t *testing.T) {
	v := loadVectors(t)
	shared := vhex(t, v["input"]["shared"])
	tr := vhex(t, v["handshake"]["transcript"])
	salt := specSalt(t, shared, nil)

	mk, err := deriveSessionKeys(tr, salt)
	if err != nil {
		t.Fatal(err)
	}
	// The vector record is client→server: read it as the server role.
	mk.sendKey, mk.recvKey = mk.recvKey, mk.sendKey
	mk.isClient = false
	// Feed the vector record through the real read path (Attach would start
	// readLoop — a competing reader on the same conn; feed the fd directly).
	mk.initAEAD()
	mk.rw = rawRWC{bytes.NewReader(vhex(t, v["record"]["openStream1Bytes"]))}
	got, err := mk.readRecord(mk.rw)
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if got.Type != MsgOpen || got.StreamID != 1 || got.Seq != 0 {
		t.Errorf("record hdr: type=%x stream=%d seq=%d", got.Type, got.StreamID, got.Seq)
	}
	if !bytes.Equal(got.Payload, vhex(t, v["openTargets"]["domain"])) {
		t.Errorf("record payload != domain target\ngot  %x\nwant %x", got.Payload, vhex(t, v["openTargets"]["domain"]))
	}
	nw, host, port, err := ParseOpenTarget(got.Payload)
	if err != nil || nw != "tcp" || host != "api.ipify.org" || port != 443 {
		t.Errorf("ParseOpenTarget: net=%q host=%q port=%d err=%v", nw, host, port, err)
	}
}

// TestVectorOpenTargets: the four §4 wire encodings.
func TestVectorOpenTargets(t *testing.T) {
	v := loadVectors(t)
	cases := []struct {
		field    string
		wantNet  string
		wantHost string
		wantPort uint16
	}{
		{"ipv4", "tcp", "93.184.216.34", 443},
		{"domain", "tcp", "api.ipify.org", 443},
		{"ipv6", "tcp", "::1", 8080},
		{"udpDomain", "udp", "dns.google", 853},
	}
	for _, c := range cases {
		b := vhex(t, v["openTargets"][c.field])
		nw, host, port, err := ParseOpenTarget(b)
		if err != nil {
			t.Errorf("%s: ParseOpenTarget failed on %x: %v", c.field, b, err)
			continue
		}
		if nw != c.wantNet || host != c.wantHost || port != c.wantPort {
			t.Errorf("%s: got net=%q host=%q port=%d want %q %q %d",
				c.field, nw, host, port, c.wantNet, c.wantHost, c.wantPort)
		}
	}
}

// TestVectorDescriptor: §10.1 parse + pin + expiry, §10.2 rendezvous path.
func TestVectorDescriptor(t *testing.T) {
	v := loadVectors(t)
	pub := vhex(t, v["input"]["serverPub"])
	desc := vhex(t, v["descriptor"]["descriptor"])
	plain := vhex(t, v["descriptor"]["plain"])
	sig := vhex(t, v["descriptor"]["signature"])

	// descriptor = plain || signature
	if !bytes.Equal(desc[:len(plain)], plain) || !bytes.Equal(desc[len(plain):], sig) {
		t.Fatal("descriptor != plain || signature")
	}
	// Signature per §10.1: Ed25519(server, "kal2-desc-v1" || plain).
	if !ed25519.Verify(ed25519.PublicKey(pub), append([]byte("kal2-desc-v1"), plain...), sig) {
		t.Fatal("descriptor signature invalid under serverPub")
	}

	expires := time.Unix(int64(binary.BigEndian.Uint32(plain[1:5])), 0)
	d, err := ParseDescriptor(desc, pub, expires.Add(-time.Minute))
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}
	if len(d.Endpoints) != 1 {
		t.Fatalf("endpoints: %d", len(d.Endpoints))
	}
	ep := d.Endpoints[0]
	if ep.Addr != "us-ech.milky.homes" || ep.Port != 443 ||
		ep.Carriers != DescCarrierVeil|DescCarrierDrift|DescCarrierCDN|DescCarrierMosaic ||
		ep.SNI != "kal.mergescribe.dev" || len(ep.ECH) != 0 ||
		ep.Flags != DescFlagPreferred {
		t.Errorf("endpoint mismatch: %+v", ep)
	}

	// Expired → reject (TTL).
	if _, err := ParseDescriptor(desc, pub, expires.Add(time.Second)); err != ErrDescriptorExpired {
		t.Errorf("expired descriptor: got %v want ErrDescriptorExpired", err)
	}
	// Wrong pin → reject (anti-substitution).
	if _, err := ParseDescriptor(desc, make([]byte, 32), expires.Add(-time.Minute)); err != ErrDescriptorSignature {
		t.Errorf("wrong pin: got %v want ErrDescriptorSignature", err)
	}
	// Tampered endpoint → signature fails.
	tampered := append([]byte(nil), desc...)
	tampered[len(plain)-2] ^= 0xff
	if _, err := ParseDescriptor(tampered, pub, expires.Add(-time.Minute)); err != ErrDescriptorSignature {
		t.Errorf("tampered descriptor: got %v want ErrDescriptorSignature", err)
	}
}

// TestRendezvousPath: §10.2 keyed path — computable only with the PSK, so a
// scanner cannot distinguish the descriptor path from any other 404.
func TestRendezvousPath(t *testing.T) {
	psk := []byte("test-psk")
	at := time.Unix(1700000000, 0)
	p := RendezvousPath(psk, at)

	epoch := uint64(1700000000) / uint64(6*60*60)
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("kal2-rdvs/"))
	m.Write([]byte(strconv.FormatUint(epoch, 10)))
	want := "/r/" + hex.EncodeToString(m.Sum(nil)[:8])
	if p != want {
		t.Errorf("path %q want %q", p, want)
	}
	// Same epoch → same path; next epoch → different path.
	if RendezvousPath(psk, at.Add(time.Hour)) != p {
		t.Error("path changed within one epoch")
	}
	if RendezvousPath(psk, at.Add(RendezvousEpoch)) == p {
		t.Error("path unchanged across epoch boundary")
	}
	// A scanner without the PSK gets an unrelated path (non-predictable).
	if RendezvousPath([]byte("wrong"), at) == p {
		t.Error("path computable without psk")
	}
}

// rawRWC adapts an incoming byte stream so readRecord can run without Attach.
type rawRWC struct{ io.Reader }

func (rawRWC) Write(p []byte) (int, error) { return len(p), nil }
func (rawRWC) Close() error                { return nil }

// wireFrame builds one encrypted record exactly per §3:
// header(type||seq||streamID||ctLen) as AD over
// AEAD(payload || pad || padLen[2,LE]).
func wireFrame(t *testing.T, key, nonceBase []byte, seq uint64, typ byte, streamID uint32, payload []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce, nonceBase)
	var sq [8]byte
	binary.BigEndian.PutUint64(sq[:], seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= sq[i]
	}
	var pl [2]byte
	binary.LittleEndian.PutUint16(pl[:], 0)
	padded := append(append([]byte{}, payload...), pl[:]...)
	ct := aead.Seal(nil, nonce, padded, nil)
	hdr := make([]byte, RecordHeaderSize)
	hdr[0] = typ
	binary.BigEndian.PutUint64(hdr[1:9], seq)
	binary.BigEndian.PutUint32(hdr[9:13], streamID)
	binary.BigEndian.PutUint32(hdr[13:17], uint32(len(ct)))
	ct = aead.Seal(nil, nonce, padded, hdr)
	return append(hdr, ct...)
}

// TestForwardCompatTypes (§12): unknown record types <0x80 are skipped
// (authenticated, decrypted, ignored); unknown ≥0x80 tears the session down.
func TestForwardCompatTypes(t *testing.T) {
	v := loadVectors(t)
	tr := vhex(t, v["handshake"]["transcript"])
	salt := specSalt(t, vhex(t, v["input"]["shared"]), nil)
	mk, err := deriveSessionKeys(tr, salt)
	if err != nil {
		t.Fatal(err)
	}
	sk := mk.recvKey // peer-to-us records seal under serverRecordKey

	var wire []byte
	wire = append(wire, wireFrame(t, sk, mk.nonceBase, 0, 0x40, 0, []byte{1})...)
	wire = append(wire, wireFrame(t, sk, mk.nonceBase, 1, MsgTicket, 0, []byte{2})...)
	wire = append(wire, wireFrame(t, sk, mk.nonceBase, 2, MsgData, 3, []byte("ok"))...)

	mk.initAEAD()
	mk.rw = rawRWC{bytes.NewReader(wire)}

	r1, err := mk.readRecord(mk.rw)
	if err != nil || r1.Type != 0x40 {
		t.Fatalf("record1: type=%x err=%v", r1.Type, err)
	}
	r2, err := mk.readRecord(mk.rw)
	if err != nil || r2.Type != MsgTicket {
		t.Fatalf("record2 (TICKET): type=%x err=%v", r2.Type, err)
	}
	r3, err := mk.readRecord(mk.rw)
	if err != nil || r3.Type != MsgData || !bytes.Equal(r3.Payload, []byte("ok")) {
		t.Fatalf("record3: type=%x payload=%q err=%v", r3.Type, r3.Payload, err)
	}

	// An unknown mandatory (≥0x80) type must tear the session down.
	wire2 := wireFrame(t, sk, mk.nonceBase, 0, 0x81, 0, nil)
	mk2, err := deriveSessionKeys(tr, salt)
	if err != nil {
		t.Fatal(err)
	}
	mk2.initAEAD()
	mk2.rw = rawRWC{bytes.NewReader(wire2)}
	if _, err := mk2.readRecord(mk2.rw); err != ErrFraming {
		t.Fatalf("mandatory unknown type: got %v want ErrFraming", err)
	}
}

// TestRecordReplayRejected (§3, §6a): a repeated record — the optimistic-OPEN
// replay class — is rejected by the sequence counter, never executed twice.
func TestRecordReplayRejected(t *testing.T) {
	v := loadVectors(t)
	tr := vhex(t, v["handshake"]["transcript"])
	salt := specSalt(t, vhex(t, v["input"]["shared"]), nil)
	mk, err := deriveSessionKeys(tr, salt)
	if err != nil {
		t.Fatal(err)
	}
	sk := mk.recvKey
	frame := wireFrame(t, sk, mk.nonceBase, 0, MsgData, 1, []byte("x"))

	mk.initAEAD()
	mk.rw = rawRWC{bytes.NewReader(append(frame, frame...))}
	if _, err := mk.readRecord(mk.rw); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if _, err := mk.readRecord(mk.rw); err != ErrReplay {
		t.Fatalf("replayed record: got %v want ErrReplay", err)
	}
}

// TestOptimisticOpenEarlyData (§6a): DATA sent right after OPEN — before
// OPEN_ACK — is delivered once the stream is accepted, exactly once.
func TestOptimisticOpenEarlyData(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	st, err := client.OpenOpt("upstream.example", 443)
	if err != nil {
		t.Fatalf("OpenOpt: %v", err)
	}
	// Early DATA before OPEN_ACK completes.
	if _, err := st.Write([]byte("early-bytes")); err != nil {
		t.Fatalf("early write: %v", err)
	}
	srv := <-accepted
	buf := make([]byte, 64)
	srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("early-bytes")) {
		t.Fatalf("early data mismatch: %q", buf[:n])
	}
	// No double delivery: a second read must block (nothing new arrived).
	done := make(chan int, 1)
	go func() {
		n, _ := srv.Read(buf)
		done <- n
	}()
	select {
	case n := <-done:
		t.Fatalf("duplicate early data delivered: %q", buf[:n])
	case <-time.After(200 * time.Millisecond):
	}
}

// TestVectorResume (§9.2/9.3): the resumption flight layout, ticket contents
// and the re-keyed record schedule.
func TestVectorResume(t *testing.T) {
	v := loadVectors(t)
	shared := vhex(t, v["input"]["shared"])
	clientEph := vhex(t, v["input"]["clientEph"])
	serverEph := vhex(t, v["input"]["serverEph"])
	rs := vhex(t, v["keys"]["resumeSecret"])
	sessionID := vhex(t, v["resume"]["sessionID"])
	ticket := vhex(t, v["resume"]["ticket"])
	tr2 := vhex(t, v["resume"]["transcript2"])
	rf := vhex(t, v["resume"]["resumeFlight"])

	// transcript2 = "KLDO-rs-" || ver || sessionID || clientEph || serverEph
	wantTr2 := specConcatTranscript([]byte("KLDO-rs-"), Version, clientEph, serverEph)
	// insert sessionID after version per §9.3
	wantTr2 = append([]byte("KLDO-rs-"), Version)
	wantTr2 = append(wantTr2, sessionID...)
	wantTr2 = append(wantTr2, clientEph...)
	wantTr2 = append(wantTr2, serverEph...)
	if !bytes.Equal(wantTr2, tr2) {
		t.Fatalf("transcript2 mismatch:\nwant %x\ngot  %x", wantTr2, tr2)
	}

	// Flight structure: magic(8) ver(1) sessionID(8) clientEph(32)
	//                   ticketLen(2,LE) ticket resumePreauth(32) checkpoint.
	if !bytes.Equal(rf[:8], []byte("KLDO-rs-")) || rf[8] != Version {
		t.Fatal("resume flight header")
	}
	if !bytes.Equal(rf[9:17], sessionID) || !bytes.Equal(rf[17:49], clientEph) {
		t.Fatal("resume flight sessionID/clientEph")
	}
	tl := int(binary.LittleEndian.Uint16(rf[49:51]))
	if tl != len(ticket) || !bytes.Equal(rf[51:51+tl], ticket) {
		t.Fatalf("ticketLen %d vs ticket %d", tl, len(ticket))
	}
	rp := rf[51+tl : 51+tl+32]
	cp := rf[51+tl+32:]

	// resumePreauth = HMAC(resumeSecret, label || magic || ver || sessionID ||
	// clientEph || ticket) — binding absent.
	m := hmac.New(sha256.New, rs)
	m.Write([]byte("mxs-in-v2/resume-preauth"))
	m.Write([]byte("KLDO-rs-"))
	m.Write([]byte{Version})
	m.Write(sessionID)
	m.Write(clientEph)
	m.Write(ticket)
	if !bytes.Equal(m.Sum(nil), rp) {
		t.Error("resumePreauth mismatch")
	}

	// checkpoint = lastRecvSeq[8,BE] || nStreams[2,BE] || {streamID,flags}.
	if len(cp) < 10 {
		t.Fatal("checkpoint short")
	}
	if binary.BigEndian.Uint64(cp[:8]) != 42 {
		t.Errorf("checkpoint lastRecvSeq=%d want 42", binary.BigEndian.Uint64(cp[:8]))
	}
	if n := binary.BigEndian.Uint16(cp[8:10]); int(n)*5+10 != len(cp) {
		t.Errorf("checkpoint nStreams=%d inconsistent with len %d", n, len(cp))
	}

	// Ticket opens under ticketKey and carries the vector's resumeSecret.
	aead, err := chacha20poly1305.New(vhex(t, v["resume"]["ticketKey"]))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aead.Open(nil, vhex(t, v["resume"]["ticketNonce"]), ticket, nil)
	if err != nil {
		t.Fatalf("ticket open: %v", err)
	}
	if pt[0] != 0x01 || !bytes.Equal(pt[1:9], sessionID) || !bytes.Equal(pt[30:62], rs) {
		t.Errorf("ticketPlain layout bad: %x", pt)
	}

	// §9.3 re-key: salt2 = HMAC(exporter-bind, shared2 || resumeSecret);
	// record keys re-derived under (salt2, transcript2).
	m2 := hmac.New(sha256.New, []byte("mxs-in-v2/exporter-bind"))
	m2.Write(shared)
	m2.Write(rs)
	salt2 := m2.Sum(nil)
	if got := specHKDF(t, salt2, tr2, []byte("mxs-in-v2/record/client"), 32); !bytes.Equal(got, vhex(t, v["resume"]["clientRecordKey2"])) {
		t.Error("clientRecordKey2 mismatch")
	}
	if got := specHKDF(t, salt2, tr2, []byte("mxs-in-v2/record/server"), 32); !bytes.Equal(got, vhex(t, v["resume"]["serverRecordKey2"])) {
		t.Error("serverRecordKey2 mismatch")
	}
}

// TestVectorMigrate: §9.4 MIGRATE payload = session checkpoint snapshot.
func TestVectorMigrate(t *testing.T) {
	v := loadVectors(t)
	p := vhex(t, v["migrate"]["payload"])
	if len(p) < 10 {
		t.Fatal("migrate payload short")
	}
	seq := binary.BigEndian.Uint64(p[:8])
	n := binary.BigEndian.Uint16(p[8:10])
	if seq != 42 || int(n)*5+10 != len(p) {
		t.Fatalf("migrate payload: seq=%d n=%d len=%d", seq, n, len(p))
	}
}

// TestVectorFinished: the Finished MAC over handshakeVerify.
func TestVectorFinished(t *testing.T) {
	v := loadVectors(t)
	tr := vhex(t, v["handshake"]["transcript"])
	salt := specSalt(t, vhex(t, v["input"]["shared"]), nil)
	hv := specHKDF(t, salt, tr, []byte("mxs-in-v2/handshake-verify"), 32)
	m := hmac.New(sha256.New, hv)
	m.Write([]byte("mxs-in-v2/finished"))
	m.Write([]byte("/client"))
	if !bytes.Equal(m.Sum(nil), vhex(t, v["keys"]["finished"])) {
		t.Error("keys.finished (client) mismatch")
	}
}
