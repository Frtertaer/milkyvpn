// genvec regenerates kaleido conformance vectors (kaleido/testdata/
// vectors.json) from the fixed input constants and the SPEC v2.1 formulas.
// It exists so the vector file stays reproducible: `go run ./cmd/genvec`.
package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	magic  = "KLDO-in-"
	magicR = "KLDO-rs-"
	ver    = 0x02
)

var (
	// Fixed inputs (SPEC testdata/README.md).
	psk        = seqBytes(32, 0x00)
	clientEph  = mustHex("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a")
	serverEph  = mustHex("493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d")
	serverSeed = []byte("kal2-vector-server-seed-00000001")
	shared     = mustHex("dcd77236231add34de0561c47859a65d304f2a8550e8df98df053cf5dfabea0b")

	sessionID   = mustHex("deadbeef00112233")
	ticketKey   = seqBytes(32, 0xa0)
	ticketNonce = seqBytes(12, 0x00)
	userID      = fill(16, 0x55)
	ticketFlags = byte(0x01)
	// expires mirrors the descriptor's; see descriptorExpires.
)

const descriptorExpires uint32 = 0x77359400

func seqBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}
func fill(n int, v byte) []byte { b := make([]byte, n); for i := range b { b[i] = v }; return b }
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
func hxs(b []byte) string { return hex.EncodeToString(b) }

// specKDF: HKDF-SHA256(ikm=salt, salt=SHA256(transcript),
// info = mxs-in-v2/transcript/<label>/<transcript>).
func specKDF(ikm, tr []byte, label string, n int) []byte {
	th := sha256.Sum256(tr)
	info := "mxs-in-v2/transcript/" + label + "/" + string(tr)
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, th[:], []byte(info)), out); err != nil {
		panic(err)
	}
	return out
}

// specSalt: shared when binding empty, else HMAC(exporter-bind, shared||binding).
func specSalt(shared, binding []byte) []byte {
	if len(binding) == 0 {
		return shared
	}
	m := hmac.New(sha256.New, []byte("mxs-in-v2/exporter-bind"))
	m.Write(shared)
	m.Write(binding)
	return m.Sum(nil)
}

func transcript(mag string, ce, se []byte, sid []byte) []byte {
	out := append([]byte(mag), ver)
	out = append(out, sid...)
	out = append(out, ce...)
	return append(out, se...)
}

// frame seals one §3 record: header AD, AEAD(payload || pad || padLen[2,LE]).
func frame(key, nonceBase []byte, seq uint64, typ byte, streamID uint32, payload, pad []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	copy(nonce, nonceBase)
	var sq [8]byte
	binary.BigEndian.PutUint64(sq[:], seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= sq[i]
	}
	var pl [2]byte
	binary.LittleEndian.PutUint16(pl[:], uint16(len(pad)))
	padded := append(append(append([]byte{}, payload...), pad...), pl[:]...)
	hdr := make([]byte, 17)
	hdr[0] = typ
	binary.BigEndian.PutUint64(hdr[1:9], seq)
	binary.BigEndian.PutUint32(hdr[9:13], streamID)
	binary.BigEndian.PutUint32(hdr[13:17], uint32(len(padded)+aead.Overhead()))
	ct := aead.Seal(nil, nonce, padded, hdr)
	return append(hdr, ct...)
}

func main() {
	out := map[string]map[string]string{}
	add := func(sec, k, v string) {
		if out[sec] == nil {
			out[sec] = map[string]string{}
		}
		out[sec][k] = v
	}

	serverPub := ed25519.NewKeyFromSeed(serverSeed).Public().(ed25519.PublicKey)
	add("input", "psk", hxs(psk))
	add("input", "clientEph", hxs(clientEph))
	add("input", "serverEph", hxs(serverEph))
	add("input", "serverPriv", hxs(serverSeed))
	add("input", "serverPub", hxs(serverPub))
	add("input", "shared", hxs(shared))

	// ---- §10.1 descriptor (one endpoint, preferred, all carriers) ----
	ep := []byte{}
	ep = append(ep, byte(len("us-ech.milky.homes")))
	ep = append(ep, "us-ech.milky.homes"...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], 443)
	ep = append(ep, b2[:]...)
	ep = append(ep, 0x0f) // veil|drift|cdn|mosaic
	ep = append(ep, byte(len("kal.mergescribe.dev")))
	ep = append(ep, "kal.mergescribe.dev"...)
	ep = append(ep, 0x00) // echLen
	ep = append(ep, 0x01) // flags: preferred

	plain := []byte{0x01}
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], descriptorExpires)
	plain = append(plain, b4[:]...)
	plain = append(plain, serverPub...)
	plain = append(plain, 0x01) // nEndpoints
	plain = append(plain, ep...)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(serverSeed), append([]byte("kal2-desc-v1"), plain...))
	add("descriptor", "plain", hxs(plain))
	add("descriptor", "signature", hxs(sig))
	add("descriptor", "descriptor", hxs(append(append([]byte{}, plain...), sig...)))

	// ---- §2 handshake ----
	tr := transcript(magic, clientEph, serverEph, nil)
	salt := specSalt(shared, nil)

	// client preauth: HMAC(psk, label || magic || ver || clientEph)
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("mxs-in-v2/client-preauth"))
	m.Write([]byte(magic))
	m.Write([]byte{ver})
	m.Write(clientEph)
	preauth := m.Sum(nil)

	// Deterministic pad (content arbitrary): pad[i] = 7*(i+1).
	pad := make([]byte, 17)
	for i := range pad {
		pad[i] = byte(7 * (i + 1))
	}
	clientFlight := append(append(append([]byte(magic), ver), clientEph...), preauth...)
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(len(pad)))
	clientFlight = append(clientFlight, lb[:]...)
	clientFlight = append(clientFlight, pad...)

	sigInput := specKDF(salt, tr, "mxs-in-v2/server-sig-input", 32)
	ssig := ed25519.Sign(ed25519.NewKeyFromSeed(serverSeed), sigInput)
	serverFlight := append(append([]byte{}, serverEph...), ssig...)

	add("handshake", "clientFlight", hxs(clientFlight))
	add("handshake", "preauth", hxs(preauth))
	add("handshake", "serverFlight", hxs(serverFlight))
	add("handshake", "signature", hxs(ssig))
	add("handshake", "transcript", hxs(tr))

	// ---- keys ----
	ck := specKDF(salt, tr, "mxs-in-v2/record/client", 32)
	sk := specKDF(salt, tr, "mxs-in-v2/record/server", 32)
	nb := specKDF(salt, tr, "mxs-in-v2/nonce-base", 8)
	hv := specKDF(salt, tr, "mxs-in-v2/handshake-verify", 32)
	rs := specKDF(salt, tr, "mxs-in-v2/resume-secret", 32)
	add("keys", "clientRecordKey", hxs(ck))
	add("keys", "serverRecordKey", hxs(sk))
	add("keys", "nonceBase", hxs(nb))
	add("keys", "handshakeVerify", hxs(hv))
	add("keys", "resumeSecret", hxs(rs))
	// finished: HMAC(handshakeVerify, "mxs-in-v2/finished" || "/client")
	fm := hmac.New(sha256.New, hv)
	fm.Write([]byte("mxs-in-v2/finished"))
	fm.Write([]byte("/client"))
	add("keys", "finished", hxs(fm.Sum(nil)))

	// ---- openTargets (§4) ----
	add("openTargets", "ipv4", hxs(mustHex("01"+"5db8d822"+"01bb")))
	add("openTargets", "domain", hxs(append(append([]byte{0x03, 0x0d}, "api.ipify.org"...), 0x01, 0xbb)))
	v6 := append([]byte{0x04}, make([]byte, 16)...)
	v6[16] = 1 // ::1
	binary.BigEndian.PutUint16(b2[:], 8080)
	add("openTargets", "ipv6", hxs(append(v6, b2[:]...)))
	udp := append([]byte{0x83, 'u', 0x0a}, "dns.google"...)
	binary.BigEndian.PutUint16(b2[:], 853)
	add("openTargets", "udpDomain", hxs(append(udp, b2[:]...)))

	// ---- record: OPEN stream 1, domain target (§3 trailer layout) ----
	recPad := seqBytes(237, 0x00)
	add("record", "openStream1Bytes", hxs(frame(ck, nb, 0, 0x01, 1, mustHex("030d6170692e69706966792e6f726701bb"), recPad)))

	// ---- §9 resumption ----
	ticketPlain := []byte{0x01}
	ticketPlain = append(ticketPlain, sessionID...)
	ticketPlain = append(ticketPlain, userID...)
	binary.BigEndian.PutUint32(b4[:], descriptorExpires)
	ticketPlain = append(ticketPlain, b4[:]...)
	ticketPlain = append(ticketPlain, ticketFlags)
	ticketPlain = append(ticketPlain, rs...)
	tAEAD, _ := chacha20poly1305.New(ticketKey)
	ticket := tAEAD.Seal(nil, ticketNonce, ticketPlain, nil)

	// resumePreauth = HMAC(resumeSecret, label || magic || ver || sessionID ||
	// clientEph || ticket)   (binding absent)
	rm := hmac.New(sha256.New, rs)
	rm.Write([]byte("mxs-in-v2/resume-preauth"))
	rm.Write([]byte(magicR))
	rm.Write([]byte{ver})
	rm.Write(sessionID)
	rm.Write(clientEph)
	rm.Write(ticket)
	resumePreauth := rm.Sum(nil)

	// checkpoint: lastRecvSeq[8,BE] || nStreams[2,BE] || {streamID[4,BE],flags}
	checkpoint := make([]byte, 0, 15)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], 42)
	checkpoint = append(checkpoint, b8[:]...)
	binary.BigEndian.PutUint16(b2[:], 1)
	checkpoint = append(checkpoint, b2[:]...)
	var s4 [4]byte
	binary.BigEndian.PutUint32(s4[:], 1)
	checkpoint = append(checkpoint, s4[:]...)
	checkpoint = append(checkpoint, 0x00)

	resumeFlight := append([]byte(magicR), ver)
	resumeFlight = append(resumeFlight, sessionID...)
	resumeFlight = append(resumeFlight, clientEph...)
	binary.LittleEndian.PutUint16(lb[:], uint16(len(ticket)))
	resumeFlight = append(resumeFlight, lb[:]...)
	resumeFlight = append(resumeFlight, ticket...)
	resumeFlight = append(resumeFlight, resumePreauth...)
	resumeFlight = append(resumeFlight, checkpoint...)

	tr2 := transcript(magicR, clientEph, serverEph, sessionID)
	// salt2 = HMAC(exporter-bind, shared2 || binding2 || resumeSecret)
	m2 := hmac.New(sha256.New, []byte("mxs-in-v2/exporter-bind"))
	m2.Write(shared) // shared2 = shared (same eph pair in the vector)
	m2.Write(rs)
	salt2 := m2.Sum(nil)
	add("resume", "sessionID", hxs(sessionID))
	add("resume", "ticketKey", hxs(ticketKey))
	add("resume", "ticketNonce", hxs(ticketNonce))
	add("resume", "ticket", hxs(ticket))
	add("resume", "resumeFlight", hxs(resumeFlight))
	add("resume", "transcript2", hxs(tr2))
	add("resume", "clientRecordKey2", hxs(specKDF(salt2, tr2, "mxs-in-v2/record/client", 32)))
	add("resume", "serverRecordKey2", hxs(specKDF(salt2, tr2, "mxs-in-v2/record/server", 32)))

	// ---- §9.4 MIGRATE payload = the checkpoint ----
	add("migrate", "payload", hxs(checkpoint))

	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
	if len(os.Args) > 1 {
		if err := os.WriteFile(os.Args[1], append(enc, '\n'), 0o644); err != nil {
			panic(err)
		}
	}
}
