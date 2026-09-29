package kal2

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// Carrier bitmap bits inside a descriptor endpoint (SPEC §10.1).
const (
	DescCarrierVeil   byte = 1 << 0
	DescCarrierDrift  byte = 1 << 1
	DescCarrierCDN    byte = 1 << 2
	DescCarrierMosaic byte = 1 << 3
)

// Descriptor endpoint flags.
const (
	DescFlagPreferred byte = 1 << 0
	DescFlagRelayHop  byte = 1 << 1
)

const descVersion = 0x01
const descSigLabel = "kal2-desc-v1"
const descSigSize = ed25519.SignatureSize // 64

// DescriptorEndpoint is one entry of a signed carrier descriptor.
type DescriptorEndpoint struct {
	Addr     string // domain or IP literal
	Port     uint16
	Carriers byte // DescCarrier* bitmap
	SNI      string
	ECH      []byte // ECHConfigList, may be empty
	Flags    byte   // DescFlag* bitmap
}

// Descriptor is a server-identity-signed endpoint list (SPEC §10).
// Trusted only while signed by the pinned server key and unexpired.
type Descriptor struct {
	Expires   time.Time
	ServerPub [32]byte // Ed25519 identity of the signing server
	Endpoints []DescriptorEndpoint

	plain []byte // exact descriptorPlain wire bytes (signed region)
}

// WireLayout returns the signed descriptorPlain bytes (§10.1 form).
func (d *Descriptor) WireLayout() []byte { return d.plain }

// SignedDescriptor produces descriptor = plain || Ed25519 signature —
// server side of §10.1.
func SignedDescriptor(identity ed25519.PrivateKey, plain []byte) []byte {
	sig := ed25519.Sign(identity, append([]byte(descSigLabel), plain...))
	out := make([]byte, 0, len(plain)+descSigSize)
	return append(append(out, plain...), sig...)
}

// ErrDescriptorExpired reports a descriptor whose TTL has passed.
var ErrDescriptorExpired Error = "session: descriptor expired"

// ErrDescriptorSignature reports a signature mismatch against the pinned key.
var ErrDescriptorSignature Error = "session: descriptor signature invalid"

// ParseDescriptor decodes and validates a §10.1 descriptor:
// signature must verify with the embedded serverPub, the embedded key must
// equal pinned, and the descriptor must not be expired. now is injectable
// for deterministic checks; pass time.Now() in production paths.
func ParseDescriptor(b, pinned []byte, now time.Time) (*Descriptor, error) {
	if len(b) < descSigSize+1+4+32+1 {
		return nil, ErrFraming
	}
	plain := b[:len(b)-descSigSize]
	sig := b[len(b)-descSigSize:]
	if len(plain) < 1+4+32+1 {
		return nil, ErrFraming
	}
	if plain[0] != descVersion {
		return nil, ErrVersion
	}
	expires := binary.BigEndian.Uint32(plain[1:5])
	var pub [32]byte
	copy(pub[:], plain[5:37])
	if !ed25519.Verify(ed25519.PublicKey(pub[:]), append([]byte(descSigLabel), plain...), sig) {
		return nil, ErrDescriptorSignature
	}
	if len(pinned) > 0 && string(pinned) != string(pub[:]) {
		return nil, ErrDescriptorSignature
	}
	if now.Unix() >= int64(expires) {
		return nil, ErrDescriptorExpired
	}
	d := &Descriptor{
		Expires: time.Unix(int64(expires), 0),
		plain:   append([]byte(nil), plain...),
	}
	copy(d.ServerPub[:], pub[:])
	rest := plain[37:]
	if len(rest) < 1 {
		return nil, ErrFraming
	}
	n := int(rest[0])
	rest = rest[1:]
	eps := make([]DescriptorEndpoint, 0, n)
	for i := 0; i < n; i++ {
		var ep DescriptorEndpoint
		if len(rest) < 1 {
			return nil, ErrFraming
		}
		al := int(rest[0])
		rest = rest[1:]
		if len(rest) < al+2+1 {
			return nil, ErrFraming
		}
		ep.Addr = string(rest[:al])
		rest = rest[al:]
		ep.Port = binary.BigEndian.Uint16(rest[:2])
		rest = rest[2:]
		ep.Carriers = rest[0]
		rest = rest[1:]
		if len(rest) < 1 {
			return nil, ErrFraming
		}
		sl := int(rest[0])
		rest = rest[1:]
		if len(rest) < sl+1 {
			return nil, ErrFraming
		}
		ep.SNI = string(rest[:sl])
		rest = rest[sl:]
		el := int(rest[0])
		rest = rest[1:]
		if len(rest) < el+1 {
			return nil, ErrFraming
		}
		ep.ECH = append([]byte(nil), rest[:el]...)
		rest = rest[el:]
		ep.Flags = rest[0]
		rest = rest[1:]
		eps = append(eps, ep)
	}
	if len(rest) != 0 {
		return nil, ErrFraming
	}
	d.Endpoints = eps
	return d, nil
}

// CarrierNames renders the endpoint's carrier bitmap for logs.
func (e DescriptorEndpoint) CarrierNames() []string {
	var names []string
	for _, c := range []struct {
		bit  byte
		name string
	}{
		{DescCarrierVeil, "veil"}, {DescCarrierDrift, "drift"},
		{DescCarrierCDN, "cdn"}, {DescCarrierMosaic, "mosaic"},
	} {
		if e.Carriers&c.bit != 0 {
			names = append(names, c.name)
		}
	}
	return names
}

// RendezvousEpoch is the descriptor publication epoch (§10.2): 6 hours.
const RendezvousEpoch = 6 * time.Hour

// RendezvousPath returns the deterministic keyed path where the server
// publishes fresh descriptors for epoch containing at (§10.2):
// "/r/" + hex16(HMAC-SHA256(psk, "kal2-rdvs/" || epoch)). A scanner
// without the PSK cannot distinguish the path from any other 404.
func RendezvousPath(psk []byte, at time.Time) string {
	epoch := uint64(at.Unix()) / uint64(RendezvousEpoch/time.Second)
	m := hmac.New(sha256.New, psk)
	fmt.Fprintf(m, "kal2-rdvs/%d", epoch)
	sum := m.Sum(nil)
	return "/r/" + hex.EncodeToString(sum[:8])
}

// MarshalPlain encodes the descriptor body (unsigned); the signature is
// appended by SignedDescriptor.
func MarshalDescriptorPlain(expires time.Time, serverPub ed25519.PublicKey, eps []DescriptorEndpoint) ([]byte, error) {
	if len(serverPub) != 32 {
		return nil, fmt.Errorf("serverPub len %d", len(serverPub))
	}
	if len(eps) > 255 {
		return nil, fmt.Errorf("too many endpoints: %d", len(eps))
	}
	out := make([]byte, 0, 64)
	out = append(out, descVersion)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(expires.Unix()))
	out = append(out, b4[:]...)
	out = append(out, serverPub...)
	out = append(out, byte(len(eps)))
	for _, ep := range eps {
		if len(ep.Addr) > 255 || len(ep.SNI) > 255 || len(ep.ECH) > 255 {
			return nil, fmt.Errorf("endpoint field too long")
		}
		out = append(out, byte(len(ep.Addr)))
		out = append(out, ep.Addr...)
		var b2 [2]byte
		binary.BigEndian.PutUint16(b2[:], ep.Port)
		out = append(out, b2[:]...)
		out = append(out, ep.Carriers)
		out = append(out, byte(len(ep.SNI)))
		out = append(out, ep.SNI...)
		out = append(out, byte(len(ep.ECH)))
		out = append(out, ep.ECH...)
		out = append(out, ep.Flags)
	}
	return out, nil
}
