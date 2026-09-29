package kal2

import (
	"crypto/rand"
	"encoding/binary"
)

// PadMode selects the record padding strategy applied by the session writer.
// The receiver is always strategy-agnostic (padding is self-delimiting), so
// the mode needs no negotiation and the two directions may differ.
type PadMode int

const (
	// PadBucketMode pads every record to a multiple of the session's random
	// bucket (256..1024 bytes). Cheap, but a passive observer sees a clean
	// comb of bucket multiples in the record-size histogram.
	PadBucketMode PadMode = iota

	// PadMimicMode pads each record to a size drawn from an HTTPS-bulk-like
	// distribution so wire length histograms resemble ordinary web traffic
	// rather than a fixed bucket comb.
	PadMimicMode
)

// mimicClusters approximates the application-record size histogram of an
// ordinary HTTPS download: small control exchanges, MTU-sized segments,
// mid-size objects and full 16 KiB TLS records. Each entry is {weight,
// min, max} for the *padded* record size; the trailing zero-range entry is
// the bulk fallback (pad the payload just enough, jittered).
var mimicClusters = [...]struct{ w, min, max int }{
	{10, 220, 900},    // headers, small JSON, protocol chatter
	{15, 1180, 1460},  // single MTU-sized segments
	{25, 2900, 4600},  // images, scripts, styles
	{30, 8000, 16384}, // full TLS record chunks
	{20, 0, 0},        // bulk: near-payload sizes with light jitter
}

// mimicPadTotal returns the padded record size to emit for a plaintext of
// `need` bytes (payload + pad-length trailer), sampled from mimicClusters.
// Payloads larger than a sampled class degrade to the bulk fallback — a
// mostly-unpadded record — which is how real HTTPS transfers look too.
func mimicPadTotal(need int) int {
	var rb [2]byte
	_, _ = rand.Read(rb[:])
	r := int(rb[0])<<8 | int(rb[1])
	roll := r % 100
	acc := 0
	pick := len(mimicClusters) - 1
	for i, c := range mimicClusters {
		acc += c.w
		if roll < acc {
			pick = i
			break
		}
	}
	c := mimicClusters[pick]
	target := 0
	if c.min > 0 {
		target = c.min + (r/100)%(c.max-c.min+1)
	}
	if target < need {
		target = need + MinPadBytes + r%MaxSessionPadBucket
	}
	return target
}

// PadMimic appends length-delimited random padding like PadBucket, but to a
// size drawn from the HTTPS-like distribution above. The pad trailer format
// is identical, so Unpad handles both.
func PadMimic(plaintext []byte) ([]byte, error) {
	n := mimicPadTotal(len(plaintext)+2) - len(plaintext) - 2
	if n < MinPadBytes {
		n = MinPadBytes
	}
	out := make([]byte, 0, len(plaintext)+2+n)
	out = append(out, plaintext...)
	padBytes := make([]byte, n)
	if _, err := rand.Read(padBytes); err != nil {
		return nil, err
	}
	out = append(out, padBytes...)
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(n))
	return append(out, lb[:]...), nil
}

// mimicBatchTargets are the coalesced-write budgets the session picks among
// under PadMimicMode: a varying burst size per flush gives an irregular TCP
// delivery pattern instead of a constant ~16 KiB pump.
var mimicBatchTargets = [...]int{1460, 2920, 4340, 8192, 12400, 16384}

// batchTarget is the coalesced-write budget for the next flush. Bucket mode
// keeps the fixed writeBatchBytes; mimic varies it per flush.
func (s *Session) batchTarget() int {
	if s.padMode != PadMimicMode {
		return writeBatchBytes
	}
	var b [1]byte
	_, _ = rand.Read(b[:])
	return mimicBatchTargets[int(b[0])%len(mimicBatchTargets)]
}
