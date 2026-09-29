package kal2

import (
	"testing"
)

func TestPadMimicRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, 500, 1460, 4096, 16000, 65536} {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i)
		}
		padded, err := PadMimic(p)
		if err != nil {
			t.Fatalf("PadMimic(%d): %v", n, err)
		}
		if len(padded) < n+2+MinPadBytes {
			t.Fatalf("PadMimic(%d): padded %d < minimum %d", n, len(padded), n+2+MinPadBytes)
		}
		got, err := Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad(PadMimic(%d)): %v", n, err)
		}
		if len(got) != n {
			t.Fatalf("round trip: got %d want %d", len(got), n)
		}
		for i := range p {
			if got[i] != p[i] {
				t.Fatalf("round trip byte %d mismatch", i)
			}
		}
	}
}

// TestMimicHistogramIsNotAComb verifies the padded sizes are spread across
// the web-like distribution instead of landing on one bucket's multiples —
// the property that distinguishes PadMimic from PadBucket on the wire.
func TestMimicHistogramIsNotAComb(t *testing.T) {
	const trials = 4000
	counts := map[int]int{}
	bucketCombs := 0
	for i := 0; i < trials; i++ {
		padded, err := PadMimic(make([]byte, 8))
		if err != nil {
			t.Fatal(err)
		}
		counts[len(padded)]++
		if len(padded)%PadBucketSize == 0 {
			bucketCombs++
		}
	}
	// A bucket strategy puts ~every record on a 256-multiple; mimic should
	// land there only by chance (~1/256 of sizes).
	if frac := float64(bucketCombs) / trials; frac > 0.1 {
		t.Fatalf("%.1f%% of padded sizes are 256-multiples — comb-shaped", frac*100)
	}
	// And the histogram must actually spread over many distinct sizes.
	if len(counts) < 1000 {
		t.Fatalf("histogram too narrow: %d distinct sizes", len(counts))
	}
	// Every cluster should get some mass (weights are all >= 10%).
	small, mid, big := 0, 0, 0
	for sz, c := range counts {
		switch {
		case sz < 1200:
			small += c
		case sz < 8000:
			mid += c
		default:
			big += c
		}
	}
	if small == 0 || mid == 0 || big == 0 {
		t.Fatalf("degenerate distribution: small=%d mid=%d big=%d", small, mid, big)
	}
}
