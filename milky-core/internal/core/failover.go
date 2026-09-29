package core

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Scorecard tracks per-carrier online health for failover ordering.
// Metrics follow DESIGN.md's health model:
//
//	ingress — handshake success rate + dial TTFB (EWMA)
//	tunnel  — session ping RTT (EWMA), migrations, deaths
//	dns     — endpoint resolution health (KAL/2 dials IP literals, so DNS
//	          never gates the tunnel path; recorded for subscription fetches)
//	egress  — post-session probe: open-stream RTT through the live session
//
// Scores decay on consecutive failures and carriers quarantine briefly after
// repeated transport deaths, so the hedged dialer prefers healthy carriers
// while still racing every candidate.
type Scorecard struct {
	mu     sync.Mutex
	per    map[string]*carrierScore
	death  map[string]int
	migOK  int
	migBad int
}

type carrierScore struct {
	attempts  int
	success   int
	fails     int // consecutive failures
	ttfb      float64
	ping      float64
	egress    float64
	dnsBad    int
	lastOK    time.Time
	deadUntil time.Time
}

func NewScorecard() *Scorecard {
	return &Scorecard{per: map[string]*carrierScore{}, death: map[string]int{}}
}

const (
	ewmaAlpha      = 0.35
	quarantineStep = 20 * time.Second
	quarantineMax  = 2 * time.Minute
)

func (s *Scorecard) score(name string) *carrierScore {
	cs, ok := s.per[name]
	if !ok {
		cs = &carrierScore{ttfb: 0.8, ping: 0.3, egress: 0.3}
		s.per[name] = cs
	}
	return cs
}

// ReportDial records carrier dial outcome + latency in seconds.
func (s *Scorecard) ReportDial(name string, ok bool, secs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs := s.score(name)
	cs.attempts++
	if ok {
		cs.success++
		cs.fails = 0
		cs.lastOK = time.Now()
		cs.ttfb = ewma(cs.ttfb, secs)
		return
	}
	cs.fails++
	if cs.fails >= 3 {
		q := time.Duration(cs.fails-2) * quarantineStep
		if q > quarantineMax {
			q = quarantineMax
		}
		cs.deadUntil = time.Now().Add(q)
	}
}

// ReportPing records a session ping RTT in seconds.
func (s *Scorecard) ReportPing(name string, secs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.score(name).ping = ewma(s.score(name).ping, secs)
}

// ReportEgress records an open-stream-through-session RTT probe.
func (s *Scorecard) ReportEgress(name string, ok bool, secs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs := s.score(name)
	if ok {
		cs.egress = ewma(cs.egress, secs)
	} else {
		cs.egress = math.Min(cs.egress*1.5, 10)
	}
}

// ReportDNS records a failed name resolution touching the control plane.
func (s *Scorecard) ReportDNS(name string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		s.score(name).dnsBad++
	}
}

// ReportDeath notes a session transport death on the carrier.
func (s *Scorecard) ReportDeath(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.death[name]++
}

// ReportMigrate counts resumption outcomes (session migrations).
func (s *Scorecard) ReportMigrate(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.migOK++
	} else {
		s.migBad++
	}
}

// Score returns 0..1: reliability weighted by latency shape. Zero means
// quarantined or never succeeded.
func (s *Scorecard) score1(cs *carrierScore) float64 {
	if time.Now().Before(cs.deadUntil) {
		return 0
	}
	reliability := 0.6 // prior
	if cs.attempts > 0 {
		reliability = float64(cs.success) / float64(cs.attempts)
	}
	lat := cs.ttfb + cs.ping + cs.egress
	latScore := 1.0 / (1.0 + lat)
	fails := math.Pow(0.7, float64(cs.fails))
	return reliability * latScore * fails
}

// Order sorts candidates best-first by current score; quarantined carriers
// sink to the bottom (still present — hedged dials may still try them).
func (s *Scorecard) Order(candidates []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), candidates...)
	sort.SliceStable(out, func(i, j int) bool {
		return s.score1(s.score(out[i])) > s.score1(s.score(out[j]))
	})
	return out
}

// Snapshot is a readable per-carrier summary for status reporting.
type Snapshot struct {
	Carrier   string
	Score     float64
	Attempts  int
	Successes int
	Fails     int
	TTFBms    int
	PingMs    int
	EgressMs  int
	Deaths    int
	Dead      bool
}

// Report returns per-carrier snapshots plus migration counters.
func (s *Scorecard) Report() (snaps []Snapshot, migOK, migBad int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, cs := range s.per {
		snaps = append(snaps, Snapshot{
			Carrier:   name,
			Score:     s.score1(cs),
			Attempts:  cs.attempts,
			Successes: cs.success,
			Fails:     cs.fails,
			TTFBms:    int(cs.ttfb * 1000),
			PingMs:    int(cs.ping * 1000),
			EgressMs:  int(cs.egress * 1000),
			Deaths:    s.death[name],
			Dead:      time.Now().Before(cs.deadUntil),
		})
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Carrier < snaps[j].Carrier })
	return snaps, s.migOK, s.migBad
}

func ewma(old, x float64) float64 {
	if old == 0 {
		return x
	}
	return old + ewmaAlpha*(x-old)
}
