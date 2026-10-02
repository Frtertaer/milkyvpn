package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Drop-ins override the main unit's ExecStart — the panel must read the
// effective (last non-empty) line or it pins stale flags/binary.
func TestParseExecStart(t *testing.T) {
	for _, tc := range []struct {
		name string
		cat  string
		want []string
	}{
		{
			"main only",
			"# /etc/systemd/system/kal2.service\n[Service]\nExecStart=/opt/kal2/srv -listen :1\n",
			[]string{"/opt/kal2/srv", "-listen", ":1"},
		},
		{
			"drop-in resets and overrides",
			"# /etc/systemd/system/kal2.service\n[Service]\nExecStart=/opt/kal2/v5 -x\n\n# /etc/systemd/system/kal2.service.d/90-rtc.conf\n[Service]\nExecStart=\nExecStart=/opt/kal2/v7 -rtc :2\n",
			[]string{"/opt/kal2/v7", "-rtc", ":2"},
		},
		{
			"later drop-in wins over earlier drop-in",
			"ExecStart=/a -old\nExecStart=\nExecStart=/b -mid\nExecStart=/c -new\n",
			[]string{"/c", "-new"},
		},
		{
			"blank reset alone yields nil",
			"ExecStart=/a -old\nExecStart=\n",
			nil,
		},
		{
			"no ExecStart",
			"[Service]\nEnvironment=X=1\n",
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseExecStart(tc.cat); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// Quota/expiry gate: disabled, expired, and over-quota users must not land in
// the users-file; 0 means unlimited on both knobs.
func TestUserActive(t *testing.T) {
	now := time.Now().Unix()
	gb := int64(1 << 30)
	for _, tc := range []struct {
		name  string
		u     panelUser
		month uint64
		want  bool
	}{
		{"plain enabled", panelUser{ID: "a"}, 0, true},
		{"admin disabled", panelUser{ID: "a", Disabled: true}, 0, false},
		{"expired", panelUser{ID: "a", ExpiresAt: now - 1}, 0, false},
		{"expires future", panelUser{ID: "a", ExpiresAt: now + 3600}, 0, true},
		{"under quota", panelUser{ID: "a", QuotaMB: 1024}, uint64(gb) - 1, true},
		{"at quota", panelUser{ID: "a", QuotaMB: 1024}, uint64(gb), false},
		{"over quota", panelUser{ID: "a", QuotaMB: 1024}, uint64(gb) * 2, false},
		{"unlimited ignores usage", panelUser{ID: "a", QuotaMB: 0}, uint64(gb) * 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.u.active(tc.month, now); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// Month aggregation: close records before the 1st of the month don't count
// toward quota; boot resets online counts.
func TestParseStatsMonth(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "stats.jsonl")
	monthStart := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.Local).Unix()
	old := monthStart - 3600
	data := `{"t":%d,"ev":"boot"}
{"t":%d,"ev":"open","uid":"a"}
{"t":%d,"ev":"close","uid":"a","up":10,"down":20}
{"t":%d,"ev":"open","uid":"a"}
{"t":%d,"ev":"close","uid":"a","up":100,"down":200}
`
	if err := os.WriteFile(f, []byte(
		fmt.Sprintf(data, monthStart, old, old, monthStart+60, monthStart+60)), 0600); err != nil {
		t.Fatal(err)
	}
	per, boot := parseStats(f)
	if boot != monthStart {
		t.Fatalf("boot=%d want %d", boot, monthStart)
	}
	a := per["a"]
	if a == nil {
		t.Fatal("no agg for a")
	}
	if a.Up != 110 || a.Down != 220 {
		t.Fatalf("totals up=%d down=%d want 110/220", a.Up, a.Down)
	}
	if a.Month != 300 {
		t.Fatalf("month=%d want 300 (only this-month close counts)", a.Month)
	}
}

// Canary reader: newest record per entry+carrier wins.
func TestCanaryLatest(t *testing.T) {
	f := filepath.Join(t.TempDir(), "canary.jsonl")
	data := `{"ts":"2026-10-01T08:00:00Z","entry":"us:443","carrier":"veil","ok":true,"ms":120}
{"ts":"2026-10-01T08:00:01Z","entry":"us:443","carrier":"veil","ok":false,"ms":0}
{"ts":"2026-10-01T08:00:02Z","entry":"cf","carrier":"mosaic","ok":true,"ms":300}
`
	if err := os.WriteFile(f, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got := canaryLatest(f)
	if len(got) != 2 {
		t.Fatalf("got %d recs want 2", len(got))
	}
	if got[0].Carrier != "mosaic" || !got[0].OK {
		t.Fatalf("newest-first: got %+v", got[0])
	}
	if got[1].Carrier != "veil" || got[1].OK {
		t.Fatalf("latest veil rec should be the fail: %+v", got[1])
	}
}

// Dead-SNI watchdog: >=3 consecutive failed direct probes marks a cover
// name dead; a passing probe resets its streak; fronted rows carry no sni
// and are ignored.
func TestDeadSNIs(t *testing.T) {
	f := filepath.Join(t.TempDir(), "canary.jsonl")
	data := `{"entry":"us:443","carrier":"veil","sni":"gone.example","ok":false}
{"entry":"us:443","carrier":"veil","sni":"gone.example","ok":false}
{"entry":"us:443","carrier":"veil","sni":"gone.example","ok":false}
{"entry":"us:443","carrier":"veil","sni":"alive.example","ok":true}
{"entry":"cf","carrier":"mosaic","front":"https://w.dev","ok":false}
{"entry":"flap","carrier":"veil","sni":"flap.example","ok":false}
{"entry":"flap","carrier":"veil","sni":"flap.example","ok":true}
{"entry":"flap","carrier":"veil","sni":"flap.example","ok":false}
{"entry":"flap","carrier":"veil","sni":"flap.example","ok":false}
`
	if err := os.WriteFile(f, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	dead := deadSNIs(f)
	if !dead["gone.example"] {
		t.Fatal("3-streak dead SNI not flagged")
	}
	if dead["alive.example"] || dead["flap.example"] {
		t.Fatalf("false positives: %+v", dead)
	}
	if _, err := os.Stat(f); err == nil && deadSNIs("/nonexistent") != nil {
		t.Fatal("missing file must yield nil, not an empty-but-falsey map")
	}
}

// dropDeadSNIs prunes dead members of an sni= comma list; an all-dead list
// or a single-SNI link comes back unchanged (never bricks).
func TestDropDeadSNIs(t *testing.T) {
	link := "kal2://psk@h:443?sni=good.example,dead.example,also.good&pub=x"
	dead := map[string]bool{"dead.example": true}
	got := dropDeadSNIs(link, dead)
	if !strings.Contains(got, "sni=good.example%2Calso.good") &&
		!strings.Contains(got, "sni=good.example,also.good") {
		t.Fatalf("dead SNI not pruned: %s", got)
	}
	if strings.Contains(got, "dead.example") {
		t.Fatalf("dead SNI survived: %s", got)
	}
	allDead := map[string]bool{"good.example": true, "dead.example": true, "also.good": true}
	if got2 := dropDeadSNIs(link, allDead); got2 != link {
		t.Fatalf("all-dead pool must pass through unchanged: %s", got2)
	}
	single := "kal2://psk@h:443?sni=only.example"
	if got3 := dropDeadSNIs(single, map[string]bool{"only.example": true}); got3 != single {
		t.Fatalf("single-SNI link rewritten: %s", got3)
	}
}
