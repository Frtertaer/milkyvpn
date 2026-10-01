// Server-side user provisioning and session accounting helpers.
//
// fileUsersFn backs ServerConfig.UsersFile: a JSON list of users that the
// listener re-reads whenever the file's mtime changes, so the panel (or an
// operator) can add/remove users without restarting the unit.
//
// statsWriter backs ServerConfig.StatsFile: one JSONL record per session
// open and close — the dashboard's accounting source.
package kal2core

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

type fileUser struct {
	ID  string `json:"id"`
	PSK string `json:"psk"` // hex or b64
}

// fileUsersFn returns a UsersFn provider re-reading path on mtime change.
// Returns nil when path is empty. A file that disappears or fails to parse
// yields an empty list (never nil-users panic); the last error is logged once
// per change.
func fileUsersFn(path string, logf func(string, ...any)) func() []carrier.User {
	if path == "" {
		return nil
	}
	var mu sync.Mutex
	var cached []carrier.User
	var mtime time.Time
	var size int64 = -1
	var lastErr string
	return func() []carrier.User {
		mu.Lock()
		defer mu.Unlock()
		st, err := os.Stat(path)
		if err != nil {
			if lastErr != err.Error() {
				lastErr = err.Error()
				if logf != nil {
					logf("users-file %s: %v", path, err)
				}
			}
			return append([]carrier.User{}, cached...)
		}
		if st.ModTime() == mtime && st.Size() == size {
			return append([]carrier.User{}, cached...)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			if logf != nil {
				logf("users-file read %s: %v", path, err)
			}
			return append([]carrier.User{}, cached...)
		}
		var fu []fileUser
		if err := json.Unmarshal(b, &fu); err != nil {
			if logf != nil {
				logf("users-file parse %s: %v", path, err)
			}
			mtime, size = st.ModTime(), st.Size()
			return append([]carrier.User{}, cached...)
		}
		out := make([]carrier.User, 0, len(fu))
		for _, u := range fu {
			k, err := DecodeKey(u.PSK)
			if err != nil || u.ID == "" {
				if logf != nil {
					logf("users-file %s: skip user %q: %v", path, u.ID, err)
				}
				continue
			}
			out = append(out, carrier.User{ID: u.ID, PSK: k})
		}
		cached = out
		mtime, size = st.ModTime(), st.Size()
		if logf != nil {
			logf("users-file %s: %d user(s)", path, len(out))
		}
		return append([]carrier.User{}, cached...)
	}
}

// statRec is one accounting line in the stats JSONL.
type statRec struct {
	T       int64  `json:"t"`
	Ev      string `json:"ev"` // "open" | "close"
	UID     string `json:"uid"`
	Carrier string `json:"carrier"`
	Remote  string `json:"remote,omitempty"`
	Up      uint64 `json:"up"`   // bytes client→server (close only)
	Down    uint64 `json:"down"` // bytes server→client (close only)
	DurMs   int64  `json:"dur_ms,omitempty"`
}

type statsWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func newStatsWriter(path string, logf func(string, ...any)) *statsWriter {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		if logf != nil {
			logf("stats-file %s: %v", path, err)
		}
		return nil
	}
	w := &statsWriter{path: path, f: f}
	// Boot marker: a restart means every earlier open session is gone, so the
	// panel resets its online count at the last boot line.
	w.write(statRec{T: time.Now().Unix(), Ev: "boot"})
	return w
}

func (w *statsWriter) write(r statRec) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return
	}
	b, err := json.Marshal(r)
	if err == nil {
		_, _ = w.f.Write(append(b, '\n'))
	}
}

func (w *statsWriter) open(s *kal2.Session, info carrier.SessionInfo) {
	w.write(statRec{T: time.Now().Unix(), Ev: "open", UID: info.UID, Carrier: info.Carrier, Remote: info.Remote})
	// Close accounting runs after ServeEgressCfg returns (session dead).
}

func (w *statsWriter) close(s *kal2.Session, info carrier.SessionInfo, started time.Time) {
	w.write(statRec{
		T: time.Now().Unix(), Ev: "close", UID: info.UID, Carrier: info.Carrier, Remote: info.Remote,
		Up: s.ReceivedBytes(), Down: s.SentBytes(), DurMs: time.Since(started).Milliseconds(),
	})
}

// Close flushes nothing (writes are unbuffered) but releases the file handle —
// required on Windows for callers that remove or rotate the file.
func (w *statsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
