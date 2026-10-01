package kal2core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// TestUsersFileHotReload: a user appended to the users file authenticates on
// the next handshake without any restart, and a removed user stops
// authenticating. This is the mechanism the panel's user CRUD relies on.
func TestUsersFileHotReload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk1, psk2 := make([]byte, 32), make([]byte, 32)
	rand.Read(psk1)
	rand.Read(psk2)

	dir := t.TempDir()
	uf := filepath.Join(dir, "users.json")
	writeUF := func(entries [][2]string) {
		var out []map[string]string
		for _, e := range entries {
			out = append(out, map[string]string{"id": e[0], "psk": e[1]})
		}
		b, _ := json.Marshal(out)
		if err := os.WriteFile(uf, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeUF(nil)

	v := carrier.NewVeilListener(carrier.VeilConfig{
		Domain:   "kal.test",
		Cert:     tspuSelfSigned(t, "kal.test"),
		Identity: priv,
		UsersFn:  fileUsersFn(uf, func(f string, a ...any) { t.Logf(f, a...) }),
		OnSession: func(s *kal2.Session, _ carrier.SessionInfo) {
			go func() {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					_ = st.Close()
				}
			}()
		},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = v.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()

	dial := func(psk []byte) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, err := carrier.DialVeil(ctx, carrier.ClientConfig{
			Addr:               addr,
			SNI:                "kal.test",
			ServerPub:          pub,
			PSK:                psk,
			InsecureSkipVerify: true,
		})
		return err
	}

	// Unknown PSK must not authenticate while the file is empty.
	if err := dial(psk1); err == nil {
		t.Fatal("empty users file accepted a client")
	}
	// Add u1 → the very next handshake succeeds (mtime-based reload).
	writeUF([][2]string{{"u1", hex.EncodeToString(psk1)}})
	if err := dial(psk1); err != nil {
		t.Fatalf("hot-added user could not authenticate: %v", err)
	}
	// Swap u1 for u2 — u1 is now rejected, u2 accepted.
	writeUF([][2]string{{"u2", hex.EncodeToString(psk2)}})
	if err := dial(psk1); err == nil {
		t.Fatal("removed user still authenticates")
	}
	if err := dial(psk2); err != nil {
		t.Fatalf("u2 could not authenticate: %v", err)
	}
}

// TestStatsFileRecords: open/close lines with uid, carrier and byte counters
// land in the stats file — what /api/stats aggregates.
func TestStatsFileRecords(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)

	dir := t.TempDir()
	sf := filepath.Join(dir, "stats.jsonl")

	// Same wiring as Serve() applies: stats writer around OnSession.
	logf := func(f string, a ...any) { t.Logf(f, a...) }
	stats := newStatsWriter(sf, logf)
	if stats == nil {
		t.Fatal("stats writer nil")
	}
	infos := make(chan carrier.SessionInfo, 1)
	done := make(chan struct{}, 1)
	v := carrier.NewVeilListener(carrier.VeilConfig{
		Domain:   "kal.test",
		Cert:     tspuSelfSigned(t, "kal.test"),
		Identity: priv,
		Users:    []carrier.User{{ID: "u-stats", PSK: psk}},
		OnSession: func(s *kal2.Session, info carrier.SessionInfo) {
			infos <- info
			stats.open(s, info)
			go func() {
				for {
					st, err := s.Accept()
					if err != nil {
						break
					}
					_ = st.Close()
				}
				<-s.WaitClosed()
				stats.close(s, info, time.Now())
				done <- struct{}{}
			}()
		},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = v.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, _, err := carrier.DialVeil(ctx, carrier.ClientConfig{
		Addr:               ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          pub,
		PSK:                psk,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var gotInfo carrier.SessionInfo
	select {
	case gotInfo = <-infos:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession never fired")
	}
	if gotInfo.UID != "u-stats" || gotInfo.Carrier != "veil" {
		t.Fatalf("SessionInfo = %+v", gotInfo)
	}
	_ = sess.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session never closed server-side")
	}
	if err := stats.Close(); err != nil {
		t.Fatal(err)
	}

	var evs []map[string]any
	if b, err := os.ReadFile(sf); err == nil {
		for _, line := range splitLines(string(b)) {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				evs = append(evs, m)
			}
		}
	}
	var haveOpen, haveClose bool
	for _, e := range evs {
		if e["ev"] == "open" && e["uid"] == "u-stats" && e["carrier"] == "veil" {
			haveOpen = true
		}
		if e["ev"] == "close" && e["uid"] == "u-stats" {
			haveClose = true
			if _, ok := e["up"]; !ok {
				t.Fatal("close rec missing byte counters")
			}
		}
	}
	if !haveOpen || !haveClose {
		t.Fatalf("stats file missing open/close records: %v", evs)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
