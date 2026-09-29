//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Regression for BUG-2026-09-29-09: the janitor replays the bypass ledger as
// route deletions when the parent dies mid-run (kill -9), then removes it.
func TestJanitorCleanupDeletesRoutes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("route(8) needs root")
	}
	const ip = "198.51.100.99"
	if err := exec.Command("route", "-n", "add", "-host", ip, "-gateway", "10.255.255.1").Run(); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	ledger := filepath.Join(t.TempDir(), "bypass.routes")
	if err := os.WriteFile(ledger, []byte(ip+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	janitorCleanup(ledger)
	if hostRouteExists(ip) {
		t.Fatal("janitor left the /32 route behind")
	}
	if _, err := os.Stat(ledger); !os.IsNotExist(err) {
		t.Fatal("janitor left the ledger behind")
	}
}

// Missing ledger = clean exit path already ran Restore — janitor is a no-op.
func TestJanitorCleanupNoLedger(t *testing.T) {
	janitorCleanup(filepath.Join(t.TempDir(), "absent.routes"))
}

// hostRouteExists: a covering /1 answers `route get` too — only an exact
// destination match counts as a leftover bypass.
func hostRouteExists(ip string) bool {
	out, err := exec.Command("route", "-n", "get", ip).Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "destination:" && f[1] == ip {
			return true
		}
	}
	return false
}
