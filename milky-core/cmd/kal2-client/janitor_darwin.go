//go:build darwin

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/tun"
)

// Route janitor — Darwin only. The /1 split-default routes die with the utun
// device, but the /32 bypass routes via the real gateway (required by
// IP_BOUND_IF) are ordinary FIB entries that survive kill -9. This child
// process watches its parent PID and replays the route ledger as deletions
// once the parent is gone, so an ungraceful death still reverts cleanly.
//
// Invocation: kal2-client -route-janitor <ledger-file>
// The parent appends one IP per line as it installs bypasses, and removes the
// file on clean shutdown (janitor exits without touching routes then).

// armRouteJanitor points the bind guard at the ledger file and spawns the
// janitor child. Called once -tun is requested on Darwin.
func armRouteJanitor(b *tun.BindGuard) {
	ledger := janitorLedgerPath()
	b.SetLedger(ledger)
	janitorSpawn(ledger)
}

func janitorSpawn(ledger string) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("kal2: route janitor spawn: %v", err)
		return
	}
	cmd := exec.Command(exe, "-route-janitor", ledger)
	// Detach the process group so terminal signals (Ctrl+C) don't kill the
	// janitor before it can clean up after a parent's kill -9.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		log.Printf("kal2: route janitor spawn: %v", err)
		return
	}
	_ = cmd.Process.Release()
}

func runRouteJanitor(ledger string) {
	ppid := os.Getppid()
	deadline := time.Now().Add(24 * time.Hour)
	for time.Now().Before(deadline) {
		if parentDead(ppid) {
			janitorCleanup(ledger)
			return
		}
		// Clean exit path removed the ledger — nothing to do.
		if _, err := os.Stat(ledger); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// parentDead reports the client is gone: reparented to launchd or PID freed.
func parentDead(ppid int) bool {
	if os.Getppid() == 1 {
		return true
	}
	return syscall.Kill(ppid, 0) == syscall.ESRCH
}

// janitorCleanup replays the ledger as route deletions.
func janitorCleanup(ledger string) {
	f, err := os.Open(ledger)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ip := strings.TrimSpace(sc.Text())
		if ip == "" {
			continue
		}
		_ = exec.Command("route", "-n", "delete", "-host", ip).Run()
	}
	f.Close()
	_ = os.Remove(ledger)
}

func janitorLedgerPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("kal2-bypass-%d.routes", os.Getpid()))
}
