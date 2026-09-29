package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenLogFileCreatesParentDirsAndBanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "sub", "kal2-client.log")
	f, err := openLogFile(path, 1<<20)
	if err != nil {
		t.Fatalf("openLogFile: %v", err)
	}
	f.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(b), "kal2-client started") {
		t.Fatalf("missing start banner in %q", b)
	}
}

// Regression BUG-2026-09-29-02: field diagnostics must survive long soaks —
// an oversized log rolls to .1 instead of growing forever.
func TestOpenLogFileRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kal2-client.log")
	old := strings.Repeat("x", 2048)
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openLogFile(path, 1024)
	if err != nil {
		t.Fatalf("openLogFile: %v", err)
	}
	f.WriteString("fresh line\n")
	f.Close()

	rot, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("rotated file: %v", err)
	}
	if string(rot) != old {
		t.Fatalf("rotation lost %d bytes", len(old)-len(rot))
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cur), "fresh line") {
		t.Fatal("new writes went to the rotated file")
	}
}

// Regression: a spawned (elevated) client is driven entirely through ctl —
// logs written before the peer connects are mirrored on connect, and 'stop'
// unblocks the runner.
func TestCtlMirrorAndStop(t *testing.T) {
	ctl, err := startCtl("127.0.0.1:0")
	if err != nil {
		t.Fatalf("startCtl: %v", err)
	}
	defer ctl.close()
	if _, err := ctl.Write([]byte("boot line\n")); err != nil {
		t.Fatalf("pre-connect write: %v", err)
	}

	port := ctl.ln.Addr().(*net.TCPAddr).Port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial ctl: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read mirrored line: %v", err)
	}
	if strings.TrimSpace(line) != "boot line" {
		t.Fatalf("mirrored %q, want boot line", line)
	}

	if _, err := fmt.Fprintln(conn, "stop"); err != nil {
		t.Fatalf("send stop: %v", err)
	}
	select {
	case <-ctl.stopCh:
	case <-time.After(2 * time.Second):
		t.Fatal("stop command never released the runner")
	}
}

// Regression BUG-2026-09-29-08: a stale conn must not consume the only
// accept. An app-side ctl conn that died without 'stop' used to leave the
// elevated helper unreachable — every later conn sat in the backlog unread,
// so its 'stop' never fired and a respawn died on address-in-use.
func TestCtlSecondPeerCanStop(t *testing.T) {
	ctl, err := startCtl("127.0.0.1:0")
	if err != nil {
		t.Fatalf("startCtl: %v", err)
	}
	defer ctl.close()
	port := ctl.ln.Addr().(*net.TCPAddr).Port
	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("dial ctl: %v", err)
		}
		return c
	}

	stale := dial()
	stale.Close() // the dead app-side conn — no 'stop' sent
	time.Sleep(100 * time.Millisecond)

	live := dial()
	defer live.Close()
	if _, err := fmt.Fprintln(live, "stop"); err != nil {
		t.Fatalf("send stop: %v", err)
	}
	select {
	case <-ctl.stopCh:
	case <-time.After(2 * time.Second):
		t.Fatal("stop on a second conn never reached the runner")
	}
}
