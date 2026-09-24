package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// ServeEgress accepts KAL streams and proxies each to its requested target
// (server-side exit path). Runs until the session ends.
func ServeEgress(sess *kal2.Session, dialer *net.Dialer, logf func(string, ...any)) error {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 15 * time.Second}
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer st.Close()
			network, host, port, err := st.Target()
			if err != nil {
				logf("egress: bad target: %v", err)
				return
			}
			target := net.JoinHostPort(host, fmt.Sprint(int(port)))
			up, err := dialer.Dial(network, target)
			if err != nil {
				logf("egress: dial %s: %v", target, err)
				_ = st.Ack(0x05)
				return
			}
			if err := st.Ack(0x00); err != nil {
				up.Close()
				return
			}
			defer up.Close()
			errCh := make(chan struct{}, 2)
			go func() { _, _ = io.CopyBuffer(up, st, make([]byte, 1<<16)); errCh <- struct{}{} }()
			go func() { _, _ = io.CopyBuffer(st, up, make([]byte, 1<<16)); errCh <- struct{}{} }()
			<-errCh
		}()
	}
}

// OpenStream is a convenience for clients: open a stream to host:port.
func OpenStream(sess *kal2.Session, host string, port uint16, timeout time.Duration) (*kal2.Stream, error) {
	if sess == nil {
		return nil, fmt.Errorf("nil session")
	}
	return sess.Open(host, port, timeout)
}

// PingSession sends a liveness ping and waits for the pong.
func PingSession(ctx context.Context, sess *kal2.Session) error {
	done := make(chan error, 1)
	go func() { done <- sess.Ping([]byte("ping"), 10*time.Second) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
