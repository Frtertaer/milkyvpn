package carrier

import (
	"io"
	"net"
	"time"
)

// ServeRelay transparently splices every accepted TCP connection to upstream.
// Deployed on a domestic (RU) relay host: clients speak veil/drift TLS+KAL to
// the egress host while the relay just moves bytes, so border DPI sees a
// domestic flow. The relay learns nothing — traffic stays end-to-end
// encrypted between client and egress.
func ServeRelay(ln net.Listener, upstream string) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			up, err := net.DialTimeout("tcp", upstream, 10*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			errCh := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(up, c); errCh <- struct{}{} }()
			go func() { _, _ = io.Copy(c, up); errCh <- struct{}{} }()
			<-errCh
		}()
	}
}
