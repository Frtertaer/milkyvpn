//go:build !darwin

package main

import "github.com/Frtertaer/milkyvpn/milky-core/internal/tun"

// Route janitor is Darwin-only: there the /32 bypass routes via the real
// gateway survive kill -9 and need a watchdog to clean them. On Linux the
// carrier bypass lives entirely on the bound socket; Windows routes through
// netsh tied to the wintun adapter.
func armRouteJanitor(b *tun.BindGuard) {}
