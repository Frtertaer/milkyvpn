# BUGS — emulator-matrix findings

Track: Android emulator matrix (API 26/29/31/34/35), `testing/` stand on
`devin/1790629023-testing-stand`. Status: **FIXED** (fix + regression test in
this change set), **OPEN**, **DOC** (documented limitation).

## BUG-1 — net_loss / dns_flip: tunnel never recovered within 90s — FIXED

- Symptom: `svc wifi disable && svc data disable` for 15s → restore → no
  CONNECTED within 90s; private-DNS flip behaved the same.
- Root cause, two layers:
  1. **Go core**: `kal2.Session` had no liveness detection. A blackholed
     carrier (packets dropped, no RST — exactly what `svc` network kill and
     many real mobile handoffs produce) keeps `WaitClosed()` silent forever:
     the read loop blocks on a socket that never errors and writes just back
     up. `EnableReconnect` therefore never redialed.
  2. **Android**: `registerNetworkCallback.onLost` ran a single reverify
     probe, then `teardownLocked()` + terminal `ERROR`. No reconnect loop.
- Fix:
  - `kal2.Session.Kill(err)` — fails streams and closes the carrier (a plain
    `Close` leaves stream readers hanging on undrained queues).
  - `kal2core.Client.EnableLiveness(every, pongTimeout, misses)` — watchdog
    that pings the live session (Ping runs in a goroutine under an outer
    deadline so a wedged outbound queue counts as a miss, not a hang) and
    `Kill`s after N misses → the existing reconnect loop redials. Wired in
    `kal2mobile` with 4s/4s/2.
  - `Client.pingMu` serializes Ping callers — the session routes each PONG to
    a single registered channel, so concurrent pings (cover + liveness) used
    to clobber each other.
  - `MilkyVpnService`: `wantsConnected` + `tunnelSupervisor` — probes the
    tunnel with a real fetch every ~10s while connected; failures flip to
    CONNECTING, ~90s of failure escalates to a fresh full connect (≤3, linear
    backoff), then honest `ERROR`. Recoverable connect() failures also retry
    the same way.
- Regression test: `milky-core/pkg/kal2core/api_test.go:
  TestLivenessRedialsBlackhole` (blackholes the carrier socket, expects kill
  + redial + working ping). CI scenarios `net_loss`, `wifi_lte`, `dns_change`.

## BUG-2 — fgs_doze: `:kal2` process dropped out of foreground under doze — FIXED

- Symptom: `dumpsys deviceidle force-idle` → `dumpsys activity processes`
  showed `:kal2` no longer in `fg` state.
- Root cause: `Kal2Service` was a bound-only service; binder importance
  (BIND_IMPORTANT from a foreground client) does not survive device idle —
  the system demotes bound secondary processes, freezing the SOCKS listener
  (TCP accepts at kernel level, no thread to accept() → wedged outbound).
- Fix: `Kal2Service` promotes itself to a real foreground service while a
  session is live (`startForeground`, `specialUse` type on API 34+,
  `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` in the manifest), demoted on `stop()`.
- Regression: CI scenarios `fgs_doze`, `battery_opt`.

## BUG-3 — verify_tunnel accepted an empty reply — FIXED (test-stand)

- The SOCKS probe `curl --socks5-hostname … ifconfig.me/ip` returning empty
  was counted as pass — "real traffic through tunnel" was never asserted.
- Fix: strict non-empty + `verify_tunnel_wait` polling window.

## BUG-4 — wait_state matched stale logcat lines — FIXED (test-stand)

- `wait_state CONNECTED` grepped the whole `logcat -d` buffer — a CONNECTED
  line written by an earlier scenario matched instantly after a disruption.
- Fix: `clear_log` before each disruptive wait; pattern requires a leading
  space (`' CONNECTED'`) so `DISCONNECTED` can never match.

## BUG-5 — `adb install` raced emulator boot — FIXED (test-stand)

- `run_emu_ci.sh` installed immediately while adbd was up but the system was
  half-booted → install failures. Now waits for `sys.boot_completed` + `pm`.

## BUG-6 — connect had no retry for the transient first-connect EOF — FIXED

- `server flight: unexpected EOF` on the first connect after a server restart
  was a hard fail (observed CI-wide). The scenario now retries the connect
  once, and the app itself retries recoverable connect failures (≤3, 2/4/6s
  backoff) — both belts live behind the error vocabulary.

## BUG-7 — missing scenario coverage — FIXED (test-stand)

- Added `on_revoke` (`appops set PKG ACTIVATE_VPN deny` → expects `onRevoke`
  log + teardown + dead tunnel; restores `allow`). On API <29 the op does not
  exist — the scenario logs `SKIP` and reports pass-with-note.
- Added `battery_opt` (deviceidle whitelist + forced doze → tunnel must live).
- All scenarios now gate the CI job (previously everything after `connect`
  was `|| true` best-effort).

## OPEN / documented limitations

- **API 29 uiautomator empty-tree flake** (run 36515454841): Flutter renders,
  no crash, but `uiautomator dump` returned no nodes for 90s. Mitigations in
  this change: `ui_ready` gate before onboarding, longer `ui_tap_desc_wait`,
  empty-dump diagnostics (window focus dump). If it still fires, the run log
  now distinguishes "empty tree" from "wrong screen".
- **`on_revoke` on API 26**: `ACTIVATE_VPN` appop doesn't exist there — SKIP.
- **`dns_leak`** remains partially observational: it asserts the VPN link
  carries the tunnel resolvers (1.1.1.1/8.8.8.8) and that resolution through
  the tunnel works; the raw `dumpsys connectivity` snapshot is also logged
  into ci-artifacts for manual review.
- **`tls_cutoff`** stays skipped in CI (needs a `-http-proxy` emulator plus a
  host-side cutproxy); runnable manually via `--proxy`.
- **`soak30`** stays out of CI (30 min vs the 45-min job budget); runnable
  manually.
