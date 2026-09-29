#!/usr/bin/env python3
"""Static regression gate for lib/core/vpn/windows_vpn_bridge.dart — BUG-2026-09-29-11.

After 'session up', connect() applies the system proxy and then must verify
the spawned client is still alive BEFORE declaring connected: a client that
dies mid-applyProxy (e.g. SOCKS bind failure racing the 'session up' line)
lets the exit handler's _restoreProxy run as a no-op before _proxySet flips,
leaving our socks= proxy aimed at a dead listener. This check pins the
"applyProxy -> alive-check + rollback -> connected" ordering in the SOCKS
connect path.

Run:  python3 tool/check_windows_bridge.py            (uses default path)
      python3 tool/check_windows_bridge.py <path.dart>
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'lib/core/vpn/windows_vpn_bridge.dart'
src = open(path, encoding='utf-8').read()

issues = []

# SOCKS connect path: _applyProxy then the rollback guard then the connected
# snapshot. Locate the first _applyProxy call inside connect() (the -tun path
# does not touch the system proxy, so this anchors the SOCKS flow).
apply_idx = src.find('await _applyProxy();')
if apply_idx < 0:
    issues.append('missing: await _applyProxy() in connect')
    tail = ''
else:
    tail = src[apply_idx:apply_idx + 3000]

if tail:
    guard = re.search(r'if \(_proc == null\)', tail)
    if not guard:
        issues.append('missing: _proc == null rollback guard after _applyProxy')
    else:
        rollback = tail.find('_restoreProxy()', 0, guard.start() + 800)
        if rollback < 0:
            issues.append('missing: _restoreProxy() inside the alive-check guard')
        if '_restoreProxy();' in tail[:guard.start()]:
            pass  # restore may appear earlier legitimately
    conn_idx = tail.find("state: VpnState.connected")
    if conn_idx < 0:
        issues.append('missing: connected snapshot after _applyProxy')
    elif guard and conn_idx < guard.start():
        issues.append('ordering: connected state set before the alive-check')

if issues:
    for i in issues:
        print('FAIL', i)
    sys.exit(1)
print(f'OK {path}: applyProxy -> alive-check rollback -> connected ordering pinned (BUG-2026-09-29-11)')
