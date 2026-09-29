#!/usr/bin/env python3
"""Static regression gate for installer/windows.iss — BUG-2026-09-29-03.

The installer used to force-kill kal2-client.exe unconditionally, which killed
a live tunnel mid-drain (routes left over, orphaned wintun adapter). The fix
drains through the client's ctl socket and WAITS for the process to exit;
taskkill /F is only a fallback. This check pins that ordering so a refactor
can't silently restore the old behaviour.

Run:  python3 tool/check_installer.py            (uses installer/windows.iss)
      python3 tool/check_installer.py <path.iss>
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'installer/windows.iss'
src = open(path, encoding='utf-8').read()

m = re.search(
    r'function PrepareToInstall.*?^end;',
    src,
    flags=re.S | re.M,
)
if not m:
    sys.exit(f'{path}: PrepareToInstall not found')
body = m.group(0)

issues = []


def require(desc, needle, before=None):
    idx = body.find(needle)
    if idx < 0:
        issues.append(f'missing: {desc}')
        return None
    if before is not None and before > idx:
        issues.append(f'ordering: {desc} must come after the drain step')
    return idx


# 1. The client's ctl 'stop' is sent (graceful drain signal).
stop_idx = require("ctl 'stop' drain", "WriteLine(''stop'')")

# 2. The installer waits for kal2-client to exit before any force-kill.
wait_idx = require(
    'Wait-Process for kal2-client',
    'Wait-Process -Name kal2-client',
)

kill_f_idx = body.find('/F /IM kal2-client.exe')
if kill_f_idx < 0:
    issues.append('missing: taskkill /F fallback for kal2-client')
if wait_idx is not None and kill_f_idx >= 0 and wait_idx > kill_f_idx:
    issues.append('ordering: Wait-Process must precede taskkill /F on kal2-client')

# 3. A client still running after the fallback (e.g. a wedged elevated -tun
#    helper the non-elevated installer cannot kill) must ABORT setup rather
#    than write over a live exe and leave a mixed install.
guard_idx = body.find('Get-Process kal2-client')
if guard_idx < 0:
    issues.append('missing: still-running kal2-client guard after taskkill /F')
elif kill_f_idx >= 0 and guard_idx < kill_f_idx:
    issues.append('ordering: still-running guard must follow taskkill /F')
if 'disconnect and run setup again' not in body:
    issues.append('missing: abort message for the still-running guard')

# 4. milkyvpn.exe: graceful WM_CLOSE before the /F fallback.
grace_idx = body.find('/IM milkyvpn.exe')
force_idx = body.find('/F /IM milkyvpn.exe')
if force_idx < 0:
    issues.append('missing: taskkill /F fallback for milkyvpn.exe')
if grace_idx < 0:
    issues.append('missing: graceful taskkill (no /F) for milkyvpn.exe')
elif force_idx >= 0 and grace_idx > force_idx:
    issues.append('ordering: graceful close must precede /F for milkyvpn.exe')

if issues:
    for i in issues:
        print('FAIL', i)
    sys.exit(1)
print(f'OK {path}: PrepareToInstall drains before killing (BUG-2026-09-29-03)')
