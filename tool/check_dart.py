#!/usr/bin/env python3
"""Mechanical consistency checker for the MilkyVPN Dart sources.

This is NOT `flutter analyze` (the Flutter SDK cannot be downloaded in this sandbox).
It is a real pass over the actual source files that catches the classes of mistakes a
hand-written UI refactor produces:

  1. unbalanced (), [], {} (string / comment aware)
  2. relative imports that do not resolve to a file on disk
  3. imports whose exported identifiers are never referenced (unused_import)
  4. `t.<member>` accesses that do not exist on the S localization class
  5. references to `Milky*` / `S` types that are neither defined nor imported
  6. local variables that are assigned but never read (unused_local_variable)
  7. widget constructor invocations missing a `key` where the class requires none - n/a
"""
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else 'lib'
issues = []


def _blank_non_interp(inner: str) -> str:
    """Blank string content but keep ${...} / $ident so identifier usage still counts."""
    res = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == '$' and i + 1 < n and (inner[i + 1] == '{' or inner[i + 1].isalpha() or inner[i + 1] == '_'):
            if inner[i + 1] == '{':
                depth = 0
                j = i + 1
                while j < n:
                    if inner[j] == '{':
                        depth += 1
                    elif inner[j] == '}':
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                res.append(inner[i + 2:j - 1])  # keep interpolation verbatim
                i = j
            else:
                m = re.match(r'\$[A-Za-z_$][\w$]*', inner[i:])
                res.append(m.group(0))
                i += len(m.group(0))
        else:
            res.append(ch if ch == '\n' else ' ')
            i += 1
    return ''.join(res)


def strip_code(src: str, keep_interp: bool = False) -> str:
    """Blank comments and string contents, keeping byte offsets (and line numbers) intact."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif c == '/' and nxt == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', src[i:j]))
            i = j
        elif c == "'" or c == '"':
            q = c
            triple = src[i:i + 3] == q * 3
            delim = q * 3 if triple else q
            j = i + len(delim)
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src.startswith(delim, j):
                    j += len(delim)
                    break
                j += 1
            inner = src[i + len(delim):max(i + len(delim), j - len(delim))]
            if keep_interp:
                inner = _blank_non_interp(inner)
            else:
                inner = re.sub(r'[^\n]', ' ', inner)
            out.append(delim[0] + inner + delim[0])
            i = j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def line_of(src: str, pos: int) -> int:
    return src.count('\n', 0, pos) + 1


files = []
for dirpath, _dirnames, filenames in os.walk(ROOT):
    for f in filenames:
        if f.endswith('.dart'):
            files.append(os.path.join(dirpath, f))
files.sort()

# ---- pass 1: structure + imports -------------------------------------------------
file_src = {}
file_clean = {}
file_defs = {}
file_ids = {}
for path in files:
    src = open(path, encoding='utf-8').read()
    clean = strip_code(src)
    file_src[path] = src
    file_clean[path] = clean
    file_ids[path] = strip_code(src, keep_interp=True)

    # bracket balance
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    for idx, ch in enumerate(clean):
        if ch in '([{':
            stack.append((ch, idx))
        elif ch in ')]}':
            if not stack or stack[-1][0] != pairs[ch]:
                issues.append(f'{path}:{line_of(src, idx)}: unbalanced "{ch}"')
                stack = []
                break
            stack.pop()
    else:
        for ch, idx in stack:
            issues.append(f'{path}:{line_of(src, idx)}: unclosed "{ch}"')

    # definitions (classes / enums / mixins / typedefs / top-level functions / consts)
    defs = set(re.findall(r'^\s*(?:abstract\s+|final\s+|sealed\s+|base\s+|interface\s+)*(?:class|enum|mixin|extension|typedef)\s+([A-Za-z_$][\w$]*)', clean, re.M))
    defs |= set(re.findall(r'^\s*(?:const|final)\s+([A-Za-z_$][\w$]*)\s*=', clean, re.M))
    defs |= set(re.findall(r'^\s*[A-Za-z_$][\w$<>,\?\s]*\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?:async\s*)?\{', clean, re.M))
    file_defs[path] = defs

# ---- pass 2: imports -------------------------------------------------------------
for path in files:
    src = file_src[path]
    clean = file_clean[path]
    body = re.sub(r'^\s*import .*$', '', file_ids[path], flags=re.M)
    for m in re.finditer(r"^\s*import\s+'([^']+)'(?:\s+as\s+(\w+))?(?:\s+show\s+([^;]+))?", src, re.M):
        uri, alias, show = m.group(1), m.group(2), m.group(3)
        if uri.startswith('package:') or uri.startswith('dart:'):
            continue
        target = os.path.normpath(os.path.join(os.path.dirname(path), uri))
        if not os.path.exists(target):
            issues.append(f'{path}:{line_of(src, m.start())}: import does not resolve: {uri}')
            continue
        if alias:
            if not re.search(r'\b%s\.' % re.escape(alias), body):
                issues.append(f'{path}:{line_of(src, m.start())}: unused import alias "{alias}" ({uri})')
            continue
        if show:
            names = [n.strip().split(' as ')[0].strip() for n in show.split(',')]
        else:
            names = sorted(file_defs.get(target, set()))
        used = any(re.search(r'\b%s\b' % re.escape(n), body) for n in names) if names else True
        if names and not used:
            issues.append(f'{path}:{line_of(src, m.start())}: unused import {uri}')

# ---- pass 3: localization members ------------------------------------------------
loc_path = os.path.join(ROOT, 'l10n/milky_strings.dart') if not ROOT.startswith('lib') else 'lib/l10n/milky_strings.dart'
if loc_path in file_clean:
    loc = file_clean[loc_path]
    members = set(re.findall(r'\b(?:String|bool|int|double)\s+(?:get\s+)?([A-Za-z_$][\w$]*)\s*(?:\(|=>|\{)', loc))
    members |= set(re.findall(r'\bString\s+([A-Za-z_$][\w$]*)\s*\(', loc))
    for path in files:
        clean = file_clean[path]
        if 'milky_strings.dart' not in file_src[path] and path != loc_path:
            continue
        for m in re.finditer(r'\b([a-z]\w*)\.([A-Za-z_$][\w$]*)', clean):
            recv, member = m.group(1), m.group(2)
            if recv not in ('t', 'S'):
                continue
            if recv == 'S' and member in ('of',):
                continue
            if member not in members:
                issues.append(f'{path}:{line_of(file_src[path], m.start())}: S.{member} is not defined in milky_strings.dart')

# ---- pass 4: Milky* type references resolve -------------------------------------
all_defs = set()
for defs in file_defs.values():
    all_defs |= defs

# Always index lib/ so test files that import package:milkyvpn/... resolve too.
def _defs_of(path):
    src = open(path, encoding='utf-8').read()
    clean = strip_code(src)
    defs = set(re.findall(r'^\s*(?:abstract\s+|final\s+|sealed\s+|base\s+|interface\s+)*(?:class|enum|mixin|extension|typedef)\s+([A-Za-z_$][\w$]*)', clean, re.M))
    defs |= set(re.findall(r'^\s*(?:const|final)\s+([A-Za-z_$][\w$]*)\s*=', clean, re.M))
    return defs


for dirpath, _d, filenames in os.walk('lib'):
    for f in filenames:
        if f.endswith('.dart'):
            all_defs |= _defs_of(os.path.join(dirpath, f))

for path in files:
    src = file_src[path]
    clean = file_clean[path]
    imported = set()
    for m in re.finditer(r"^\s*import\s+'([^']+)'", src, re.M):
        uri = m.group(1)
        if uri.startswith('package:') or uri.startswith('dart:'):
            continue
        target = os.path.normpath(os.path.join(os.path.dirname(path), uri))
        imported |= file_defs.get(target, set())
    visible = all_defs if path.startswith('lib/') else imported | all_defs
    for m in re.finditer(r'\b(Milky[A-Z]\w*)\b', clean):
        name = m.group(1)
        if name in visible:
            continue
        # constructor call of a locally defined private class is fine
        issues.append(f'{path}:{line_of(src, m.start())}: unknown type {name}')

# ---- pass 5: Dart syntax mistakes a regex can still catch -----------------------
for path in files:
    clean = file_clean[path]
    for m in re.finditer(r'^\s*(?:[\w<>?,\s]+?)\s+get\s+([A-Za-z_$][\w$]*)\s*\(', clean, re.M):
        issues.append(f'{path}:{line_of(file_src[path], m.start())}: getter "{m.group(1)}" takes parameters (must be a method)')

# ---- pass 6: unused locals -------------------------------------------------------
for path in files:
    clean = file_ids[path]
    for m in re.finditer(r'^\s{4,}final\s+([A-Za-z_$][\w$]*)\s*=\s*[^;]+;', clean, re.M):
        name = m.group(1)
        occurrences = len(re.findall(r'\b%s\b' % re.escape(name), clean))
        if occurrences <= 1:
            issues.append(f'{path}:{line_of(file_src[path], m.start())}: unused local "{name}"')

seen = set()
report = []
for i in issues:
    if i not in seen:
        seen.add(i)
        report.append(i)
for r in sorted(report):
    print(r)
print(f'\n{len(files)} dart files checked, {len(report)} issue(s)')
