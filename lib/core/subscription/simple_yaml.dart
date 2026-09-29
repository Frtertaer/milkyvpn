/// Minimal YAML subset reader for proxy list imports.
///
/// Scope (deliberately bounded — not a general YAML implementation):
///  * block maps (`key: value`, `key:` followed by an indented map/list)
///  * block sequences (`- scalar`, `- key: value` starting a map item)
///  * flow maps `{a: b, c: d}` and flow sequences `[a, b]` on a single line
///  * single/double-quoted scalars; `|`/`>` block scalars are NOT supported
///    (out of scope for clash/sing-box proxy lists)
///  * `#` comments, blank lines, `---`/`...` document markers
///  * scalar typing: null, true/false, int, double, else string
///
/// Returns `Map<String, Object?>` where nested values are Map / List / scalar.
library;

class SimpleYaml {
  const SimpleYaml._();

  /// Parses a YAML document into a Map. Throws [FormatException] on syntax the
  /// subset cannot handle; callers must treat it as malformed input.
  static Map<String, Object?> parse(String text) {
    final lines = <_Line>[];
    for (final raw in text.split(RegExp(r'\r?\n'))) {
      final withoutComment = _stripComment(raw);
      if (withoutComment.trim().isEmpty) continue;
      final trimmed = withoutComment.trimRight();
      if (trimmed.trim() == '---' || trimmed.trim() == '...') continue;
      final indent = _indentOf(trimmed);
      lines.add(_Line(indent, trimmed.trim()));
    }
    if (lines.isEmpty) return const {};
    var pos = 0;
    final node = _parseBlock(lines, pos, lines.first.indent, (p) => pos = p);
    return node is Map<String, Object?> ? node : const {};
  }

  // ------------------------------------------------------------ internals

  static int _indentOf(String s) {
    var n = 0;
    while (n < s.length && s.codeUnitAt(n) == 0x20) {
      n++;
    }
    return n;
  }

  static String _stripComment(String line) {
    var inSingle = false, inDouble = false;
    for (var i = 0; i < line.length; i++) {
      final ch = line[i];
      if (ch == "'" && !inDouble) inSingle = !inSingle;
      if (ch == '"' && !inSingle) inDouble = !inDouble;
      if (ch == '#' && !inSingle && !inDouble) {
        if (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t') {
          return line.substring(0, i);
        }
      }
    }
    return line;
  }

  /// Parses a block node at [indent] starting at line [pos]; returns the node
  /// and reports the new position via [setPos].
  static Object? _parseBlock(
    List<_Line> lines,
    int pos,
    int indent,
    void Function(int) setPos,
  ) {
    if (pos >= lines.length) {
      return null;
    }
    if (lines[pos].text.startsWith('- ')) {
      return _parseSeq(lines, pos, indent, setPos);
    }
    return _parseMap(lines, pos, indent, setPos);
  }

  static Map<String, Object?> _parseMap(
    List<_Line> lines,
    int pos,
    int indent,
    void Function(int) setPos,
  ) {
    final map = <String, Object?>{};
    var p = pos;
    while (p < lines.length) {
      final line = lines[p];
      if (line.indent < indent) break;
      if (line.indent > indent) {
        throw FormatException('unexpected indent: ${line.text}');
      }
      if (line.text.startsWith('- ')) break; // sequence follows
      final kv = _splitKey(line.text);
      if (kv == null) {
        throw FormatException('expected key: value, got: ${line.text}');
      }
      final key = kv.key;
      final rest = kv.value;
      p++;
      if (rest.isEmpty) {
        // Nested block or null.
        if (p < lines.length && lines[p].indent > indent) {
          map[key] = _parseBlock(lines, p, lines[p].indent, (np) => p = np);
        } else if (p < lines.length &&
            lines[p].indent == indent &&
            lines[p].text.startsWith('- ')) {
          // `key:` then a same-indent sequence (YAML allows seq at key indent).
          map[key] = _parseSeq(lines, p, indent, (np) => p = np);
        } else {
          map[key] = null;
        }
      } else {
        map[key] = _parseScalar(rest);
      }
    }
    setPos(p);
    return map;
  }

  static List<Object?> _parseSeq(
    List<_Line> lines,
    int pos,
    int indent,
    void Function(int) setPos,
  ) {
    final list = <Object?>[];
    var p = pos;
    while (p < lines.length) {
      final line = lines[p];
      if (line.indent != indent || !line.text.startsWith('- ')) break;
      final itemText = line.text.substring(2).trim();
      p++;
      if (itemText.isEmpty) {
        // `-` alone: nested block on following deeper indent.
        if (p < lines.length && lines[p].indent > indent) {
          list.add(_parseBlock(lines, p, lines[p].indent, (np) => p = np));
        } else {
          list.add(null);
        }
        continue;
      }
      // Inline continuation: subsequent deeper-indented lines belong to a map
      // whose first key is on the `-` line.
      final kv = _splitKey(itemText);
      if (kv != null) {
        final map = <String, Object?>{};
        if (kv.value.isEmpty) {
          if (p < lines.length && lines[p].indent > indent) {
            map[kv.key] = _parseBlock(lines, p, lines[p].indent, (np) => p = np);
          } else {
            map[kv.key] = null;
          }
        } else {
          map[kv.key] = _parseScalar(kv.value);
        }
        // Merge following deeper-indented key: value lines into this map.
        while (p < lines.length && lines[p].indent > indent) {
          final sub = lines[p];
          if (sub.text.startsWith('- ')) break;
          final subKv = _splitKey(sub.text);
          if (subKv == null) {
            throw FormatException('expected key: value, got: ${sub.text}');
          }
          p++;
          if (subKv.value.isEmpty) {
            if (p < lines.length && lines[p].indent > sub.indent) {
              map[subKv.key] = _parseBlock(
                lines,
                p,
                lines[p].indent,
                (np) => p = np,
              );
            } else {
              map[subKv.key] = null;
            }
          } else {
            map[subKv.key] = _parseScalar(subKv.value);
          }
        }
        list.add(map);
      } else {
        list.add(_parseScalar(itemText));
      }
    }
    setPos(p);
    return list;
  }

  /// Splits `key: value` (key may be quoted). Returns null when there is no
  /// top-level `key:` separator — e.g. the text is a scalar or flow node.
  static _KeyValue? _splitKey(String text) {
    var inSingle = false, inDouble = false, depth = 0;
    for (var i = 0; i < text.length; i++) {
      final ch = text[i];
      if (ch == "'" && !inDouble) inSingle = !inSingle;
      if (ch == '"' && !inSingle) inDouble = !inDouble;
      if (!inSingle && !inDouble) {
        if (ch == '{' || ch == '[') depth++;
        if (ch == '}' || ch == ']') depth--;
        if (ch == ':' && depth == 0) {
          if (i + 1 == text.length ||
              text[i + 1] == ' ' ||
              text[i + 1] == '\t') {
            final key = _unquote(text.substring(0, i).trim());
            return _KeyValue(key, text.substring(i + 1).trim());
          }
        }
      }
    }
    return null;
  }

  static String _unquote(String s) {
    if (s.length >= 2) {
      if (s.startsWith('"') && s.endsWith('"')) {
        return _unescapeDouble(s.substring(1, s.length - 1));
      }
      if (s.startsWith("'") && s.endsWith("'")) {
        return s.substring(1, s.length - 1).replaceAll("''", "'");
      }
    }
    return s;
  }

  static String _unescapeDouble(String s) => s
      .replaceAll(r'\n', '\n')
      .replaceAll(r'\t', '\t')
      .replaceAll(r'\"', '"')
      .replaceAll(r'\\', r'\');

  static Object? _parseScalar(String text) {
    if (text.startsWith('{') && text.endsWith('}')) {
      return _parseFlowMap(text);
    }
    if (text.startsWith('[') && text.endsWith(']')) {
      return _parseFlowSeq(text);
    }
    final lower = text.toLowerCase();
    if (lower == 'null' || lower == '~' || text.isEmpty) return null;
    if (lower == 'true') return true;
    if (lower == 'false') return false;
    final intVal = int.tryParse(text);
    if (intVal != null) return intVal;
    final dblVal = double.tryParse(text);
    if (dblVal != null && !text.startsWith('.')) return dblVal;
    return _unquote(text);
  }

  static List<String> _splitFlow(String inner) {
    final parts = <String>[];
    var inSingle = false, inDouble = false, depth = 0, start = 0;
    for (var i = 0; i < inner.length; i++) {
      final ch = inner[i];
      if (ch == "'" && !inDouble) inSingle = !inSingle;
      if (ch == '"' && !inSingle) inDouble = !inDouble;
      if (!inSingle && !inDouble) {
        if (ch == '{' || ch == '[') depth++;
        if (ch == '}' || ch == ']') depth--;
        if (ch == ',' && depth == 0) {
          parts.add(inner.substring(start, i).trim());
          start = i + 1;
        }
      }
    }
    final tail = inner.substring(start).trim();
    if (tail.isNotEmpty) parts.add(tail);
    return parts;
  }

  static Map<String, Object?> _parseFlowMap(String text) {
    final inner = text.substring(1, text.length - 1).trim();
    if (inner.isEmpty) return const {};
    final map = <String, Object?>{};
    for (final part in _splitFlow(inner)) {
      final kv = _splitKey(part);
      if (kv == null) continue;
      map[kv.key] = _parseScalar(kv.value);
    }
    return map;
  }

  static List<Object?> _parseFlowSeq(String text) {
    final inner = text.substring(1, text.length - 1).trim();
    if (inner.isEmpty) return const [];
    return _splitFlow(inner).map(_parseScalar).toList();
  }
}

class _Line {
  const _Line(this.indent, this.text);
  final int indent;
  final String text;
}

class _KeyValue {
  const _KeyValue(this.key, this.value);
  final String key;
  final String value;
}
