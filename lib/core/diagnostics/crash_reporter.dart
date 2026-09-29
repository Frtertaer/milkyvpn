import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import '../security/redactor.dart';

/// Crash reporting without secrets: uncaught framework/isolate errors are
/// written to a local JSONL file, run through [Redactor] and stripped of
/// filesystem paths — a report is shareable as-is, nothing in it identifies
/// the user, the device owner or the subscription.
///
/// There is no upload: the report exists so the user can copy it from
/// Diagnostics. `latest()` returns the newest record for that.
class CrashReporter {
  CrashReporter._();

  static const _maxBytes = 512 * 1024;
  static File? _file;

  /// Install the hooks. Call once, before `runApp`.
  static Future<void> install() async {
    try {
      _file = await _open();
    } catch (_) {
      _file = null; // no writable dir → logging only, never crash on install
    }

    final prev = FlutterError.onError;
    FlutterError.onError = (details) {
      _record('flutter', details.exceptionAsString(), details.stack);
      prev?.call(details);
    };
    PlatformDispatcher.instance.onError = (error, stack) {
      _record('isolate', error.toString(), stack);
      return false;
    };
  }

  /// All stored records, oldest → newest. Empty when no writable file.
  static Future<List<CrashRecord>> reports() async {
    final f = _file ?? await _open();
    if (f == null || !f.existsSync()) return const [];
    _file = f;
    final out = <CrashRecord>[];
    for (final line in await f.readAsLines()) {
      if (line.trim().isEmpty) continue;
      try {
        out.add(CrashRecord.fromJson(jsonDecode(line) as Map<String, Object?>));
      } catch (_) {/* skip torn tail line */}
    }
    return out;
  }

  static Future<CrashRecord?> latest() async {
    final all = await reports();
    return all.isEmpty ? null : all.last;
  }

  static Future<File?> _open() async {
    final dir = await getApplicationSupportDirectory();
    final crashDir = Directory('${dir.path}/crash');
    if (!crashDir.existsSync()) crashDir.createSync(recursive: true);
    final f = File('${crashDir.path}/crash.log');
    if (f.existsSync() && f.lengthSync() > _maxBytes) {
      // keep the tail: rewrite newest half
      final lines = await f.readAsLines();
      await f.writeAsString(lines.skip(lines.length ~/ 2).join('\n'));
    }
    return f;
  }

  static void _record(String kind, String message, StackTrace? stack) {
    const r = Redactor();
    final rec = CrashRecord(
      ts: DateTime.now().toUtc(),
      kind: kind,
      errorClass: r.errorClass(message),
      message: _sanitize(r.redact(message)),
      stack: _sanitizeStack(stack),
    );
    try {
      _file?.writeAsStringSync(
        '${jsonEncode(rec.toJson())}\n',
        mode: FileMode.append,
      );
    } catch (_) {/* never let reporting crash the app */}
  }

  /// Absolute paths carry the OS username — keep basenames only.
  static String _sanitize(String s) => s.replaceAllMapped(
        RegExp('(?:[A-Za-z]:)?[/\\\\][^\\s,()"\']+'),
        (m) => m[0]!.split(RegExp('[/\\\\]')).last,
      );

  static String? _sanitizeStack(StackTrace? stack) {
    if (stack == null) return null;
    final lines = stack.toString().split('\n');
    final kept = <String>[];
    for (var line in lines) {
      line = _sanitize(line.trim());
      if (line.isNotEmpty) kept.add(line);
      if (kept.length >= 12) break;
    }
    return kept.isEmpty ? null : kept.join('\n');
  }
}

class CrashRecord {
  const CrashRecord({
    required this.ts,
    required this.kind,
    required this.errorClass,
    required this.message,
    this.stack,
  });

  final DateTime ts;
  final String kind; // 'flutter' | 'isolate' | 'zone'
  final String errorClass;
  final String message;
  final String? stack;

  Map<String, Object?> toJson() => {
        'ts': ts.toIso8601String(),
        'kind': kind,
        'errorClass': errorClass,
        'message': message,
        if (stack != null) 'stack': stack,
      };

  factory CrashRecord.fromJson(Map<String, Object?> j) => CrashRecord(
        ts: DateTime.tryParse(j['ts'] as String? ?? '') ??
            DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
        kind: j['kind'] as String? ?? 'unknown',
        errorClass: j['errorClass'] as String? ?? 'unknown',
        message: j['message'] as String? ?? '',
        stack: j['stack'] as String?,
      );
}
