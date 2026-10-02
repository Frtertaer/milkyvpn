import 'dart:async';
import 'dart:io';

/// Measures tunnel throughput and latency via the local SOCKS5 inbound the
/// core always opens on loopback (127.0.0.1:10808 — see XrayConfigBuilder).
///
/// The app's own sockets bypass the TUN (loop-avoidance exclusion), so a
/// plain HttpClient would measure the physical link, not the tunnel — the
/// probe therefore speaks SOCKS5 directly.
class SpeedResult {
  const SpeedResult({required this.pingMs, required this.downMbps});
  final int pingMs;
  final double downMbps;
}

class SpeedTestException implements Exception {
  const SpeedTestException(this.code);
  final String code;
  @override
  String toString() => 'SpeedTestException($code)';
}

/// Plain-HTTP speedtest endpoints (HTTPS would need a TLS stack over the raw
/// socket — the file is public and only throughput matters).
const _targets = [
  ('cachefly.cachefly.net', '/10mb.test'),
  ('speedtest.tele2.net', '/10MB.zip'),
];

Future<SpeedResult> runSpeedTest({
  String socksHost = '127.0.0.1',
  // Which loopback SOCKS is live depends on the engine: xray binds 10808
  // always; the native kal2 core binds 11808. Try both.
  int? socksPort,
  int maxBytes = 2 * 1024 * 1024,
  Duration cap = const Duration(seconds: 25),
}) async {
  final ports = socksPort != null
      ? <int>[socksPort]
      : Platform.isAndroid
      ? const [10808, 11808]
      : const [11808, 10808];
  SpeedTestException? last;
  // A dead/blocked measurement endpoint is indistinguishable from a dead
  // tunnel on a single target — fall through ports×targets before giving up.
  for (final port in ports) {
    for (final (host, path) in _targets) {
      try {
        return await _measure(socksHost, port, host, path, maxBytes, cap);
      } on SpeedTestException catch (e) {
        last = e;
        if (e.code == 'proxy_unreachable') break; // nothing on this port — next
      }
    }
  }
  throw last ?? const SpeedTestException('tunnel_unreachable');
}

Future<SpeedResult> _measure(
  String socksHost,
  int socksPort,
  String host,
  String path,
  int maxBytes,
  Duration cap,
) async {
  final sw = Stopwatch()..start();
  Socket sock;
  try {
    sock = await Socket.connect(
      socksHost,
      socksPort,
      timeout: const Duration(seconds: 5),
    );
  } catch (_) {
    throw const SpeedTestException('proxy_unreachable');
  }
  try {
    // A Socket allows a single listen() — every phase reads through one
    // buffered subscription.
    final reader = _BufferedSocket(sock);
    // Greeting: VER=5, 1 method, no-auth.
    sock.add(const [0x05, 0x01, 0x00]);
    final hello = await reader
        .take(2)
        .timeout(const Duration(seconds: 5), onTimeout: () => []);
    if (hello.length < 2 || hello[0] != 0x05 || hello[1] == 0xff) {
      throw const SpeedTestException('proxy_unreachable');
    }
    // CONNECT to the target host (domain form, ATYP=0x03).
    final hb = host.codeUnits;
    sock.add([
      0x05, 0x01, 0x00, 0x03, hb.length,
      ...hb,
      0x00, 0x50, // port 80
    ]);
    final reply = await reader
        .take(4)
        .timeout(const Duration(seconds: 5), onTimeout: () => []);
    if (reply.length < 4 || reply[1] != 0x00) {
      throw const SpeedTestException('tunnel_unreachable');
    }
    final atyp = reply[3];
    final skip = atyp == 0x01
        ? 6 // IPv4 + port
        : atyp == 0x04
        ? 18 // IPv6 + port
        : null;
    if (skip == null) {
      // ATYP=0x03: first byte is the length.
      final l = await reader
          .take(1)
          .timeout(const Duration(seconds: 5), onTimeout: () => [0]);
      await reader
          .take(l[0] + 2)
          .timeout(const Duration(seconds: 5), onTimeout: () => []);
    } else {
      await reader
          .take(skip)
          .timeout(const Duration(seconds: 5), onTimeout: () => []);
    }

    // Ping ≈ handshake + CONNECT until this point (control-plane latency).
    final pingMs = sw.elapsedMilliseconds;

    final req =
        'GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n';
    sock.add(req.codeUnits);

    var got = 0;
    final dl = Stopwatch()..start();
    final done = Completer<void>();
    late StreamSubscription<List<int>> sub;
    sub = reader.stream.listen(
      (chunk) {
        got += chunk.length;
        if (got >= maxBytes) {
          unawaited(sub.cancel());
          if (!done.isCompleted) done.complete();
        }
      },
      onDone: () {
        if (!done.isCompleted) done.complete();
      },
      onError: (_) {
        if (!done.isCompleted) done.complete();
      },
    );
    await done.future.timeout(
      cap,
      onTimeout: () {
        unawaited(sub.cancel());
      },
    );
    final secs = dl.elapsedMilliseconds / 1000;
    if (got < 64 * 1024 || secs <= 0) {
      throw const SpeedTestException('no_data');
    }
    final mbps = got * 8 / secs / 1e6;
    return SpeedResult(pingMs: pingMs, downMbps: mbps);
  } finally {
    sock.destroy();
  }
}

/// Single-subscription buffered reader — a Socket allows only one listen(),
/// so every handshake phase drains this buffer instead of re-listening, and
/// the download phase consumes [stream] (broadcast from the same source).
class _BufferedSocket {
  _BufferedSocket(Socket s) {
    _sub = s.listen(
      (c) {
        _buf.addAll(c);
        _chunks.add(c);
        _drainWaiters();
      },
      onDone: () {
        _closed = true;
        _chunks.close();
        _drainWaiters();
      },
      onError: (Object e) {
        _error = e;
        _closed = true;
        _chunks.addError(e);
        _drainWaiters();
      },
    );
  }
  late final StreamSubscription<List<int>> _sub;
  final _chunks = StreamController<List<int>>.broadcast();
  Future<void> close() => _sub.cancel();
  final _buf = <int>[];
  Completer<List<int>>? _waiter;
  int _want = 0;
  bool _closed = false;
  Object? _error;

  /// Everything the socket receives from now on (handshake bytes consumed via
  /// [take] were already emitted before callers subscribe).
  Stream<List<int>> get stream => _chunks.stream;

  /// Resolves with the next [n] bytes; fewer when the socket closes first.
  Future<List<int>> take(int n) {
    if (_buf.length >= n) {
      final out = _buf.sublist(0, n);
      _buf.removeRange(0, n);
      return Future.value(out);
    }
    if (_closed) {
      final out = List<int>.from(_buf);
      _buf.clear();
      return _error != null ? Future.error(_error!) : Future.value(out);
    }
    _want = n;
    _waiter = Completer<List<int>>();
    return _waiter!.future;
  }

  void _drainWaiters() {
    final w = _waiter;
    if (w == null || w.isCompleted) return;
    if (_buf.length >= _want) {
      final out = _buf.sublist(0, _want);
      _buf.removeRange(0, _want);
      _waiter = null;
      w.complete(out);
    } else if (_closed) {
      final out = List<int>.from(_buf);
      _buf.clear();
      _waiter = null;
      if (_error != null) {
        w.completeError(_error!);
      } else {
        w.complete(out);
      }
    }
  }
}
