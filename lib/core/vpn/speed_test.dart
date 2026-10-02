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
  // Android: Xray loopback inbound (XrayConfigBuilder socksPort).
  // Desktop: kal2-client -socks (WindowsProcessVpnBridge.defaultSocksAddr).
  int? socksPort,
  int maxBytes = 6 * 1024 * 1024,
  Duration cap = const Duration(seconds: 25),
}) async {
  socksPort ??= Platform.isAndroid ? 10808 : 11808;
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
    // Greeting: VER=5, 1 method, no-auth.
    sock.add(const [0x05, 0x01, 0x00]);
    final hello = await _read(sock, 2, const Duration(seconds: 5));
    if (hello.length < 2 || hello[0] != 0x05 || hello[1] == 0xff) {
      throw const SpeedTestException('proxy_unreachable');
    }
    // CONNECT to the target host (domain form, ATYP=0x03).
    final host = _targets[0].$1;
    final hb = host.codeUnits;
    sock.add([
      0x05, 0x01, 0x00, 0x03, hb.length,
      ...hb,
      0x00, 0x50, // port 80
    ]);
    final reply = await _read(sock, 4, const Duration(seconds: 5));
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
      final l = await _read(sock, 1, const Duration(seconds: 5));
      await _read(sock, l[0] + 2, const Duration(seconds: 5));
    } else {
      await _read(sock, skip, const Duration(seconds: 5));
    }

    // Ping ≈ handshake + CONNECT until this point (control-plane latency).
    final pingMs = sw.elapsedMilliseconds;

    final req =
        'GET ${_targets[0].$2} HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n';
    sock.add(req.codeUnits);

    var got = 0;
    final dl = Stopwatch()..start();
    final done = Completer<void>();
    late StreamSubscription<List<int>> sub;
    sub = sock.listen(
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

Future<List<int>> _read(Socket s, int n, Duration t) {
  final c = Completer<List<int>>();
  final buf = <int>[];
  late StreamSubscription<List<int>> sub;
  sub = s.listen(
    (chunk) {
      buf.addAll(chunk);
      if (buf.length >= n) {
        unawaited(sub.cancel());
        if (!c.isCompleted) c.complete(buf.sublist(0, n));
      }
    },
    onDone: () {
      if (!c.isCompleted) c.complete(buf);
    },
    onError: (Object e) {
      if (!c.isCompleted) c.completeError(e);
    },
  );
  return c.future.timeout(
    t,
    onTimeout: () {
      unawaited(sub.cancel());
      return buf;
    },
  );
}
