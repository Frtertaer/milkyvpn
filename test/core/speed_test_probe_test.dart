import 'dart:async';
import 'dart:io';

import 'package:async/async.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/vpn/speed_test.dart';

/// A minimal in-process SOCKS5 server that completes the handshake then
/// streams bytes — enough to prove the probe consumes the socket through a
/// single subscription (the old code re-listened and threw Bad state).
Future<ServerSocket> _fakeSocks() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  unawaited(
    server.forEach((client) async {
      final q = StreamQueue<List<int>>(client);
      final hello = await q.next.timeout(const Duration(seconds: 3));
      expect(hello, [0x05, 0x01, 0x00]);
      client.add([0x05, 0x00]);
      final conn = await q.next.timeout(const Duration(seconds: 3));
      expect(conn[0], 0x05);
      expect(conn[1], 0x01);
      client.add([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
      // Wait for the HTTP request then reply with a fixed body.
      final req = await q.next.timeout(const Duration(seconds: 3));
      expect(String.fromCharCodes(req), contains('GET'));
      final body = List<int>.filled(200 * 1024, 0x61);
      client.add(body);
      await client.flush();
      await client.close();
    }),
  );
  return server;
}

void main() {
  test('speedtest completes through a live SOCKS inbound', () async {
    final socks = await _fakeSocks();
    addTearDown(socks.close);
    final r = await runSpeedTest(
      socksPort: socks.port,
      maxBytes: 100 * 1024,
      cap: const Duration(seconds: 5),
    );
    expect(r.downMbps, greaterThan(0));
    expect(r.pingMs, greaterThanOrEqualTo(0));
  });

  test('proxy_unreachable when no SOCKS listens', () async {
    await expectLater(
      runSpeedTest(socksPort: 1, cap: const Duration(seconds: 3)),
      throwsA(
        isA<SpeedTestException>().having(
          (e) => e.code,
          'code',
          'proxy_unreachable',
        ),
      ),
    );
  });
}
