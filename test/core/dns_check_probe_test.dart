import 'dart:async';
import 'dart:io';

import 'package:async/async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/vpn/dns_check.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';

class _FakeBridge extends VpnBridge {
  @override
  Future<String> privateDnsMode() async => 'off';
  @override
  Future<String> privateDnsSpecifier() async => '';
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      Future<dynamic>.error(UnimplementedError());
}

/// SOCKS5 server that answers CONNECT then speaks TCP-DNS.
Future<ServerSocket> _fakeSocksDns() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  unawaited(
    server.forEach((client) async {
      final q = StreamQueue<List<int>>(client);
      await q.next.timeout(const Duration(seconds: 3));
      client.add([0x05, 0x00]);
      final conn = await q.next.timeout(const Duration(seconds: 3));
      expect(conn[1], 0x01);
      client.add([0x05, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35]);
      // Read the length-prefixed query (may arrive in one or two chunks).
      var msg = await q.next.timeout(const Duration(seconds: 3));
      while (msg.length < 2) {
        msg = [...msg, ...await q.next.timeout(const Duration(seconds: 3))];
      }
      final want = (msg[0] << 8) | msg[1];
      while (msg.length < 2 + want) {
        msg = [...msg, ...await q.next.timeout(const Duration(seconds: 3))];
      }
      // Header-only answer: ID echoed, QR+RA, RCODE 0, ANCOUNT 1.
      final answer = [
        msg[2], msg[3], // id
        0x81, 0x80, // flags: QR|RD|RA
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      ];
      client.add([0x00, answer.length, ...answer]);
      await client.flush();
      await client.close();
    }),
  );
  return server;
}

void main() {
  test('DoH-via-tunnel probe succeeds through a live SOCKS inbound', () async {
    final socks = await _fakeSocksDns();
    addTearDown(socks.close);
    final r = await checkDns(_FakeBridge(), socksPorts: [socks.port]);
    expect(r.dohViaTunnel, isTrue);
  });
}
