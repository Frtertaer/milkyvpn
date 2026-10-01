import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/profile_health.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';

VpnProfile prof(
  String id, {
  String? address,
  int port = 443,
  String network = 'veil',
  String? front,
}) => VpnProfile(
  id: id,
  protocol: 'kal2',
  address: address ?? '$id.example.invalid',
  port: port,
  secret: '00',
  remark: 'x',
  network: network,
  front: front,
);

void main() {
  test('live listener reports ms', () async {
    final srv = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(srv.close);
    // The server accepts then immediately drops probe sockets.
    unawaited(srv.forEach((s) => s.destroy()));
    final r = await ProfileHealth.probe(
      prof('x', address: '127.0.0.1', port: srv.port),
    );
    expect(r.dead, isFalse);
    expect(r.udp, isFalse);
    expect(r.ms, isNotNull);
  });

  test('unreachable host reports dead', () async {
    final r = await ProfileHealth.probe(
      prof('x', address: '10.255.255.1', port: 443),
      timeout: const Duration(milliseconds: 300),
    );
    expect(r.dead, isTrue);
    expect(r.ms, isNull);
  });

  test('udp carriers are skipped, not marked dead', () async {
    for (final net in ['quic2', 'rtc', 'quasar']) {
      final r = await ProfileHealth.probe(prof('x', network: net));
      expect(r.udp, isTrue, reason: net);
      expect(r.dead, isFalse);
      expect(r.ms, isNull);
    }
  });

  test('dialTarget prefers front relay host over entry address', () {
    final p = prof(
      'x',
      address: '23.133.88.167',
      port: 443,
      front: 'https://milky-front.milky-front.workers.dev',
    );
    final (host, port) = ProfileHealth.dialTarget(p);
    expect(host, 'milky-front.milky-front.workers.dev');
    expect(port, 443);
  });

  test('dialTarget falls back to entry when no front', () {
    final (host, port) = ProfileHealth.dialTarget(
      prof('x', address: '1.2.3.4', port: 20444),
    );
    expect(host, '1.2.3.4');
    expect(port, 20444);
  });
}
