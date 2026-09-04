import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/subscription_parser.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/subscription/subscription_stats.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';

import 'subscription_test.dart' show FakeFetcher;

String fixture(String n) => File('test/fixtures/$n').readAsStringSync();

/// 16 lines where the last 6 are byte-identical repeats of the first 6: true duplicates.
String duplicateHeavySubscription() {
  final lines = fixture('subscription_16_fake.txt').split('\n').where((l) => l.isNotEmpty).toList();
  return [...lines.take(10), ...lines.take(6)].join('\n');
}

/// The old bug class: 6 extra lines that SHARE endpoint/transport/security/path with the
/// first 6 but carry DIFFERENT credentials (UUID) and names. The pre-V2 parser collapsed
/// them to 10 profiles; the credential-aware identity must keep all 16.
String sameEndpointDifferentCredentials() {
  final lines = fixture('subscription_16_fake.txt').split('\n').where((l) => l.isNotEmpty).toList();
  final base = lines.take(10).toList();
  final twins = <String>[];
  for (var i = 0; i < 6; i++) {
    final line = lines[i];
    final renamed = line
        .replaceAll(RegExp('#.*\$'), '#Mirror-${i + 1}')
        .replaceAll(RegExp(r'^vless://[0-9a-fA-F-]+@'), 'vless://000000ff-0000-4000-8000-00000000000$i@')
        .replaceAll(RegExp(r'^hysteria2://[^@]+@'), 'hysteria2://mirrorpass$i@')
        .replaceAll(RegExp(r'^hy2://[^@]+@'), 'hy2://mirrorpass$i@');
    twins.add(renamed);
  }
  return [...base, ...twins].join('\n');
}

void main() {
  const parser = SubscriptionParser();

  group('subscription numbers are explainable', () {
    test('clean 16-profile subscription: 16 lines, 16 profiles, 16 compatible', () {
      final result = parser.parse(fixture('subscription_16_fake.txt'));
      final stats = SubscriptionStats(
        totalLines: result.totalLines,
        profiles: result.profiles.length,
        malformed: result.malformedLines,
        duplicates: result.duplicateEntries,
        compatible: SubscriptionStats.compatibleCount(result.profiles),
      );

      expect(stats.totalLines, 16);
      expect(stats.profiles, 16);
      expect(stats.compatible, 16);
      expect(stats.malformed, 0);
      expect(stats.duplicates, 0);
      expect(stats.isAccounted, isTrue);
      expect(stats.incompatible, 0);
    });

    test('true duplicates are counted, not silently dropped: 16 lines -> 10 profiles', () {
      final result = parser.parse(duplicateHeavySubscription());
      expect(result.totalLines, 16);
      expect(result.profiles.length, 10);
      expect(result.malformedLines, 0);
      expect(result.duplicateEntries, 6);
      expect(result.totalLines, result.profiles.length + result.malformedLines + result.duplicateEntries);
    });

    test('REGRESSION: same endpoint + different UUID = distinct profiles (16 stays 16)', () {
      // Mutation/control for the pre-V2 dedupe bug: the old endpoint-only identity
      // returned 10 profiles here. The credential-aware identity must return 16.
      final result = parser.parse(sameEndpointDifferentCredentials());
      expect(result.totalLines, 16);
      expect(result.profiles.length, 16, reason: 'different credentials are different profiles');
      expect(result.duplicateEntries, 0);
      expect(result.malformedLines, 0);
    });

    test('REGRESSION: same endpoint + different SNI/public key = distinct profiles', () {
      const a = 'vless://00000001-0000-4000-8000-000000000001@fi1.example.invalid:443?type=tcp&security=reality&sni=www.example.com&pbk=KEY_A&flow=xtls-rprx-vision#One';
      const b = 'vless://00000001-0000-4000-8000-000000000001@fi1.example.invalid:443?type=tcp&security=reality&sni=www.example.org&pbk=KEY_B&flow=xtls-rprx-vision#Two';
      final result = parser.parse('$a\n$b');
      expect(result.profiles.length, 2, reason: 'SNI/public key are part of the tunnel identity');
    });

    test('unsupported protocols are parsed but not executable (16 parsed, fewer compatible)', () {
      final lines = fixture('subscription_16_fake.txt').split('\n').where((l) => l.isNotEmpty).toList();
      final body = [
        ...lines.take(10),
        'vmess://eyJhIjoiMSJ9@us9.example.invalid:443#USA-8 VMess',
        'trojan://pw@us10.example.invalid:443#USA-9 Trojan',
        'ss://YWVz@us11.example.invalid:8388#USA-10 SS',
        'vless://00000010-0000-4000-8000-000000000010@us12.example.invalid:443?type=grpc&security=tls#USA-11 gRPC',
        'vless://00000011-0000-4000-8000-000000000011@us13.example.invalid:443?type=tcp&security=reality&sni=www.example.com#USA-12 RealityNoKey',
        'vless://00000012-0000-4000-8000-000000000012@us14.example.invalid:443?type=ws&security=reality&sni=www.example.com&pbk=FAKEPBK_H#USA-13 RealityWS',
      ].join('\n');

      final result = parser.parse(body);
      final stats = SubscriptionStats(
        totalLines: result.totalLines,
        profiles: result.profiles.length,
        malformed: result.malformedLines,
        duplicates: result.duplicateEntries,
        compatible: SubscriptionStats.compatibleCount(result.profiles),
      );

      expect(stats.totalLines, 16);
      expect(stats.profiles, 16, reason: 'unsupported schemes are still parsed');
      expect(stats.compatible, 10, reason: '6 of them cannot be executed by this engine');
      expect(stats.incompatible, 6);
      expect(stats.isAccounted, isTrue);
    });

    test('static compatibility mirrors the Kotlin engine validation', () {
      const realityNoKey = VpnProfile(
        id: 'a',
        protocol: 'vless',
        address: 'h.example',
        port: 443,
        secret: 's',
        remark: 'x',
        network: 'tcp',
        security: 'reality',
      );
      const realityWithKey = VpnProfile(
        id: 'b',
        protocol: 'vless',
        address: 'h.example',
        port: 443,
        secret: 's',
        remark: 'x',
        network: 'tcp',
        security: 'reality',
        publicKey: 'PBK',
      );
      const realityWs = VpnProfile(
        id: 'c',
        protocol: 'vless',
        address: 'h.example',
        port: 443,
        secret: 's',
        remark: 'x',
        network: 'ws',
        security: 'reality',
        publicKey: 'PBK',
      );
      const wsTls = VpnProfile(
        id: 'd',
        protocol: 'vless',
        address: 'h.example',
        port: 443,
        secret: 's',
        remark: 'x',
        network: 'ws',
        security: 'tls',
      );
      const hy2 = VpnProfile(
        id: 'e',
        protocol: 'hysteria2',
        address: 'h.example',
        port: 443,
        secret: 'pw',
        remark: 'x',
        network: 'hysteria',
        security: 'tls',
      );
      const other = VpnProfile(
        id: 'f',
        protocol: 'vmess',
        address: 'h.example',
        port: 443,
        secret: 's',
        remark: 'x',
        network: 'other',
        security: 'other',
      );

      expect(realityNoKey.isStaticCompatible, isFalse);
      expect(realityWithKey.isStaticCompatible, isTrue);
      expect(realityWs.isStaticCompatible, isFalse);
      expect(wsTls.isStaticCompatible, isTrue);
      expect(hy2.isStaticCompatible, isTrue);
      expect(other.isStaticCompatible, isFalse);
    });

    test('snapshot round-trip through secure storage keeps the counters', () async {
      final store = MemorySecureStore();
      final repo = SubscriptionRepository(store: store, fetcher: FakeFetcher(duplicateHeavySubscription()));
      await repo.load();
      final snap = await repo.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');
      expect(snap.profiles.length, 10);
      expect(snap.duplicateEntries, 6);
      expect(snap.totalEntries, 16);

      final reopened = SubscriptionRepository(store: store, fetcher: FakeFetcher(''));
      await reopened.load();
      expect(reopened.snapshot?.profiles.length, 10);
      expect(reopened.snapshot?.duplicateEntries, 6);
      expect(reopened.snapshot?.totalEntries, 16);
      expect(SubscriptionStats.from(reopened.snapshot).isAccounted, isTrue);
    });
  });
}
