import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/security/redactor.dart';
import 'package:milkyvpn/core/security/subscription_url_policy.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_parser.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';

String fixture(String n) => File('test/fixtures/$n').readAsStringSync();

class FakeFetcher implements SubscriptionFetcher {
  FakeFetcher(this.body, {this.headers = const {}});
  String body;
  Map<String, String> headers;
  int calls = 0;
  @override
  Future<FetchedSubscription> fetch(Uri url) async {
    calls++;
    return FetchedSubscription(body: body, headers: headers);
  }
}

void main() {
  const parser = SubscriptionParser();
  const policy = SubscriptionUrlPolicy();

  group('parser', () {
    test('decodes base64 (padded, unpadded, url-safe, whitespace) to 16 profiles', () {
      final b64 = fixture('subscription_16_fake.b64');
      expect(parser.parse(b64).profiles.length, 16);
      expect(parser.parse(b64.replaceAll('=', '')).profiles.length, 16);
      expect(parser.parse(b64.replaceAll('+', '-').replaceAll('/', '_')).profiles.length, 16);
      final spaced = b64.replaceAllMapped(RegExp('.{60}'), (m) => '${m[0]}\n  ');
      expect(parser.parse(spaced).profiles.length, 16);
      expect(parser.parse(fixture('subscription_16_fake.txt')).profiles.length, 16);
    });

    test('16 profiles: 9 Finland, 7 USA; families detected', () {
      final r = parser.parse(fixture('subscription_16_fake.txt'));
      expect(r.malformedLines, 0);
      expect(r.profiles.where((p) => p.location == ServerLocation.finland).length, 9);
      expect(r.profiles.where((p) => p.location == ServerLocation.usa).length, 7);
      expect(r.profiles.where((p) => p.kind == ProfileKind.vlessRealityTcp).length, 5);
      expect(r.profiles.where((p) => p.kind == ProfileKind.vlessWsTls).length, 4);
      expect(r.profiles.where((p) => p.kind == ProfileKind.vlessXhttp).length, 3);
      expect(r.profiles.where((p) => p.kind == ProfileKind.hysteria2).length, 4);
    });

    test('vless reality fields', () {
      final p = parser.parseLine(fixture('subscription_16_fake.txt').split('\n').first)!;
      expect(p.protocol, 'vless');
      expect(p.security, 'reality');
      expect(p.network, 'tcp');
      expect(p.sni, 'www.example.com');
      expect(p.publicKey, startsWith('FAKEPBK_A'));
      expect(p.shortId, '0a0b0c0d');
      expect(p.flow, 'xtls-rprx-vision');
      expect(p.fingerprint, 'chrome');
      expect(p.remark, 'Finland-1 Reality');
      expect(p.secret, '00000001-0000-4000-8000-000000000001');
    });

    test('ws parser handles url-encoded path and host', () {
      final p = parser.parseLine(fixture('subscription_16_fake.txt').split('\n')[3])!;
      expect(p.kind, ProfileKind.vlessWsTls);
      expect(p.path, '/ws?ed=2048');
      expect(p.host, 'cdn-fi.example.invalid');
    });

    test('xhttp parser', () {
      final p = parser.parseLine(fixture('subscription_16_fake.txt').split('\n')[5])!;
      expect(p.kind, ProfileKind.vlessXhttp);
      expect(p.xhttpMode, 'packet-up');
      expect(p.path, '/xh');
    });

    test('hysteria2 parser incl. hy2 alias, IPv4, obfs', () {
      final p = parser.parseLine(fixture('subscription_16_fake.txt').split('\n')[8])!;
      expect(p.kind, ProfileKind.hysteria2);
      expect(p.address, '203.0.113.12');
      expect(p.port, 8443);
      expect(p.secret, 'fakepass8');
      expect(p.obfsPassword, 'fakeobfs');
      expect(p.sni, 'hy.example.invalid');
    });

    test('malformed lines are isolated, valid ones survive', () {
      final good = fixture('subscription_16_fake.txt').split('\n').where((l) => l.isNotEmpty).toList();
      final body = [good[0], 'vless://not-a-uuid@host:443', 'garbage', 'vless://00000001-0000-4000-8000-000000000001@host:99999', '', '# comment', 'hysteria2://@h:443', good[1]].join('\n');
      final r = parser.parse(body);
      expect(r.profiles.length, 2);
      expect(r.malformedLines, 4);
      expect(parser.parse(''), isA<SubscriptionParseResult>());
      expect(parser.parse('%%%%').profiles, isEmpty);
    });

    test('unsupported schemes counted but marked other', () {
      final p = parser.parseLine('vmess://abc@h.example:443#x');
      expect(p?.kind, ProfileKind.other);
    });

    test('expiry from subscription-userinfo header', () {
      final r = parser.parse(fixture('subscription_16_fake.b64'), headers: {'Subscription-Userinfo': 'upload=1; download=2; total=3; expire=1900000000'});
      expect(r.expiresAt, DateTime.fromMillisecondsSinceEpoch(1900000000 * 1000, isUtc: true));
    });

    test('redactedRemark never contains credentials', () {
      final p = parser.parseLine('vless://00000001-0000-4000-8000-000000000001@h.example:443?security=none#00000001-0000-4000-8000-000000000001 Srv')!;
      expect(p.redactedRemark, 'Srv');
      expect(p.toDiagnosticString(), isNot(contains('0000-4000')));
    });
  });

  group('url allowlist', () {
    test('accepts canonical url only', () {
      expect(policy.isAllowed('https://sub.milky.homes/s/AbCdEf123456'), isTrue);
      expect(policy.validate('https://sub.milky.homes/s/AbCdEf123456')!.toString(), 'https://sub.milky.homes/s/AbCdEf123456');
      expect(policy.isAllowed('  https://sub.milky.homes/s/AbCdEf123456  '), isTrue);
    });
    test('rejects http, other hosts, localhost, private ip, file, javascript, tricks', () {
      for (final bad in [
        'http://sub.milky.homes/s/AbCdEf123456',
        'https://evil.example/s/AbCdEf123456',
        'https://sub.milky.homes.evil.example/s/AbCdEf123456',
        'https://localhost/s/AbCdEf123456',
        'https://127.0.0.1/s/AbCdEf123456',
        'https://192.168.1.1/s/AbCdEf123456',
        'https://10.0.0.1/s/AbCdEf123456',
        'file:///etc/passwd',
        'javascript:alert(1)',
        'https://sub.milky.homes/other/AbCdEf123456',
        'https://sub.milky.homes/s/../../x',
        'https://sub.milky.homes/s/AbCdEf123456?x=1',
        'https://sub.milky.homes/s/AbCdEf123456#f',
        'https://user@sub.milky.homes/s/AbCdEf123456',
        'https://sub.milky.homes:8443/s/AbCdEf123456',
        'https://sub.milky.homes/s/short',
        'https://sub.milky.homes/s/a b c d e f g h',
        '',
      ]) {
        expect(policy.isAllowed(bad), isFalse, reason: bad);
      }
    });
    test('deep link extraction + sanitization', () {
      expect(policy.fromDeepLink('milkyvpn://import?url=https%3A%2F%2Fsub.milky.homes%2Fs%2FAbCdEf123456')!.path, '/s/AbCdEf123456');
      expect(policy.fromDeepLink('milkyvpn://import?url=http://sub.milky.homes/s/AbCdEf123456'), isNull);
      expect(policy.fromDeepLink('milkyvpn://other?url=https://sub.milky.homes/s/AbCdEf123456'), isNull);
      expect(policy.fromDeepLink('https://import?url=https://sub.milky.homes/s/AbCdEf123456'), isNull);
      expect(SubscriptionUrlPolicy.redact(Uri.parse('https://sub.milky.homes/s/AbCdEf123456')), isNot(contains('AbCdEf')));
    });
  });

  group('redactor', () {
    test('strips uuid, token, userinfo, query creds', () {
      const r = Redactor();
      final s = r.redact('vless://00000001-0000-4000-8000-000000000001@h:443?pbk=FAKEPBK_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab from https://sub.milky.homes/s/SECRET_TOKEN_1234');
      expect(s, isNot(contains('00000001-0000')));
      expect(s, isNot(contains('SECRET_TOKEN')));
      expect(s, isNot(contains('FAKEPBK')));
      expect(s, isNot(contains('sid=ab')));
      expect(r.errorClass(const SocketException('timed out')), 'timeout');
      expect(r.errorClass(null), 'unknown');
    });
  });

  group('repository + secure storage abstraction', () {
    test('import stores url and snapshot in secure store only; remove clears', () async {
      final store = MemorySecureStore();
      final repo = SubscriptionRepository(store: store, fetcher: FakeFetcher(fixture('subscription_16_fake.b64')));
      await repo.load();
      expect(repo.hasSubscription, isFalse);
      final snap = await repo.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');
      expect(snap.profiles.length, 16);
      expect(store.data.keys, containsAll(['subscription_url', 'subscription_snapshot']));
      expect(repo.redactedUrl, isNot(contains('AbCdEf')));
      final repo2 = SubscriptionRepository(store: store, fetcher: FakeFetcher(''));
      await repo2.load();
      expect(repo2.snapshot?.profiles.length, 16);
      await repo2.remove();
      expect(store.data, isEmpty);
    });
    test('rejects disallowed url without fetching', () async {
      final f = FakeFetcher('x');
      final repo = SubscriptionRepository(store: MemorySecureStore(), fetcher: f);
      await expectLater(repo.importFromUrl('http://sub.milky.homes/s/AbCdEf123456'), throwsA(isA<SubscriptionFetchException>()));
      expect(f.calls, 0);
    });
    test('empty subscription rejected', () async {
      final repo = SubscriptionRepository(store: MemorySecureStore(), fetcher: FakeFetcher('garbage\nmore'));
      await expectLater(repo.importFromUrl('https://sub.milky.homes/s/AbCdEf123456'), throwsA(predicate((e) => e is SubscriptionFetchException && e.errorClass == 'no_profiles')));
    });
  });

  group('profile selector', () {
    test('auto prefers Reality, bounded, filters by location', () {
      final all = parser.parse(fixture('subscription_16_fake.txt')).profiles;
      const sel = ProfileSelector();
      final auto = sel.candidates(all, LocationChoice.auto);
      expect(auto.length, 4);
      expect(auto.every((p) => p.kind == ProfileKind.vlessRealityTcp), isTrue);
      final us = sel.candidates(all, LocationChoice.usa, maxAttempts: 10);
      expect(us.length, 7);
      expect(us.every((p) => p.location == ServerLocation.usa), isTrue);
      expect(sel.candidates(all, LocationChoice.finland, maxAttempts: 10).length, 9);
      expect(sel.candidates(all.where((p) => p.kind == ProfileKind.other).toList(), LocationChoice.auto), isEmpty);
    });
  });
}
