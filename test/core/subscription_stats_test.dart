import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_parser.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/subscription/subscription_stats.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';

import 'subscription_test.dart' show FakeFetcher;

String fixture(String name) => File('test/fixtures/$name').readAsStringSync();

List<String> fixtureLines() => fixture(
  'subscription_16_fake.txt',
).split('\n').where((line) => line.isNotEmpty).toList();

/// Six byte-identical repeats: these are true duplicates.
String duplicateHeavySubscription() {
  final lines = fixtureLines();
  return [...lines.take(10), ...lines.take(6)].join('\n');
}

/// Six entries share the old endpoint-only key with the first six but have new UUIDs.
String sameEndpointDifferentCredentials() {
  final lines = fixtureLines();
  final twins = <String>[];
  for (var index = 0; index < 6; index++) {
    twins.add(
      lines[index].replaceFirst(
        RegExp(r'^vless://[0-9a-fA-F-]+@'),
        'vless://000000ff-0000-4000-8000-00000000000$index@',
      ),
    );
  }
  return [...lines.take(10), ...twins].join('\n');
}

String identityVless({
  String uuid = '10000000-0000-4000-8000-000000000001',
  String address = 'edge.example.invalid',
  int port = 443,
  String remark = 'Finland Primary',
  Map<String, String> overrides = const {},
  bool reverseQuery = false,
}) {
  final query = <String, String>{
    'type': 'xhttp',
    'security': 'reality',
    'sni': 'front.example.invalid',
    'fp': 'chrome',
    'pbk': 'PUBLIC_KEY_A',
    'sid': 'abcd',
    'spx': '/crawl-a',
    'flow': 'xtls-rprx-vision',
    'host': 'cdn.example.invalid',
    'path': '/milky',
    'mode': 'packet-up',
    'alpn': 'h2,http/1.1',
    'allowInsecure': '0',
  };
  for (final entry in overrides.entries) {
    if (entry.value == '__omit__') {
      query.remove(entry.key);
    } else {
      query[entry.key] = entry.value;
    }
  }
  final entries = reverseQuery
      ? query.entries.toList().reversed
      : query.entries;
  final encodedQuery = entries
      .map(
        (entry) =>
            '${Uri.encodeQueryComponent(entry.key)}='
            '${Uri.encodeQueryComponent(entry.value)}',
      )
      .join('&');
  return 'vless://$uuid@$address:$port?$encodedQuery#'
      '${Uri.encodeComponent(remark)}';
}

String identityHysteria({
  String scheme = 'hysteria2',
  String password = 'password-a',
  String obfsPassword = 'obfs-a',
  String insecure = '0',
  String remark = 'Finland Hysteria',
}) =>
    '$scheme://$password@hy.example.invalid:443?'
    'sni=hy.example.invalid&alpn=h3&insecure=$insecure&'
    'obfs=salamander&obfs-password=$obfsPassword#'
    '${Uri.encodeComponent(remark)}';

String legacyEndpointIdentity(VpnProfile profile) => [
  profile.protocol,
  profile.address,
  profile.port,
  VpnProfile.normalizeNetwork(profile.network),
  profile.security,
  profile.path ?? '',
].join('|');

Map<String, dynamic> storedSnapshot(MemorySecureStore store) =>
    jsonDecode(store.data['subscription_snapshot']!) as Map<String, dynamic>;

void removeCurrentCountSchema(Map<String, dynamic> snapshot) {
  for (final key in [
    'schemaVersion',
    'receivedEntryCount',
    'parsedProfileCount',
    'postDedupeProfileCount',
    'droppedDuplicateCount',
    'malformedEntryCount',
  ]) {
    snapshot.remove(key);
  }
}

void main() {
  const parser = SubscriptionParser();

  group('explicit subscription metrics', () {
    test('clean canonical fixture reports every boundary as 16', () {
      final result = parser.parse(fixture('subscription_16_fake.txt'));

      expect(result.receivedEntryCount, 16);
      expect(result.parsedProfileCount, 16);
      expect(result.postDedupeProfileCount, 16);
      expect(result.droppedDuplicateCount, 0);
      expect(result.malformedEntryCount, 0);
      expect(result.compatibleProfileCount, 16);
      expect(result.isAccounted, isTrue);

      final stats = SubscriptionStats(
        totalLines: result.totalLines,
        profiles: result.profiles.length,
        malformed: result.malformedLines,
        duplicates: result.duplicateEntries,
        compatible: result.compatibleProfileCount,
      );
      expect(stats.receivedEntryCount, 16);
      expect(stats.parsedProfileCount, 16);
      expect(stats.postDedupeProfileCount, 16);
      expect(stats.droppedDuplicateCount, 0);
      expect(stats.malformedEntryCount, 0);
      expect(stats.compatibleProfileCount, 16);
      expect(stats.isAccounted, isTrue);
      expect(stats.needsRefresh, isFalse);
      expect(stats.incompatible, 0);
    });

    test(
      'true duplicates are counted: 16 received -> 16 parsed -> 10 retained',
      () {
        final result = parser.parse(duplicateHeavySubscription());

        expect(result.receivedEntryCount, 16);
        expect(result.parsedProfileCount, 16);
        expect(result.postDedupeProfileCount, 10);
        expect(result.droppedDuplicateCount, 6);
        expect(result.malformedEntryCount, 0);
        expect(result.isAccounted, isTrue);
      },
    );

    test('malformed control reports 16 received -> 10 parsed', () {
      final body = [
        ...fixtureLines().take(10),
        'not-a-uri',
        'unknown://credential@unknown.example.invalid:443',
        'vless://not-a-uuid@bad.example.invalid:443',
        'hysteria2://@empty.example.invalid:443',
        'vless://10000000-0000-4000-8000-000000000001@bad port:443',
        'vless://10000000-0000-4000-8000-000000000001@bad.example.invalid:70000',
      ].join('\n');

      final result = parser.parse(body);
      expect(result.receivedEntryCount, 16);
      expect(result.parsedProfileCount, 10);
      expect(result.postDedupeProfileCount, 10);
      expect(result.droppedDuplicateCount, 0);
      expect(result.malformedEntryCount, 6);
      expect(result.compatibleProfileCount, 10);
      expect(result.isAccounted, isTrue);
    });

    test('unsupported control reports 16 parsed and 10 compatible', () {
      final body = [
        ...fixtureLines().take(10),
        'vmess://data@us9.example.invalid:443#USA-8',
        'trojan://pw@us10.example.invalid:443#USA-9',
        'ss://YWVz@us11.example.invalid:8388#USA-10',
        'vless://00000010-0000-4000-8000-000000000010@us12.example.invalid:443?type=grpc&security=tls#USA-11',
        'vless://00000011-0000-4000-8000-000000000011@us13.example.invalid:443?type=tcp&security=reality&sni=www.example.com#USA-12',
        'vless://00000012-0000-4000-8000-000000000012@us14.example.invalid:443?type=ws&security=reality&pbk=PUBLIC_KEY_H#USA-13',
      ].join('\n');

      final result = parser.parse(body);
      expect(result.receivedEntryCount, 16);
      expect(result.parsedProfileCount, 16);
      expect(result.postDedupeProfileCount, 16);
      expect(result.droppedDuplicateCount, 0);
      expect(result.malformedEntryCount, 0);
      expect(result.compatibleProfileCount, 10);
    });
  });

  group('canonical profile identity', () {
    test('regression fixture proves the old 16 -> 10 collision class', () {
      final result = parser.parse(sameEndpointDifferentCredentials());
      final oldKeys = result.profiles.map(legacyEndpointIdentity).toSet();

      expect(
        oldKeys.length,
        10,
        reason: 'control must collide under the old key',
      );
      expect(result.receivedEntryCount, 16);
      expect(result.postDedupeProfileCount, 16);
      expect(result.droppedDuplicateCount, 0);
    });

    test(
      'each connection or selection field independently prevents collapse',
      () {
        final base = identityVless();
        final mutations = <String, String>{
          'UUID': identityVless(uuid: '20000000-0000-4000-8000-000000000002'),
          'address': identityVless(address: 'edge-2.example.invalid'),
          'port': identityVless(port: 8443),
          'network': identityVless(overrides: const {'type': 'ws'}),
          'security': identityVless(overrides: const {'security': 'tls'}),
          'SNI': identityVless(
            overrides: const {'sni': 'other-front.example.invalid'},
          ),
          'fingerprint': identityVless(overrides: const {'fp': 'firefox'}),
          'Reality public key': identityVless(
            overrides: const {'pbk': 'PUBLIC_KEY_B'},
          ),
          'Reality short id': identityVless(overrides: const {'sid': 'dcba'}),
          'Reality spiderX': identityVless(
            overrides: const {'spx': '/crawl-b'},
          ),
          'flow': identityVless(overrides: const {'flow': 'different-flow'}),
          'HTTP host': identityVless(
            overrides: const {'host': 'cdn-2.example.invalid'},
          ),
          'path': identityVless(overrides: const {'path': '/other'}),
          'XHTTP mode': identityVless(overrides: const {'mode': 'stream-up'}),
          'ALPN': identityVless(overrides: const {'alpn': 'http/1.1'}),
          'allowInsecure': identityVless(
            overrides: const {'allowInsecure': '1'},
          ),
          'remark': identityVless(remark: 'Finland Secondary'),
          'derived location': identityVless(
            remark: '\u0421\u0428\u0410 Secondary',
          ),
        };

        for (final entry in mutations.entries) {
          final result = parser.parse('$base\n${entry.value}');
          expect(
            result.postDedupeProfileCount,
            2,
            reason: '${entry.key} must be part of identity',
          );
          expect(result.droppedDuplicateCount, 0, reason: entry.key);
        }
      },
    );

    test(
      'hysteria password and obfuscation password independently prevent collapse',
      () {
        final base = identityHysteria();
        final passwordMutation = parser.parse(
          '$base\n${identityHysteria(password: 'password-b')}',
        );
        final obfsMutation = parser.parse(
          '$base\n${identityHysteria(obfsPassword: 'obfs-b')}',
        );

        expect(passwordMutation.postDedupeProfileCount, 2);
        expect(obfsMutation.postDedupeProfileCount, 2);
      },
    );

    test(
      'exact repeats collapse and opaque ids do not contain credentials',
      () {
        final base = identityVless();
        final result = parser.parse('$base\n$base');

        expect(result.postDedupeProfileCount, 1);
        expect(result.droppedDuplicateCount, 1);
        expect(result.profiles.single.id, isNot(contains('10000000')));
        expect(result.profiles.single.id, isNot(contains('PUBLIC_KEY_A')));
      },
    );

    test(
      'query order, aliases, defaults, host case, and bool syntax normalize',
      () {
        const uuid = '30000000-0000-4000-8000-000000000003';
        const explicit =
            'vless://$uuid@EDGE.example.invalid:443?path=%2F&fp=chrome&'
            'allowInsecure=0&servername=EDGE.example.invalid&pbk=KEY&'
            'security=REALITY&type=raw#Finland';
        const defaults =
            'vless://$uuid@edge.example.invalid:443?type=tcp&security=reality&'
            'pbk=KEY#Finland';

        final result = parser.parse('$explicit\n$defaults');
        expect(result.postDedupeProfileCount, 1);
        expect(result.droppedDuplicateCount, 1);

        final xhttpAliases = parser.parse(
          '${identityVless()}\n'
          '${identityVless(overrides: const {'type': 'splithttp'})}',
        );
        expect(xhttpAliases.postDedupeProfileCount, 1);

        final reordered = parser.parse(
          '${identityVless()}\n${identityVless(reverseQuery: true)}',
        );
        expect(reordered.postDedupeProfileCount, 1);

        final boolAliases = parser.parse(
          '${identityVless(overrides: const {'allowInsecure': '1'})}\n'
          '${identityVless(overrides: const {'allowInsecure': 'TRUE'})}',
        );
        expect(boolAliases.postDedupeProfileCount, 1);
      },
    );

    test('normalized identity fields match the native payload', () {
      const uuid = '40000000-0000-4000-8000-000000000004';
      const padded =
          'vless://$uuid@edge.example.invalid:443?type=%20RAW%20&'
          'security=%20REALITY%20&sni=%20Front.Example.Invalid%20&'
          'host=%20CDN.Example.Invalid%20&fp=%20CHROME%20&'
          'mode=%20AUTO%20&pbk=KEY#Finland';
      const canonical =
          'vless://$uuid@edge.example.invalid:443?type=tcp&security=reality&'
          'sni=Front.Example.Invalid&host=CDN.Example.Invalid&fp=chrome&'
          'mode=auto&pbk=KEY#Finland';

      final result = parser.parse('$padded\n$canonical');
      expect(result.postDedupeProfileCount, 1);
      expect(result.droppedDuplicateCount, 1);

      final profile = result.profiles.single;
      expect(profile.network, 'tcp');
      expect(profile.security, 'reality');
      expect(profile.sni, 'Front.Example.Invalid');
      expect(profile.host, 'CDN.Example.Invalid');
      expect(profile.fingerprint, 'chrome');
      expect(profile.xhttpMode, 'auto');
      expect(profile.isStaticCompatible, isTrue);
    });

    test('hy2 and hysteria2 aliases normalize', () {
      final result = parser.parse(
        '${identityHysteria()}\n${identityHysteria(scheme: 'hy2')}',
      );
      expect(result.postDedupeProfileCount, 1);
      expect(result.droppedDuplicateCount, 1);
    });

    test('Russian remarks derive stable public locations', () {
      final finland = parser.parseLine(
        identityVless(
          remark: '\u0424\u0438\u043d\u043b\u044f\u043d\u0434\u0438\u044f',
        ),
      );
      final usa = parser.parseLine(
        identityVless(
          remark:
              '\u0421\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u043d\u044b\u0435 \u0428\u0442\u0430\u0442\u044b',
        ),
      );
      expect(finland?.location, ServerLocation.finland);
      expect(usa?.location, ServerLocation.usa);
    });

    test('diagnostic remark strips profile credential material', () {
      const profile = VpnProfile(
        id: 'opaque',
        protocol: 'vless',
        address: 'edge.example.invalid',
        port: 443,
        secret: '10000000-0000-4000-8000-000000000001',
        remark:
            'Node 10000000-0000-4000-8000-000000000001 PUBLIC_KEY abcd obfs-secret',
        publicKey: 'PUBLIC_KEY',
        shortId: 'abcd',
        obfsPassword: 'obfs-secret',
      );

      final diagnostic = profile.toDiagnosticString();
      expect(diagnostic, isNot(contains(profile.secret)));
      expect(diagnostic, isNot(contains(profile.publicKey!)));
      expect(diagnostic, isNot(contains(profile.shortId!)));
      expect(diagnostic, isNot(contains(profile.obfsPassword!)));
    });
  });

  group('compatibility boundary', () {
    test(
      'static compatibility rejects invalid security accepted by old XHTTP check',
      () {
        final profile = parser.parseLine(
          identityVless(overrides: const {'security': 'mystery'}),
        );
        expect(profile, isNotNull);
        expect(profile!.kind, ProfileKind.vlessXhttp);
        expect(profile.isStaticCompatible, isFalse);
      },
    );

    test(
      'static compatibility covers supported and rejected profile families',
      () {
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
      },
    );
  });

  group('snapshot schema and migration', () {
    test(
      'current snapshot round-trip keeps explicit trusted counters',
      () async {
        final store = MemorySecureStore();
        final repository = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(duplicateHeavySubscription()),
        );
        await repository.load();
        final snapshot = await repository.importFromUrl(
          'https://sub.milky.homes/s/AbCdEf123456',
        );

        expect(
          snapshot.schemaVersion,
          SubscriptionSnapshot.currentSchemaVersion,
        );
        expect(snapshot.receivedEntryCount, 16);
        expect(snapshot.parsedProfileCount, 16);
        expect(snapshot.postDedupeProfileCount, 10);
        expect(snapshot.droppedDuplicateCount, 6);
        expect(snapshot.malformedEntryCount, 0);
        expect(snapshot.countsTrusted, isTrue);

        final encoded = storedSnapshot(store);
        expect(encoded['receivedEntryCount'], 16);
        expect(encoded['parsedProfileCount'], 16);
        expect(encoded['postDedupeProfileCount'], 10);
        expect(encoded['droppedDuplicateCount'], 6);

        final reopened = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(''),
        );
        await reopened.load();
        final stats = SubscriptionStats.from(reopened.snapshot);
        expect(reopened.countsTrusted, isTrue);
        expect(reopened.needsRefresh, isFalse);
        expect(stats.countsTrusted, isTrue);
        expect(stats.isAccounted, isTrue);
        expect(stats.parsedProfileCount, 16);
        expect(stats.postDedupeProfileCount, 10);
      },
    );

    test(
      'legacy stale 10 loads without fetch but marks counts untrusted',
      () async {
        final store = MemorySecureStore();
        final writer = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(duplicateHeavySubscription()),
        );
        await writer.load();
        await writer.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');

        final legacy = storedSnapshot(store);
        removeCurrentCountSchema(legacy);
        legacy['total'] = 16;
        legacy['malformed'] = 0;
        legacy.remove('duplicates');
        store.data['subscription_snapshot'] = jsonEncode(legacy);

        final fetcher = FakeFetcher(fixture('subscription_16_fake.txt'));
        final reopened = SubscriptionRepository(store: store, fetcher: fetcher);
        await reopened.load();

        expect(
          fetcher.calls,
          0,
          reason: 'load must never refresh over the network',
        );
        expect(reopened.snapshot?.profiles.length, 10);
        expect(reopened.snapshot?.schemaVersion, 0);
        expect(reopened.snapshot?.countsTrusted, isFalse);
        expect(reopened.countsTrusted, isFalse);
        expect(reopened.needsRefresh, isTrue);
        final staleStats = SubscriptionStats.from(reopened.snapshot);
        expect(staleStats.countsTrusted, isFalse);
        expect(staleStats.needsRefresh, isTrue);

        final refreshed = await reopened.refresh();
        expect(fetcher.calls, 1);
        expect(refreshed?.postDedupeProfileCount, 16);
        expect(refreshed?.countsTrusted, isTrue);
        expect(reopened.needsRefresh, isFalse);
      },
    );

    test(
      'unversioned snapshot stays untrusted even when legacy totals reconcile',
      () async {
        final store = MemorySecureStore();
        final writer = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(duplicateHeavySubscription()),
        );
        await writer.load();
        await writer.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');

        final legacy = storedSnapshot(store);
        removeCurrentCountSchema(legacy);
        store.data['subscription_snapshot'] = jsonEncode(legacy);

        final reopened = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(''),
        );
        await reopened.load();
        expect(reopened.snapshot?.isCountInvariantValid, isTrue);
        expect(reopened.snapshot?.countsTrusted, isFalse);
        expect(reopened.needsRefresh, isTrue);
      },
    );

    test(
      'current schema with contradictory redundant count is untrusted',
      () async {
        final store = MemorySecureStore();
        final writer = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(duplicateHeavySubscription()),
        );
        await writer.load();
        await writer.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');

        final corrupt = storedSnapshot(store);
        corrupt['parsedProfileCount'] = 15;
        store.data['subscription_snapshot'] = jsonEncode(corrupt);

        final reopened = SubscriptionRepository(
          store: store,
          fetcher: FakeFetcher(''),
        );
        await reopened.load();
        expect(reopened.snapshot?.countsTrusted, isFalse);
        expect(reopened.needsRefresh, isTrue);
      },
    );

    test(
      'URL without snapshot needs refresh, but load remains offline',
      () async {
        final store = MemorySecureStore();
        store.data['subscription_url'] =
            'https://sub.milky.homes/s/AbCdEf123456';
        final fetcher = FakeFetcher(fixture('subscription_16_fake.txt'));
        final repository = SubscriptionRepository(
          store: store,
          fetcher: fetcher,
        );

        await repository.load();
        expect(repository.hasSubscription, isTrue);
        expect(repository.snapshot, isNull);
        expect(repository.countsTrusted, isFalse);
        expect(repository.needsRefresh, isTrue);
        expect(fetcher.calls, 0);
      },
    );

    test('no subscription does not request a refresh', () async {
      final repository = SubscriptionRepository(
        store: MemorySecureStore(),
        fetcher: FakeFetcher(''),
      );
      await repository.load();
      expect(repository.needsRefresh, isFalse);
    });
  });
}
