import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/app/app_settings.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'vpn_controller_test.dart' show FakeBridge, p;

class _RecoveryFetch implements SubscriptionFetcher {
  @override
  Future<FetchedSubscription> fetch(Uri url) async => FetchedSubscription(
    body:
        'vless://00000001-0000-4000-8000-000000000001@fi.example.invalid:443?security=tls#Finland',
    headers: const {},
  );
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('damaged cache retains validated credential and can refresh', () async {
    final store = MemorySecureStore();
    store.data['subscription_url'] =
        'https://sub.milky.homes/s/SYNTHETIC_12345';
    store.data['subscription_snapshot'] = '{broken';
    final repo = SubscriptionRepository(
      store: store,
      fetcher: _RecoveryFetch(),
    );
    await repo.load();
    expect(repo.hasSubscription, isTrue);
    expect(repo.snapshot, isNull);
    expect(repo.needsRefresh, isTrue);
    expect((await repo.refresh())!.parsedProfileCount, 1);
  });

  test(
    'unknown preference indices and types fall back to system and Auto',
    () async {
      for (final value in <Object>[-1, 99, 'removed-enum']) {
        SharedPreferences.setMockInitialValues({
          'theme_mode': value,
          'location': value,
        });
        final settings = await AppSettings.load();
        expect(settings.themeMode, ThemeMode.system);
        expect(settings.location, LocationChoice.auto);
      }
    },
  );

  test(
    'remark strips URLs, bearer credentials and unrelated keys before bridge',
    () {
      final profile = p(
        'a',
        remark:
            'Finland https://sub.milky.homes/s/SECRET_TOKEN Bearer EXAMPLE_AUTH ?pbk=OTHER_KEY',
      );
      final label = profile.redactedRemark;
      for (final secret in [
        'https://',
        'SECRET_TOKEN',
        'EXAMPLE_AUTH',
        'OTHER_KEY',
      ]) {
        expect(label, isNot(contains(secret)));
      }
      expect(profile.toBridgeMap()['remark'], label);
    },
  );

  test('late connected event for A cannot complete B verification', () async {
    final bridge = FakeBridge()..hang = true;
    final controller = VpnController(
      bridge: bridge,
      attemptTimeout: const Duration(seconds: 2),
    );
    final pending = controller.connect([p('a'), p('b')], LocationChoice.auto);
    await Future<void>.delayed(const Duration(milliseconds: 10));
    bridge.emit(
      const VpnSnapshot(
        state: VpnState.error,
        profileId: 'a',
        errorCode: 'timeout',
      ),
    );
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(bridge.connectCalls, ['a', 'b']);
    bridge.emit(const VpnSnapshot(state: VpnState.connected, profileId: 'a'));
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(controller.isConnected, isFalse);
    expect(controller.attemptingLocation, ServerLocation.finland);
    bridge.emit(const VpnSnapshot(state: VpnState.connected, profileId: 'b'));
    expect(await pending, isTrue);
    expect(controller.activeProfile!.id, 'b');
    controller.dispose();
  });

  test(
    'cancel during verification rejects subsequent connected event',
    () async {
      final bridge = FakeBridge()..hang = true;
      final controller = VpnController(
        bridge: bridge,
        attemptTimeout: const Duration(seconds: 2),
      );
      final pending = controller.connect([p('a'), p('b')], LocationChoice.auto);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      await controller.disconnect();
      bridge.emit(const VpnSnapshot(state: VpnState.connected, profileId: 'a'));
      expect(await pending, isFalse);
      await Future<void>.delayed(Duration.zero);
      expect(controller.isConnected, isFalse);
      expect(bridge.connectCalls, ['a']);
      controller.dispose();
    },
  );
}
