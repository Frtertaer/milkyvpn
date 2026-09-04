import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/app/app_settings.dart';
import 'package:milkyvpn/app/milky_device.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;

/// Bridge that reports an emulator, so diagnostics can be asserted end to end.
class EmulatorBridge extends FakeBridge {
  @override
  Future<Map<String, Object?>> deviceInfo() async => <String, Object?>{
        'sdkInt': 34,
        'release': '14',
        'abi': 'x86_64',
        'model': 'sdk_gphone64_x86_64',
        'manufacturer': 'Google',
        'isEmulator': true,
      };
}

class _NoFetch implements SubscriptionFetcher {
  @override
  Future<FetchedSubscription> fetch(Uri url) async => throw SubscriptionFetchException('offline');
}

class _FixtureFetch implements SubscriptionFetcher {
  _FixtureFetch(this.body);
  final String body;
  @override
  Future<FetchedSubscription> fetch(Uri url) async => FetchedSubscription(body: body, headers: const {});
}

/// Pumps the real app.
///
/// `disableAnimations` stops the ambient orb/aurora loops so `pumpAndSettle` terminates —
/// the same path a user takes when the OS asks apps to reduce motion.
Future<void> pumpMilky(
  WidgetTester tester, {
  required SubscriptionRepository repo,
  required VpnController vpn,
  FakeBridge? bridge,
  MilkyDevice device = const MilkyDevice(),
  bool onboardingDone = true,
  ThemeMode themeMode = ThemeMode.dark,
  Size size = const Size(390, 844),
}) async {
  SharedPreferences.setMockInitialValues(<String, Object>{
    'onboarding_done': onboardingDone,
    'theme_mode': themeMode.index,
  });
  final settings = await AppSettings.load();
  final b = bridge ?? FakeBridge();
  await tester.binding.setSurfaceSize(size);
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MediaQuery(
      data: MediaQueryData(size: size, disableAnimations: true),
      child: MilkyApp(settings: settings, repo: repo, vpn: vpn, bridge: b, device: device),
    ),
  );
  await tester.pumpAndSettle();
}

Future<SubscriptionRepository> emptyRepo() async {
  final repo = SubscriptionRepository(store: MemorySecureStore(), fetcher: _NoFetch());
  await repo.load();
  return repo;
}

/// A repository already holding a parsed subscription (no network in tests).
Future<SubscriptionRepository> repoWith(String body) async {
  final repo = SubscriptionRepository(store: MemorySecureStore(), fetcher: _FixtureFetch(body));
  await repo.load();
  await repo.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');
  return repo;
}

String fixture(String name) => File('test/fixtures/$name').readAsStringSync();
