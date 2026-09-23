import 'dart:io';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/app/app_settings.dart';
import 'package:milkyvpn/app/milky_device.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;

bool _fontsLoaded = false;

/// Widget tests do not load application fonts automatically. Goldens must rasterize the
/// same bundled Manrope and Material icon assets as the Android application, otherwise
/// Cyrillic and icons appear as tofu squares and the snapshot is not a product review.
Future<void> loadMilkyTestFonts() async {
  if (_fontsLoaded) return;
  final manrope = FontLoader('Manrope')
    ..addFont(rootBundle.load('assets/fonts/Manrope-Regular.ttf'))
    ..addFont(rootBundle.load('assets/fonts/Manrope-Medium.ttf'))
    ..addFont(rootBundle.load('assets/fonts/Manrope-SemiBold.ttf'))
    ..addFont(rootBundle.load('assets/fonts/Manrope-Bold.ttf'))
    ..addFont(rootBundle.load('assets/fonts/Manrope-ExtraBold.ttf'));
  final material = FontLoader('MaterialIcons')
    ..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'));
  await Future.wait([manrope.load(), material.load()]);
  _fontsLoaded = true;
}

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
  Future<FetchedSubscription> fetch(Uri url) async =>
      throw SubscriptionFetchException('offline');
}

class _FixtureFetch implements SubscriptionFetcher {
  _FixtureFetch(this.body);
  final String body;
  @override
  Future<FetchedSubscription> fetch(Uri url) async =>
      FetchedSubscription(body: body, headers: const {});
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
  await loadMilkyTestFonts();
  SharedPreferences.setMockInitialValues(<String, Object>{
    'onboarding_done': onboardingDone,
    'theme_mode': themeMode.index,
  });
  final settings = await AppSettings.load();
  final b = bridge ?? FakeBridge();
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = size;
  addTearDown(() {
    tester.view.resetDevicePixelRatio();
    tester.view.resetPhysicalSize();
  });
  await tester.pumpWidget(
    MediaQuery(
      data: MediaQueryData.fromView(
        tester.view,
      ).copyWith(disableAnimations: true),
      child: MilkyApp(
        settings: settings,
        repo: repo,
        vpn: vpn,
        bridge: b,
        device: device,
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<SubscriptionRepository> emptyRepo() async {
  final repo = SubscriptionRepository(
    store: MemorySecureStore(),
    fetcher: _NoFetch(),
  );
  await repo.load();
  return repo;
}

/// A repository already holding a parsed subscription (no network in tests).
Future<SubscriptionRepository> repoWith(
  String body, {
  bool goldenDates = false,
}) async {
  final store = MemorySecureStore();
  final repo = SubscriptionRepository(
    store: store,
    fetcher: _FixtureFetch(body),
  );
  await repo.load();
  await repo.importFromUrl('https://sub.milky.homes/s/AbCdEf123456');
  if (goldenDates) {
    final cached =
        jsonDecode(store.data['subscription_snapshot']!)
            as Map<String, dynamic>;
    cached['updatedAt'] = '2026-09-05T09:00:00Z';
    cached['expiresAt'] = '2100-01-01T00:00:00Z';
    store.data['subscription_snapshot'] = jsonEncode(cached);
    await repo.load();
  }
  return repo;
}

String fixture(String name) => File('test/fixtures/$name').readAsStringSync();
