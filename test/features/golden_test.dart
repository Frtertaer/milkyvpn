import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;
import '../support/harness.dart';

/// Every attempt fails, so the failure sheet is deterministic.
class _FailAllBridge extends FakeBridge {
  @override
  Future<void> connect(VpnProfile p) async {
    connectCalls.add(p.id);
    emit(VpnSnapshot(state: VpnState.connecting, profileId: p.id, profileRemark: p.redactedRemark));
    emit(VpnSnapshot(state: VpnState.error, profileId: p.id, errorCode: 'proxyerror'));
  }
}

/// Golden tests for the Milky Glass screens.
///
/// They are **opt-in** because golden PNGs depend on the host font stack and Skia
/// version, so committing them from one machine makes CI on another machine red:
///
///   MILKY_GOLDENS=1 flutter test --update-goldens test/features/golden_test.dart   # record
///   MILKY_GOLDENS=1 flutter test test/features/golden_test.dart                    # compare
///
/// The layout/overflow assertions in `home_states_test.dart` and `ui_smoke_test.dart`
/// always run, so `flutter test` on its own still verifies every screen builds.
void main() {
  final enabled = Platform.environment['MILKY_GOLDENS'] == '1';
  const skipReason = 'set MILKY_GOLDENS=1 to record/compare golden images';

  Future<void> record(WidgetTester tester, String name) async {
    await tester.pump(const Duration(milliseconds: 50));
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/$name.png'));
  }

  testWidgets('home disconnected (dark)', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, size: const Size(390, 844));
    await record(tester, 'home_disconnected_dark');
    vpn.dispose();
  }, skip: enabled ? false : skipReason);

  testWidgets('home disconnected (light)', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, themeMode: ThemeMode.light);
    await record(tester, 'home_disconnected_light');
    vpn.dispose();
  }, skip: enabled ? false : skipReason);

  testWidgets('home connecting', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final bridge = FakeBridge()..hang = true;
    final vpn = VpnController(bridge: bridge, attemptTimeout: const Duration(seconds: 30), maxAttempts: 2);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pump(const Duration(milliseconds: 30));
    await record(tester, 'home_connecting');
    vpn.dispose();
    await tester.pumpWidget(const SizedBox());
  }, skip: enabled ? false : skipReason);

  testWidgets('home connected', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pumpAndSettle();
    await record(tester, 'home_connected_finland');
    vpn.dispose();
    await tester.pumpWidget(const SizedBox());
  }, skip: enabled ? false : skipReason);

  testWidgets('subscription', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const ValueKey('milky_nav_1')));
    await tester.pumpAndSettle();
    await record(tester, 'subscription');
    vpn.dispose();
  }, skip: enabled ? false : skipReason);

  testWidgets('settings', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const ValueKey('milky_nav_2')));
    await tester.pumpAndSettle();
    await record(tester, 'settings');
    vpn.dispose();
  }, skip: enabled ? false : skipReason);

  testWidgets('failure sheet', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final bridge = _FailAllBridge();
    final vpn = VpnController(bridge: bridge, attemptTimeout: const Duration(milliseconds: 200), maxAttempts: 2);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pumpAndSettle();
    await record(tester, 'failure_sheet');
    vpn.dispose();
    await tester.pumpWidget(const SizedBox());
  }, skip: enabled ? false : skipReason);

  testWidgets('onboarding page 1', (tester) async {
    final repo = await emptyRepo();
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, onboardingDone: false);
    await record(tester, 'onboarding_1');
    vpn.dispose();
  }, skip: enabled ? false : skipReason);

  testWidgets('tablet home', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, size: const Size(1024, 1366));
    await record(tester, 'home_tablet');
    vpn.dispose();
  }, skip: enabled ? false : skipReason);
}
