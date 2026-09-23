import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;
import '../support/harness.dart';
import 'package:milkyvpn/app/milky_device.dart';
import 'package:milkyvpn/design/milky_sheet.dart';
import 'package:milkyvpn/features/home/home_screen.dart';

/// Every attempt fails, so the failure sheet is deterministic.
class _FailAllBridge extends FakeBridge {
  @override
  Future<void> connect(VpnProfile p) async {
    connectCalls.add(p.id);
    emit(
      VpnSnapshot(
        state: VpnState.connecting,
        profileId: p.id,
        profileRemark: p.redactedRemark,
      ),
    );
    emit(
      VpnSnapshot(
        state: VpnState.error,
        profileId: p.id,
        errorCode: 'proxyerror',
      ),
    );
  }
}

/// Mandatory golden tests render the real Flutter application with bundled fonts.
///
void main() {
  Future<void> record(WidgetTester tester, String name) async {
    await tester.pump(const Duration(milliseconds: 50));
    await expectLater(
      find.byType(MaterialApp),
      matchesGoldenFile('goldens/$name.png'),
    );
  }

  testWidgets('home disconnected (dark)', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, size: const Size(390, 844));
    await record(tester, 'home_disconnected_dark');
    vpn.dispose();
  });

  testWidgets('home disconnected (light)', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, themeMode: ThemeMode.light);
    await record(tester, 'home_disconnected_light');
    vpn.dispose();
  });

  testWidgets('home connecting', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final bridge = FakeBridge()..hang = true;
    final vpn = VpnController(
      bridge: bridge,
      attemptTimeout: const Duration(seconds: 30),
      maxAttempts: 2,
    );
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pump(const Duration(milliseconds: 30));
    await record(tester, 'home_connecting');
    bridge.emit(
      VpnSnapshot(
        state: VpnState.connected,
        profileId: bridge.connectCalls.first,
        profileRemark: 'Finland',
        connectedSince: DateTime.now(),
      ),
    );
    await tester.pumpAndSettle();
    vpn.dispose();
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('home connected', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pumpAndSettle();
    await record(tester, 'home_connected_finland');
    vpn.dispose();
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('subscription', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const ValueKey('milky_nav_1')));
    await tester.pumpAndSettle();
    await record(tester, 'subscription');
    vpn.dispose();
  });

  testWidgets('settings', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const ValueKey('milky_nav_2')));
    await tester.pumpAndSettle();
    await record(tester, 'settings');
    vpn.dispose();
  });

  testWidgets('failure sheet', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final bridge = _FailAllBridge();
    final vpn = VpnController(
      bridge: bridge,
      attemptTimeout: const Duration(milliseconds: 200),
      maxAttempts: 2,
    );
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pumpAndSettle();
    await record(tester, 'failure_sheet');
    vpn.dispose();
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('onboarding page 1', (tester) async {
    final repo = await emptyRepo();
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, onboardingDone: false);
    await record(tester, 'onboarding_1');
    vpn.dispose();
  });

  testWidgets('tablet home', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, size: const Size(1024, 1366));
    await record(tester, 'home_tablet');
    vpn.dispose();
  });
  for (final page in [2, 3]) {
    testWidgets('onboarding page $page', (tester) async {
      final repo = await emptyRepo();
      final vpn = VpnController(bridge: FakeBridge());
      await pumpMilky(tester, repo: repo, vpn: vpn, onboardingDone: false);
      await tester.tap(find.text('Продолжить'));
      await tester.pumpAndSettle();
      if (page == 3) {
        await tester.tap(find.text('Понятно, продолжить'));
        await tester.pumpAndSettle();
      }
      await record(tester, 'onboarding_$page');
      await tester.pumpWidget(const SizedBox());
      vpn.dispose();
    });
  }

  testWidgets('connected USA', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.text('США'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pumpAndSettle();
    expect(vpn.activeLocation, ServerLocation.usa);
    await record(tester, 'home_connected_usa');
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  testWidgets('manual Finland connecting', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final bridge = FakeBridge()..hang = true;
    final vpn = VpnController(bridge: bridge);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);
    await tester.tap(find.text('Финляндия'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pump(const Duration(milliseconds: 30));
    await record(tester, 'home_connecting_finland');
    await vpn.disconnect();
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  testWidgets('diagnostics and private details sheet', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final bridge = EmulatorBridge();
    final vpn = VpnController(bridge: bridge);
    await pumpMilky(
      tester,
      repo: repo,
      vpn: vpn,
      bridge: bridge,
      device: await MilkyDevice.load(bridge),
    );
    await tester.tap(find.byKey(const ValueKey('milky_nav_2')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Диагностика'));
    await tester.tap(find.text('Диагностика'));
    await tester.pumpAndSettle();
    await record(tester, 'diagnostics');
    await tester.ensureVisible(find.text('Детали отчёта'));
    await tester.tap(find.text('Детали отчёта'));
    await tester.pumpAndSettle();
    await record(tester, 'diagnostics_details');
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  testWidgets('remove subscription sheet', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    await tester.tap(find.byKey(const ValueKey('milky_nav_1')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Удалить подписку'));
    await tester.pumpAndSettle();
    await record(tester, 'remove_subscription');
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  testWidgets('import success uses the actual parsed counts', (tester) async {
    final repo = await repoWith(
      fixture('subscription_16_fake.txt'),
      goldenDates: true,
    );
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    final context = tester.element(find.byType(HomeScreen));
    final snap = repo.snapshot!;
    final sheet = MilkySuccessSheet.show(
      context,
      parsedCount: snap.parsedProfileCount,
      compatibleCount: snap.profiles.where((p) => p.isStaticCompatible).length,
    );
    await tester.pumpAndSettle();
    expect(find.text('Подписка добавлена'), findsOneWidget);
    await record(tester, 'import_success');
    await tester.tap(find.text('Перейти к подключению'));
    await tester.pumpAndSettle();
    expect(await sheet, isTrue);
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  for (final entry in <String, Size>{
    'home_small': const Size(320, 568),
    'home_large': const Size(430, 932),
    'tablet_landscape': const Size(1280, 800),
  }.entries) {
    testWidgets(entry.key, (tester) async {
      final repo = await repoWith(
        fixture('subscription_16_fake.txt'),
        goldenDates: true,
      );
      final vpn = VpnController(bridge: FakeBridge());
      await pumpMilky(tester, repo: repo, vpn: vpn, size: entry.value);
      await record(tester, entry.key);
      await tester.pumpWidget(const SizedBox());
      vpn.dispose();
    });
  }
}
