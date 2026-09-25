import 'dart:ui' show Tristate;

import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/design/milky_connect_orb.dart';
import 'package:milkyvpn/design/milky_theme.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;
import '../support/harness.dart';

const _smallPhone = Size(320, 568);

void _useTextScale(WidgetTester tester, double scale) {
  tester.platformDispatcher.textScaleFactorTestValue = scale;
  addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
}

void _expectNoLayoutError(WidgetTester tester, String screen) {
  expect(tester.takeException(), isNull, reason: '$screen must not overflow');
}

Future<void> _disposeApp(WidgetTester tester, VpnController vpn) async {
  vpn.dispose();
  await tester.pumpWidget(const SizedBox.shrink());
}

Finder _labelledSemantics(String label) => find.byWidgetPredicate(
  (widget) => widget is Semantics && widget.properties.label == label,
  description: 'Semantics(label: $label)',
);

void main() {
  for (final scale in <double>[1, 1.5, 2]) {
    testWidgets(
      '320x568 onboarding keeps all three Russian steps usable at ${scale}x text',
      (tester) async {
        _useTextScale(tester, scale);
        final repo = await emptyRepo();
        final bridge = FakeBridge();
        final vpn = VpnController(bridge: bridge);

        await pumpMilky(
          tester,
          repo: repo,
          vpn: vpn,
          bridge: bridge,
          onboardingDone: false,
          size: _smallPhone,
        );

        expect(find.text('VPN без сложных настроек'), findsOneWidget);
        expect(
          MediaQuery.textScalerOf(
            tester.element(find.text('VPN без сложных настроек')),
          ).scale(16),
          closeTo(16 * scale, 0.01),
        );
        _expectNoLayoutError(tester, 'onboarding step 1 at ${scale}x');

        await tester.tap(find.text('Продолжить'));
        await tester.pumpAndSettle();
        expect(find.text('Защищённое VPN-соединение'), findsOneWidget);
        expect(find.text('Телефон'), findsOneWidget);
        expect(find.text('Интернет'), findsOneWidget);
        _expectNoLayoutError(tester, 'onboarding step 2 at ${scale}x');

        await tester.tap(find.text('Понятно, продолжить'));
        await tester.pumpAndSettle();
        expect(find.text('Добавьте подписку'), findsWidgets);
        expect(find.text('Добавить подписку'), findsOneWidget);
        expect(find.text('Помощь'), findsOneWidget);
        _expectNoLayoutError(tester, 'onboarding step 3 at ${scale}x');

        await _disposeApp(tester, vpn);
      },
    );

    testWidgets('320x568 subscription remains readable at ${scale}x text', (
      tester,
    ) async {
      _useTextScale(tester, scale);
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);

      await pumpMilky(
        tester,
        repo: repo,
        vpn: vpn,
        bridge: bridge,
        size: _smallPhone,
      );

      await tester.tap(find.byKey(const ValueKey('milky_nav_1')));
      await tester.pumpAndSettle();
      expect(find.text('Профилей получено'), findsOneWidget);
      expect(find.text('Совместимо'), findsOneWidget);
      await tester.ensureVisible(find.text('Дополнительно'));
      await tester.tap(find.text('Дополнительно'));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        find.text('Скопировать ссылку'),
        180,
        scrollable: find.byType(Scrollable).first,
      );
      _expectNoLayoutError(tester, 'subscription at ${scale}x');

      await _disposeApp(tester, vpn);
    });

    testWidgets('320x568 settings remain readable at ${scale}x text', (
      tester,
    ) async {
      _useTextScale(tester, scale);
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);

      await pumpMilky(
        tester,
        repo: repo,
        vpn: vpn,
        bridge: bridge,
        size: _smallPhone,
      );

      await tester.tap(find.byKey(const ValueKey('milky_nav_2')));
      await tester.pumpAndSettle();
      expect(find.text('Автоподключение'), findsOneWidget);
      expect(find.text('Always-on VPN'), findsOneWidget);
      await tester.scrollUntilVisible(
        find.text('Версия'),
        180,
        scrollable: find.byType(Scrollable).first,
      );
      expect(find.text('Конфиденциальность'), findsOneWidget);
      _expectNoLayoutError(tester, 'settings at ${scale}x');

      await _disposeApp(tester, vpn);
    });
  }

  testWidgets('country selector exposes three 48dp semantic tap targets', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    try {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(
        tester,
        repo: repo,
        vpn: vpn,
        bridge: bridge,
        size: _smallPhone,
      );

      for (final label in <String>['Авто', 'Финляндия', 'США']) {
        final finder = _labelledSemantics(label);
        expect(finder, findsOneWidget);
        final widget = tester.widget<Semantics>(finder);
        expect(widget.properties.button, isTrue, reason: label);
        expect(widget.properties.enabled, isTrue, reason: label);
        final size = tester.getSize(finder);
        expect(size.width, greaterThanOrEqualTo(48), reason: label);
        expect(size.height, greaterThanOrEqualTo(48), reason: label);
      }

      await tester.scrollUntilVisible(
        find.text('США'),
        80,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.tap(_labelledSemantics('США'));
      await tester.pumpAndSettle();
      expect(
        tester.widget<Semantics>(_labelledSemantics('США')).properties.selected,
        isTrue,
      );
      await _disposeApp(tester, vpn);
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('orb is an enabled semantic action and honors reduced motion', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    try {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      final orb = find.byKey(const Key('connect_orb'));
      final data = tester.getSemantics(orb).getSemanticsData();
      expect(data.flagsCollection.isButton, isTrue);
      expect(data.flagsCollection.isEnabled, Tristate.isTrue);
      expect(data.hasAction(SemanticsAction.tap), isTrue);
      expect(data.label, contains('Нажмите, чтобы подключиться'));
      expect(data.label, contains('ВКЛЮЧИТЬ'));
      expect(data.value, 'Не подключено');
      expect(MediaQuery.of(tester.element(orb)).disableAnimations, isTrue);
      expect(tester.binding.transientCallbackCount, 0);

      await tester.tap(orb);
      await tester.pumpAndSettle();
      expect(vpn.isConnected, isTrue);
      expect(find.text('ОТКЛЮЧИТЬ'), findsOneWidget);
      await _disposeApp(tester, vpn);
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('orb pauses its animation while app lifecycle is inactive', (
    tester,
  ) async {
    await loadMilkyTestFonts();
    await tester.pumpWidget(
      MaterialApp(
        theme: MilkyTheme.dark(),
        home: const MediaQuery(
          data: MediaQueryData(disableAnimations: false),
          child: Scaffold(
            body: Center(
              child: MilkyConnectOrb(
                state: MilkyOrbState.idle,
                onTap: _noop,
                semanticLabel: 'Подключить VPN',
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pump();
    expect(tester.binding.transientCallbackCount, greaterThan(0));

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    expect(tester.binding.transientCallbackCount, 0);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(tester.binding.transientCallbackCount, greaterThan(0));

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}

void _noop() {}
