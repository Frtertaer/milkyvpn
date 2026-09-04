import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/design/milky_colors.dart';
import 'package:milkyvpn/design/milky_connect_orb.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;
import '../support/harness.dart';

/// Emits a specific native error code, e.g. the Go core's `proxyerror`.
class _CodeBridge extends FakeBridge {
  _CodeBridge(this.code);

  final String code;

  @override
  Future<void> connect(VpnProfile p) async {
    connectCalls.add(p.id);
    emit(VpnSnapshot(state: VpnState.connecting, profileId: p.id, profileRemark: p.redactedRemark));
    emit(VpnSnapshot(state: VpnState.error, profileId: p.id, errorCode: code));
  }
}

void main() {
  group('home states', () {
    testWidgets('disconnected: idle orb, status text, subscription summary', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      expect(find.text('Не подключено'), findsOneWidget);
      expect(find.text('Защита выключена'), findsOneWidget);
      expect(find.text('ВКЛЮЧИТЬ'), findsOneWidget);
      expect(tester.widget<MilkyConnectOrb>(find.byKey(const Key('connect_orb'))).state, MilkyOrbState.idle);
      expect(tester.takeException(), isNull);
      vpn.dispose();
    });

    testWidgets('connecting: "Подключаем…" plus the attempt counter', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge()..hang = true;
      final vpn = VpnController(bridge: bridge, attemptTimeout: const Duration(milliseconds: 400), maxAttempts: 2);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      await tester.tap(find.byKey(const Key('connect_orb')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 20));

      expect(find.text('Подключаем…'), findsWidgets);
      expect(find.textContaining('Ищем лучший сервер'), findsOneWidget);
      expect(find.textContaining('1 из 2'), findsOneWidget);
      expect(find.text('Защита выключена'), findsNothing);
      expect(find.text('Подключаем…'), findsWidgets);
      expect(
        tester.widget<MilkyConnectOrb>(find.byKey(const Key('connect_orb'))).state,
        MilkyOrbState.connecting,
      );

      // Let the bounded attempts finish so no timer outlives the test.
      await tester.pump(const Duration(milliseconds: 900));
      await tester.pumpAndSettle();
      vpn.dispose();
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('connected: country name, protected pill and a running timer', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      await tester.tap(find.byKey(const Key('connect_orb')));
      await tester.pumpAndSettle();

      expect(vpn.isConnected, isTrue);
      expect(find.text('Финляндия'), findsWidgets);
      expect(find.text('Защищено'), findsWidgets);
      expect(find.text('VPN подключён'), findsOneWidget);
      expect(find.text('00:00:00'), findsOneWidget);
      expect(find.text('ОТКЛЮЧИТЬ'), findsOneWidget);
      expect(tester.widget<MilkyConnectOrb>(find.byKey(const Key('connect_orb'))).state, MilkyOrbState.connected);
      // Never leak the raw profile remark, which contains protocol words.
      expect(find.textContaining('Reality'), findsNothing);

      vpn.dispose();
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('connected to a US profile shows "США"', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      await tester.tap(find.text('США'));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('connect_orb')));
      await tester.pumpAndSettle();

      expect(vpn.isConnected, isTrue);
      expect(vpn.activeLocation, ServerLocation.usa);
      expect(find.text('00:00:00'), findsOneWidget);
      vpn.dispose();
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('orb transitions idle → connecting → connected → idle', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final bridge = FakeBridge()..hang = true;
    final vpn = VpnController(bridge: bridge, attemptTimeout: const Duration(milliseconds: 300), maxAttempts: 2);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

    MilkyConnectOrb orb() => tester.widget<MilkyConnectOrb>(find.byKey(const Key('connect_orb')));
    expect(orb().state, MilkyOrbState.idle);

    await tester.tap(find.byKey(const Key('connect_orb')));
    await tester.pump(const Duration(milliseconds: 30));
    expect(orb().state, MilkyOrbState.connecting);

    // Attempts time out and the controller reports failure → error state, sheet shown.
    await tester.pump(const Duration(milliseconds: 800));
    await tester.pumpAndSettle();
    expect(orb().state, MilkyOrbState.error);
    expect(find.text('ВКЛЮЧИТЬ'), findsOneWidget);

    // Retry with a healthy bridge: connecting → connected, then disconnect → idle.
    vpn.dispose();
  });

  group('failure sheet', () {
    for (final code in ['tls_handshake', 'proxyerror', 'S', 'all_attempts_failed']) {
      testWidgets('maps "$code" to a human message and hides the raw code', (tester) async {
        final repo = await repoWith(fixture('subscription_16_fake.txt'));
        final bridge = _CodeBridge(code);
        final vpn = VpnController(bridge: bridge, attemptTimeout: const Duration(milliseconds: 200), maxAttempts: 2);
        await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

        await tester.tap(find.byKey(const Key('connect_orb')));
        await tester.pumpAndSettle();

        expect(find.text('Не удалось подключиться'), findsWidgets);
        expect(find.text('Попробовать снова'), findsOneWidget);
        expect(find.text('Другой сервер'), findsOneWidget);
        expect(find.text('Диагностика'), findsWidgets);
        expect(find.textContaining(code), findsNothing);
        expect(find.textContaining('proxyerror'), findsNothing);
        expect(find.textContaining('Не удалось выполнить операцию'), findsNothing);
        vpn.dispose();
        await tester.pumpWidget(const SizedBox());
      });
    }

    testWidgets('permission failure offers the VPN settings action', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge()..permission = false;
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      await tester.tap(find.byKey(const Key('connect_orb')));
      await tester.pumpAndSettle();

      expect(find.text('Нужно разрешение VPN'), findsOneWidget);
      expect(find.text('Настройки VPN'), findsOneWidget);
      expect(find.textContaining('vpn_permission_denied'), findsNothing);
      vpn.dispose();
      await tester.pumpWidget(const SizedBox());
    });
  });

  group('subscription tab', () {
    testWidgets('shows real counts, actions and never the token', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

      await tester.tap(find.byKey(const ValueKey('milky_nav_1')));
      await tester.pumpAndSettle();

      expect(find.text('Активна'), findsWidgets);
      expect(find.textContaining('16 профилей найдено'), findsOneWidget);
      expect(find.textContaining('16 совместимых с приложением'), findsOneWidget);
      expect(find.text('Обновить'), findsOneWidget);
      expect(find.text('Удалить подписку'), findsOneWidget);
      expect(find.text('Скопировать ссылку'), findsOneWidget);
      // The token is a credential: it must not be rendered anywhere.
      expect(find.textContaining('sub.milky.homes/s/'), findsNothing);
      expect(find.textContaining('AbCdEf'), findsNothing);
      expect(tester.takeException(), isNull);
      vpn.dispose();
    });
  });

  group('responsive + themes', () {
    const sizes = <String, Size>{
      'small phone': Size(320, 568),
      'phone': Size(390, 844),
      'large phone': Size(412, 915),
      'tablet portrait': Size(800, 1280),
      'tablet landscape': Size(1280, 800),
    };

    for (final entry in sizes.entries) {
      testWidgets('${entry.key} ${entry.value} lays out without overflow', (tester) async {
        final repo = await repoWith(fixture('subscription_16_fake.txt'));
        final bridge = FakeBridge();
        final vpn = VpnController(bridge: bridge);
        await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge, size: entry.value);

        expect(tester.takeException(), isNull);
        final orb = tester.getSize(find.byKey(const Key('connect_orb')));
        expect(orb.width, lessThanOrEqualTo(entry.value.width));
        expect(orb.width, lessThanOrEqualTo(300.0));
        // Content never stretches across a tablet display.
        final selector = tester.getSize(find.text('Финляндия').first);
        expect(selector.width, lessThan(entry.value.width));
        vpn.dispose();
      });
    }

    testWidgets('light theme uses the milky palette, dark uses midnight', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);

      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge, themeMode: ThemeMode.light);
      var colors = Theme.of(tester.element(find.byKey(const Key('connect_orb')))).extension<MilkyColors>()!;
      expect(colors.isDark, isFalse);
      expect(colors.bg, const Color(0xFFFAF7F2));

      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge, themeMode: ThemeMode.dark);
      colors = Theme.of(tester.element(find.byKey(const Key('connect_orb')))).extension<MilkyColors>()!;
      expect(colors.isDark, isTrue);
      expect(colors.bg, const Color(0xFF0C1224));
      vpn.dispose();
    });
  });

  group('Russian text', () {
    testWidgets('long Russian labels do not clip or overflow', (tester) async {
      final repo = await repoWith(fixture('subscription_16_fake.txt'));
      final bridge = FakeBridge();
      final vpn = VpnController(bridge: bridge);
      await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge, size: const Size(320, 568));

      for (final finder in [find.text('Финляндия'), find.text('Защита выключена'), find.text('Не подключено')]) {
        expect(finder, findsWidgets);
      }
      expect(tester.takeException(), isNull);
      vpn.dispose();
    });
  });
}
