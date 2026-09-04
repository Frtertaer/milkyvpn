import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/design/milky_connect_orb.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;
import '../support/harness.dart';

void main() {
  testWidgets('onboarding -> disclosure -> import -> home shows the disconnected state', (tester) async {
    final repo = await emptyRepo();
    final bridge = FakeBridge();
    final vpn = VpnController(bridge: bridge);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge, onboardingDone: false);

    // Page 1 — the orb is the first thing a new user sees.
    expect(find.text('VPN без сложных настроек'), findsOneWidget);
    expect(find.byKey(const Key('connect_orb')), findsOneWidget);
    await tester.tap(find.text('Продолжить'));
    await tester.pumpAndSettle();

    // Page 2 — truthful disclosure, no marketing wall of text.
    expect(find.text('Защищённое VPN-соединение'), findsOneWidget);
    expect(find.textContaining('VpnService'), findsOneWidget);
    expect(find.text('Телефон'), findsOneWidget);
    expect(find.text('Интернет'), findsOneWidget);
    await tester.tap(find.text('Понятно, продолжить'));
    await tester.pumpAndSettle();

    // Page 3 — add the subscription.
    expect(find.text('Добавьте подписку'), findsWidgets);
    expect(find.text('У меня пока нет подписки'), findsOneWidget);
    await tester.tap(find.text('У меня пока нет подписки'));
    await tester.pumpAndSettle();

    // Home.
    expect(find.byKey(const Key('state_text')), findsOneWidget);
    expect(find.text('Не подключено'), findsOneWidget);
    expect(find.text('Защита выключена'), findsOneWidget);
    expect(find.text('Авто'), findsOneWidget);
    expect(find.text('Финляндия'), findsOneWidget);
    expect(find.text('США'), findsOneWidget);

    // The orb is the connect control and it is inert without a subscription.
    final orb = tester.widget<MilkyConnectOrb>(find.byKey(const Key('connect_orb')));
    expect(orb.enabled, isFalse);
    expect(orb.state, MilkyOrbState.disabled);

    // No protocol jargon anywhere on the main screen.
    for (final w in ['VLESS', 'Reality', 'XHTTP', 'Hysteria', 'SNI', 'UUID']) {
      expect(find.textContaining(w), findsNothing);
    }
    vpn.dispose();
  });

  testWidgets('home with a subscription is ready to connect and reports real counts', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final bridge = FakeBridge();
    final vpn = VpnController(bridge: bridge);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

    expect(find.text('Не подключено'), findsOneWidget);
    expect(find.text('Нажмите, чтобы подключиться'), findsOneWidget);
    // 16 parsed profiles, all 16 executable by this engine.
    expect(find.textContaining('16 профилей'), findsWidgets);
    expect(find.textContaining('16 совместимых'), findsWidgets);
    final orb = tester.widget<MilkyConnectOrb>(find.byKey(const Key('connect_orb')));
    expect(orb.enabled, isTrue);
    expect(orb.state, MilkyOrbState.idle);
    vpn.dispose();
  });

  testWidgets('nav bar switches to the subscription and settings tabs', (tester) async {
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final bridge = FakeBridge();
    final vpn = VpnController(bridge: bridge);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge);

    await tester.tap(find.byKey(const ValueKey('milky_nav_2')));
    await tester.pumpAndSettle();
    expect(find.text('Подключение'), findsWidgets);
    expect(find.text('Автоподключение'), findsOneWidget);
    expect(find.text('Always-on VPN'), findsOneWidget);
    expect(find.text('Автоподключение'), findsOneWidget);
    expect(find.text('Диагностика'), findsWidgets);

    await tester.tap(find.byKey(const ValueKey('milky_nav_0')));
    await tester.pumpAndSettle();
    expect(find.text('Не подключено'), findsOneWidget);
    vpn.dispose();
  });
}
