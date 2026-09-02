import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/app/app_settings.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;

class _NoFetch implements SubscriptionFetcher {
  @override
  Future<FetchedSubscription> fetch(Uri url) async => throw SubscriptionFetchException('offline');
}

void main() {
  testWidgets('onboarding -> disclosure -> home shows Не подключено and Подключить', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final settings = await AppSettings.load();
    final repo = SubscriptionRepository(store: MemorySecureStore(), fetcher: _NoFetch());
    await repo.load();
    final bridge = FakeBridge();
    final vpn = VpnController(bridge: bridge);
    await tester.pumpWidget(MilkyApp(settings: settings, repo: repo, vpn: vpn, bridge: bridge));
    await tester.pumpAndSettle();
    expect(find.text('Простой VPN без ручной настройки серверов.'), findsOneWidget);
    await tester.tap(find.text('Продолжить'));
    await tester.pumpAndSettle();
    expect(find.textContaining('VpnService'), findsOneWidget);
    expect(find.textContaining('100%'), findsNothing);
    await tester.tap(find.text('Понятно, продолжить'));
    await tester.pumpAndSettle();
    expect(find.text('Добавить подписку'), findsWidgets);
    await tester.tap(find.text('У меня пока нет подписки'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('state_text')), findsOneWidget);
    expect(find.text('Не подключено'), findsOneWidget);
    expect(find.text('Подключить'), findsOneWidget);
    expect(find.text('Авто'), findsOneWidget);
    // No protocol jargon on the main screen.
    for (final w in ['VLESS', 'Reality', 'XHTTP', 'Hysteria', 'SNI', 'UUID']) {
      expect(find.textContaining(w), findsNothing);
    }
    // Connect button disabled without subscription.
    expect(tester.widget<FilledButton>(find.byKey(const Key('connect_button'))).onPressed, isNull);
    vpn.dispose();
  });

  testWidgets('home shows the connected server and a distinct disconnecting label', (tester) async {
    SharedPreferences.setMockInitialValues({'onboarding_done': true});
    final settings = await AppSettings.load();
    final repo = SubscriptionRepository(store: MemorySecureStore(), fetcher: _NoFetch());
    await repo.load();
    final bridge = FakeBridge();
    final vpn = VpnController(bridge: bridge);
    await tester.pumpWidget(MilkyApp(settings: settings, repo: repo, vpn: vpn, bridge: bridge));
    await tester.pumpAndSettle();
    expect(find.text('Не подключено'), findsOneWidget);

    bridge.emit(VpnSnapshot(state: VpnState.connected, profileRemark: 'Finland', connectedSince: DateTime.now()));
    await tester.pump();
    await tester.pump();
    expect(find.text('Подключено'), findsOneWidget);
    expect(find.text('Сервер: Finland'), findsOneWidget);
    expect(find.text('Отключение…'), findsNothing);

    bridge.emit(const VpnSnapshot(state: VpnState.disconnecting));
    await tester.pump();
    await tester.pump();
    expect(find.text('Отключение…'), findsOneWidget);
    expect(find.text('Подключено'), findsNothing);
    expect(find.text('Сервер: Finland'), findsNothing);
    vpn.dispose();
  });

  testWidgets('import screen can reveal the subscription link', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: ImportScreen()));
    TextField field() => tester.widget<TextField>(find.byType(TextField));
    expect(field().obscureText, isTrue);
    expect(find.byIcon(Icons.visibility_outlined), findsOneWidget);
    await tester.tap(find.byIcon(Icons.visibility_outlined));
    await tester.pump();
    expect(field().obscureText, isFalse);
    await tester.tap(find.byIcon(Icons.visibility_off_outlined));
    await tester.pump();
    expect(field().obscureText, isTrue);
  });
}
