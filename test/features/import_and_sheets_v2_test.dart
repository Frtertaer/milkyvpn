import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/errors/milky_error.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/design/milky_error_sheet.dart';
import 'package:milkyvpn/design/milky_sheet.dart';
import 'package:milkyvpn/features/home/home_screen.dart';

import '../core/vpn_controller_test.dart' show FakeBridge;
import '../support/harness.dart';

class _ImportFetch implements SubscriptionFetcher {
  @override
  Future<FetchedSubscription> fetch(Uri url) async => FetchedSubscription(
    body: fixture('subscription_16_fake.txt'), headers: const {},
  );
}

void main() {
  testWidgets('three visible onboarding steps import actual fixture and reach Home', (tester) async {
    final store = MemorySecureStore();
    final repo = SubscriptionRepository(store: store, fetcher: _ImportFetch());
    await repo.load();
    final bridge = FakeBridge();
    final vpn = VpnController(bridge: bridge);
    await pumpMilky(tester, repo: repo, vpn: vpn, bridge: bridge, onboardingDone: false);
    expect(find.text('VPN без сложных настроек').hitTestable(), findsOneWidget);
    await tester.tap(find.text('Продолжить'));
    await tester.pumpAndSettle();
    expect(find.text('Защищённое VPN-соединение').hitTestable(), findsOneWidget);
    await tester.tap(find.text('Понятно, продолжить'));
    await tester.pumpAndSettle();
    expect(find.text('Добавьте подписку').hitTestable(), findsOneWidget);
    await tester.tap(find.text('Добавить подписку'));
    await tester.pumpAndSettle();
    const credential = 'https://sub.milky.homes/s/SYNTHETIC_TOKEN_123';
    await tester.enterText(find.byType(TextField), credential);
    expect(tester.widget<TextField>(find.byType(TextField)).obscureText, isTrue);
    await tester.tap(find.text('Добавить'));
    await tester.pumpAndSettle();
    expect(repo.snapshot!.parsedProfileCount, 16);
    expect(store.data['subscription_url'], credential);
    expect(find.byType(MilkySuccessSheet), findsOneWidget);
    expect(find.text(credential), findsNothing);
    final action = find.descendant(of: find.byType(MilkySuccessSheet), matching: find.text('Перейти к подключению'));
    await tester.tap(action);
    await tester.pumpAndSettle();
    expect(find.byType(HomeScreen), findsOneWidget);
    expect(vpn.isConnected, isFalse);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  testWidgets('error sheet stays scrollable at 2x Russian text with private errors', (tester) async {
    tester.platformDispatcher.textScaleFactorTestValue = 2;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final repo = await repoWith(fixture('subscription_16_fake.txt'));
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn, size: const Size(320, 568));
    final context = tester.element(find.byType(HomeScreen));
    var retry = false;
    final pending = MilkyErrorSheet.show(context, error: MilkyError.fromCode('proxyerror'),
      onRetry: () => retry = true, onChooseServer: () {}, onOpenDiagnostics: () {});
    await tester.pumpAndSettle();
    expect(find.textContaining('proxyerror'), findsNothing);
    await tester.ensureVisible(find.text('Попробовать снова'));
    await tester.tap(find.text('Попробовать снова'));
    await tester.pumpAndSettle();
    await pending;
    expect(retry, isTrue);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });

  testWidgets('Android system bars are real overlay styles, no fake status text', (tester) async {
    final repo = await emptyRepo();
    final vpn = VpnController(bridge: FakeBridge());
    await pumpMilky(tester, repo: repo, vpn: vpn);
    final styles = tester.widgetList<AnnotatedRegion<SystemUiOverlayStyle>>(find.byType(AnnotatedRegion<SystemUiOverlayStyle>));
    expect(styles.any((w) => w.value.statusBarColor == Colors.transparent && w.value.statusBarIconBrightness == Brightness.light), isTrue);
    expect(find.text('9:41'), findsNothing);
    await tester.pumpWidget(const SizedBox());
    vpn.dispose();
  });
}
