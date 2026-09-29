import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:milkyvpn/app/app_settings.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/design/milky_theme.dart';
import 'package:milkyvpn/features/settings/settings_screen.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _FakeBridge extends Mock implements VpnBridge {}

class _NeverFetch implements SubscriptionFetcher {
  @override
  Future<FetchedSubscription> fetch(Uri url) =>
      throw SubscriptionFetchException('offline');
}

Future<void> _pumpSettings(
  WidgetTester tester, {
  required SubscriptionRepository repo,
}) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final settings = await AppSettings.load();
  final bridge = _FakeBridge();
  when(() => bridge.openVpnSettings()).thenAnswer((_) async => true);
  await tester.pumpWidget(
    MultiProvider(
      providers: [
        ChangeNotifierProvider<AppSettings>.value(value: settings),
        ChangeNotifierProvider<SubscriptionRepository>.value(value: repo),
        Provider<VpnBridge>.value(value: bridge),
      ],
      child: MaterialApp(
        locale: const Locale('en'),
        theme: MilkyTheme.dark(),
        home: const Scaffold(body: SettingsScreen()),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _tapRefresh(WidgetTester tester) async {
  final row = find.text('Refresh subscription');
  await tester.ensureVisible(row);
  await tester.tap(row);
  await tester.pumpAndSettle();
}

void main() {
  group('SettingsScreen refresh row', () {
    testWidgets(
      'link-imported profile set reports it cannot be refreshed '
      '(BUG-2026-09-29-05)',
      (tester) async {
        final repo = SubscriptionRepository(
          store: MemorySecureStore(),
          fetcher: _NeverFetch(),
        );
        await repo.load();
        await repo.importFromText(
          'kal2://aabbccdd@1.2.3.4:443?sni=example.com&pub=eeff',
        );
        expect(repo.hasSubscription, isTrue);

        await _pumpSettings(tester, repo: repo);
        await _tapRefresh(tester);

        expect(
          find.text('Imported profiles cannot be refreshed'),
          findsOneWidget,
        );
        expect(find.text('No subscription'), findsNothing);
      },
    );

    testWidgets('empty store still reports no subscription', (tester) async {
      final repo = SubscriptionRepository(
        store: MemorySecureStore(),
        fetcher: _NeverFetch(),
      );
      await repo.load();
      expect(repo.hasSubscription, isFalse);

      await _pumpSettings(tester, repo: repo);
      await _tapRefresh(tester);

      expect(find.text('No subscription'), findsWidgets);
    });

    testWidgets(
      'Always-on VPN row is Android-only, hidden on other platforms '
      '(BUG-2026-09-29-04)',
      (tester) async {
        final repo = SubscriptionRepository(
          store: MemorySecureStore(),
          fetcher: _NeverFetch(),
        );
        await repo.load();

        await _pumpSettings(tester, repo: repo);

        expect(find.text('Always-on VPN'), findsNothing);
      },
    );
  });
}
