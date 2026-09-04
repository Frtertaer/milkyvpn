import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:provider/provider.dart';

import 'app/app_settings.dart';
import 'app/milky_device.dart';
import 'core/security/subscription_url_policy.dart';
import 'core/storage/secure_store.dart';
import 'core/subscription/subscription_repository.dart';
import 'core/vpn/vpn_bridge.dart';
import 'core/vpn/vpn_controller.dart';
import 'design/milky_error_sheet.dart';
import 'design/milky_theme.dart';
import 'features/import/import_screen.dart';
import 'features/onboarding/onboarding_screen.dart';
import 'features/shell/milky_shell.dart';
import 'l10n/milky_strings.dart';

// Re-exported so `package:milkyvpn/main.dart` keeps exposing the app constants.
export 'app/app_info.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Real system bars, edge-to-edge: the app paints its own backdrop under them.
  SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    systemNavigationBarColor: Colors.transparent,
  ));
  final settings = await AppSettings.load();
  final bridge = MethodChannelVpnBridge();
  final repo = SubscriptionRepository(store: KeystoreSecureStore(), fetcher: HttpsSubscriptionFetcher());
  await repo.load();
  final vpn = VpnController(bridge: bridge);
  await vpn.init();
  final device = await MilkyDevice.load(bridge);
  runApp(MilkyApp(settings: settings, repo: repo, vpn: vpn, bridge: bridge, device: device));
}

/// Composition root. Themes come from the Milky Glass design system.
class MilkyApp extends StatelessWidget {
  const MilkyApp({
    super.key,
    required this.settings,
    required this.repo,
    required this.vpn,
    required this.bridge,
    this.device = const MilkyDevice(),
  });

  final AppSettings settings;
  final SubscriptionRepository repo;
  final VpnController vpn;
  final VpnBridge bridge;
  final MilkyDevice device;

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: settings),
        ChangeNotifierProvider.value(value: repo),
        ChangeNotifierProvider.value(value: vpn),
        Provider<VpnBridge>.value(value: bridge),
        Provider<MilkyDevice>.value(value: device),
      ],
      child: Consumer<AppSettings>(
        builder: (context, s, _) => MaterialApp(
          title: 'MilkyVPN',
          debugShowCheckedModeBanner: false,
          themeMode: s.themeMode,
          theme: MilkyTheme.light(),
          darkTheme: MilkyTheme.dark(),
          locale: const Locale('ru'),
          supportedLocales: const [Locale('ru'), Locale('en')],
          localizationsDelegates: GlobalMaterialLocalizations.delegates,
          home: const RootScreen(),
        ),
      ),
    );
  }
}

/// Onboarding gate, deep-link intake and auto-connect.
class RootScreen extends StatefulWidget {
  const RootScreen({super.key});

  @override
  State<RootScreen> createState() => _RootScreenState();
}

class _RootScreenState extends State<RootScreen> {
  StreamSubscription<String>? _links;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      final bridge = context.read<VpnBridge>();
      final settings = context.read<AppSettings>();
      final repo = context.read<SubscriptionRepository>();
      final vpn = context.read<VpnController>();
      try {
        final initial = await bridge.getInitialLink();
        if (initial != null) _handleLink(initial);
        _links = bridge.links.listen(_handleLink);
      } catch (_) {
        // Deep links are a bonus path; the app must still start without a platform channel.
      }
      final snapshot = repo.snapshot;
      if (settings.autoConnect && repo.hasSubscription && snapshot != null) {
        if (!vpn.isConnected && !vpn.isBusy) vpn.connect(snapshot.profiles, settings.location);
      }
    });
  }

  void _handleLink(String link) {
    final url = const SubscriptionUrlPolicy().fromDeepLink(link);
    if (!mounted) return;
    final t = S.of(context);
    if (url == null) {
      ScaffoldMessenger.maybeOf(context)?.showSnackBar(SnackBar(content: Text(t.urlNotAllowed)));
      return;
    }
    final repo = context.read<SubscriptionRepository>();
    // Bottom sheet, not a full-screen dialog: the link only needs one calm decision.
    showMilkyConfirmSheet(
      context,
      title: t.addSubscriptionQuestion,
      body: t.deepLinkBody,
      confirmLabel: t.add,
      cancelLabel: t.cancel,
      danger: false,
    ).then((ok) async {
      if (ok != true || !mounted) return;
      try {
        await repo.importFromUrl(url.toString());
        MilkyHaptics.success();
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t.importOk)));
      } catch (_) {
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t.error)));
      }
    });
  }

  @override
  void dispose() {
    _links?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = context.watch<AppSettings>();
    return s.onboardingDone ? const MilkyShell() : const OnboardingScreen();
  }
}
