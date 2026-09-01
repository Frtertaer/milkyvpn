import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';

import 'app/app_settings.dart';
import 'core/security/redactor.dart';
import 'core/security/subscription_url_policy.dart';
import 'core/storage/secure_store.dart';
import 'core/subscription/subscription_repository.dart';
import 'core/subscription/vpn_profile.dart';
import 'core/vpn/vpn_bridge.dart';
import 'core/vpn/vpn_controller.dart';

const kAppVersion = '0.1.0+1';
const kSupportUrl = 'https://t.me/MilkyVPNbot';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final settings = await AppSettings.load();
  final bridge = MethodChannelVpnBridge();
  final repo = SubscriptionRepository(store: KeystoreSecureStore(), fetcher: HttpsSubscriptionFetcher());
  await repo.load();
  final vpn = VpnController(bridge: bridge);
  await vpn.init();
  runApp(MilkyApp(settings: settings, repo: repo, vpn: vpn, bridge: bridge));
}

class MilkyApp extends StatelessWidget {
  const MilkyApp({super.key, required this.settings, required this.repo, required this.vpn, required this.bridge});
  final AppSettings settings;
  final SubscriptionRepository repo;
  final VpnController vpn;
  final VpnBridge bridge;

  static const _accent = Color(0xFF3B6FD8);

  ThemeData _theme(Brightness b) {
    final scheme = ColorScheme.fromSeed(seedColor: _accent, brightness: b);
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: b == Brightness.light ? const Color(0xFFFAF8F5) : const Color(0xFF121316),
      cardTheme: CardThemeData(elevation: 0, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20))),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(56), shape: const StadiumBorder(), textStyle: const TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: settings),
        ChangeNotifierProvider.value(value: repo),
        ChangeNotifierProvider.value(value: vpn),
        Provider<VpnBridge>.value(value: bridge),
      ],
      child: Consumer<AppSettings>(
        builder: (context, s, _) => MaterialApp(
          title: 'MilkyVPN',
          debugShowCheckedModeBanner: false,
          themeMode: s.themeMode,
          theme: _theme(Brightness.light),
          darkTheme: _theme(Brightness.dark),
          locale: const Locale('ru'),
          supportedLocales: const [Locale('ru'), Locale('en')],
          localizationsDelegates: GlobalMaterialLocalizations.delegates,
          home: const RootScreen(),
        ),
      ),
    );
  }
}

/// Handles onboarding gate + deep links.
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
      final bridge = context.read<VpnBridge>();
      final s = context.read<AppSettings>();
      final repo = context.read<SubscriptionRepository>();
      final vpn = context.read<VpnController>();
      try {
        final initial = await bridge.getInitialLink();
        if (initial != null) _handleLink(initial);
        _links = bridge.links.listen(_handleLink);
      } catch (_) {}
      if (s.autoConnect && repo.hasSubscription && repo.snapshot != null && mounted) {
        if (!vpn.isConnected && !vpn.isBusy) vpn.connect(repo.snapshot!.profiles, s.location);
      }
    });
  }

  void _handleLink(String link) {
    final url = const SubscriptionUrlPolicy().fromDeepLink(link);
    if (!mounted) return;
    if (url == null) {
      ScaffoldMessenger.maybeOf(context)?.showSnackBar(SnackBar(content: Text(S.of(context).urlNotAllowed)));
      return;
    }
    Navigator.of(context).push(MaterialPageRoute(builder: (_) => DeepLinkConfirmScreen(url: url)));
  }

  @override
  void dispose() {
    _links?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = context.watch<AppSettings>();
    return s.onboardingDone ? const HomeScreen() : const OnboardingScreen();
  }
}

// ------------------------------------------------------------------ onboarding

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  int _page = 0;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final repo = context.watch<SubscriptionRepository>();
    Widget body;
    switch (_page) {
      case 0:
        body = _Page(
          key: const ValueKey('ob1'),
          icon: const MilkyLogo(size: 96),
          title: t.appName,
          text: t.tagline,
          button: t.cont,
          onTap: () => setState(() => _page = 1),
        );
        break;
      case 1:
        body = _Page(
          key: const ValueKey('ob2'),
          icon: const Icon(Icons.shield_outlined, size: 72),
          title: t.disclosureTitle,
          text: t.disclosureBody,
          button: t.understood,
          onTap: () => repo.hasSubscription ? _finish() : setState(() => _page = 2),
        );
        break;
      default:
        body = _Page(
          key: const ValueKey('ob3'),
          icon: const Icon(Icons.link, size: 72),
          title: t.addSubscription,
          text: t.t('Вставьте ссылку на подписку MilkyVPN, чтобы начать.', 'Paste your MilkyVPN subscription link to get started.'),
          button: t.addSubscription,
          onTap: () async {
            final ok = await Navigator.of(context).push<bool>(MaterialPageRoute(builder: (_) => const ImportScreen()));
            if (ok == true) _finish();
          },
          secondary: t.noSubscriptionYet,
          onSecondary: _finish,
        );
    }
    return Scaffold(body: SafeArea(child: AnimatedSwitcher(duration: const Duration(milliseconds: 250), child: body)));
  }

  void _finish() => context.read<AppSettings>().setOnboardingDone();
}

class _Page extends StatelessWidget {
  const _Page({super.key, required this.icon, required this.title, required this.text, required this.button, required this.onTap, this.secondary, this.onSecondary});
  final Widget icon;
  final String title, text, button;
  final VoidCallback onTap;
  final String? secondary;
  final VoidCallback? onSecondary;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(28),
      child: Column(
        children: [
          const Spacer(),
          icon,
          const SizedBox(height: 28),
          Text(title, style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w700), textAlign: TextAlign.center),
          const SizedBox(height: 16),
          Text(text, style: Theme.of(context).textTheme.bodyLarge, textAlign: TextAlign.center),
          const Spacer(),
          FilledButton(onPressed: onTap, child: Text(button)),
          if (secondary != null) TextButton(onPressed: onSecondary, child: Text(secondary!)),
        ],
      ),
    );
  }
}

class MilkyLogo extends StatelessWidget {
  const MilkyLogo({super.key, this.size = 64});
  final double size;
  @override
  Widget build(BuildContext context) {
    final c = Theme.of(context).colorScheme;
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(color: c.primary, borderRadius: BorderRadius.circular(size * 0.3)),
      child: Icon(Icons.water_drop_rounded, color: Colors.white, size: size * 0.6),
    );
  }
}

// ------------------------------------------------------------------ home

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  Timer? _tick;
  @override
  void initState() {
    super.initState();
    _tick = Timer.periodic(const Duration(seconds: 1), (_) => setState(() {}));
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final vpn = context.watch<VpnController>();
    final repo = context.watch<SubscriptionRepository>();
    final settings = context.watch<AppSettings>();
    final c = Theme.of(context).colorScheme;

    final String stateText;
    final Color stateColor;
    switch (vpn.state) {
      case VpnState.connected:
        stateText = t.connected;
        stateColor = const Color(0xFF2E9E5B);
        break;
      case VpnState.connecting:
      case VpnState.disconnecting:
        stateText = t.connecting;
        stateColor = c.primary;
        break;
      default:
        stateText = t.notConnected;
        stateColor = c.onSurface;
    }
    final since = vpn.connectedSince;
    final dur = since == null || !vpn.isConnected ? null : DateTime.now().difference(since);
    final err = vpn.isBusy || vpn.isConnected ? null : vpn.lastErrorClass;

    return Scaffold(
      appBar: AppBar(
        title: Row(children: [const MilkyLogo(size: 30), const SizedBox(width: 10), Text(t.appName, style: const TextStyle(fontWeight: FontWeight.w700))]),
        actions: [
          IconButton(icon: const Icon(Icons.card_membership_outlined), tooltip: t.subscription, onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SubscriptionScreen()))),
          IconButton(icon: const Icon(Icons.settings_outlined), tooltip: t.settings, onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SettingsScreen()))),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              Card(
                child: ListTile(
                  leading: Icon(repo.hasSubscription ? Icons.check_circle_outline : Icons.error_outline, color: repo.hasSubscription ? const Color(0xFF2E9E5B) : c.error),
                  title: Text(repo.hasSubscription ? '${t.subscription}: ${repo.snapshot?.isActive == true ? t.active : t.unavailable}' : t.noSubscription),
                  subtitle: repo.hasSubscription ? Text('${t.serversCount}: ${repo.snapshot?.profiles.length ?? 0}') : null,
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => repo.hasSubscription ? const SubscriptionScreen() : const ImportScreen())),
                ),
              ),
              const Spacer(),
              Text(stateText, key: const Key('state_text'), style: Theme.of(context).textTheme.displaySmall?.copyWith(fontWeight: FontWeight.w700, color: stateColor), textAlign: TextAlign.center),
              const SizedBox(height: 8),
              if (dur != null) Text(_fmt(dur), style: Theme.of(context).textTheme.titleMedium?.copyWith(color: c.onSurfaceVariant)),
              if (vpn.isBusy) const Padding(padding: EdgeInsets.only(top: 12), child: SizedBox(width: 28, height: 28, child: CircularProgressIndicator(strokeWidth: 3))),
              if (err != null && err != 'cancelled')
                Padding(padding: const EdgeInsets.only(top: 12), child: Text(t.errorText(err), style: TextStyle(color: c.error), textAlign: TextAlign.center)),
              const Spacer(),
              SegmentedButton<LocationChoice>(
                segments: [
                  ButtonSegment(value: LocationChoice.auto, label: Text(t.auto)),
                  ButtonSegment(value: LocationChoice.finland, label: Text(t.finland)),
                  ButtonSegment(value: LocationChoice.usa, label: Text(t.usa)),
                ],
                selected: {settings.location},
                onSelectionChanged: vpn.isBusy ? null : (s) => settings.setLocation(s.first),
              ),
              const SizedBox(height: 20),
              FilledButton(
                key: const Key('connect_button'),
                onPressed: !repo.hasSubscription || vpn.isBusy && !vpn.isConnected && vpn.state != VpnState.connecting
                    ? null
                    : () async {
                        if (vpn.isConnected || vpn.isBusy) {
                          await vpn.disconnect();
                        } else {
                          await vpn.connect(repo.snapshot?.profiles ?? const [], settings.location);
                        }
                      },
                style: vpn.isConnected || vpn.isBusy ? FilledButton.styleFrom(backgroundColor: c.surfaceContainerHighest, foregroundColor: c.onSurface) : null,
                child: Text(vpn.isConnected || vpn.isBusy ? t.disconnect : t.connect),
              ),
            ],
          ),
        ),
      ),
    );
  }

  static String _fmt(Duration d) {
    String two(int n) => n.toString().padLeft(2, '0');
    return '${two(d.inHours)}:${two(d.inMinutes % 60)}:${two(d.inSeconds % 60)}';
  }
}

// ------------------------------------------------------------------ import

class ImportScreen extends StatefulWidget {
  const ImportScreen({super.key});
  @override
  State<ImportScreen> createState() => _ImportScreenState();
}

class _ImportScreenState extends State<ImportScreen> {
  final _ctrl = TextEditingController();
  bool _busy = false;
  String? _err;

  Future<void> _paste() async {
    final d = await Clipboard.getData(Clipboard.kTextPlain);
    if (d?.text != null) setState(() => _ctrl.text = d!.text!.trim());
  }

  Future<void> _import() async {
    final t = S.of(context);
    final repo = context.read<SubscriptionRepository>();
    final nav = Navigator.of(context);
    final msg = ScaffoldMessenger.of(context);
    setState(() {
      _busy = true;
      _err = null;
    });
    try {
      await repo.importFromUrl(_ctrl.text);
      msg.showSnackBar(SnackBar(content: Text(t.importOk)));
      nav.pop(true);
    } on SubscriptionFetchException catch (e) {
      setState(() => _err = t.errorText(e.errorClass));
    } catch (e) {
      setState(() => _err = t.errorText(const Redactor().errorClass(e)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.addSubscription)),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              TextField(
                controller: _ctrl,
                obscureText: true,
                enableSuggestions: false,
                autocorrect: false,
                decoration: InputDecoration(labelText: t.subscriptionUrlHint, hintText: 'https://sub.milky.homes/s/…', border: const OutlineInputBorder(), errorText: _err),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(onPressed: _paste, icon: const Icon(Icons.paste), label: Text(t.pasteFromClipboard)),
              const Spacer(),
              FilledButton(onPressed: _busy ? null : _import, child: _busy ? const SizedBox(height: 22, width: 22, child: CircularProgressIndicator(strokeWidth: 2)) : Text(t.import)),
            ],
          ),
        ),
      ),
    );
  }
}

class DeepLinkConfirmScreen extends StatelessWidget {
  const DeepLinkConfirmScreen({super.key, required this.url});
  final Uri url;
  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.addSubscription)),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(children: [
            const Spacer(),
            Text(t.addSubscriptionQuestion, style: Theme.of(context).textTheme.headlineSmall, textAlign: TextAlign.center),
            const SizedBox(height: 12),
            Text(SubscriptionUrlPolicy.redact(url), style: Theme.of(context).textTheme.bodyMedium),
            const SizedBox(height: 12),
            Text(t.deepLinkBody, textAlign: TextAlign.center),
            const Spacer(),
            FilledButton(
              onPressed: () async {
                final repo = context.read<SubscriptionRepository>();
                final msg = ScaffoldMessenger.of(context);
                final nav = Navigator.of(context);
                try {
                  await repo.importFromUrl(url.toString());
                  msg.showSnackBar(SnackBar(content: Text(t.importOk)));
                } on SubscriptionFetchException catch (e) {
                  msg.showSnackBar(SnackBar(content: Text(t.errorText(e.errorClass))));
                }
                nav.pop();
              },
              child: Text(t.add),
            ),
            TextButton(onPressed: () => Navigator.pop(context), child: Text(t.cancel)),
          ]),
        ),
      ),
    );
  }
}

// ------------------------------------------------------------------ subscription

class SubscriptionScreen extends StatelessWidget {
  const SubscriptionScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final repo = context.watch<SubscriptionRepository>();
    final snap = repo.snapshot;
    return Scaffold(
      appBar: AppBar(title: Text(t.subscription)),
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          ListTile(title: Text(t.status), trailing: Text(snap?.isActive == true ? t.active : t.unavailable)),
          if (snap?.expiresAt != null) ListTile(title: Text(t.expires), trailing: Text(snap!.expiresAt!.toLocal().toString().substring(0, 10))),
          ListTile(title: Text(t.serversCount), trailing: Text('${snap?.profiles.length ?? 0}')),
          if (repo.redactedUrl != null) ListTile(title: const Text('URL'), trailing: Text(repo.redactedUrl!)),
          const SizedBox(height: 16),
          if (repo.hasSubscription)
            FilledButton.tonal(
              onPressed: () async {
                final msg = ScaffoldMessenger.of(context);
                try {
                  await repo.refresh();
                  msg.showSnackBar(SnackBar(content: Text(t.importOk)));
                } on SubscriptionFetchException catch (e) {
                  msg.showSnackBar(SnackBar(content: Text(t.errorText(e.errorClass))));
                }
              },
              child: Text(t.refreshSubscription),
            )
          else
            FilledButton(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const ImportScreen())), child: Text(t.addSubscription)),
          const SizedBox(height: 8),
          if (repo.hasSubscription)
            TextButton(
              style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
              onPressed: () async {
                final ok = await showDialog<bool>(
                  context: context,
                  builder: (d) => AlertDialog(
                    title: Text(t.removeSubscription),
                    content: Text(t.removeConfirm),
                    actions: [TextButton(onPressed: () => Navigator.pop(d, false), child: Text(t.cancel)), TextButton(onPressed: () => Navigator.pop(d, true), child: Text(t.remove))],
                  ),
                );
                if (!context.mounted || ok != true) return;
                final vpn = context.read<VpnController>();
                final bridge = context.read<VpnBridge>();
                if (vpn.isConnected || vpn.isBusy) await vpn.disconnect();
                try {
                  await bridge.clearActiveProfile();
                } catch (_) {}
                await repo.remove();
              },
              child: Text(t.removeSubscription),
            ),
        ]),
      ),
    );
  }
}

// ------------------------------------------------------------------ settings / diagnostics

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final s = context.watch<AppSettings>();
    final bridge = context.read<VpnBridge>();
    return Scaffold(
      appBar: AppBar(title: Text(t.settings)),
      body: SafeArea(
        child: ListView(children: [
          SwitchListTile(title: Text(t.autoConnect), value: s.autoConnect, onChanged: s.setAutoConnect),
          ListTile(
            title: Text(t.theme),
            trailing: DropdownButton<ThemeMode>(
              value: s.themeMode,
              onChanged: (m) => m == null ? null : s.setThemeMode(m),
              items: [
                DropdownMenuItem(value: ThemeMode.system, child: Text(t.themeSystem)),
                DropdownMenuItem(value: ThemeMode.light, child: Text(t.themeLight)),
                DropdownMenuItem(value: ThemeMode.dark, child: Text(t.themeDark)),
              ],
            ),
          ),
          ListTile(
            leading: const Icon(Icons.refresh),
            title: Text(t.checkSubscriptionUpdate),
            onTap: () async {
              final msg = ScaffoldMessenger.of(context);
              try {
                final r = await context.read<SubscriptionRepository>().refresh();
                msg.showSnackBar(SnackBar(content: Text(r == null ? t.noSubscription : t.importOk)));
              } on SubscriptionFetchException catch (e) {
                msg.showSnackBar(SnackBar(content: Text(t.errorText(e.errorClass))));
              }
            },
          ),
          ListTile(leading: const Icon(Icons.vpn_lock), title: Text(t.alwaysOn), onTap: bridge.openVpnSettings),
          ListTile(leading: const Icon(Icons.bug_report_outlined), title: Text(t.diagnostics), onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const DiagnosticsScreen()))),
          ListTile(leading: const Icon(Icons.privacy_tip_outlined), title: Text(t.privacy), onTap: () => showDialog(context: context, builder: (_) => AlertDialog(title: Text(t.privacy), content: SingleChildScrollView(child: Text(t.privacyBody))))),
          ListTile(leading: const Icon(Icons.info_outline), title: Text(t.about), subtitle: Text('MilkyVPN $kAppVersion · Xray-core')),
          ListTile(leading: const Icon(Icons.support_agent), title: Text(t.support), onTap: () => launchUrl(Uri.parse(kSupportUrl), mode: LaunchMode.externalApplication)),
        ]),
      ),
    );
  }
}

class DiagnosticsScreen extends StatefulWidget {
  const DiagnosticsScreen({super.key});
  @override
  State<DiagnosticsScreen> createState() => _DiagnosticsScreenState();
}

class _DiagnosticsScreenState extends State<DiagnosticsScreen> {
  String _core = '…';
  Map<String, Object?> _dev = const {};
  @override
  void initState() {
    super.initState();
    final b = context.read<VpnBridge>();
    b.coreVersion().then((v) => mounted ? setState(() => _core = v) : null).catchError((_) {});
    b.deviceInfo().then((v) => mounted ? setState(() => _dev = v) : null).catchError((_) {});
  }

  String _text(BuildContext context) {
    final vpn = context.read<VpnController>();
    final repo = context.read<SubscriptionRepository>();
    const r = Redactor();
    return r.redact([
      'MilkyVPN $kAppVersion',
      'Android ${_dev['release'] ?? '?'} (API ${_dev['sdkInt'] ?? '?'}, ${_dev['abi'] ?? '?'})',
      'Core: $_core',
      'State: ${vpn.state.name}',
      'Profile: ${vpn.activeRemark ?? '-'}',
      'Last error: ${vpn.lastErrorClass ?? '-'}',
      'Attempts: ${vpn.attemptsMade}',
      'Parsed profiles: ${repo.snapshot?.profiles.length ?? 0} (malformed: ${repo.snapshot?.malformedEntries ?? 0})',
      'Compatible profiles: ${vpn.compatibleCount}',
      'Subscription: ${repo.hasSubscription ? 'present' : 'none'}',
    ].join('\n'));
  }

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final text = _text(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.diagnostics)),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(children: [
            Expanded(child: SingleChildScrollView(child: SelectableText(text, style: const TextStyle(fontFamily: 'monospace')))),
            FilledButton.tonal(
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: text));
                if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t.copied)));
              },
              child: Text(t.copyDiagnostics),
            ),
          ]),
        ),
      ),
    );
  }
}
