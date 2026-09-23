import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../core/vpn/vpn_controller.dart';
import '../../design/milky_aurora.dart';

import '../../design/milky_navigation_bar.dart';
import '../../l10n/milky_strings.dart';
import '../home/home_screen.dart';
import '../settings/settings_screen.dart';
import '../subscription/subscription_screen.dart';

/// Root of the authenticated app: one aurora backdrop, three destinations, floating nav.
class MilkyShell extends StatefulWidget {
  const MilkyShell({super.key});

  @override
  State<MilkyShell> createState() => _MilkyShellState();
}

class _MilkyShellState extends State<MilkyShell> {
  int _tab = 0;

  void _go(int index) {
    if (index == _tab) return;
    setState(() => _tab = index);
  }

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final vpn = context.watch<VpnController>();

    final dark = Theme.of(context).brightness == Brightness.dark;
    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarIconBrightness: dark ? Brightness.light : Brightness.dark,
        statusBarBrightness: dark ? Brightness.dark : Brightness.light,
        systemNavigationBarColor: Colors.transparent,
        systemNavigationBarIconBrightness: dark
            ? Brightness.light
            : Brightness.dark,
      ),
      child: MilkyBackdrop(
        intensity: _tab == 0
            ? (vpn.isBusy ? .64 : (vpn.isConnected ? .75 : .4))
            : .16,
        glowAnchor: const Alignment(0, -.28),
        child: Scaffold(
          backgroundColor: Colors.transparent,
          body: SafeArea(
            bottom: false,
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(
                  maxWidth: 600,
                  maxHeight: 960,
                ),
                child: Column(
                  children: [
                    Expanded(
                      child: IndexedStack(
                        index: _tab,
                        children: [
                          TickerMode(
                            enabled: _tab == 0,
                            child: HomeScreen(
                              key: const ValueKey('tab_home'),
                              onOpenTab: _go,
                            ),
                          ),
                          const SubscriptionScreen(
                            key: ValueKey('tab_subscription'),
                          ),
                          SettingsScreen(
                            key: const ValueKey('tab_settings'),
                            onOpenSubscription: () => _go(1),
                          ),
                        ],
                      ),
                    ),
                    MilkyNavigationBar(
                      index: _tab,
                      onChanged: _go,
                      labels: [t.home, t.subscription, t.settings],
                      icons: const [
                        Icons.home_outlined,
                        Icons.layers_outlined,
                        Icons.tune_rounded,
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
