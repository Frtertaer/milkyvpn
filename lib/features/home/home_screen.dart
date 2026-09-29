import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../app/app_settings.dart';
import '../../app/milky_device.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../core/subscription/vpn_profile.dart';
import '../../core/vpn/vpn_bridge.dart';
import '../../core/vpn/vpn_controller.dart';
import '../../design/milky_brand.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_connect_orb.dart';
import '../../design/milky_error_sheet.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_sheet.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';
import '../import/import_screen.dart';
import '../settings/diagnostics_screen.dart';
import '../subscription/milky_subscription_card.dart';
import 'milky_server_selector.dart';

/// The home screen: brand + protection badge, the connect orb, status, location picker,
/// subscription summary. Everything is centred in a phone-measure column.
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.onOpenTab});

  final ValueChanged<int> onOpenTab;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool _working = false;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final vpn = context.watch<VpnController>();
    final repo = context.watch<SubscriptionRepository>();
    final settings = context.watch<AppSettings>();

    final orbState = _orbState(vpn, repo);
    final counts = locationCounts(
      repo.snapshot?.profiles ?? const <VpnProfile>[],
    );

    final orb = MilkyConnectOrb(
      key: const Key('connect_orb'),
      size: MediaQuery.sizeOf(context).height < 650 ? 180 : null,
      state: orbState,
      enabled: !_working && !vpn.isBusy,
      progress: vpn.isBusy ? _progress(vpn) : null,
      caption: _orbCaption(t, orbState),
      semanticLabel: vpn.isConnected ? t.tapToDisconnect : t.tapToConnect,
      semanticValue: _statusText(t, vpn, repo),
      onTap: _toggle,
    );
    final selector = MilkyServerSelector(
      value: settings.location,
      counts: counts,
      enabled: !vpn.isBusy,
      onChanged: (choice) {
        if (choice == settings.location) return;
        context.read<AppSettings>().setLocation(choice);
      },
    );
    final subscription = MilkySubscriptionStatus(
      snapshot: repo.snapshot,
      onTap: () => repo.hasSubscription ? widget.onOpenTab(1) : _openImport(),
    );

    return LayoutBuilder(
      builder: (context, bounds) {
        final topBar = _TopBar(
          state: vpn.state,
          connected: vpn.isConnected,
          onOpenSettings: () => widget.onOpenTab(2),
        );
        final status = _StatusBlock(vpn: vpn, repo: repo);
        final addButton = repo.hasSubscription
            ? null
            : MilkyPrimaryButton(
                label: t.addSubscription,
                icon: Icons.add_rounded,
                onPressed: _openImport,
              );

        return SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
          child: MilkyColumn(
            shrinkWrap: true,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                topBar,
                SizedBox(
                  height: bounds.maxHeight > 760
                      ? 48
                      : (bounds.maxHeight < 580 ? 8 : 20),
                ),
                Center(child: orb),
                const SizedBox(height: 18),
                status,
                SizedBox(height: bounds.maxHeight < 580 ? 16 : 28),
                selector,
                const SizedBox(height: 12),
                subscription,
                if (addButton != null) ...[
                  const SizedBox(height: MilkySpace.md),
                  addButton,
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  static double _progress(VpnController vpn) {
    final total = vpn.attemptTotal <= 0 ? 1 : vpn.attemptTotal;
    final done = vpn.attemptsMade <= 0 ? 0.35 : vpn.attemptsMade - 0.65;
    return (done / total).clamp(0.08, 0.96);
  }

  static String? _orbCaption(S t, MilkyOrbState state) {
    switch (state) {
      case MilkyOrbState.connected:
        return t.orbDisconnect;
      case MilkyOrbState.connecting:
      case MilkyOrbState.disabled:
        return null;
      case MilkyOrbState.idle:
      case MilkyOrbState.error:
        return t.orbConnect;
    }
  }

  static MilkyOrbState _orbState(
    VpnController vpn,
    SubscriptionRepository repo,
  ) {
    if (vpn.isBusy) return MilkyOrbState.connecting;
    if (vpn.isConnected) return MilkyOrbState.connected;
    if (!repo.hasSubscription) return MilkyOrbState.disabled;
    final err = vpn.lastError;
    if (err != null && !err.isCancelled) return MilkyOrbState.error;
    return MilkyOrbState.idle;
  }

  String _statusText(S t, VpnController vpn, SubscriptionRepository repo) {
    if (vpn.state == VpnState.disconnecting) return t.disconnecting;
    if (vpn.isBusy) return t.connecting;
    if (vpn.isConnected) return t.protectionOn;
    if (!repo.hasSubscription) return t.needSubscription;
    return t.notConnected;
  }

  Future<void> _toggle() async {
    final vpn = context.read<VpnController>();
    final repo = context.read<SubscriptionRepository>();
    final settings = context.read<AppSettings>();
    final device = context.read<MilkyDevice>();

    if (vpn.isBusy) return;
    if (vpn.isConnected) {
      MilkyHaptics.disconnect();
      await vpn.disconnect();
      return;
    }
    if (!repo.hasSubscription) {
      _openImport();
      return;
    }
    if (_working) return;
    setState(() => _working = true);
    MilkyHaptics.connect();
    final bool ok;
    try {
      ok = await vpn.connect(
        repo.snapshot?.profiles ?? const <VpnProfile>[],
        settings.location,
      );
    } finally {
      if (mounted) setState(() => _working = false);
    }
    if (!mounted) return;
    if (ok) {
      MilkyHaptics.success();
      return;
    }
    final err = vpn.lastError;
    if (err == null || err.isCancelled) return;
    MilkyHaptics.error();
    await MilkyErrorSheet.show(
      context,
      error: err.withDeviceContext(isEmulator: device.isEmulator),
      onRetry: _toggle,
      onChooseServer: _pickAnotherLocation,
      onAddSubscription: _openImport,
      onOpenVpnSettings: () => context.read<VpnBridge>().openVpnSettings(),
      onOpenDiagnostics: () => Navigator.of(context).push(
        MaterialPageRoute<void>(builder: (_) => const DiagnosticsScreen()),
      ),
    );
  }

  /// "Другой сервер": move off Auto (or off the current country) and retry immediately.
  Future<void> _pickAnotherLocation() async {
    final settings = context.read<AppSettings>();
    final counts = locationCounts(
      context.read<SubscriptionRepository>().snapshot?.profiles ?? [],
    );
    final next = await showModalBottomSheet<LocationChoice>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => MilkySheetFrame(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(S.of(ctx).chooseCountry, style: MilkyType.headline),
            const SizedBox(height: 24),
            MilkyServerSelector(
              value: settings.location,
              counts: counts,
              onChanged: (choice) => Navigator.of(ctx).pop(choice),
            ),
          ],
        ),
      ),
    );
    if (next == null) return;
    await settings.setLocation(next);
    if (mounted) _toggle();
  }

  void _openImport() {
    Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => const ImportScreen()));
  }
}

// ------------------------------------------------------------------ top bar

class _TopBar extends StatelessWidget {
  const _TopBar({
    required this.state,
    required this.connected,
    required this.onOpenSettings,
  });

  final VpnState state;
  final bool connected;
  final VoidCallback onOpenSettings;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final busy =
        state == VpnState.connecting || state == VpnState.disconnecting;

    final String label;
    final Color color;
    if (state == VpnState.disconnecting) {
      label = t.disconnecting;
      color = c.accent;
    } else if (busy) {
      label = t.protectionConnecting;
      color = c.accent;
    } else if (connected) {
      label = t.protectionOn;
      color = c.positive;
    } else {
      label = t.protectionOff;
      color = c.textFaint;
    }

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const MilkyWordmark(size: 24),
              const SizedBox(height: 8),
              MilkyStatusPill(
                label: label,
                color: color,
                compact: true,
                pulse: busy,
              ),
            ],
          ),
        ),
        const SizedBox(width: 12),
        MilkyIconButton(
          icon: Icons.tune_rounded,
          tooltip: t.settings,
          size: 48,
          onPressed: onOpenSettings,
        ),
      ],
    );
  }
}
// ------------------------------------------------------------------ status block

class _StatusBlock extends StatelessWidget {
  const _StatusBlock({required this.vpn, required this.repo});

  final VpnController vpn;
  final SubscriptionRepository repo;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);

    if (vpn.isBusy) {
      final attempt = vpn.attemptsMade <= 0 ? 1 : vpn.attemptsMade;
      final location = vpn.attemptingLocation;
      final searchText = location == null
          ? t.searchingServer
          : '${t.searchingServer} · ${_locationLabel(t, location)}';
      return Column(
        key: const Key('state_text'),
        children: [
          Text(
            vpn.state == VpnState.disconnecting ? t.disconnecting : t.connecting,
            textAlign: TextAlign.center,
            style: MilkyType.headline.copyWith(color: c.accent),
          ),
          const SizedBox(height: 6),
          Text(
            '$searchText  ${t.attemptOf(attempt, vpn.attemptTotal)}',
            textAlign: TextAlign.center,
            maxLines: 2,
            style: MilkyType.bodySmall.copyWith(color: c.textMuted),
          ),
        ],
      );
    }

    if (vpn.isConnected) {
      final where = _locationLabel(t, vpn.activeLocation);
      return Column(
        key: const Key('state_text'),
        children: [
          Text(
            where,
            textAlign: TextAlign.center,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: MilkyType.display.copyWith(fontSize: 30, color: c.text),
          ),
          const SizedBox(height: 8),
          Wrap(
            alignment: WrapAlignment.center,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              MilkyStatusPill(
                label: t.protectedShort,
                color: c.positive,
                compact: true,
              ),
              const SizedBox(width: MilkySpace.sm),
              _ConnectionClock(
                since: vpn.connectedSince,
                style: MilkyType.subtitle.copyWith(color: c.textMuted),
              ),
            ],
          ),
        ],
      );
    }

    final err = vpn.lastError;
    final showInlineError = err != null && !err.isCancelled;

    return Column(
      key: const Key('state_text'),
      children: [
        Text(
          t.notConnected,
          textAlign: TextAlign.center,
          style: MilkyType.headline.copyWith(color: c.text),
        ),
        const SizedBox(height: 6),
        Text(
          showInlineError
              ? t.errorBody(err.kind)
              : (repo.hasSubscription ? t.tapToConnect : t.needSubscription),
          textAlign: TextAlign.center,
          style: MilkyType.bodySmall.copyWith(
            color: showInlineError ? c.danger : c.textMuted,
          ),
        ),
      ],
    );
  }

  static String _locationLabel(S t, ServerLocation? loc) {
    switch (loc) {
      case ServerLocation.finland:
        return t.finland;
      case ServerLocation.usa:
        return t.usa;
      case ServerLocation.unknown:
      case null:
        return t.connected;
    }
  }
}

/// Ticks once per second while connected, without rebuilding the rest of the screen.
class _ConnectionClock extends StatefulWidget {
  const _ConnectionClock({required this.since, required this.style});

  final DateTime? since;
  final TextStyle style;

  @override
  State<_ConnectionClock> createState() => _ConnectionClockState();
}

class _ConnectionClockState extends State<_ConnectionClock> {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  static String format(Duration d) {
    String two(int n) => n.toString().padLeft(2, '0');
    return '${two(d.inHours)}:${two(d.inMinutes % 60)}:${two(d.inSeconds % 60)}';
  }

  @override
  Widget build(BuildContext context) {
    final since = widget.since;
    final dur = since == null
        ? Duration.zero
        : DateTime.now().difference(since);
    return Text(
      format(dur < Duration.zero ? Duration.zero : dur),
      style: widget.style,
    );
  }
}
