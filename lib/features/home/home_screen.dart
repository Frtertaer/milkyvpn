import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../app/app_settings.dart';
import '../../app/milky_device.dart';
import '../../core/subscription/profile_health.dart';
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
import '../update/update_flow.dart';
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
  void initState() {
    super.initState();
    // Self-update check: GitHub Releases only ships Android APKs and the
    // Windows installer today, so other platforms skip the API call.
    if (Platform.isAndroid || Platform.isWindows) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) UpdateFlow.checkOnLaunch(context);
      });
    }
  }

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
    final selector = Row(
      children: [
        Expanded(
          child: MilkyServerSelector(
            value: settings.location,
            counts: counts,
            enabled: !vpn.isBusy,
            onChanged: (choice) {
              if (choice == settings.location) return;
              final s = context.read<AppSettings>();
              s.setSelectedProfile(null);
              s.setLocation(choice);
            },
          ),
        ),
        const SizedBox(width: 8),
        MilkyIconButton(
          icon: Icons.public_rounded,
          tooltip: t.chooseCountry,
          onPressed: vpn.isBusy ? null : _pickServerFromHome,
        ),
      ],
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
        profileId: settings.selectedProfileId,
      );
    } finally {
      if (mounted) setState(() => _working = false);
    }
    if (!mounted) return;
    if (ok) {
      MilkyHaptics.success();
      if (vpn.pinnedFellBack) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(S.of(context).pinnedFellBack)));
      }
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

  /// The country/profile sheet shared by the error-recovery flow and the
  /// home-screen picker button.
  Future<(LocationChoice?, String?)?> _showServerSheet() {
    final settings = context.read<AppSettings>();
    final counts = locationCounts(
      context.read<SubscriptionRepository>().snapshot?.profiles ?? [],
    );
    final profiles =
        context.read<SubscriptionRepository>().snapshot?.profiles ??
            const <VpnProfile>[];
    return showModalBottomSheet<(LocationChoice?, String?)>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => MilkySheetFrame(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Text(S.of(ctx).chooseCountry, style: MilkyType.headline),
            ),
            const SizedBox(height: 24),
            MilkyServerSelector(
              value: settings.location,
              counts: counts,
              onChanged: (choice) => Navigator.of(ctx).pop((choice, null)),
            ),
            if (profiles.isNotEmpty) ...[
              const SizedBox(height: 16),
              _ProfilePickList(
                profiles: profiles,
                selectedId: settings.selectedProfileId,
                onPick: (id) => Navigator.of(ctx).pop((null, id)),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _applyServerPick((LocationChoice?, String?) next) async {
    final settings = context.read<AppSettings>();
    final (choice, profileId) = next;
    if (profileId != null) {
      await settings.setSelectedProfile(profileId);
    } else {
      await settings.setSelectedProfile(null);
      if (choice != null) await settings.setLocation(choice);
    }
  }

  /// Home-screen picker: same sheet as the error flow, but only applies the
  /// choice — the user starts the connect with the orb when ready.
  Future<void> _pickServerFromHome() async {
    final next = await _showServerSheet();
    if (next == null) return;
    await _applyServerPick(next);
  }

  /// "Другой сервер": move off Auto (or off the current country) and retry immediately.
  Future<void> _pickAnotherLocation() async {
    final next = await _showServerSheet();
    if (next == null) return;
    await _applyServerPick(next);
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

// ------------------------------------------------------------------ profile pick

/// The per-profile list inside the server sheet: tap a profile to pin it —
/// connects use exactly that server until the user picks a location again.
class _ProfilePickList extends StatefulWidget {
  const _ProfilePickList({
    required this.profiles,
    required this.selectedId,
    required this.onPick,
  });

  final List<VpnProfile> profiles;
  final String? selectedId;
  final ValueChanged<String> onPick;

  /// Distinguisher chip text: `carrier` plus the front host when the profile
  /// dials a front relay — several profiles on the same host:port are
  /// otherwise indistinguishable in this list.
  static String _tagFor(VpnProfile p) {
    final carrier = p.network.trim();
    final front = p.front ??
        (p.fronts != null && p.fronts!.isNotEmpty ? p.fronts!.first : null);
    final host = _frontHost(front);
    return [if (carrier.isNotEmpty) carrier, if (host != null) host]
        .join(' · ');
  }

  /// Registered host of a front= URL, middle-truncated when long so the chip
  /// stays narrow (`milky-front.mi…workers.dev` keeps the domain tail).
  static String? _frontHost(String? front) {
    if (front == null) return null;
    final f = front.trim();
    if (f.isEmpty) return null;
    final uri = Uri.tryParse(f.contains('://') ? f : 'https://$f');
    final host = (uri?.host ?? '').trim();
    if (host.isEmpty) return f;
    if (host.length <= 26) return host;
    final labels = host.split('.');
    if (labels.length < 3) return '${host.substring(0, 25)}…';
    final tail = '${labels[labels.length - 2]}.${labels.last}';
    if (tail.length > 22) return '${host.substring(0, 25)}…';
    return '${host.substring(0, 25 - tail.length)}…$tail';
  }

  @override
  State<_ProfilePickList> createState() => _ProfilePickListState();
}

class _ProfilePickListState extends State<_ProfilePickList> {
  Map<String, ProfileProbe> _health = const {};

  @override
  void initState() {
    super.initState();
    ProfileHealth.measure(widget.profiles).then((m) {
      if (mounted) setState(() => _health = m);
    });
  }

  /// Health chip text for a probe result — ms RTT, 'udp' for UDP-only
  /// carriers, 'мёртв' when the dial target didn't answer.
  static String? _healthText(ProfileProbe? h, S t) {
    if (h == null) return null;
    if (h.udp) return 'udp';
    if (h.dead) return t.profileDead;
    final ms = h.ms;
    return ms == null ? null : '$ms ms';
  }

  /// Chip tint: healthy accent, slow warning, dead danger.
  static Color _healthColor(ProfileProbe? h, MilkyColors c) {
    if (h == null || h.udp) return c.accent;
    if (h.dead) return c.danger;
    final ms = h.ms ?? 9999;
    if (ms <= 300) return c.accent;
    if (ms <= 800) return c.warning;
    return c.danger;
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final items =
        widget.profiles.where((p) => p.isStaticCompatible).toList(growable: false);
    if (items.isEmpty) return const SizedBox.shrink();
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(t.profiles, style: MilkyType.bodySmall),
        const SizedBox(height: 8),
        ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 280),
          child: ListView.separated(
            shrinkWrap: true,
            itemCount: items.length,
            separatorBuilder: (_, __) => const SizedBox(height: 6),
            itemBuilder: (ctx, i) {
              final p = items[i];
              final sel = p.id == widget.selectedId;
              final label = p.redactedRemark.trim().isEmpty
                  ? '${p.address}:${p.port}'
                  : p.redactedRemark.trim();
              final tag = _ProfilePickList._tagFor(p);
              final health = _health[p.id];
              final healthText = _healthText(health, t);
              final healthColor = _healthColor(health, c);
              return Material(
                color: sel
                    ? c.accent.withValues(alpha: 0.14)
                    : (c.isDark
                        ? c.glassTint
                        : Colors.white.withValues(alpha: 0.6)),
                borderRadius: BorderRadius.circular(MilkyRadius.control),
                child: InkWell(
                  borderRadius: BorderRadius.circular(MilkyRadius.control),
                  onTap: () => widget.onPick(p.id),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 14,
                      vertical: 12,
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: Text(
                            label,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: MilkyType.body,
                          ),
                        ),
                        if (tag.isNotEmpty) ...[
                          const SizedBox(width: 8),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 3,
                            ),
                            decoration: BoxDecoration(
                              color: c.accent.withValues(alpha: 0.10),
                              borderRadius: BorderRadius.circular(999),
                              border: Border.all(
                                color: c.accent.withValues(alpha: 0.35),
                              ),
                            ),
                            child: Text(
                              tag,
                              maxLines: 1,
                              style: MilkyType.label.copyWith(
                                color: c.accent,
                                fontSize: 10.5,
                                letterSpacing: 0.4,
                              ),
                            ),
                          ),
                        ],
                        if (healthText != null) ...[
                          const SizedBox(width: 6),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 7,
                              vertical: 3,
                            ),
                            decoration: BoxDecoration(
                              color: healthColor.withValues(alpha: 0.10),
                              borderRadius: BorderRadius.circular(999),
                              border: Border.all(
                                color: healthColor.withValues(alpha: 0.4),
                              ),
                            ),
                            child: Text(
                              healthText,
                              maxLines: 1,
                              style: MilkyType.label.copyWith(
                                color: healthColor,
                                fontSize: 10.5,
                                letterSpacing: 0.4,
                              ),
                            ),
                          ),
                        ],
                        if (sel) ...[
                          const SizedBox(width: 6),
                          Icon(Icons.check_rounded, size: 18, color: c.accent),
                        ],
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}
