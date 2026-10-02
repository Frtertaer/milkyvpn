import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../app/app_info.dart';
import '../../app/app_settings.dart';
import '../../core/errors/milky_error.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../core/vpn/dns_check.dart';
import '../../core/vpn/speed_test.dart';
import '../../core/vpn/vpn_bridge.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_brand.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_error_sheet.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_setting_row.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';
import '../update/update_flow.dart';
import 'apps_screen.dart';
import 'diagnostics_screen.dart';

/// Settings as grouped glass cards with custom rows — not a Material preference list.
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, this.onOpenSubscription});

  final VoidCallback? onOpenSubscription;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _refreshing = false;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final c = context.milky;
    final s = context.watch<AppSettings>();
    final repo = context.watch<SubscriptionRepository>();
    final bridge = context.read<VpnBridge>();

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(
        MilkySpace.screen,
        MilkySpace.sm,
        MilkySpace.screen,
        MilkySpace.xxl,
      ),
      child: MilkyColumn(
        maxWidth: MilkyLayout.maxReadingWidth,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(t.settings, style: MilkyType.display.copyWith(fontSize: 30)),
            const SizedBox(height: MilkySpace.xl),

            MilkySectionHeader(t.groupConnection),
            MilkyGlassCard(
              elevated: false,
              padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
              child: Column(
                children: [
                  MilkySettingRow(
                    icon: Icons.power_settings_new_rounded,
                    title: t.autoConnect,
                    subtitle: t.autoConnectHint,
                    value: s.autoConnect,
                    onChanged: s.setAutoConnect,
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  // Full-TUN exists on Windows only; Android tunnels via
                  // VpnService already.
                  if (Platform.isWindows)
                    MilkySettingRow(
                      icon: Icons.lan_rounded,
                      title: t.fullTunnel,
                      subtitle: t.fullTunnelHint,
                      value: s.fullTunnel,
                      onChanged: s.setFullTunnel,
                    ),
                  if (Platform.isWindows)
                    const MilkyHairline(indent: MilkySpace.lg),
                  // Always-on VPN is an Android VpnService feature; the
                  // same tap elsewhere opened unrelated OS settings.
                  if (Platform.isAndroid)
                    MilkySettingRow(
                      icon: Icons.vpn_lock_rounded,
                      title: t.alwaysOn,
                      subtitle: t.alwaysOnHint,
                      showChevron: true,
                      onTap: () => bridge.openVpnSettings(),
                    ),
                  if (Platform.isAndroid)
                    const MilkyHairline(indent: MilkySpace.lg),
                  // Per-app split tunneling — Android VpnService only.
                  if (Platform.isAndroid)
                    MilkySettingRow(
                      icon: Icons.apps_rounded,
                      title: t.splitApps,
                      subtitle: t.splitAppsHint,
                      showChevron: true,
                      onTap: () => Navigator.of(context).push(
                        MaterialPageRoute<void>(
                          builder: (_) => const AppsScreen(),
                        ),
                      ),
                    ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.speed_rounded,
                    title: t.speedtest,
                    subtitle: t.speedtestHint,
                    showChevron: true,
                    onTap: _runSpeedTest,
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.dns_rounded,
                    title: t.dnsCheck,
                    subtitle: t.dnsCheckHint,
                    showChevron: true,
                    onTap: () => _runDnsCheck(bridge),
                  ),
                ],
              ),
            ),

            const SizedBox(height: MilkySpace.sm),
            MilkySectionHeader(t.groupApp),
            MilkyGlassCard(
              elevated: false,
              padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(
                      MilkySpace.lg,
                      MilkySpace.md,
                      MilkySpace.lg,
                      MilkySpace.lg,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Container(
                              width: 34,
                              height: 34,
                              decoration: BoxDecoration(
                                color: c.accentSoft,
                                borderRadius: BorderRadius.circular(11),
                              ),
                              child: Icon(
                                Icons.dark_mode_rounded,
                                size: 18,
                                color: c.accent,
                              ),
                            ),
                            const SizedBox(width: MilkySpace.md),
                            Text(t.theme, style: MilkyType.subtitle),
                          ],
                        ),
                        const SizedBox(height: MilkySpace.md),
                        MilkySegmented<ThemeMode>(
                          values: const [
                            ThemeMode.system,
                            ThemeMode.light,
                            ThemeMode.dark,
                          ],
                          selected: s.themeMode,
                          onSelected: s.setThemeMode,
                          labelOf: (m) {
                            switch (m) {
                              case ThemeMode.system:
                                return t.themeSystem;
                              case ThemeMode.light:
                                return t.themeLight;
                              case ThemeMode.dark:
                                return t.themeDark;
                            }
                          },
                        ),
                      ],
                    ),
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.refresh_rounded,
                    title: t.checkSubscriptionUpdate,
                    subtitle: repo.hasSubscription ? null : t.noSubscription,
                    trailing: _refreshing
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : null,
                    onTap: _refreshing ? null : _refresh,
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.sync_rounded,
                    title: t.autoUpdateSub,
                    subtitle: t.autoUpdateSubHint,
                    value: s.autoUpdateSub,
                    onChanged: s.setAutoUpdateSub,
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.system_update_alt_rounded,
                    title: t.appUpdate,
                    subtitle: kAppVersion,
                    showChevron: true,
                    onTap: () => UpdateFlow.check(context, manual: true),
                  ),
                ],
              ),
            ),

            const SizedBox(height: MilkySpace.sm),
            MilkySectionHeader(t.groupHelp),
            MilkyGlassCard(
              elevated: false,
              padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
              child: Column(
                children: [
                  MilkySettingRow(
                    icon: Icons.troubleshoot_rounded,
                    title: t.diagnostics,
                    subtitle: t.diagnosticsHint,
                    showChevron: true,
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => const DiagnosticsScreen(),
                      ),
                    ),
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.support_agent_rounded,
                    title: t.support,
                    subtitle: t.supportHint,
                    showChevron: true,
                    onTap: _openSupport,
                  ),
                ],
              ),
            ),

            const SizedBox(height: MilkySpace.sm),
            MilkySectionHeader(t.groupAbout),
            MilkyGlassCard(
              elevated: false,
              padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
              child: Column(
                children: [
                  MilkySettingRow(
                    icon: Icons.privacy_tip_rounded,
                    title: t.privacy,
                    showChevron: true,
                    onTap: () => _showInfo(context, t.privacy, t.privacyBody),
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.info_rounded,
                    title: t.about,
                    subtitle: t.aboutBody,
                    showChevron: true,
                    onTap: () => _showInfo(
                      context,
                      t.about,
                      '${t.aboutBody}\n\n${t.version}: $kAppVersion',
                    ),
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.tag_rounded,
                    title: t.version,
                    trailing: Text(
                      kAppVersion,
                      style: MilkyType.chip.copyWith(color: c.textMuted),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: MilkySpace.xl),
            Center(child: MilkyWordmark(size: 15)),
          ],
        ),
      ),
    );
  }

  Future<void> _refresh() async {
    final t = S.of(context);
    final repo = context.read<SubscriptionRepository>();
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _refreshing = true);
    try {
      final snap = await repo.refresh();
      if (!mounted) return;
      MilkyHaptics.success();
      messenger.showSnackBar(
        SnackBar(
          content: Text(
            snap == null
                ? (repo.hasSubscription ? t.notRefreshable : t.noSubscription)
                : t.importOk,
          ),
        ),
      );
    } on SubscriptionFetchException catch (e) {
      if (!mounted) return;
      MilkyHaptics.error();
      await MilkyErrorSheet.show(
        context,
        error: MilkyError.fromCode(e.errorClass),
        onRetry: _refresh,
        onOpenDiagnostics: () => Navigator.of(context).push(
          MaterialPageRoute<void>(builder: (_) => const DiagnosticsScreen()),
        ),
      );
    } finally {
      if (mounted) setState(() => _refreshing = false);
    }
  }

  Future<void> _openSupport() async {
    final uri = Uri.parse(kSupportUrl);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } else if (mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(S.of(context).supportHint)));
    }
  }

  /// DNS posture: Private DNS mode + DoH through the tunnel and directly.
  void _runDnsCheck(VpnBridge bridge) {
    final c = context.milky;
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      barrierColor: c.scrim,
      builder: (ctx) => SafeArea(
        top: false,
        child: MilkyColumn(
          maxWidth: MilkyLayout.maxReadingWidth,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(
              MilkySpace.md,
              0,
              MilkySpace.md,
              MilkySpace.md,
            ),
            child: MilkyGlassCard(
              radius: MilkyRadius.sheet,
              padding: const EdgeInsets.all(MilkySpace.xxl),
              child: _DnsCheckBody(future: checkDns(bridge)),
            ),
          ),
        ),
      ),
    );
  }

  /// Throughput probe through the tunnel's loopback SOCKS inbound.
  void _runSpeedTest() {
    final c = context.milky;
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      barrierColor: c.scrim,
      builder: (ctx) => SafeArea(
        top: false,
        child: MilkyColumn(
          maxWidth: MilkyLayout.maxReadingWidth,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(
              MilkySpace.md,
              0,
              MilkySpace.md,
              MilkySpace.md,
            ),
            child: MilkyGlassCard(
              radius: MilkyRadius.sheet,
              padding: const EdgeInsets.all(MilkySpace.xxl),
              child: _SpeedtestBody(future: runSpeedTest()),
            ),
          ),
        ),
      ),
    );
  }

  void _showInfo(BuildContext context, String title, String body) {
    final c = context.milky;
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: c.scrim,
      builder: (ctx) => SafeArea(
        top: false,
        child: MilkyColumn(
          maxWidth: MilkyLayout.maxReadingWidth,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(
              MilkySpace.md,
              0,
              MilkySpace.md,
              MilkySpace.md,
            ),
            child: MilkyGlassCard(
              radius: MilkyRadius.sheet,
              padding: const EdgeInsets.all(MilkySpace.xxl),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: MilkyType.headline),
                  const SizedBox(height: MilkySpace.md),
                  Flexible(
                    child: SingleChildScrollView(
                      child: Text(
                        body,
                        style: MilkyType.body.copyWith(color: c.textMuted),
                      ),
                    ),
                  ),
                  const SizedBox(height: MilkySpace.xl),
                  MilkyGhostButton(
                    label: S.of(ctx).cancel,
                    onPressed: () => Navigator.of(ctx).pop(),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Speedtest sheet body: spinner while measuring, then ping + Mbps or a
/// failure note (VPN off / proxy unreachable).
class _SpeedtestBody extends StatelessWidget {
  const _SpeedtestBody({required this.future});

  final Future<SpeedResult> future;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final c = context.milky;
    return FutureBuilder<SpeedResult>(
      future: future,
      builder: (ctx, snap) {
        if (snap.connectionState != ConnectionState.done) {
          return Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(t.speedtest, style: MilkyType.headline),
              const SizedBox(height: MilkySpace.xl),
              const SizedBox(
                width: 28,
                height: 28,
                child: CircularProgressIndicator(strokeWidth: 2.5),
              ),
              const SizedBox(height: MilkySpace.md),
              Text(
                t.speedtestRunning,
                style: MilkyType.bodySmall.copyWith(color: c.textMuted),
              ),
            ],
          );
        }
        final r = snap.data;
        return Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(t.speedtest, style: MilkyType.headline),
            const SizedBox(height: MilkySpace.lg),
            if (r != null) ...[
              Text(
                t.speedtestResult(r.pingMs, r.downMbps),
                style: MilkyType.subtitle,
              ),
              const SizedBox(height: MilkySpace.xs),
              Text(
                t.speedtestNote,
                style: MilkyType.bodySmall.copyWith(color: c.textMuted),
              ),
            ] else
              Text(
                t.speedtestFail,
                style: MilkyType.body.copyWith(color: c.textMuted),
              ),
            const SizedBox(height: MilkySpace.xl),
            MilkyGhostButton(
              label: t.close,
              onPressed: () => Navigator.of(ctx).pop(),
            ),
          ],
        );
      },
    );
  }
}

/// DNS-check sheet body: spinner, then Private-DNS mode, tunnel-DoH verdict
/// and a direct-path note.
class _DnsCheckBody extends StatelessWidget {
  const _DnsCheckBody({required this.future});

  final Future<DnsCheckResult> future;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final c = context.milky;
    return FutureBuilder<DnsCheckResult>(
      future: future,
      builder: (ctx, snap) {
        if (snap.connectionState != ConnectionState.done) {
          return Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(t.dnsCheck, style: MilkyType.headline),
              const SizedBox(height: MilkySpace.xl),
              const SizedBox(
                width: 28,
                height: 28,
                child: CircularProgressIndicator(strokeWidth: 2.5),
              ),
              const SizedBox(height: MilkySpace.md),
              Text(
                t.dnsChecking,
                style: MilkyType.bodySmall.copyWith(color: c.textMuted),
              ),
            ],
          );
        }
        final r = snap.data;
        if (r == null) {
          return Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(t.dnsCheck, style: MilkyType.headline),
              const SizedBox(height: MilkySpace.lg),
              Text(
                t.dnsCheckFail,
                style: MilkyType.body.copyWith(color: c.textMuted),
              ),
              const SizedBox(height: MilkySpace.xl),
              MilkyGhostButton(
                label: t.close,
                onPressed: () => Navigator.of(ctx).pop(),
              ),
            ],
          );
        }
        final pdns = switch (r.privateDnsMode) {
          'hostname' => t.dnsPrivateHostname(r.privateDnsSpecifier),
          'opportunistic' => t.dnsPrivateAuto,
          'off' => t.dnsPrivateOff,
          _ => t.dnsPrivateUnknown,
        };
        return Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(t.dnsCheck, style: MilkyType.headline),
            const SizedBox(height: MilkySpace.lg),
            _DnsLine(
              ok: r.dohViaTunnel,
              text: r.dohViaTunnel ? t.dnsTunnelOk : t.dnsTunnelFail,
            ),
            const SizedBox(height: MilkySpace.sm),
            _DnsLine(ok: !r.privateDnsOff, text: pdns),
            const SizedBox(height: MilkySpace.sm),
            _DnsLine(
              ok: !r.leakSuspected,
              text: r.dohDirect ? t.dnsDirectOpen : t.dnsDirectClosed,
            ),
            const SizedBox(height: MilkySpace.xl),
            MilkyGhostButton(
              label: t.close,
              onPressed: () => Navigator.of(ctx).pop(),
            ),
          ],
        );
      },
    );
  }
}

class _DnsLine extends StatelessWidget {
  const _DnsLine({required this.ok, required this.text});

  final bool ok;
  final String text;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(
          ok ? Icons.check_circle_outline_rounded : Icons.error_outline_rounded,
          size: 18,
          color: ok ? c.accent : c.danger,
        ),
        const SizedBox(width: MilkySpace.sm),
        Expanded(child: Text(text, style: MilkyType.bodySmall)),
      ],
    );
  }
}
