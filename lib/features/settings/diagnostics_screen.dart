import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../app/app_info.dart';
import '../../app/milky_device.dart';
import '../../core/errors/milky_error.dart';
import '../../core/security/redactor.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../core/subscription/subscription_stats.dart';
import '../../core/vpn/vpn_bridge.dart';
import '../../core/vpn/vpn_controller.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_screen.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// The only screen where technical codes are allowed to appear.
class DiagnosticsScreen extends StatefulWidget {
  const DiagnosticsScreen({super.key});

  @override
  State<DiagnosticsScreen> createState() => _DiagnosticsScreenState();
}

class _DiagnosticsScreenState extends State<DiagnosticsScreen> {
  String _core = '…';

  @override
  void initState() {
    super.initState();
    context.read<VpnBridge>().coreVersion().then((v) {
      if (mounted) setState(() => _core = v);
    }).catchError((Object _) {
      if (mounted) setState(() => _core = 'unavailable');
    });
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final vpn = context.watch<VpnController>();
    final repo = context.watch<SubscriptionRepository>();
    final device = context.watch<MilkyDevice>();
    final stats = SubscriptionStats.from(repo.snapshot);

    final MilkyError? err = vpn.lastError?.withDeviceContext(isEmulator: device.isEmulator);
    final rows = _rows(context, t, vpn, repo, device, stats, err);
    final report = _report(context, t, vpn, repo, device, stats, err);

    return MilkyScreen(
      appBar: AppBar(
        title: Text(t.diagnostics, style: MilkyType.title),
        leading: MilkyIconButton(
          icon: Icons.arrow_back_rounded,
          size: 38,
          onPressed: () => Navigator.of(context).pop(),
        ),
      ),
      child: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(MilkySpace.screen, MilkySpace.sm, MilkySpace.screen, MilkySpace.xxl),
          child: MilkyColumn(
            maxWidth: MilkyLayout.maxReadingWidth,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (err != null)
                  MilkyGlassCard(
                    tone: MilkyGlassTone.danger,
                    padding: const EdgeInsets.all(MilkySpace.xl),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        MilkySectionHeader(t.diagLastError, padding: EdgeInsets.zero),
                        Text(err.diagnosticsCode, style: MilkyType.mono.copyWith(color: c.text, fontWeight: FontWeight.w700)),
                        const SizedBox(height: MilkySpace.xs),
                        Text(
                          '${t.diagCategory}: ${err.category.diagnosticsToken}',
                          style: MilkyType.bodySmall.copyWith(color: c.textMuted),
                        ),
                      ],
                    ),
                  ),
                if (err != null) const SizedBox(height: MilkySpace.md),
                MilkyGlassCard(
                  padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
                  child: Column(
                    children: [
                      for (var i = 0; i < rows.length; i++) ...[
                        if (i > 0) const MilkyHairline(indent: MilkySpace.lg),
                        _DiagRow(label: rows[i].$1, value: rows[i].$2),
                      ],
                    ],
                  ),
                ),
                const SizedBox(height: MilkySpace.lg),
                MilkySectionHeader(t.advanced),
                MilkyGlassCard(
                  padding: const EdgeInsets.all(MilkySpace.lg),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Text(t.diagHint, style: MilkyType.bodySmall.copyWith(color: c.textMuted)),
                      const SizedBox(height: MilkySpace.md),
                      SelectableText(report, style: MilkyType.mono.copyWith(color: c.textFaint)),
                    ],
                  ),
                ),
                const SizedBox(height: MilkySpace.xl),
                MilkyPrimaryButton(
                  label: t.copyDiagnostics,
                  icon: Icons.copy_rounded,
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: report));
                    if (!mounted) return;
                    MilkyHaptics.tap();
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t.copied)));
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  List<(String, String)> _rows(
    BuildContext context,
    S t,
    VpnController vpn,
    SubscriptionRepository repo,
    MilkyDevice device,
    SubscriptionStats stats,
    MilkyError? err,
  ) {
    return [
      (t.diagDevice, device.summary.isEmpty ? 'unknown' : device.summary),
      (t.diagDeviceType, device.isEmulator ? t.diagEmulator : t.diagRealDevice),
      ('Android', device.osVersion.isEmpty ? '?' : '${device.osVersion} (API ${device.sdkInt})'),
      ('ABI', device.abi.isEmpty ? '?' : device.abi),
      (t.diagCore, _core),
      (t.diagState, vpn.state.name),
      (t.diagProfile, vpn.activeRemark ?? t.diagNone),
      (t.diagAttempts, '${vpn.attemptsMade}/${vpn.attemptTotal}'),
      (t.diagSubscription, repo.hasSubscription ? '${stats.profiles} / ${stats.compatible}' : t.diagNone),
      (t.diagLastError, err?.diagnosticsCode ?? t.diagNone),
      (t.diagCategory, err?.category.diagnosticsToken ?? MilkyFailureCategory.none.diagnosticsToken),
      (t.version, kAppVersion),
    ];
  }

  /// Credential-free report (everything passes through [Redactor]).
  String _report(
    BuildContext context,
    S t,
    VpnController vpn,
    SubscriptionRepository repo,
    MilkyDevice device,
    SubscriptionStats stats,
    MilkyError? err,
  ) {
    const r = Redactor();
    return r.redact([
      'MilkyVPN $kAppVersion',
      'Android ${device.osVersion.isEmpty ? '?' : device.osVersion} (API ${device.sdkInt}, ${device.abi})',
      'Device: ${device.summary} (${device.isEmulator ? 'emulator' : 'physical'})',
      'Core: $_core',
      'State: ${vpn.state.name}',
      'Profile: ${vpn.activeRemark ?? '-'}',
      'Attempts: ${vpn.attemptsMade}/${vpn.attemptTotal}',
      'Last error: ${err?.diagnosticsCode ?? '-'} (raw: ${vpn.lastErrorClass ?? '-'})',
      'Category: ${err?.category.diagnosticsToken ?? MilkyFailureCategory.none.diagnosticsToken}',
      'Subscription: ${repo.hasSubscription ? 'present' : 'none'}',
      'Lines: ${stats.totalLines}, profiles: ${stats.profiles}, compatible: ${stats.compatible}, '
          'duplicates: ${stats.duplicates}, malformed: ${stats.malformed}',
    ].join('\n'));
  }
}

class _DiagRow extends StatelessWidget {
  const _DiagRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: MilkySpace.lg, vertical: 11),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: Text(label, style: MilkyType.bodySmall.copyWith(color: c.textMuted))),
          const SizedBox(width: MilkySpace.md),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: MilkyType.bodySmall.copyWith(color: c.text, fontFamily: 'monospace'),
            ),
          ),
        ],
      ),
    );
  }
}
