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
import '../../design/milky_motion.dart';
import '../../design/milky_screen.dart';
import '../../design/milky_sheet.dart';
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
    context
        .read<VpnBridge>()
        .coreVersion()
        .then((v) {
          if (mounted) setState(() => _core = v);
        })
        .catchError((Object _) {
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

    final MilkyError? err = vpn.lastError?.withDeviceContext(
      isEmulator: device.isEmulator,
    );
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
                if (err != null)
                  MilkyGlassCard(
                    tone: MilkyGlassTone.danger,
                    padding: const EdgeInsets.all(MilkySpace.xl),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        MilkySectionHeader(
                          t.diagLastError,
                          padding: EdgeInsets.zero,
                        ),
                        DiagnosticsCodeLine(
                          value: err.diagnosticsCode,
                          style: MilkyType.mono.copyWith(
                            color: c.text,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: MilkySpace.xs),
                        Text(
                          '${t.diagCategory}: ${err.category.diagnosticsToken}',
                          style: MilkyType.bodySmall.copyWith(
                            color: c.textMuted,
                          ),
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
                        _DiagRow(
                          label: rows[i].$1,
                          value: rows[i].$2,
                          valueIsCode:
                              err != null && rows[i].$1 == t.diagLastError,
                        ),
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
                      Text(
                        t.diagHint,
                        style: MilkyType.bodySmall.copyWith(color: c.textMuted),
                      ),
                      const SizedBox(height: MilkySpace.md),
                      MilkyGhostButton(
                        label: t.reportDetails,
                        onPressed: () => showModalBottomSheet<void>(
                          context: context,
                          isScrollControlled: true,
                          backgroundColor: Colors.transparent,
                          builder: (_) => MilkySheetFrame(
                            child: SelectableText(
                              report,
                              style: MilkyType.mono.copyWith(
                                color: c.textMuted,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: MilkySpace.xl),
                MilkyPrimaryButton(
                  label: t.copyDiagnostics,
                  icon: Icons.copy_rounded,
                  onPressed: () async {
                    final messenger = ScaffoldMessenger.of(context);
                    await Clipboard.setData(ClipboardData(text: report));
                    if (!mounted) return;
                    MilkyHaptics.tap();
                    messenger.showSnackBar(SnackBar(content: Text(t.copied)));
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
      (device.platformLabel, device.osLabel),
      (t.diagCore, _core),
      (t.diagState, vpn.state.name),
      (t.diagProfile, const Redactor().redact(vpn.activeRemark ?? t.diagNone)),
      (
        t.diagSubscription,
        !repo.hasSubscription
            ? t.diagNone
            : stats.countsTrusted
            ? '${stats.parsedProfileCount} / ${stats.postDedupeProfileCount} / ${stats.compatibleProfileCount}'
            : t.countsNotVerified,
      ),
      (t.diagLastError, err?.diagnosticsCode ?? t.diagNone),
      (
        t.diagCategory,
        err?.category.diagnosticsToken ??
            MilkyFailureCategory.none.diagnosticsToken,
      ),
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
    final stageLines = <String>[
      if (vpn.native.lastSuccessfulStage != null)
        'LAST_SUCCESSFUL_STAGE = ${vpn.native.lastSuccessfulStage}',
      if (vpn.native.firstFailedStage != null)
        'FIRST_FAILED_STAGE = ${vpn.native.firstFailedStage}',
    ];
    return r.redact(
      [
        'MilkyVPN $kAppVersion',
        '${device.platformLabel} ${device.osLabel}',
        'Core: $_core',
        'State: ${vpn.state.name}',
        'Busy: ${vpn.isBusy ? 'yes' : 'no'}',
        'Profile: ${vpn.activeRemark ?? '-'}',
        'Last error: ${err?.diagnosticsCode ?? '-'}',
        'Category: ${err?.category.diagnosticsToken ?? MilkyFailureCategory.none.diagnosticsToken}',
        ...stageLines,
        'Subscription: ${repo.hasSubscription ? 'present' : 'none'}',
        'Counts trusted: ${stats.countsTrusted}',
        'Entries received: ${stats.receivedEntryCount}, parsed: ${stats.parsedProfileCount}, '
            'post-dedupe: ${stats.postDedupeProfileCount}, compatible: ${stats.compatibleProfileCount}, '
            'duplicates dropped: ${stats.droppedDuplicateCount}, malformed: ${stats.malformedEntryCount}',
      ].join('\n'),
    );
  }
}

class _DiagRow extends StatelessWidget {
  const _DiagRow({
    required this.label,
    required this.value,
    this.valueIsCode = false,
  });

  final String label;
  final String value;
  final bool valueIsCode;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: MilkySpace.lg,
        vertical: 11,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Text(
              label,
              style: MilkyType.bodySmall.copyWith(color: c.textMuted),
            ),
          ),
          const SizedBox(width: MilkySpace.md),
          Flexible(
            child: valueIsCode
                ? DiagnosticsCodeLine(
                    value: value,
                    alignment: Alignment.centerRight,
                    style: MilkyType.bodySmall.copyWith(
                      color: c.text,
                      fontFamily: MilkyType.family,
                    ),
                  )
                : Text(
                    value,
                    textAlign: TextAlign.right,
                    style: MilkyType.bodySmall.copyWith(
                      color: c.text,
                      fontFamily: MilkyType.family,
                    ),
                  ),
          ),
        ],
      ),
    );
  }
}

/// Keeps diagnostic tokens copyable and on one line at large text scales.
class DiagnosticsCodeLine extends StatelessWidget {
  const DiagnosticsCodeLine({
    required this.value,
    required this.style,
    this.alignment = Alignment.centerLeft,
    super.key,
  });

  final String value;
  final TextStyle style;
  final Alignment alignment;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: ConstrainedBox(
          constraints: BoxConstraints(minWidth: constraints.maxWidth),
          child: Align(
            alignment: alignment,
            child: SelectableText(value, maxLines: 1, style: style),
          ),
        ),
      ),
    );
  }
}
