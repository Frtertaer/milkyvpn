import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../app/app_settings.dart';
import '../../core/errors/milky_error.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../core/vpn/vpn_bridge.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_error_sheet.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_setting_row.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';
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
      padding: const EdgeInsets.fromLTRB(MilkySpace.screen, MilkySpace.sm, MilkySpace.screen, MilkySpace.xxl),
      child: MilkyColumn(
        maxWidth: MilkyLayout.maxReadingWidth,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(t.settings, style: MilkyType.display.copyWith(fontSize: 30)),
            const SizedBox(height: MilkySpace.xl),

            MilkySectionHeader(t.groupConnection),
            MilkyGlassCard(
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
                  MilkySettingRow(
                    icon: Icons.vpn_lock_rounded,
                    title: t.alwaysOn,
                    subtitle: t.alwaysOnHint,
                    showChevron: true,
                    onTap: () => bridge.openVpnSettings(),
                  ),
                ],
              ),
            ),

            const SizedBox(height: MilkySpace.sm),
            MilkySectionHeader(t.groupApp),
            MilkyGlassCard(
              padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(MilkySpace.lg, MilkySpace.md, MilkySpace.lg, MilkySpace.lg),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Container(
                              width: 34,
                              height: 34,
                              decoration: BoxDecoration(color: c.accentSoft, borderRadius: BorderRadius.circular(11)),
                              child: Icon(Icons.dark_mode_rounded, size: 18, color: c.accent),
                            ),
                            const SizedBox(width: MilkySpace.md),
                            Text(t.theme, style: MilkyType.subtitle),
                          ],
                        ),
                        const SizedBox(height: MilkySpace.md),
                        MilkySegmented<ThemeMode>(
                          values: const [ThemeMode.system, ThemeMode.light, ThemeMode.dark],
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
                        ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                        : null,
                    onTap: _refreshing ? null : _refresh,
                  ),
                ],
              ),
            ),

            const SizedBox(height: MilkySpace.sm),
            MilkySectionHeader(t.groupHelp),
            MilkyGlassCard(
              padding: const EdgeInsets.symmetric(vertical: MilkySpace.xs),
              child: Column(
                children: [
                  MilkySettingRow(
                    icon: Icons.troubleshoot_rounded,
                    title: t.diagnostics,
                    subtitle: t.diagnosticsHint,
                    showChevron: true,
                    onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const DiagnosticsScreen())),
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
                    onTap: () => _showInfo(context, t.about, '${t.aboutBody}\n\n${t.version}: $kAppVersion'),
                  ),
                  const MilkyHairline(indent: MilkySpace.lg),
                  MilkySettingRow(
                    icon: Icons.tag_rounded,
                    title: t.version,
                    trailing: Text(kAppVersion, style: MilkyType.chip.copyWith(color: c.textMuted)),
                  ),
                ],
              ),
            ),
            const SizedBox(height: MilkySpace.xl),
            Center(
              child: MilkyWordmark(size: 15),
            ),
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
      messenger.showSnackBar(SnackBar(content: Text(snap == null ? t.noSubscription : t.importOk)));
    } on SubscriptionFetchException catch (e) {
      if (!mounted) return;
      MilkyHaptics.error();
      await MilkyErrorSheet.show(
        context,
        error: MilkyError.fromCode(e.errorClass),
        onRetry: _refresh,
        onOpenDiagnostics: () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const DiagnosticsScreen())),
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
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(S.of(context).supportHint)));
    }
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
            padding: const EdgeInsets.fromLTRB(MilkySpace.md, 0, MilkySpace.md, MilkySpace.md),
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
                      child: Text(body, style: MilkyType.body.copyWith(color: c.textMuted)),
                    ),
                  ),
                  const SizedBox(height: MilkySpace.xl),
                  MilkyGhostButton(label: S.of(ctx).cancel, onPressed: () => Navigator.of(ctx).pop()),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
