import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../core/errors/milky_error.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../core/vpn/vpn_bridge.dart';
import '../../core/vpn/vpn_controller.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_error_sheet.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';
import '../import/import_screen.dart';
import '../settings/diagnostics_screen.dart';
import 'milky_subscription_card.dart';

/// Card-based subscription screen: one large status card, real counts, two actions.
/// The subscription URL itself is never rendered — it is a credential.
class SubscriptionScreen extends StatefulWidget {
  const SubscriptionScreen({super.key});

  @override
  State<SubscriptionScreen> createState() => _SubscriptionScreenState();
}

class _SubscriptionScreenState extends State<SubscriptionScreen> {
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final repo = context.watch<SubscriptionRepository>();
    final snap = repo.snapshot;

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(MilkySpace.screen, MilkySpace.sm, MilkySpace.screen, MilkySpace.xxl),
      child: MilkyColumn(
        maxWidth: MilkyLayout.maxReadingWidth,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(t.subscription, style: MilkyType.display.copyWith(fontSize: 30)),
            const SizedBox(height: MilkySpace.xl),
            if (snap == null)
              MilkyGlassCard(
                padding: const EdgeInsets.all(MilkySpace.xxl),
                child: Column(
                  children: [
                    Icon(Icons.card_membership_rounded, size: 40, color: c.textFaint),
                    const SizedBox(height: MilkySpace.md),
                    Text(t.subscriptionEmptyTitle, textAlign: TextAlign.center, style: MilkyType.title),
                    const SizedBox(height: MilkySpace.sm),
                    Text(t.subscriptionEmptyBody, textAlign: TextAlign.center, style: MilkyType.bodySmall.copyWith(color: c.textMuted)),
                    const SizedBox(height: MilkySpace.xl),
                    MilkyPrimaryButton(
                      label: t.addSubscription,
                      icon: Icons.add_rounded,
                      onPressed: () => Navigator.of(context).push(MaterialPageRoute<bool>(builder: (_) => const ImportScreen())),
                    ),
                  ],
                ),
              )
            else ...[
              MilkySubscriptionCard(snapshot: snap, compact: false),
              const SizedBox(height: MilkySpace.lg),
              MilkyPrimaryButton(
                label: _busy ? t.importing : t.refresh,
                icon: Icons.refresh_rounded,
                loading: _busy,
                onPressed: _busy ? null : _refresh,
              ),
              const SizedBox(height: MilkySpace.md),
              MilkyGhostButton(
                label: t.removeSubscription,
                icon: Icons.delete_outline_rounded,
                foreground: c.danger,
                onPressed: _busy ? null : _remove,
              ),
              const SizedBox(height: MilkySpace.xxl),
              MilkySectionHeader(t.advanced),
              MilkyGlassCard(
                padding: EdgeInsets.zero,
                child: _AdvancedRow(
                  icon: Icons.content_copy_rounded,
                  title: t.copyLink,
                  subtitle: t.subscriptionHint,
                  onTap: _copyLink,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _refresh() async {
    final repo = context.read<SubscriptionRepository>();
    final t = S.of(context);
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _busy = true);
    try {
      final snap = await repo.refresh();
      if (!mounted) return;
      if (snap == null) {
        messenger.showSnackBar(SnackBar(content: Text(t.noSubscription)));
      } else {
        MilkyHaptics.success();
        messenger.showSnackBar(SnackBar(content: Text(t.importOk)));
      }
    } on SubscriptionFetchException catch (e) {
      if (!mounted) return;
      MilkyHaptics.error();
      await MilkyErrorSheet.show(
        context,
        error: MilkyError.fromCode(e.errorClass),
        onRetry: _refresh,
        onOpenDiagnostics: _openDiagnostics,
      );
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _remove() async {
    final t = S.of(context);
    final repo = context.read<SubscriptionRepository>();
    final vpn = context.read<VpnController>();
    final bridge = context.read<VpnBridge>();
    final ok = await showMilkyConfirmSheet(
      context,
      title: t.removeSubscription,
      body: t.removeConfirm,
      confirmLabel: t.remove,
      cancelLabel: t.cancel,
    );
    if (!ok || !mounted) return;
    if (vpn.isConnected || vpn.isBusy) await vpn.disconnect();
    try {
      await bridge.clearActiveProfile();
    } catch (_) {
      // Best effort: the sealed profile is only usable with a stored subscription.
    }
    await repo.remove();
    if (!mounted) return;
    MilkyHaptics.disconnect();
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t.removeSubscription)));
  }

  Future<void> _copyLink() async {
    final t = S.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final url = context.read<SubscriptionRepository>().urlForCopy;
    if (url == null) return;
    await MilkyClipboard.copy(url);
    messenger.showSnackBar(SnackBar(content: Text(t.linkCopied)));
  }

  void _openDiagnostics() {
    Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const DiagnosticsScreen()));
  }
}

class _AdvancedRow extends StatelessWidget {
  const _AdvancedRow({required this.icon, required this.title, required this.subtitle, required this.onTap});

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return MilkyPressable(
      onTap: onTap,
      scale: 0.99,
      child: Padding(
        padding: const EdgeInsets.all(MilkySpace.lg),
        child: Row(
          children: [
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(color: c.accentSoft, borderRadius: BorderRadius.circular(11)),
              child: Icon(icon, size: 18, color: c.accent),
            ),
            const SizedBox(width: MilkySpace.md),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: MilkyType.subtitle),
                  const SizedBox(height: 2),
                  Text(subtitle, style: MilkyType.bodySmall.copyWith(color: c.textMuted)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Clipboard write. Isolated so tests can stub the platform channel.
abstract final class MilkyClipboard {
  static Future<void> copy(String text) => Clipboard.setData(ClipboardData(text: text));
}
