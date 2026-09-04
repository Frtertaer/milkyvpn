import 'package:flutter/material.dart';

import '../../core/subscription/subscription_repository.dart';
import '../../core/subscription/subscription_stats.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// Subscription presentation. Compact on the home screen, full on the subscription tab.
class MilkySubscriptionCard extends StatelessWidget {
  const MilkySubscriptionCard({super.key, required this.snapshot, this.onTap, this.compact = true});

  final SubscriptionSnapshot? snapshot;
  final VoidCallback? onTap;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    return compact ? _compact(context) : _full(context);
  }

  Widget _compact(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final stats = SubscriptionStats.from(snapshot);
    final active = snapshot?.isActive ?? false;

    final String subtitle;
    if (snapshot == null) {
      subtitle = t.subscriptionEmptyBody;
    } else {
      final parts = <String>[
        snapshot!.expiresAt == null ? t.noExpiry : '${t.expires}: ${t.dateLong(snapshot!.expiresAt!)}',
        '${t.profilesShort(stats.profiles)} • ${t.compatibleShort(stats.compatible)}',
      ];
      subtitle = parts.join('  ·  ');
    }

    return MilkyGlassCard(
      onTap: onTap,
      padding: const EdgeInsets.symmetric(horizontal: MilkySpace.lg, vertical: MilkySpace.md),
      child: Row(
        children: [
          Container(
            width: 38,
            height: 38,
            decoration: BoxDecoration(
              color: active ? c.positiveSoft : c.accentSoft,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              snapshot == null ? Icons.add_rounded : Icons.card_membership_rounded,
              size: 19,
              color: active ? c.positive : c.accent,
            ),
          ),
          const SizedBox(width: MilkySpace.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(t.subscription, style: MilkyType.subtitle.copyWith(color: c.text)),
                    const SizedBox(width: MilkySpace.sm),
                    Flexible(
                      child: MilkyStatusPill(
                        label: snapshot == null ? t.noSubscription : (active ? t.active : t.expired),
                        color: snapshot == null ? c.textFaint : (active ? c.positive : c.danger),
                        compact: true,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 3),
                Text(
                  subtitle,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: MilkyType.bodySmall.copyWith(color: c.textMuted, height: 1.35),
                ),
              ],
            ),
          ),
          const SizedBox(width: MilkySpace.sm),
          Icon(Icons.chevron_right_rounded, size: 22, color: c.textFaint),
        ],
      ),
    );
  }

  Widget _full(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final stats = SubscriptionStats.from(snapshot);
    final active = snapshot?.isActive ?? false;

    return MilkyGlassCard(
      padding: const EdgeInsets.all(MilkySpace.xxl),
      tone: snapshot == null ? MilkyGlassTone.neutral : (active ? MilkyGlassTone.positive : MilkyGlassTone.danger),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(child: MilkySectionHeader(t.subscription, padding: EdgeInsets.zero)),
              MilkyStatusPill(
                label: snapshot == null ? t.noSubscription : (active ? t.active : t.expired),
                color: snapshot == null ? c.textFaint : (active ? c.positive : c.danger),
                compact: true,
              ),
            ],
          ),
          const SizedBox(height: MilkySpace.md),
          Text(
            snapshot?.expiresAt == null ? t.noExpiry : t.dateLong(snapshot!.expiresAt!),
            style: MilkyType.display.copyWith(fontSize: 28, color: c.text),
          ),
          const SizedBox(height: MilkySpace.xxs),
          Text(
            snapshot?.expiresAt == null ? t.subscriptionHint : t.expires,
            style: MilkyType.bodySmall.copyWith(color: c.textMuted),
          ),
          const SizedBox(height: MilkySpace.xl),
          const MilkyHairline(),
          const SizedBox(height: MilkySpace.sm),
          _StatRow(label: t.profiles, value: t.profilesFound(stats.profiles)),
          _StatRow(label: t.compatibility, value: t.profilesCompatible(stats.compatible), muted: stats.incompatible == 0),
          if (stats.duplicates > 0) _StatRow(label: t.duplicatesSkipped(stats.duplicates), value: '', muted: true),
          if (stats.malformed > 0) _StatRow(label: t.malformedSkipped(stats.malformed), value: '', muted: true),
          if (snapshot != null) _StatRow(label: t.lastUpdated, value: t.dateTimeShort(snapshot!.updatedAt), muted: true),
        ],
      ),
    );
  }
}

class _StatRow extends StatelessWidget {
  const _StatRow({required this.label, required this.value, this.muted = false});

  final String label;
  final String value;
  final bool muted;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 9),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: Text(label, style: MilkyType.bodySmall.copyWith(color: muted ? c.textFaint : c.textMuted))),
          if (value.isNotEmpty) ...[
            const SizedBox(width: MilkySpace.md),
            Text(value, textAlign: TextAlign.right, style: MilkyType.chip.copyWith(color: muted ? c.textMuted : c.text)),
          ],
        ],
      ),
    );
  }
}


/// One-line subscription status for the home screen: "● Подписка активна · до 1 января 2100".
///
/// The full dashboard lives in the Subscription tab; home stays focused on the orb.
class MilkySubscriptionStatus extends StatelessWidget {
  const MilkySubscriptionStatus({super.key, required this.snapshot, this.onTap});

  final SubscriptionSnapshot? snapshot;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final has = snapshot != null;
    final active = snapshot?.isActive ?? false;

    final String label;
    final Color dot;
    if (!has) {
      label = t.noSubscription;
      dot = c.textFaint;
    } else if (active) {
      label = snapshot!.expiresAt == null ? t.subActiveForever : t.subActiveUntil(t.dateLong(snapshot!.expiresAt!));
      dot = c.positive;
    } else {
      label = '${t.subscription} · ${t.expired}';
      dot = c.danger;
    }

    return Semantics(
      button: true,
      label: label,
      child: MilkyPressable(
        onTap: onTap,
        scale: 0.98,
        child: Container(
          height: 46,
          padding: const EdgeInsets.symmetric(horizontal: MilkySpace.lg),
          decoration: BoxDecoration(
            color: c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.6),
            borderRadius: BorderRadius.circular(MilkyRadius.control),
            border: Border.all(color: c.stroke),
          ),
          child: Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: dot,
                  boxShadow: [BoxShadow(color: dot.withValues(alpha: 0.55), blurRadius: 6)],
                ),
              ),
              const SizedBox(width: MilkySpace.sm),
              Expanded(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: MilkyType.bodySmall.copyWith(color: c.textMuted, fontWeight: FontWeight.w600),
                ),
              ),
              Icon(Icons.chevron_right_rounded, size: 18, color: c.textFaint),
            ],
          ),
        ),
      ),
    );
  }
}
