import 'package:flutter/material.dart';

import '../../core/subscription/vpn_profile.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// The location picker: three compact glass cards instead of a Material segmented button.
///
/// Counts are real (compatible profiles per location). Latency is never shown because the
/// app does not measure it before connecting — an invented "52 ms" would be a lie.
class MilkyServerSelector extends StatelessWidget {
  const MilkyServerSelector({
    super.key,
    required this.value,
    required this.onChanged,
    required this.counts,
    this.enabled = true,
  });

  final LocationChoice value;
  final ValueChanged<LocationChoice> onChanged;
  final Map<LocationChoice, int> counts;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    return Row(
      children: [
        Expanded(
          child: _ServerCard(
            leading: const Icon(Icons.auto_awesome_rounded, size: 19),
            label: t.auto,
            sublabel: t.autoHint,
            count: null,
            selected: value == LocationChoice.auto,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.auto),
          ),
        ),
        const SizedBox(width: MilkySpace.sm),
        Expanded(
          child: _ServerCard(
            leading: const _Flag('🇫🇮'),
            label: t.finland,
            sublabel: null,
            count: counts[LocationChoice.finland] ?? 0,
            selected: value == LocationChoice.finland,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.finland),
          ),
        ),
        const SizedBox(width: MilkySpace.sm),
        Expanded(
          child: _ServerCard(
            leading: const _Flag('🇺🇸'),
            label: t.usa,
            sublabel: null,
            count: counts[LocationChoice.usa] ?? 0,
            selected: value == LocationChoice.usa,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.usa),
          ),
        ),
      ],
    );
  }
}

class _Flag extends StatelessWidget {
  const _Flag(this.emoji);
  final String emoji;

  @override
  Widget build(BuildContext context) => Text(emoji, style: const TextStyle(fontSize: 19, height: 1.1));
}

class _ServerCard extends StatelessWidget {
  const _ServerCard({
    required this.leading,
    required this.label,
    required this.sublabel,
    required this.count,
    required this.selected,
    required this.enabled,
    required this.onTap,
  });

  final Widget leading;
  final String label;
  final String? sublabel;
  final int? count;
  final bool selected;
  final bool enabled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final dimmed = !enabled || (sublabel == null && (count ?? 0) == 0);
    return Semantics(
      button: true,
      selected: selected,
      enabled: enabled,
      label: label,
      child: MilkyPressable(
        onTap: enabled ? () {
          MilkyHaptics.select();
          onTap();
        } : null,
        scale: 0.96,
        child: AnimatedContainer(
          duration: MilkyMotion.base,
          curve: MilkyMotion.standard,
          height: 84,
          padding: const EdgeInsets.symmetric(horizontal: MilkySpace.sm, vertical: MilkySpace.md),
          decoration: BoxDecoration(
            gradient: selected
                ? LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [c.accent.withValues(alpha: c.isDark ? 0.30 : 0.18), c.accentSoft],
                  )
                : null,
            color: selected ? null : (c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.66)),
            borderRadius: BorderRadius.circular(MilkyRadius.control),
            border: Border.all(color: selected ? c.accent.withValues(alpha: 0.55) : c.stroke, width: selected ? 1.4 : 1),
            boxShadow: selected
                ? [BoxShadow(color: c.accent.withValues(alpha: c.isDark ? 0.28 : 0.16), blurRadius: 20, offset: const Offset(0, 8), spreadRadius: -6)]
                : null,
          ),
          child: Opacity(
            opacity: dimmed ? 0.5 : 1,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                DefaultTextStyle(
                  style: MilkyType.chip.copyWith(color: selected ? c.accent : c.textMuted),
                  child: leading,
                ),
                const SizedBox(height: 6),
                Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.center,
                  style: MilkyType.chip.copyWith(
                    color: selected ? c.text : c.textMuted,
                    fontWeight: selected ? FontWeight.w700 : FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  sublabel ?? (count == null || count == 0 ? '—' : '$count'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.center,
                  style: MilkyType.bodySmall.copyWith(fontSize: 11, color: selected ? c.accent : c.textFaint),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Builds the per-location counts from the parsed subscription.
Map<LocationChoice, int> locationCounts(List<VpnProfile> profiles) {
  final compatible = profiles.where((p) => p.isStaticCompatible).toList();
  return <LocationChoice, int>{
    LocationChoice.auto: compatible.length,
    LocationChoice.finland: compatible.where((p) => p.location == ServerLocation.finland).length,
    LocationChoice.usa: compatible.where((p) => p.location == ServerLocation.usa).length,
  };
}
