import 'package:flutter/material.dart';

import '../../core/subscription/vpn_profile.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// The location picker: one glass capsule, three 56 dp segments.
///
/// Counts are real (compatible profiles per location) and shown as a quiet badge.
/// Latency is never shown because the app does not measure it before connecting —
/// an invented "52 ms" would be a lie. No protocol names, hostnames or UUIDs.
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
    final c = context.milky;
    final t = S.of(context);
    return Container(
      height: 56,
      padding: const EdgeInsets.all(5),
      decoration: BoxDecoration(
        color: c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.66),
        borderRadius: BorderRadius.circular(MilkyRadius.control),
        border: Border.all(color: c.stroke),
      ),
      child: Row(
        children: [
          _Segment(
            leading: const Icon(Icons.auto_awesome_rounded, size: 15),
            label: t.auto,
            selected: value == LocationChoice.auto,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.auto),
          ),
          const SizedBox(width: 4),
          _Segment(
            leading: const _Flag('🇫🇮'),
            label: t.finland,
            selected: value == LocationChoice.finland,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.finland),
          ),
          const SizedBox(width: 4),
          _Segment(
            leading: const _Flag('🇺🇸'),
            label: t.usa,
            selected: value == LocationChoice.usa,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.usa),
          ),
        ],
      ),
    );
  }
}

class _Flag extends StatelessWidget {
  const _Flag(this.emoji);
  final String emoji;

  @override
  Widget build(BuildContext context) => Text(emoji, style: const TextStyle(fontSize: 15, height: 1.1));
}

class _Segment extends StatelessWidget {
  const _Segment({
    required this.leading,
    required this.label,
    required this.count,
    required this.showCount,
    required this.selected,
    required this.enabled,
    required this.onTap,
  });

  final Widget leading;
  final String label;
  final bool selected;
  final bool enabled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final dimmed = !enabled;
    return Expanded(
      child: Semantics(
        button: true,
        selected: selected,
        enabled: enabled,
        label: label,
        child: MilkyPressable(
          onTap: enabled
              ? () {
                  MilkyHaptics.select();
                  onTap();
                }
              : null,
          scale: 0.96,
          child: AnimatedContainer(
            duration: MilkyMotion.base,
            curve: MilkyMotion.standard,
            decoration: BoxDecoration(
              gradient: selected
                  ? LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        c.accent.withValues(alpha: c.isDark ? 0.34 : 0.20),
                        c.accentSoft,
                      ],
                    )
                  : null,
              borderRadius: BorderRadius.circular(MilkyRadius.control - 4),
              border: Border.all(
                color: selected ? c.accent.withValues(alpha: 0.55) : Colors.transparent,
                width: 1.2,
              ),
              boxShadow: selected
                  ? [
                      BoxShadow(
                        color: c.accent.withValues(alpha: c.isDark ? 0.26 : 0.14),
                        blurRadius: 14,
                        offset: const Offset(0, 5),
                        spreadRadius: -5,
                      ),
                    ]
                  : null,
            ),
            child: Opacity(
              opacity: dimmed ? 0.5 : 1,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  DefaultTextStyle(
                    style: MilkyType.chip.copyWith(color: selected ? c.accent : c.textMuted),
                    child: leading,
                  ),
                  const SizedBox(width: 6),
                  Flexible(
                    child: Text(
                      label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: MilkyType.chip.copyWith(
                        color: selected ? c.text : c.textMuted,
                        fontWeight: selected ? FontWeight.w700 : FontWeight.w600,
                      ),
                    ),
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

/// Builds the per-location counts from the parsed subscription.
Map<LocationChoice, int> locationCounts(List<VpnProfile> profiles) {
  final compatible = profiles.where((p) => p.isStaticCompatible).toList();
  return <LocationChoice, int>{
    LocationChoice.auto: compatible.length,
    LocationChoice.finland: compatible.where((p) => p.location == ServerLocation.finland).length,
    LocationChoice.usa: compatible.where((p) => p.location == ServerLocation.usa).length,
  };
}
