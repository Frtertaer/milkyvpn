import 'package:flutter/material.dart';

import '../../core/subscription/country_codes.dart';
import '../../core/subscription/vpn_profile.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// The location picker: one glass capsule — "auto" plus a segment per country
/// actually present in the subscription. The set is open-ended: a server in
/// any country surfaces here instead of being folded into "auto".
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
    final codes = counts.keys.where((k) => k != locationAuto).toList();
    return Container(
      constraints: const BoxConstraints(minHeight: 58),
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.66),
        borderRadius: BorderRadius.circular(MilkyRadius.control),
        border: Border.all(color: c.stroke),
      ),
      child: codes.length <= 2
          ? Row(
              children: [
                Expanded(
                  child: _Segment(
                    leading: const Icon(Icons.auto_awesome_rounded, size: 15),
                    label: t.auto,
                    selected: value == locationAuto,
                    enabled: enabled,
                    onTap: () => onChanged(locationAuto),
                  ),
                ),
                for (final code in codes) ...[
                  const SizedBox(width: 4),
                  Expanded(
                    child: _Segment(
                      leading: _FlagText(code),
                      label: countryName(code, ru: t.ru),
                      selected: value == code,
                      enabled: enabled,
                      onTap: () => onChanged(code),
                    ),
                  ),
                ],
              ],
            )
          // More than two countries: the capsule turns into a scroll strip
          // rather than squeezing segments unreadably thin.
          : SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: [
                  _Segment(
                    leading: const Icon(Icons.auto_awesome_rounded, size: 15),
                    label: t.auto,
                    selected: value == locationAuto,
                    enabled: enabled,
                    onTap: () => onChanged(locationAuto),
                  ),
                  for (final code in codes) ...[
                    const SizedBox(width: 4),
                    _Segment(
                      leading: _FlagText(code),
                      label: countryName(code, ru: t.ru),
                      selected: value == code,
                      enabled: enabled,
                      onTap: () => onChanged(code),
                    ),
                  ],
                ],
              ),
            ),
    );
  }
}

/// Emoji flag — the picker is open-ended, so flags come from the code rather
/// than a hand-painted set.
class _FlagText extends StatelessWidget {
  const _FlagText(this.code);
  final String code;

  @override
  Widget build(BuildContext context) => ExcludeSemantics(
    child: Text(flagEmoji(code), style: const TextStyle(fontSize: 14)),
  );
}

class _Segment extends StatelessWidget {
  const _Segment({
    required this.leading,
    required this.label,
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
    final largeText =
        MediaQuery.textScalerOf(context).scale(14) > 18 ||
        MediaQuery.sizeOf(context).width < 360;
    return Semantics(
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
          constraints: const BoxConstraints(minHeight: 48, minWidth: 72),
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 10),
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
              color: selected
                  ? c.accent.withValues(alpha: 0.55)
                  : Colors.transparent,
              width: 1.2,
            ),
            boxShadow: selected
                ? [
                    BoxShadow(
                      color: c.accent.withValues(
                        alpha: c.isDark ? 0.26 : 0.14,
                      ),
                      blurRadius: 14,
                      offset: const Offset(0, 5),
                      spreadRadius: -5,
                    ),
                  ]
                : null,
          ),
          child: Opacity(
            opacity: dimmed ? 0.5 : 1,
            child: Flex(
              direction: largeText ? Axis.vertical : Axis.horizontal,
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                DefaultTextStyle(
                  style: MilkyType.chip.copyWith(
                    color: selected ? c.accent : c.textMuted,
                  ),
                  child: leading,
                ),
                SizedBox(width: largeText ? 0 : 5, height: largeText ? 4 : 0),
                Flexible(
                  child: Text(
                    label,
                    maxLines: largeText ? null : 1,
                    textAlign: TextAlign.center,
                    style: MilkyType.chip.copyWith(
                      color: selected ? c.text : c.textMuted,
                      fontWeight: selected
                          ? FontWeight.w700
                          : FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Builds the per-location counts from the parsed subscription: 'auto' first,
/// then each detected country sorted by profile count (then code).
Map<LocationChoice, int> locationCounts(List<VpnProfile> profiles) {
  final compatible = profiles.where((p) => p.isStaticCompatible).toList();
  final byCode = <String, int>{};
  for (final p in compatible) {
    final loc = p.location;
    if (loc != null) byCode.update(loc, (n) => n + 1, ifAbsent: () => 1);
  }
  final codes = byCode.keys.toList()
    ..sort((a, b) {
      final d = byCode[b]!.compareTo(byCode[a]!);
      return d != 0 ? d : a.compareTo(b);
    });
  return <LocationChoice, int>{
    locationAuto: compatible.length,
    for (final code in codes) code: byCode[code]!,
  };
}
