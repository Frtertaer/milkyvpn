import 'package:flutter/material.dart';

import '../../core/subscription/vpn_profile.dart';
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
      constraints: const BoxConstraints(minHeight: 58),
      padding: const EdgeInsets.all(4),
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
            leading: const _Flag(_FlagKind.finland),
            label: t.finland,
            selected: value == LocationChoice.finland,
            enabled: enabled,
            onTap: () => onChanged(LocationChoice.finland),
          ),
          const SizedBox(width: 4),
          _Segment(
            leading: const _Flag(_FlagKind.usa),
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

enum _FlagKind { finland, usa }

class _Flag extends StatelessWidget {
  const _Flag(this.kind);
  final _FlagKind kind;

  @override
  Widget build(BuildContext context) => ExcludeSemantics(
    child: CustomPaint(size: const Size(22, 14), painter: _FlagPainter(kind)),
  );
}

class _FlagPainter extends CustomPainter {
  const _FlagPainter(this.kind);

  final _FlagKind kind;

  @override
  void paint(Canvas canvas, Size size) {
    final rect = Offset.zero & size;
    final clip = RRect.fromRectAndRadius(rect, const Radius.circular(2.5));
    canvas.save();
    canvas.clipRRect(clip);
    if (kind == _FlagKind.finland) {
      canvas.drawRect(rect, Paint()..color = const Color(0xFFF7F8FC));
      final blue = Paint()..color = const Color(0xFF244A9B);
      canvas.drawRect(
        Rect.fromLTWH(size.width * 0.29, 0, size.width * 0.16, size.height),
        blue,
      );
      canvas.drawRect(
        Rect.fromLTWH(0, size.height * 0.40, size.width, size.height * 0.22),
        blue,
      );
    } else {
      const red = Color(0xFFBD3650);
      const white = Color(0xFFF7F3EE);
      final stripe = size.height / 7;
      for (var i = 0; i < 7; i++) {
        canvas.drawRect(
          Rect.fromLTWH(0, i * stripe, size.width, stripe + 0.25),
          Paint()..color = i.isEven ? red : white,
        );
      }
      canvas.drawRect(
        Rect.fromLTWH(0, 0, size.width * 0.46, stripe * 4),
        Paint()..color = const Color(0xFF273B7A),
      );
    }
    canvas.restore();
    canvas.drawRRect(
      clip,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 0.7
        ..color = const Color(0x33000000),
    );
  }

  @override
  bool shouldRepaint(covariant _FlagPainter oldDelegate) =>
      oldDelegate.kind != kind;
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
            constraints: const BoxConstraints(minHeight: 48),
            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 2),
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
      ),
    );
  }
}

/// Builds the per-location counts from the parsed subscription.
Map<LocationChoice, int> locationCounts(List<VpnProfile> profiles) {
  final compatible = profiles.where((p) => p.isStaticCompatible).toList();
  return <LocationChoice, int>{
    LocationChoice.auto: compatible.length,
    LocationChoice.finland: compatible
        .where((p) => p.location == ServerLocation.finland)
        .length,
    LocationChoice.usa: compatible
        .where((p) => p.location == ServerLocation.usa)
        .length,
  };
}
