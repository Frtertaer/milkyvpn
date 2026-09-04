import 'package:flutter/material.dart';

import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_theme.dart';
import 'milky_tokens.dart';

/// Visual tone of a glass surface.
enum MilkyGlassTone { neutral, accent, positive, danger, muted }

/// The core surface of MilkyVPN: a translucent, softly lit glass panel with a hairline
/// specular edge. Nothing here is a stock [Card].
class MilkyGlassCard extends StatelessWidget {
  const MilkyGlassCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(MilkySpace.xl),
    this.radius = MilkyRadius.card,
    this.tone = MilkyGlassTone.neutral,
    this.onTap,
    this.elevated = true,
    this.selected = false,
  });

  final Widget child;
  final EdgeInsetsGeometry padding;
  final double radius;
  final MilkyGlassTone tone;
  final VoidCallback? onTap;
  final bool elevated;
  final bool selected;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final br = BorderRadius.circular(radius);

    final Color tint;
    final Color borderColor;
    switch (tone) {
      case MilkyGlassTone.accent:
        tint = c.accentSoft;
        borderColor = c.accent.withValues(alpha: 0.42);
        break;
      case MilkyGlassTone.positive:
        tint = c.positiveSoft;
        borderColor = c.positive.withValues(alpha: 0.36);
        break;
      case MilkyGlassTone.danger:
        tint = c.dangerSoft;
        borderColor = c.danger.withValues(alpha: 0.34);
        break;
      case MilkyGlassTone.muted:
        tint = c.isDark ? c.glassTint : c.surfaceRaised;
        borderColor = c.stroke;
        break;
      case MilkyGlassTone.neutral:
        tint = c.isDark ? c.glassTint : c.glassTint;
        borderColor = selected ? c.accent.withValues(alpha: 0.5) : c.stroke;
        break;
    }

    final fill = LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: [
        Color.alphaBlend(c.glassHighlight.withValues(alpha: c.isDark ? 0.10 : 0.75), tint),
        tint,
      ],
    );

    Widget content = DecoratedBox(
      decoration: BoxDecoration(
        borderRadius: br,
        gradient: fill,
        border: Border.all(color: borderColor, width: selected ? 1.4 : 1),
      ),
      child: ClipRRect(
        borderRadius: br,
        child: Stack(
          children: [
            // Specular top edge — the "glass" read.
            Positioned(
              left: 0,
              right: 0,
              top: 0,
              height: 1.2,
              child: DecoratedBox(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [c.glassHighlight.withValues(alpha: c.isDark ? 0.5 : 0.9), c.glassHighlight.withValues(alpha: 0)],
                  ),
                ),
              ),
            ),
            Padding(padding: padding, child: child),
          ],
        ),
      ),
    );

    if (onTap != null) {
      content = MilkyPressable(onTap: onTap, child: content);
    }

    return Container(
      decoration: BoxDecoration(
        borderRadius: br,
        boxShadow: elevated
            ? [
                BoxShadow(
                  color: c.shadow.withValues(alpha: c.isDark ? 0.55 : 0.16),
                  blurRadius: 26,
                  offset: const Offset(0, 12),
                  spreadRadius: -8,
                ),
                if (tone == MilkyGlassTone.accent)
                  BoxShadow(color: c.accent.withValues(alpha: 0.14), blurRadius: 28, offset: const Offset(0, 10), spreadRadius: -6),
              ]
            : null,
      ),
      child: content,
    );
  }
}

/// Section caption above a group of glass cards ("Подключение", "Приложение"…).
class MilkySectionHeader extends StatelessWidget {
  const MilkySectionHeader(this.title, {super.key, this.trailing, this.padding = const EdgeInsets.fromLTRB(MilkySpace.xxs, MilkySpace.xxl, MilkySpace.xxs, MilkySpace.md)});

  final String title;
  final Widget? trailing;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: padding,
      child: Row(
        children: [
          Expanded(
            child: Text(title.toUpperCase(), style: MilkyType.label.copyWith(color: c.textFaint)),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

/// Hairline separator that fades out at both ends instead of a hard Material divider.
class MilkyHairline extends StatelessWidget {
  const MilkyHairline({super.key, this.indent = 0});

  final double indent;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: EdgeInsets.symmetric(horizontal: indent),
      child: SizedBox(
        height: 1,
        child: DecoratedBox(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [c.stroke.withValues(alpha: 0), c.stroke, c.stroke.withValues(alpha: 0)],
            ),
          ),
        ),
      ),
    );
  }
}

/// Small rounded label with a leading dot/icon: "● Активна", "Защита выключена".
class MilkyStatusPill extends StatelessWidget {
  const MilkyStatusPill({
    super.key,
    required this.label,
    this.color,
    this.icon,
    this.pulse = false,
    this.compact = false,
  });

  final String label;
  final Color? color;
  final IconData? icon;

  /// Adds a slow breathing dot while a connection is being established.
  final bool pulse;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final tint = color ?? c.textMuted;
    return Container(
      padding: EdgeInsets.symmetric(horizontal: compact ? MilkySpace.md : MilkySpace.lg, vertical: compact ? 6 : 8),
      decoration: BoxDecoration(
        color: tint.withValues(alpha: c.isDark ? 0.14 : 0.10),
        borderRadius: MilkyRadius.pillRadius,
        border: Border.all(color: tint.withValues(alpha: c.isDark ? 0.34 : 0.24)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: compact ? 13 : 15, color: tint),
            const SizedBox(width: 6),
          ] else ...[
            _Dot(color: tint, pulse: pulse),
            const SizedBox(width: 7),
          ],
          Text(
            label,
            style: (compact ? MilkyType.bodySmall : MilkyType.chip).copyWith(color: tint, fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }
}

class _Dot extends StatefulWidget {
  const _Dot({required this.color, this.pulse = false});
  final Color color;
  final bool pulse;

  @override
  State<_Dot> createState() => _DotState();
}

class _DotState extends State<_Dot> with SingleTickerProviderStateMixin, MilkyAutoPause {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(milliseconds: 1400));

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (widget.pulse && !milkyReduceMotion(context) && !_c.isAnimating) {
      _c.repeat(reverse: true);
    } else if (!widget.pulse) {
      _c.stop();
      _c.value = 0;
    }
  }

  @override
  void pauseMilkyAnimations() => _c.stop();

  @override
  void resumeMilkyAnimations() {
    if (widget.pulse && !_c.isAnimating) _c.repeat(reverse: true);
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _c,
      builder: (context, _) {
        final t = widget.pulse ? _c.value : 0.0;
        return Container(
          width: 8 + t * 1.5,
          height: 8 + t * 1.5,
          decoration: BoxDecoration(
            color: widget.color,
            shape: BoxShape.circle,
            boxShadow: [BoxShadow(color: widget.color.withValues(alpha: 0.35 + t * 0.3), blurRadius: 6 + t * 6)],
          ),
        );
      },
    );
  }
}

/// Constrained column that keeps content at a readable phone measure on large screens.
class MilkyColumn extends StatelessWidget {
  const MilkyColumn({
    super.key,
    required this.child,
    this.maxWidth = MilkyLayout.maxContentWidth,
    this.padding = EdgeInsets.zero,
    this.alignment = Alignment.topCenter,
  });

  final Widget child;
  final double maxWidth;
  final EdgeInsetsGeometry padding;
  final Alignment alignment;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: alignment,
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: maxWidth),
        child: Padding(padding: padding, child: child),
      ),
    );
  }
}
