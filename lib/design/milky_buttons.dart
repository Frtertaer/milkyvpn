import 'package:flutter/material.dart';

import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_theme.dart';
import 'milky_tokens.dart';

enum MilkyButtonTone { accent, positive, danger, quiet }

/// Primary call to action. Pill geometry, gradient core, restrained glow — the only loud
/// element on a screen besides the orb.
class MilkyPrimaryButton extends StatelessWidget {
  const MilkyPrimaryButton({
    super.key,
    required this.label,
    this.onPressed,
    this.icon,
    this.loading = false,
    this.tone = MilkyButtonTone.accent,
    this.height = 56,
    this.expanded = true,
  });

  final String label;
  final VoidCallback? onPressed;
  final IconData? icon;
  final bool loading;
  final MilkyButtonTone tone;
  final double height;
  final bool expanded;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final enabled = onPressed != null && !loading;

    final List<Color> gradient;
    final Color foreground;
    switch (tone) {
      case MilkyButtonTone.accent:
        gradient = [c.accent, c.accentDeep];
        foreground = c.isDark ? const Color(0xFF08101F) : Colors.white;
        break;
      case MilkyButtonTone.positive:
        gradient = [c.positive, Color.alphaBlend(c.accentDeep, c.positive)];
        foreground = const Color(0xFF06170F);
        break;
      case MilkyButtonTone.danger:
        gradient = [c.danger, Color.alphaBlend(const Color(0xFF7A1B2E), c.danger)];
        foreground = Colors.white;
        break;
      case MilkyButtonTone.quiet:
        gradient = [c.surfaceRaised, c.surface];
        foreground = c.text;
        break;
    }

    final radius = BorderRadius.circular(height / 2);

    final content = AnimatedContainer(
      duration: MilkyMotion.fast,
      curve: MilkyMotion.standard,
      height: height,
      width: expanded ? double.infinity : null,
      padding: EdgeInsets.symmetric(horizontal: expanded ? MilkySpace.xxl : MilkySpace.xxl),
      decoration: BoxDecoration(
        borderRadius: radius,
        gradient: enabled ? LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: gradient) : null,
        color: enabled ? null : (c.isDark ? c.surface : c.surfaceRaised),
        border: enabled ? null : Border.all(color: c.stroke),
        boxShadow: enabled && tone != MilkyButtonTone.quiet
            ? [
                BoxShadow(
                  color: gradient.first.withValues(alpha: c.isDark ? 0.40 : 0.26),
                  blurRadius: 26,
                  offset: const Offset(0, 12),
                  spreadRadius: -6,
                ),
              ]
            : null,
      ),
      child: Row(
        mainAxisSize: expanded ? MainAxisSize.max : MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          AnimatedSwitcher(
            duration: MilkyMotion.fast,
            child: loading
                ? SizedBox(
                    key: const ValueKey('spinner'),
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2.4, color: foreground),
                  )
                : icon == null
                    ? const SizedBox.shrink(key: ValueKey('none'))
                    : Icon(icon, key: const ValueKey('icon'), size: 20, color: foreground),
          ),
          if (loading || icon != null) const SizedBox(width: MilkySpace.md),
          Flexible(
            child: Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
              style: MilkyType.button.copyWith(color: enabled ? foreground : c.textFaint),
            ),
          ),
        ],
      ),
    );

    return Semantics(
      button: true,
      enabled: enabled,
      label: label,
      child: MilkyPressable(
        onTap: enabled ? onPressed : null,
        scale: 0.985,
        dim: 0.94,
        child: content,
      ),
    );
  }
}

/// Secondary action: quiet glass, hairline border.
class MilkyGhostButton extends StatelessWidget {
  const MilkyGhostButton({
    super.key,
    required this.label,
    this.onPressed,
    this.icon,
    this.height = 52,
    this.expanded = true,
    this.foreground,
  });

  final String label;
  final VoidCallback? onPressed;
  final IconData? icon;
  final double height;
  final bool expanded;
  final Color? foreground;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final fg = foreground ?? c.text;
    final enabled = onPressed != null;
    return Semantics(
      button: true,
      enabled: enabled,
      label: label,
      child: MilkyPressable(
        onTap: onPressed,
        scale: 0.985,
        dim: 0.9,
        child: Container(
          height: height,
          width: expanded ? double.infinity : null,
          padding: const EdgeInsets.symmetric(horizontal: MilkySpace.xl),
          decoration: BoxDecoration(
            color: c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.7),
            borderRadius: BorderRadius.circular(height / 2),
            border: Border.all(color: c.strokeStrong),
          ),
          child: Row(
            mainAxisSize: expanded ? MainAxisSize.max : MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              if (icon != null) ...[
                Icon(icon, size: 19, color: enabled ? fg : c.textFaint),
                const SizedBox(width: MilkySpace.sm),
              ],
              Flexible(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.center,
                  style: MilkyType.button.copyWith(color: enabled ? fg : c.textFaint),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Small tappable glass tile for text-only actions inside cards.
class MilkyLinkButton extends StatelessWidget {
  const MilkyLinkButton({super.key, required this.label, this.onPressed, this.icon, this.color});

  final String label;
  final VoidCallback? onPressed;
  final IconData? icon;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final fg = color ?? c.accent;
    return MilkyPressable(
      onTap: onPressed,
      scale: 0.97,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: MilkySpace.sm, horizontal: MilkySpace.xs),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (icon != null) ...[
              Icon(icon, size: 17, color: fg),
              const SizedBox(width: 6),
            ],
            Text(label, style: MilkyType.chip.copyWith(color: fg)),
          ],
        ),
      ),
    );
  }
}

/// Round glass icon control (top-bar profile / settings, sheet close).
class MilkyIconButton extends StatelessWidget {
  const MilkyIconButton({
    super.key,
    required this.icon,
    this.onPressed,
    this.tooltip,
    this.size = 44,
    this.color,
    this.filled = false,
  });

  final IconData icon;
  final VoidCallback? onPressed;
  final String? tooltip;
  final double size;
  final Color? color;
  final bool filled;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final fg = color ?? c.text;
    final Widget box = MilkyPressable(
      onTap: onPressed,
      scale: 0.92,
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          color: filled ? c.accentSoft : (c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.8)),
          shape: BoxShape.circle,
          border: Border.all(color: filled ? c.accent.withValues(alpha: 0.4) : c.stroke),
        ),
        child: Icon(icon, size: size * 0.46, color: fg),
      ),
    );
    if (tooltip == null) return box;
    return Tooltip(message: tooltip!, child: box);
  }
}
