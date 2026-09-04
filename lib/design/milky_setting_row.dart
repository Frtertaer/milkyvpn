import 'package:flutter/material.dart';

import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_theme.dart';
import 'milky_tokens.dart';

/// A row inside a settings glass group: icon tile + title/subtitle + control.
/// Replaces `SwitchListTile` / `ListTile` everywhere in MilkyVPN.
class MilkySettingRow extends StatelessWidget {
  const MilkySettingRow({
    super.key,
    required this.title,
    this.icon,
    this.subtitle,
    this.trailing,
    this.onTap,
    this.value,
    this.onChanged,
    this.danger = false,
    this.showChevron = false,
  });

  final String title;
  final IconData? icon;
  final String? subtitle;
  final Widget? trailing;
  final VoidCallback? onTap;

  /// When non-null the row renders a [MilkyToggle] and toggles on tap.
  final bool? value;
  final ValueChanged<bool>? onChanged;
  final bool danger;
  final bool showChevron;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final titleColor = danger ? c.danger : c.text;

    final row = Container(
      constraints: const BoxConstraints(minHeight: 62),
      padding: const EdgeInsets.symmetric(horizontal: MilkySpace.lg, vertical: MilkySpace.md),
      child: Row(
        children: [
          if (icon != null) ...[
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(
                color: danger ? c.dangerSoft : c.accentSoft,
                borderRadius: BorderRadius.circular(11),
              ),
              child: Icon(icon, size: 18, color: danger ? c.danger : c.accent),
            ),
            const SizedBox(width: MilkySpace.md),
          ],
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(title, style: MilkyType.subtitle.copyWith(color: titleColor)),
                if (subtitle != null && subtitle!.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(subtitle!, style: MilkyType.bodySmall.copyWith(color: c.textMuted)),
                ],
              ],
            ),
          ),
          const SizedBox(width: MilkySpace.md),
          if (value != null)
            MilkyToggle(value: value!, onChanged: onChanged)
          else if (trailing != null)
            trailing!
          else if (showChevron)
            Icon(Icons.chevron_right_rounded, size: 22, color: c.textFaint),
        ],
      ),
    );

    if (onTap == null && onChanged == null) return row;
    return MilkyPressable(
      onTap: () {
        if (value != null && onChanged != null) {
          onChanged!(!value!);
        } else {
          onTap?.call();
        }
      },
      scale: 0.995,
      dim: 0.92,
      child: row,
    );
  }
}

/// Custom switch. 48×28 pill, sliding knob with a spring curve and an accent glow when on.
class MilkyToggle extends StatelessWidget {
  const MilkyToggle({super.key, required this.value, this.onChanged, this.enabled = true});

  final bool value;
  final ValueChanged<bool>? onChanged;
  final bool enabled;

  static const double _w = 48;
  static const double _h = 28;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final active = onChanged != null && enabled;
    return Semantics(
      toggled: value,
      enabled: active,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: active ? () {
          MilkyHaptics.select();
          onChanged!(!value);
        } : null,
        child: AnimatedContainer(
          duration: MilkyMotion.base,
          curve: MilkyMotion.pop,
          width: _w,
          height: _h,
          padding: const EdgeInsets.all(3),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(_h / 2),
            gradient: value
                ? LinearGradient(colors: [c.accent, c.accentDeep])
                : null,
            color: value ? null : (c.isDark ? c.surfaceRaised : const Color(0xFFE2DFD8)),
            boxShadow: value
                ? [BoxShadow(color: c.accent.withValues(alpha: 0.34), blurRadius: 12, offset: const Offset(0, 3), spreadRadius: -2)]
                : null,
          ),
          child: Align(
            alignment: value ? Alignment.centerRight : Alignment.centerLeft,
            child: AnimatedContainer(
              duration: MilkyMotion.base,
              curve: MilkyMotion.pop,
              width: _h - 6,
              height: _h - 6,
              decoration: BoxDecoration(
                color: value ? Colors.white : (c.isDark ? c.textMuted : Colors.white),
                shape: BoxShape.circle,
                boxShadow: [BoxShadow(color: Colors.black.withValues(alpha: 0.18), blurRadius: 4, offset: const Offset(0, 1))],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Segmented control used for the theme picker and other small exclusive choices.
class MilkySegmented<T> extends StatelessWidget {
  const MilkySegmented({super.key, required this.values, required this.selected, required this.onSelected, required this.labelOf, this.enabled = true});

  final List<T> values;
  final T selected;
  final ValueChanged<T> onSelected;
  final String Function(T value) labelOf;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: c.isDark ? c.glassTint : c.surfaceRaised,
        borderRadius: BorderRadius.circular(MilkyRadius.control),
        border: Border.all(color: c.stroke),
      ),
      child: Row(
        children: [
          for (final v in values)
            Expanded(
              child: MilkyPressable(
                onTap: enabled ? () {
                  if (v != selected) {
                    MilkyHaptics.select();
                    onSelected(v);
                  }
                } : null,
                child: AnimatedContainer(
                  duration: MilkyMotion.fast,
                  curve: MilkyMotion.standard,
                  height: 38,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: v == selected ? (c.isDark ? c.accentSoft : Colors.white) : Colors.transparent,
                    borderRadius: BorderRadius.circular(MilkyRadius.chip),
                    border: Border.all(color: v == selected ? c.accent.withValues(alpha: 0.35) : Colors.transparent),
                  ),
                  child: Text(
                    labelOf(v),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: MilkyType.chip.copyWith(color: v == selected ? c.text : c.textMuted),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
