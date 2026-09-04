import 'package:flutter/material.dart';

import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_theme.dart';
import 'milky_tokens.dart';

/// Floating glass navigation bar: three clearly labelled destinations, no mystery icons.
class MilkyNavigationBar extends StatelessWidget {
  const MilkyNavigationBar({
    super.key,
    required this.index,
    required this.onChanged,
    required this.labels,
    required this.icons,
    this.enabled = true,
  });

  final int index;
  final ValueChanged<int> onChanged;
  final List<String> labels;
  final List<IconData> icons;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final bottom = MediaQuery.paddingOf(context).bottom;
    return Padding(
      padding: EdgeInsets.fromLTRB(MilkySpace.lg, 0, MilkySpace.lg, 12 + bottom),
      child: MilkyColumn(
        maxWidth: MilkyLayout.maxContentWidth,
        child: Container(
          height: MilkyLayout.navBarHeight,
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            color: c.isDark ? const Color(0xE6131B31) : const Color(0xF2FFFFFF),
            borderRadius: BorderRadius.circular(26),
            border: Border.all(color: c.stroke),
            boxShadow: [
              BoxShadow(
                color: c.shadow.withValues(alpha: c.isDark ? 0.6 : 0.18),
                blurRadius: 30,
                offset: const Offset(0, 14),
                spreadRadius: -10,
              ),
            ],
          ),
          child: Row(
            children: [
              for (var i = 0; i < labels.length; i++)
                Expanded(
                  child: _NavItem(
                    key: ValueKey('milky_nav_$i'),
                    label: labels[i],
                    icon: icons[i],
                    selected: i == index,
                    onTap: enabled ? () => onChanged(i) : null,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _NavItem extends StatelessWidget {
  const _NavItem({super.key, required this.label, required this.icon, required this.selected, this.onTap});

  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Semantics(
      selected: selected,
      button: true,
      label: label,
      child: MilkyPressable(
        onTap: onTap,
        scale: 0.96,
        child: AnimatedContainer(
          duration: MilkyMotion.base,
          curve: MilkyMotion.standard,
          margin: const EdgeInsets.symmetric(horizontal: 3),
          decoration: BoxDecoration(
            color: selected ? c.accentSoft : Colors.transparent,
            borderRadius: BorderRadius.circular(20),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 21, color: selected ? c.accent : c.textFaint),
              const SizedBox(height: 3),
              Text(
                label,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: MilkyType.bodySmall.copyWith(
                  fontSize: 11.5,
                  height: 1.1,
                  fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
                  color: selected ? c.text : c.textFaint,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
