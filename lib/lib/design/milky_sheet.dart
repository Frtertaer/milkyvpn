import 'package:flutter/material.dart';

import '../l10n/milky_strings.dart';
import 'milky_buttons.dart';
import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_theme.dart';

/// A content-sized sheet with a scrollable escape hatch for keyboards and large text.
class MilkySheetFrame extends StatelessWidget {
  const MilkySheetFrame({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) => SafeArea(
    top: false,
    child: Align(
      alignment: Alignment.bottomCenter,
      heightFactor: 1,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: 480,
          maxHeight: MediaQuery.sizeOf(context).height * .9,
        ),
        child: SingleChildScrollView(
          padding: EdgeInsets.fromLTRB(
            12,
            0,
            12,
            12 + MediaQuery.viewInsetsOf(context).bottom,
          ),
          child: Container(
            padding: const EdgeInsets.fromLTRB(24, 12, 24, 24),
            decoration: BoxDecoration(
              color: context.milky.surface,
              borderRadius: BorderRadius.circular(30),
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Center(
                  child: Container(
                    width: 36,
                    height: 4,
                    decoration: BoxDecoration(
                      color: context.milky.strokeStrong,
                      borderRadius: BorderRadius.circular(4),
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                child,
              ],
            ),
          ),
        ),
      ),
    ),
  );
}

class MilkySuccessSheet extends StatelessWidget {
  const MilkySuccessSheet({
    super.key,
    required this.parsedCount,
    required this.compatibleCount,
  });
  final int parsedCount, compatibleCount;

  static Future<bool> show(
    BuildContext context, {
    required int parsedCount,
    required int compatibleCount,
  }) async =>
      await showModalBottomSheet<bool>(
        context: context,
        isScrollControlled: true,
        backgroundColor: Colors.transparent,
        barrierColor: context.milky.scrim,
        builder: (_) => MilkySuccessSheet(
          parsedCount: parsedCount,
          compatibleCount: compatibleCount,
        ),
      ) ??
      false;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    return MilkySheetFrame(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Center(
            child: TweenAnimationBuilder<double>(
              tween: Tween(begin: .85, end: 1),
              duration: milkyReduceMotion(context)
                  ? Duration.zero
                  : const Duration(milliseconds: 400),
              builder: (_, value, child) =>
                  Transform.scale(scale: value, child: child),
              child: Container(
                width: 80,
                height: 80,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: c.positiveSoft,
                ),
                child: Icon(Icons.check_rounded, color: c.positive, size: 38),
              ),
            ),
          ),
          const SizedBox(height: 24),
          Text(
            t.importOk,
            textAlign: TextAlign.center,
            style: MilkyType.headline,
          ),
          const SizedBox(height: 12),
          Text(
            '${t.profilesFound(parsedCount)}\n${t.profilesCompatible(compatibleCount)}',
            textAlign: TextAlign.center,
            style: MilkyType.body.copyWith(color: c.textMuted),
          ),
          const SizedBox(height: 28),
          MilkyPrimaryButton(
            label: t.goToConnect,
            onPressed: () => Navigator.of(context).pop(true),
          ),
        ],
      ),
    );
  }
}
