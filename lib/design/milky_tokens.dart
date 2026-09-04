import 'package:flutter/animation.dart';

/// Spacing scale. Every surface in MilkyVPN is built from these steps so vertical rhythm
/// stays consistent between screens.
abstract final class MilkySpace {
  static const double xxs = 2;
  static const double xs = 4;
  static const double sm = 8;
  static const double md = 12;
  static const double lg = 16;
  static const double xl = 20;
  static const double xxl = 24;
  static const double huge = 32;
  static const double giant = 44;
  static const double screen = 20;
}

/// Corner geometry. Rounded, never sharp — the whole product reads as soft glass.
abstract final class MilkyRadius {
  static const double chip = 14;
  static const double control = 18;
  static const double card = 24;
  static const double hero = 32;
  static const double sheet = 32;
  static const double pill = 999;

  static BorderRadius get cardRadius => BorderRadius.circular(card);
  static BorderRadius get controlRadius => BorderRadius.circular(control);
  static BorderRadius get chipRadius => BorderRadius.circular(chip);
  static BorderRadius get pillRadius => BorderRadius.circular(pill);
}

/// Motion language. Fast for feedback, slow only for the signature orb.
abstract final class MilkyMotion {
  static const Duration instant = Duration(milliseconds: 110);
  static const Duration fast = Duration(milliseconds: 180);
  static const Duration base = Duration(milliseconds: 280);
  static const Duration slow = Duration(milliseconds: 480);
  static const Duration breathing = Duration(milliseconds: 4200);
  static const Duration orbit = Duration(milliseconds: 11000);
  static const Duration flow = Duration(milliseconds: 2600);

  static const Curve standard = Curves.easeOutCubic;
  static const Curve emphasize = Curves.easeOutQuint;
  static const Curve gentle = Curves.easeInOutSine;
  static const Curve pop = Curves.easeOutBack;
}

/// Responsive layout rules.
///
/// MilkyVPN is a phone product. On tablets/foldables/desktop the content column keeps a
/// comfortable measure instead of stretching controls across the display.
abstract final class MilkyLayout {
  /// Primary interaction column (orb, selector, primary buttons).
  static const double maxContentWidth = 560;

  /// Reading surfaces (settings lists, subscription details) may be slightly wider.
  static const double maxReadingWidth = 640;

  static const double minTouchTarget = 48;
  static const double navBarHeight = 68;

  static double content(double available) => available > maxContentWidth ? maxContentWidth : available;
  static double reading(double available) => available > maxReadingWidth ? maxReadingWidth : available;

  /// True when the viewport is wide enough to stop behaving like a phone.
  static bool isLargeScreen(double availableWidth) => availableWidth >= 720;
}

/// Orb geometry, derived from the available width so it dominates a phone but never
/// overflows a small one.
abstract final class MilkyOrbMetrics {
  static double diameterFor(double availableWidth) {
    final target = availableWidth * 0.66;
    if (target < 210) return 210;
    if (target > 300) return 300;
    return target;
  }
}
