import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'milky_colors.dart';
import 'milky_tokens.dart';

/// The single typographic voice of MilkyVPN: **Manrope** (OFL-1.1, bundled in
/// `assets/fonts`, full Cyrillic coverage so Russian strings never fall back or clip).
abstract final class MilkyType {
  static const String family = 'Manrope';

  static const TextStyle display = TextStyle(
    fontFamily: family,
    fontSize: 34,
    height: 1.08,
    letterSpacing: -0.9,
    fontWeight: FontWeight.w800,
  );

  static const TextStyle heroNumber = TextStyle(
    fontFamily: family,
    fontSize: 30,
    height: 1.1,
    letterSpacing: 0.4,
    fontWeight: FontWeight.w700,
    fontFeatures: [FontFeature.tabularFigures()],
  );

  static const TextStyle headline = TextStyle(
    fontFamily: family,
    fontSize: 23,
    height: 1.2,
    letterSpacing: -0.5,
    fontWeight: FontWeight.w700,
  );

  static const TextStyle title = TextStyle(
    fontFamily: family,
    fontSize: 17,
    height: 1.25,
    letterSpacing: -0.2,
    fontWeight: FontWeight.w600,
  );

  static const TextStyle subtitle = TextStyle(
    fontFamily: family,
    fontSize: 15,
    height: 1.35,
    letterSpacing: -0.1,
    fontWeight: FontWeight.w600,
  );

  static const TextStyle body = TextStyle(
    fontFamily: family,
    fontSize: 15,
    height: 1.5,
    letterSpacing: -0.05,
    fontWeight: FontWeight.w400,
  );

  static const TextStyle bodySmall = TextStyle(
    fontFamily: family,
    fontSize: 13.5,
    height: 1.45,
    letterSpacing: 0,
    fontWeight: FontWeight.w400,
  );

  static const TextStyle button = TextStyle(
    fontFamily: family,
    fontSize: 16,
    height: 1.2,
    letterSpacing: -0.1,
    fontWeight: FontWeight.w600,
  );

  static const TextStyle chip = TextStyle(
    fontFamily: family,
    fontSize: 14,
    height: 1.2,
    letterSpacing: -0.1,
    fontWeight: FontWeight.w600,
  );

  static const TextStyle label = TextStyle(
    fontFamily: family,
    fontSize: 12,
    height: 1.3,
    letterSpacing: 0.9,
    fontWeight: FontWeight.w700,
  );

  static const TextStyle mono = TextStyle(
    fontFamily: 'monospace',
    fontSize: 12.5,
    height: 1.6,
    fontWeight: FontWeight.w400,
  );
}

/// Screen transitions: a short fade plus an 12 px rise. Cheaper and calmer than the
/// Material zoom, and it reads as "the glass slides in".
class MilkyPageTransitionsBuilder extends PageTransitionsBuilder {
  const MilkyPageTransitionsBuilder();

  @override
  Widget buildTransitions<T>(PageRoute<T> route, BuildContext context, Animation<double> animation, Animation<double> secondaryAnimation, Widget child) {
    final curved = CurvedAnimation(parent: animation, curve: MilkyMotion.standard, reverseCurve: Curves.easeInCubic);
    return FadeTransition(
      opacity: curved,
      child: SlideTransition(
        position: Tween<Offset>(begin: const Offset(0, 0.035), end: Offset.zero).animate(curved),
        child: child,
      ),
    );
  }
}

/// Builds the two intentionally designed themes.
abstract final class MilkyTheme {
  static ThemeData light() => _build(MilkyColors.light);
  static ThemeData dark() => _build(MilkyColors.dark);

  static ThemeData _build(MilkyColors c) {
    final scheme = ColorScheme.fromSeed(
      seedColor: c.accentDeep,
      brightness: c.isDark ? Brightness.dark : Brightness.light,
    ).copyWith(
      primary: c.accent,
      onPrimary: c.isDark ? const Color(0xFF070C1A) : Colors.white,
      secondary: c.auroraB,
      surface: c.surface,
      onSurface: c.text,
      onSurfaceVariant: c.textMuted,
      outline: c.stroke,
      error: c.danger,
      onError: Colors.white,
    );

    final textTheme = TextTheme(
      displayLarge: MilkyType.display.copyWith(fontSize: 40),
      displayMedium: MilkyType.display,
      displaySmall: MilkyType.display.copyWith(fontSize: 28),
      headlineLarge: MilkyType.headline.copyWith(fontSize: 27),
      headlineMedium: MilkyType.headline,
      headlineSmall: MilkyType.headline.copyWith(fontSize: 20),
      titleLarge: MilkyType.title.copyWith(fontSize: 19),
      titleMedium: MilkyType.title,
      titleSmall: MilkyType.subtitle,
      bodyLarge: MilkyType.body,
      bodyMedium: MilkyType.bodySmall,
      bodySmall: MilkyType.bodySmall.copyWith(fontSize: 12.5),
      labelLarge: MilkyType.button,
      labelMedium: MilkyType.chip,
      labelSmall: MilkyType.label,
    ).apply(bodyColor: c.text, displayColor: c.text);

    return ThemeData(
      useMaterial3: true,
      brightness: c.isDark ? Brightness.dark : Brightness.light,
      colorScheme: scheme,
      fontFamily: MilkyType.family,
      textTheme: textTheme,
      scaffoldBackgroundColor: c.bg,
      canvasColor: c.bg,
      // No stock Material ink: every control has its own pressed feedback.
      splashFactory: NoSplash.splashFactory,
      splashColor: Colors.transparent,
      highlightColor: Colors.transparent,
      hoverColor: Colors.transparent,
      extensions: <ThemeExtension<dynamic>>[c],
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        scrolledUnderElevation: 0,
        elevation: 0,
        centerTitle: false,
        foregroundColor: c.text,
        titleTextStyle: MilkyType.title.copyWith(color: c.text),
        systemOverlayStyle: c.isDark ? SystemUiOverlayStyle.light : SystemUiOverlayStyle.dark,
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: c.surfaceRaised,
        contentTextStyle: MilkyType.bodySmall.copyWith(color: c.text),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(MilkyRadius.control), side: BorderSide(color: c.stroke)),
        insetPadding: const EdgeInsets.fromLTRB(MilkySpace.lg, 0, MilkySpace.lg, MilkySpace.xxl),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: c.isDark ? c.glassTint : c.surfaceRaised,
        contentPadding: const EdgeInsets.symmetric(horizontal: MilkySpace.lg, vertical: MilkySpace.lg),
        hintStyle: MilkyType.body.copyWith(color: c.textFaint),
        labelStyle: MilkyType.bodySmall.copyWith(color: c.textMuted),
        errorStyle: MilkyType.bodySmall.copyWith(color: c.danger),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(MilkyRadius.control),
          borderSide: BorderSide(color: c.stroke),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(MilkyRadius.control),
          borderSide: BorderSide(color: c.stroke),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(MilkyRadius.control),
          borderSide: BorderSide(color: c.accent, width: 1.6),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(MilkyRadius.control),
          borderSide: BorderSide(color: c.danger),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(MilkyRadius.control),
          borderSide: BorderSide(color: c.danger, width: 1.6),
        ),
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(
        color: c.accent,
        linearTrackColor: c.stroke,
        circularTrackColor: Colors.transparent,
      ),
      dividerTheme: DividerThemeData(color: c.stroke, thickness: 1, space: 1),
      pageTransitionsTheme: const PageTransitionsTheme(
        builders: <TargetPlatform, PageTransitionsBuilder>{
          TargetPlatform.android: MilkyPageTransitionsBuilder(),
          TargetPlatform.iOS: MilkyPageTransitionsBuilder(),
          TargetPlatform.macOS: MilkyPageTransitionsBuilder(),
          TargetPlatform.windows: MilkyPageTransitionsBuilder(),
          TargetPlatform.linux: MilkyPageTransitionsBuilder(),
          TargetPlatform.fuchsia: MilkyPageTransitionsBuilder(),
        },
      ),
    );
  }
}
