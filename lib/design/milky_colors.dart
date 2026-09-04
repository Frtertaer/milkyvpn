import 'package:flutter/material.dart';

/// The "Milky Glass" palette.
///
/// Dark mode is a deep midnight room lit by a soft aurora; light mode is warm milk with
/// cool blue-violet shadows. The two are designed separately — dark is not an inversion.
@immutable
class MilkyColors extends ThemeExtension<MilkyColors> {
  const MilkyColors({
    required this.isDark,
    required this.bg,
    required this.bgDeep,
    required this.surface,
    required this.surfaceRaised,
    required this.glassTint,
    required this.glassHighlight,
    required this.stroke,
    required this.strokeStrong,
    required this.text,
    required this.textMuted,
    required this.textFaint,
    required this.accent,
    required this.accentDeep,
    required this.accentSoft,
    required this.auroraA,
    required this.auroraB,
    required this.auroraC,
    required this.positive,
    required this.positiveSoft,
    required this.warning,
    required this.danger,
    required this.dangerSoft,
    required this.shadow,
    required this.scrim,
    required this.milk,
  });

  final bool isDark;

  /// Page background (top of the vertical gradient).
  final Color bg;

  /// Deepest background tone (bottom of the gradient / behind the aurora).
  final Color bgDeep;

  /// Card / sheet surface.
  final Color surface;

  /// Pressed or nested surface.
  final Color surfaceRaised;

  /// Frosted glass fill.
  final Color glassTint;

  /// Specular edge highlight on glass.
  final Color glassHighlight;

  final Color stroke;
  final Color strokeStrong;

  final Color text;
  final Color textMuted;
  final Color textFaint;

  /// Interactive brand colour (links, primary button core, focus).
  final Color accent;
  final Color accentDeep;

  /// Translucent accent wash used for selected states.
  final Color accentSoft;

  /// Aurora gradient stops (blue → violet → cyan).
  final Color auroraA;
  final Color auroraB;
  final Color auroraC;

  final Color positive;
  final Color positiveSoft;
  final Color warning;
  final Color danger;
  final Color dangerSoft;

  final Color shadow;
  final Color scrim;

  /// The literal "milk" tone inside the connect orb.
  final Color milk;

  /// Midnight navy / warm milk presets.
  static const MilkyColors dark = MilkyColors(
    isDark: true,
    bg: Color(0xFF0C1224),
    bgDeep: Color(0xFF060912),
    surface: Color(0xFF131B31),
    surfaceRaised: Color(0xFF1A2340),
    glassTint: Color(0x14FFFFFF),
    glassHighlight: Color(0x2EFFFFFF),
    stroke: Color(0x1FFFFFFF),
    strokeStrong: Color(0x33FFFFFF),
    text: Color(0xFFF2F5FF),
    textMuted: Color(0xFFA6B0CE),
    textFaint: Color(0xFF727D9E),
    accent: Color(0xFF7C97FF),
    accentDeep: Color(0xFF4C6EF5),
    accentSoft: Color(0x2E7C97FF),
    auroraA: Color(0xFF3E6BFF),
    auroraB: Color(0xFF8B6BFF),
    auroraC: Color(0xFF37CFE6),
    positive: Color(0xFF3BDCA0),
    positiveSoft: Color(0x2E3BDCA0),
    warning: Color(0xFFF7C25B),
    danger: Color(0xFFFF7E7E),
    dangerSoft: Color(0x2EFF7E7E),
    shadow: Color(0xCC02040C),
    scrim: Color(0xC405070F),
    milk: Color(0xFFF6F2EA),
  );

  static const MilkyColors light = MilkyColors(
    isDark: false,
    bg: Color(0xFFFAF7F2),
    bgDeep: Color(0xFFEFEAE2),
    surface: Color(0xFFFFFFFF),
    surfaceRaised: Color(0xFFF4F1EB),
    glassTint: Color(0xB8FFFFFF),
    glassHighlight: Color(0xE6FFFFFF),
    stroke: Color(0x14141A2B),
    strokeStrong: Color(0x24141A2B),
    text: Color(0xFF131A2B),
    textMuted: Color(0xFF59627A),
    textFaint: Color(0xFF8B93A7),
    accent: Color(0xFF3F63D8),
    accentDeep: Color(0xFF2F4CB0),
    accentSoft: Color(0x1F3F63D8),
    auroraA: Color(0xFF6C93F5),
    auroraB: Color(0xFFB39CF7),
    auroraC: Color(0xFF79D8E4),
    positive: Color(0xFF12996A),
    positiveSoft: Color(0x1F12996A),
    warning: Color(0xFFB87A12),
    danger: Color(0xFFD6454F),
    dangerSoft: Color(0x1AD6454F),
    shadow: Color(0x1F3B4B8C),
    scrim: Color(0x8C2A2F42),
    milk: Color(0xFFFFFFFF),
  );

  @override
  MilkyColors copyWith({
    bool? isDark,
    Color? bg,
    Color? bgDeep,
    Color? surface,
    Color? surfaceRaised,
    Color? glassTint,
    Color? glassHighlight,
    Color? stroke,
    Color? strokeStrong,
    Color? text,
    Color? textMuted,
    Color? textFaint,
    Color? accent,
    Color? accentDeep,
    Color? accentSoft,
    Color? auroraA,
    Color? auroraB,
    Color? auroraC,
    Color? positive,
    Color? positiveSoft,
    Color? warning,
    Color? danger,
    Color? dangerSoft,
    Color? shadow,
    Color? scrim,
    Color? milk,
  }) {
    return MilkyColors(
      isDark: isDark ?? this.isDark,
      bg: bg ?? this.bg,
      bgDeep: bgDeep ?? this.bgDeep,
      surface: surface ?? this.surface,
      surfaceRaised: surfaceRaised ?? this.surfaceRaised,
      glassTint: glassTint ?? this.glassTint,
      glassHighlight: glassHighlight ?? this.glassHighlight,
      stroke: stroke ?? this.stroke,
      strokeStrong: strokeStrong ?? this.strokeStrong,
      text: text ?? this.text,
      textMuted: textMuted ?? this.textMuted,
      textFaint: textFaint ?? this.textFaint,
      accent: accent ?? this.accent,
      accentDeep: accentDeep ?? this.accentDeep,
      accentSoft: accentSoft ?? this.accentSoft,
      auroraA: auroraA ?? this.auroraA,
      auroraB: auroraB ?? this.auroraB,
      auroraC: auroraC ?? this.auroraC,
      positive: positive ?? this.positive,
      positiveSoft: positiveSoft ?? this.positiveSoft,
      warning: warning ?? this.warning,
      danger: danger ?? this.danger,
      dangerSoft: dangerSoft ?? this.dangerSoft,
      shadow: shadow ?? this.shadow,
      scrim: scrim ?? this.scrim,
      milk: milk ?? this.milk,
    );
  }

  @override
  MilkyColors lerp(covariant MilkyColors? other, double t) {
    if (other == null) return this;
    return MilkyColors(
      isDark: t < 0.5 ? isDark : other.isDark,
      bg: Color.lerp(bg, other.bg, t)!,
      bgDeep: Color.lerp(bgDeep, other.bgDeep, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      surfaceRaised: Color.lerp(surfaceRaised, other.surfaceRaised, t)!,
      glassTint: Color.lerp(glassTint, other.glassTint, t)!,
      glassHighlight: Color.lerp(glassHighlight, other.glassHighlight, t)!,
      stroke: Color.lerp(stroke, other.stroke, t)!,
      strokeStrong: Color.lerp(strokeStrong, other.strokeStrong, t)!,
      text: Color.lerp(text, other.text, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      textFaint: Color.lerp(textFaint, other.textFaint, t)!,
      accent: Color.lerp(accent, other.accent, t)!,
      accentDeep: Color.lerp(accentDeep, other.accentDeep, t)!,
      accentSoft: Color.lerp(accentSoft, other.accentSoft, t)!,
      auroraA: Color.lerp(auroraA, other.auroraA, t)!,
      auroraB: Color.lerp(auroraB, other.auroraB, t)!,
      auroraC: Color.lerp(auroraC, other.auroraC, t)!,
      positive: Color.lerp(positive, other.positive, t)!,
      positiveSoft: Color.lerp(positiveSoft, other.positiveSoft, t)!,
      warning: Color.lerp(warning, other.warning, t)!,
      danger: Color.lerp(danger, other.danger, t)!,
      dangerSoft: Color.lerp(dangerSoft, other.dangerSoft, t)!,
      shadow: Color.lerp(shadow, other.shadow, t)!,
      scrim: Color.lerp(scrim, other.scrim, t)!,
      milk: Color.lerp(milk, other.milk, t)!,
    );
  }
}

/// Convenience accessor: `final c = MilkyColors.of(context);`
extension MilkyColorsX on BuildContext {
  MilkyColors get milky => Theme.of(this).extension<MilkyColors>() ?? (Theme.of(this).brightness == Brightness.dark ? MilkyColors.dark : MilkyColors.light);
}
