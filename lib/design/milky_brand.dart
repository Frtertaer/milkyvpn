import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'milky_colors.dart';
import 'milky_theme.dart';

/// The MilkyVPN mark: a milk droplet carrying an **M** as its surface wave.
///
/// Drawn as vector paths (not a bitmap) so it stays crisp from the 20 px top bar up to the
/// 300 px orb, and so it inherits the theme colours in light and dark mode.
abstract final class MilkyMark {
  /// Teardrop silhouette fitted into [r].
  static Path droplet(Rect r) {
    final w = r.width;
    final h = r.height;
    final cx = r.left + w / 2;
    final topY = r.top + h * 0.03;
    final bulbR = w * 0.355;
    final bulbCy = r.top + h * 0.615;
    final path = Path()..moveTo(cx, topY);
    path.cubicTo(
      cx + w * 0.11,
      r.top + h * 0.30,
      cx + bulbR * 1.02,
      r.top + h * 0.375,
      cx + bulbR,
      bulbCy,
    );
    path.arcTo(Rect.fromCircle(center: Offset(cx, bulbCy), radius: bulbR), 0, math.pi, false);
    path.cubicTo(
      cx - bulbR * 1.02,
      r.top + h * 0.375,
      cx - w * 0.11,
      r.top + h * 0.30,
      cx,
      topY,
    );
    return path..close();
  }

  /// The M inside the droplet, as a stroked open path.
  static Path letter(Rect r) {
    final w = r.width;
    final h = r.height;
    final cx = r.left + w / 2;
    final bulbCy = r.top + h * 0.615;
    final boxW = w * 0.44;
    final boxH = h * 0.26;
    final left = cx - boxW / 2;
    final top = bulbCy - boxH * 0.42;
    return Path()
      ..moveTo(left, top + boxH)
      ..lineTo(left + boxW * 0.24, top)
      ..lineTo(left + boxW * 0.5, top + boxH * 0.58)
      ..lineTo(left + boxW * 0.76, top)
      ..lineTo(left + boxW, top + boxH);
  }

  /// Paints the mark into [rect].
  static void paint(
    Canvas canvas,
    Rect rect, {
    required Color fill,
    required Color glyph,
    Color? glow,
    double glyphWeight = 0.095,
  }) {
    final drop = droplet(rect);
    if (glow != null) {
      canvas.drawPath(
        drop,
        Paint()
          ..color = glow
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 14),
      );
    }
    canvas.drawPath(drop, Paint()..shader = LinearGradient(
      begin: Alignment.topCenter,
      end: Alignment.bottomCenter,
      colors: [Color.alphaBlend(Colors.white.withValues(alpha: 0.22), fill), fill],
    ).createShader(rect));
    canvas.drawPath(
      letter(rect),
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = rect.width * glyphWeight
        ..strokeCap = StrokeCap.round
        ..strokeJoin = StrokeJoin.round
        ..color = glyph,
    );
  }
}

/// The mark as a widget, optionally on a glass tile.
class MilkyLogoMark extends StatelessWidget {
  const MilkyLogoMark({super.key, this.size = 40, this.fill, this.glyph, this.onTile = false, this.glow = false});

  final double size;
  final Color? fill;
  final Color? glyph;
  final bool onTile;
  final bool glow;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final markFill = fill ?? c.accent;
    final markGlyph = glyph ?? (c.isDark ? const Color(0xFF0A1020) : Colors.white);
    final Widget mark = SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _MarkPainter(fill: markFill, glyph: markGlyph, glow: glow ? markFill.withValues(alpha: 0.45) : null),
      ),
    );
    if (!onTile) return mark;
    return Container(
      padding: EdgeInsets.all(size * 0.22),
      decoration: BoxDecoration(
        color: c.isDark ? c.glassTint : Colors.white.withValues(alpha: 0.8),
        borderRadius: BorderRadius.circular(size * 0.42),
        border: Border.all(color: c.stroke),
      ),
      child: mark,
    );
  }
}

class _MarkPainter extends CustomPainter {
  _MarkPainter({required this.fill, required this.glyph, this.glow});

  final Color fill;
  final Color glyph;
  final Color? glow;

  @override
  void paint(Canvas canvas, Size size) {
    MilkyMark.paint(canvas, Offset.zero & size, fill: fill, glyph: glyph, glow: glow);
  }

  @override
  bool shouldRepaint(_MarkPainter old) => old.fill != fill || old.glyph != glyph || old.glow != glow;
}

/// Wordmark: the mark plus "MilkyVPN" with the VPN part visually lighter.
class MilkyWordmark extends StatelessWidget {
  const MilkyWordmark({super.key, this.size = 22, this.showMark = true});

  final double size;
  final bool showMark;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (showMark) ...[
          MilkyLogoMark(size: size * 1.15),
          SizedBox(width: size * 0.42),
        ],
        Text.rich(
          TextSpan(
            children: [
              TextSpan(text: 'Milky', style: MilkyType.title.copyWith(fontSize: size, color: c.text, fontWeight: FontWeight.w800)),
              TextSpan(text: 'VPN', style: MilkyType.title.copyWith(fontSize: size, color: c.accent, fontWeight: FontWeight.w700)),
            ],
          ),
        ),
      ],
    );
  }
}
