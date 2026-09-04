import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_tokens.dart';

/// The ambient background of every MilkyVPN screen: a deep gradient room with three slow
/// aurora lights drifting behind the content.
///
/// It is a single [CustomPaint] with five draws per frame — no blur, no particles — and it
/// stops completely when the app is backgrounded or the user asks to reduce motion.
class MilkyBackdrop extends StatefulWidget {
  const MilkyBackdrop({
    super.key,
    required this.child,
    this.intensity = 0.55,
    this.glowAnchor = Alignment.center,
  });

  final Widget child;

  /// 0 = nearly flat background, 1 = full aurora.
  final double intensity;

  /// Where the strongest light sits (the home screen anchors it behind the orb).
  final Alignment glowAnchor;

  @override
  State<MilkyBackdrop> createState() => _MilkyBackdropState();
}

class _MilkyBackdropState extends State<MilkyBackdrop> with SingleTickerProviderStateMixin, MilkyAutoPause {
  late final AnimationController _c = AnimationController(vsync: this, duration: MilkyMotion.flow);

  @override
  void initState() {
    super.initState();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final reduce = milkyReduceMotion(context);
    if (reduce) {
      _c.value = 0.35;
      _c.stop();
    } else if (!_c.isAnimating) {
      _c.repeat();
    }
  }

  @override
  void pauseMilkyAnimations() => _c.stop();

  @override
  void resumeMilkyAnimations() {
    if (!_c.isAnimating) _c.repeat();
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return DecoratedBox(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [c.bg, c.bgDeep],
        ),
      ),
      child: Stack(
        fit: StackFit.expand,
        children: [
          RepaintBoundary(
            child: AnimatedBuilder(
              animation: _c,
              builder: (context, _) => CustomPaint(
                painter: _AuroraPainter(
                  t: _c.value,
                  colors: c,
                  intensity: widget.intensity,
                  anchor: widget.glowAnchor,
                ),
              ),
            ),
          ),
          widget.child,
        ],
      ),
    );
  }
}

class _AuroraPainter extends CustomPainter {
  _AuroraPainter({required this.t, required this.colors, required this.intensity, required this.anchor});

  final double t;
  final MilkyColors colors;
  final double intensity;
  final Alignment anchor;

  @override
  void paint(Canvas canvas, Size size) {
    final w = size.width;
    final h = size.height;
    final phase = t * 2 * math.pi;

    // Three drifting lights. Radii are large so the gradients stay soft without a blur.
    _blob(
      canvas,
      center: Offset(w * (0.16 + 0.06 * math.sin(phase)), h * (0.10 + 0.03 * math.cos(phase))),
      radius: w * 0.95,
      color: colors.auroraA,
      alpha: 0.30 * intensity,
    );
    _blob(
      canvas,
      center: Offset(w * (0.92 + 0.05 * math.cos(phase * 0.8)), h * (0.24 + 0.04 * math.sin(phase * 0.8))),
      radius: w * 0.85,
      color: colors.auroraB,
      alpha: 0.26 * intensity,
    );
    _blob(
      canvas,
      center: Offset(w * (0.50 + 0.10 * math.sin(phase * 0.6 + 1.2)), h * (0.94 + 0.03 * math.cos(phase * 0.6))),
      radius: w * 1.1,
      color: colors.auroraC,
      alpha: 0.16 * intensity,
    );

    // Anchor glow — the light that belongs to the connect orb.
    final ax = (anchor.x + 1) / 2 * w;
    final ay = (anchor.y + 1) / 2 * h;
    _blob(canvas, center: Offset(ax, ay), radius: w * 0.78, color: colors.accent, alpha: 0.16 * intensity);

    // Bottom vignette keeps the navigation bar legible.
    canvas.drawRect(
      Offset.zero & size,
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Colors.transparent, colors.bgDeep.withValues(alpha: colors.isDark ? 0.55 : 0.28)],
        ).createShader(Offset.zero & size),
    );
  }

  void _blob(Canvas canvas, {required Offset center, required double radius, required Color color, required double alpha}) {
    canvas.drawCircle(
      center,
      radius,
      Paint()
        ..shader = RadialGradient(
          colors: [color.withValues(alpha: alpha), color.withValues(alpha: 0)],
          stops: const [0, 1],
        ).createShader(Rect.fromCircle(center: center, radius: radius)),
    );
  }

  @override
  bool shouldRepaint(_AuroraPainter old) =>
      old.t != t || old.intensity != intensity || old.colors != colors || old.anchor != anchor;
}

/// A soft, static radial glow used behind the orb and inside cards.
class MilkyGlow extends StatelessWidget {
  const MilkyGlow({super.key, required this.color, this.size = 220, this.opacity = 0.35, this.child});

  final Color color;
  final double size;
  final double opacity;
  final Widget? child;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: DecoratedBox(
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: RadialGradient(
            colors: [color.withValues(alpha: opacity), color.withValues(alpha: 0)],
            stops: const [0, 1],
          ),
        ),
        child: child,
      ),
    );
  }
}
