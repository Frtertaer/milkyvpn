import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'milky_brand.dart';
import 'milky_colors.dart';
import 'milky_motion.dart';
import 'milky_theme.dart';
import 'milky_tokens.dart';

enum MilkyOrbState { idle, connecting, connected, error, disabled }

/// **The visual signature of MilkyVPN.**
///
/// A large glass sphere holding a slowly moving pool of milk. It breathes when idle, turns
/// into a rotating liquid halo while connecting, and lights up with a protected ring and a
/// drawn-in check once the tunnel is verified. One [CustomPaint], no particles, no blur
/// filters, and it stops rendering entirely when the app is backgrounded.
class MilkyConnectOrb extends StatefulWidget {
  const MilkyConnectOrb({
    super.key,
    required this.state,
    required this.onTap,
    this.size,
    this.progress,
    this.enabled = true,
    this.caption,
    this.semanticLabel = '',
    this.semanticValue = '',
  });

  final MilkyOrbState state;
  final VoidCallback? onTap;

  /// Diameter. Defaults to [MilkyOrbMetrics.diameterFor] of the available width.
  final double? size;

  /// Determinate connecting progress (0..1). When null the halo spins indeterminate.
  final double? progress;

  final bool enabled;

  /// Small caps action word rendered directly under the sphere: ВКЛЮЧИТЬ / ОТКЛЮЧИТЬ.
  final String? caption;
  final String semanticLabel;
  final String semanticValue;

  @override
  State<MilkyConnectOrb> createState() => _MilkyConnectOrbState();
}

class _MilkyConnectOrbState extends State<MilkyConnectOrb> with TickerProviderStateMixin, MilkyAutoPause {
  late final AnimationController _loop;
  late final AnimationController _energy;
  late final AnimationController _check;
  bool _reduce = false;

  static double _target(MilkyOrbState s) {
    switch (s) {
      case MilkyOrbState.idle:
        return 0.16;
      case MilkyOrbState.connecting:
        return 0.62;
      case MilkyOrbState.connected:
        return 1;
      case MilkyOrbState.error:
        return 0.34;
      case MilkyOrbState.disabled:
        return 0.06;
    }
  }

  @override
  void initState() {
    super.initState();
    _loop = AnimationController(vsync: this, duration: MilkyMotion.breathing);
    _energy = AnimationController(vsync: this, duration: const Duration(milliseconds: 620), value: _target(widget.state));
    _check = AnimationController(vsync: this, duration: const Duration(milliseconds: 460));
    if (widget.state == MilkyOrbState.connected) _check.value = 1;
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _reduce = milkyReduceMotion(context);
    if (_reduce) {
      _loop.stop();
      _loop.value = 0.25;
      _energy.value = _target(widget.state);
      if (widget.state == MilkyOrbState.connected) _check.value = 1;
    } else if (!_loop.isAnimating) {
      _loop.repeat();
    }
  }

  @override
  void didUpdateWidget(MilkyConnectOrb old) {
    super.didUpdateWidget(old);
    if (old.state != widget.state) {
      if (_reduce) {
        _energy.value = _target(widget.state);
      } else {
        _energy.animateTo(_target(widget.state), curve: MilkyMotion.emphasize);
      }
      if (widget.state == MilkyOrbState.connected) {
        if (_reduce) {
          _check.value = 1;
        } else {
          _check.forward(from: 0);
        }
      } else {
        _check.reset();
      }
    }
  }

  @override
  void pauseMilkyAnimations() => _loop.stop();

  @override
  void resumeMilkyAnimations() {
    if (!_reduce && !_loop.isAnimating) _loop.repeat();
  }

  @override
  void dispose() {
    _loop.dispose();
    _energy.dispose();
    _check.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final available = MediaQuery.sizeOf(context).width;
    final diameter = widget.size ?? MilkyOrbMetrics.diameterFor(available);
    final active = widget.enabled && widget.onTap != null;

    final captionColor = switch (widget.state) {
      MilkyOrbState.connected => c.positive,
      MilkyOrbState.error => c.danger,
      MilkyOrbState.disabled => c.textFaint,
      _ => c.textMuted,
    };

    return Semantics(
      button: true,
      enabled: active,
      label: widget.caption == null ? widget.semanticLabel : '${widget.semanticLabel}. ${widget.caption}',
      value: widget.semanticValue,
      child: MilkyPressable(
        onTap: active ? widget.onTap : null,
        scale: 0.97,
        dim: 1,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: diameter,
              height: diameter,
              child: RepaintBoundary(
                child: AnimatedBuilder(
                  animation: Listenable.merge(<Listenable>[_loop, _energy, _check]),
                  builder: (context, _) => CustomPaint(
                    painter: _OrbPainter(
                      t: _loop.value,
                      energy: _energy.value,
                      check: _check.value,
                      progress: widget.progress,
                      state: widget.state,
                      colors: c,
                    ),
                  ),
                ),
              ),
            ),
            if (widget.caption != null) ...[
              const SizedBox(height: MilkySpace.md),
              Text(
                widget.caption!,
                textAlign: TextAlign.center,
                style: MilkyType.bodySmall.copyWith(
                  color: captionColor,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 2.4,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _OrbPainter extends CustomPainter {
  _OrbPainter({
    required this.t,
    required this.energy,
    required this.check,
    required this.progress,
    required this.state,
    required this.colors,
  });

  final double t;
  final double energy;
  final double check;
  final double? progress;
  final MilkyOrbState state;
  final MilkyColors colors;

  @override
  void paint(Canvas canvas, Size size) {
    final c = colors;
    final radius = math.min(size.width, size.height) / 2;
    final center = Offset(size.width / 2, size.height / 2);
    final phase = t * 2 * math.pi;

    // State colour: accent while working, mint when protected, coral on failure.
    final Color stateColor;
    switch (state) {
      case MilkyOrbState.connected:
        stateColor = c.positive;
        break;
      case MilkyOrbState.error:
        stateColor = c.danger;
        break;
      case MilkyOrbState.disabled:
        stateColor = c.textFaint;
        break;
      default:
        stateColor = c.accent;
    }

    // Breathing: slow and small when idle, faster and stronger while connecting.
    final breath = state == MilkyOrbState.connecting
        ? 0.018 * math.sin(phase * 2.2)
        : 0.012 * math.sin(phase);
    canvas.translate(center.dx, center.dy);
    canvas.scale(1 + breath);
    canvas.translate(-center.dx, -center.dy);

    // 1 — Ambient halo.
    final haloR = radius * 1.02;
    canvas.drawCircle(
      center,
      haloR,
      Paint()
        ..shader = RadialGradient(
          colors: [
            stateColor.withValues(alpha: 0.05 + 0.30 * energy),
            stateColor.withValues(alpha: 0.03 + 0.10 * energy),
            stateColor.withValues(alpha: 0),
          ],
          stops: const [0.35, 0.72, 1],
        ).createShader(Rect.fromCircle(center: center, radius: haloR)),
    );

    // 2 — Rim track.
    final rimR = radius * 0.855;
    canvas.drawCircle(
      center,
      rimR,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2
        ..color = (c.isDark ? Colors.white : const Color(0xFF1B2340)).withValues(alpha: 0.07 + 0.06 * energy),
    );

    // 3 — Rotating liquid halo (connecting) / protected ring (connected).
    if (state == MilkyOrbState.connecting) {
      final p = progress;
      if (p != null) {
        final rect = Rect.fromCircle(center: center, radius: rimR);
        canvas.drawArc(
          rect,
          -math.pi / 2,
          2 * math.pi * p.clamp(0.0, 1.0),
          false,
          Paint()
            ..style = PaintingStyle.stroke
            ..strokeWidth = 3.4
            ..strokeCap = StrokeCap.round
            ..shader = SweepGradient(
              colors: [c.auroraC, c.accent, c.auroraB, c.auroraC],
              transform: GradientRotation(-math.pi / 2 + phase * 0.6),
            ).createShader(rect),
        );
      } else {
        final rect = Rect.fromCircle(center: center, radius: rimR);
        final paint = Paint()
          ..style = PaintingStyle.stroke
          ..strokeWidth = 3.4
          ..strokeCap = StrokeCap.round
          ..shader = SweepGradient(
            colors: [c.auroraC, c.accent, c.auroraB, c.auroraC],
            transform: GradientRotation(phase),
          ).createShader(rect);
        for (var i = 0; i < 3; i++) {
          canvas.drawArc(rect, phase + i * (2 * math.pi / 3), 1.15, false, paint);
        }
      }
    } else if (state == MilkyOrbState.connected) {
      canvas.drawCircle(
        center,
        rimR,
        Paint()
          ..style = PaintingStyle.stroke
          ..strokeWidth = 2.6
          ..color = stateColor.withValues(alpha: 0.55),
      );
      // Travelling light on the protected ring.
      final a = phase * 0.9;
      canvas.drawCircle(
        center + Offset(math.cos(a) * rimR, math.sin(a) * rimR),
        4.2,
        Paint()
          ..color = stateColor
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3),
      );
      canvas.drawCircle(center + Offset(math.cos(a) * rimR, math.sin(a) * rimR), 2.4, Paint()..color = Colors.white.withValues(alpha: 0.9));
    }

    // 4 — Glass sphere.
    final discR = radius * 0.635;
    final discRect = Rect.fromCircle(center: center, radius: discR);
    canvas.drawCircle(
      center,
      discR,
      Paint()
        ..shader = RadialGradient(
          center: const Alignment(-0.45, -0.6),
          colors: [
            (c.isDark ? Colors.white : Colors.white).withValues(alpha: 0.10 + 0.10 * energy),
            (c.isDark ? const Color(0xFF1B2440) : const Color(0xFFEDE8E0)).withValues(alpha: c.isDark ? 0.55 : 0.85),
            c.isDark ? const Color(0xFF0E1428) : const Color(0xFFE4DFD6),
          ],
          stops: const [0, 0.62, 1],
        ).createShader(discRect),
    );

    // 5 — Milk pool, clipped inside the sphere.
    canvas.save();
    canvas.clipPath(Path()..addOval(discRect));
    final poolR = discR * (0.78 + 0.05 * energy);
    final amp = 0.014 + 0.030 * energy;
    final pool = _blob(center, poolR, phase, amp);
    canvas.drawPath(
      pool,
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [
            c.milk.withValues(alpha: 0.10 + 0.22 * energy),
            c.milk.withValues(alpha: 0.04 + 0.10 * energy),
          ],
        ).createShader(Rect.fromCircle(center: center, radius: poolR)),
    );
    canvas.drawPath(
      pool,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.2
        ..color = c.milk.withValues(alpha: 0.10 + 0.16 * energy),
    );
    canvas.restore();

    // 6 — Rim of the sphere.
    canvas.drawCircle(
      center,
      discR,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.3
        ..shader = LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Colors.white.withValues(alpha: c.isDark ? 0.34 : 0.85),
            Colors.white.withValues(alpha: 0.04),
          ],
        ).createShader(discRect),
    );

    // 7 — Mark / check.
    final markSize = discR * 0.92;
    final markRect = Rect.fromCenter(center: center, width: markSize, height: markSize);
    final markOpacity = (1 - check).clamp(0.0, 1.0);
    if (markOpacity > 0.01) {
      final glyph = state == MilkyOrbState.error ? c.danger : (state == MilkyOrbState.idle ? c.textMuted : stateColor);
      canvas.saveLayer(markRect, Paint()..color = Colors.white.withValues(alpha: markOpacity));
      MilkyMark.paint(
        canvas,
        markRect,
        fill: Color.lerp(glyph, c.accent, 0.35 * energy)!,
        glyph: c.isDark ? const Color(0xFF0A1020) : Colors.white,
        glow: energy > 0.5 ? stateColor.withValues(alpha: 0.35 * energy) : null,
      );
      canvas.restore();
    }
    if (check > 0.01) {
      final box = Rect.fromCenter(center: center, width: discR * 0.66, height: discR * 0.66);
      final path = Path()
        ..moveTo(box.left + box.width * 0.24, box.top + box.height * 0.54)
        ..lineTo(box.left + box.width * 0.44, box.top + box.height * 0.73)
        ..lineTo(box.left + box.width * 0.78, box.top + box.height * 0.30);
      final metrics = path.computeMetrics();
      final trimmed = Path();
      for (final m in metrics) {
        trimmed.addPath(m.extractPath(0, m.length * check.clamp(0.0, 1.0)), Offset.zero);
      }
      canvas.drawPath(
        trimmed,
        Paint()
          ..style = PaintingStyle.stroke
          ..strokeWidth = discR * 0.115
          ..strokeCap = StrokeCap.round
          ..strokeJoin = StrokeJoin.round
          ..color = stateColor
          ..maskFilter = const MaskFilter.blur(BlurStyle.solid, 2),
      );
      canvas.drawPath(
        trimmed,
        Paint()
          ..style = PaintingStyle.stroke
          ..strokeWidth = discR * 0.10
          ..strokeCap = StrokeCap.round
          ..strokeJoin = StrokeJoin.round
          ..color = Colors.white.withValues(alpha: 0.92),
      );
    }
  }

  Path _blob(Offset center, double radius, double phase, double amp) {
    const steps = 44;
    final path = Path();
    for (var i = 0; i <= steps; i++) {
      final a = i / steps * 2 * math.pi;
      final wobble = 1 +
          amp * (0.6 * math.sin(a * 3 + phase) + 0.4 * math.sin(a * 5 - phase * 1.4));
      final r = radius * wobble;
      final x = center.dx + math.cos(a) * r;
      final y = center.dy + math.sin(a) * r * 0.94;
      if (i == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }
    return path..close();
  }

  @override
  bool shouldRepaint(_OrbPainter old) =>
      old.t != t || old.energy != energy || old.check != check || old.progress != progress || old.state != state || old.colors != colors;
}
