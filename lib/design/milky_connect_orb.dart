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

class _MilkyConnectOrbState extends State<MilkyConnectOrb>
    with TickerProviderStateMixin, WidgetsBindingObserver, MilkyAutoPause {
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
    _energy = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 620),
      value: _target(widget.state),
    );
    _check = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 460),
    );
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
  void pauseMilkyAnimations() {
    _loop.stop();
    _energy.stop();
    _check.stop();
  }

  @override
  void resumeMilkyAnimations() {
    _energy.value = _target(widget.state);
    _check.value = widget.state == MilkyOrbState.connected ? 1 : 0;
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
      label: widget.caption == null
          ? widget.semanticLabel
          : '${widget.semanticLabel}. ${widget.caption}',
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
                  animation: Listenable.merge(<Listenable>[
                    _loop,
                    _energy,
                    _check,
                  ]),
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
  final double t, energy, check;
  final double? progress;
  final MilkyOrbState state;
  final MilkyColors colors;

  @override
  void paint(Canvas canvas, Size size) {
    final c = colors;
    final phase = t * math.pi * 2;
    final center = size.center(Offset.zero);
    final radius = size.shortestSide * .385;
    final connected = state == MilkyOrbState.connected;
    final failed = state == MilkyOrbState.error;
    final tint = failed ? c.danger : (connected ? c.auroraC : c.auroraB);
    final bounds = Rect.fromCircle(center: center, radius: radius);
    final halo = Rect.fromCircle(center: center, radius: radius * 1.32);
    // A radial falloff replaces expensive backdrop/mask blur filters.
    canvas.drawOval(
      halo,
      Paint()
        ..shader = RadialGradient(
          colors: [
            tint.withValues(alpha: .09 + energy * .12),
            tint.withValues(alpha: 0),
          ],
          stops: const [.45, 1],
        ).createShader(halo),
    );

    canvas.save();
    canvas.translate(center.dx, center.dy);
    canvas.rotate(.025 * math.sin(phase));
    canvas.scale(1 + .009 * math.sin(phase));
    canvas.translate(-center.dx, -center.dy);
    final silhouette = _contour(center, radius, phase);
    canvas.drawPath(
      silhouette,
      Paint()
        ..shader = RadialGradient(
          center: const Alignment(-.65, -.75),
          radius: 1.4,
          colors: failed
              ? const [Color(0xFFF4D8DE), Color(0xFFB695BB), Color(0xFF56486A)]
              : connected
              ? const [
                  Color(0xFFF9F7ED),
                  Color(0xFFC2EAE8),
                  Color(0xFF8EA5DE),
                  Color(0xFF514776),
                ]
              : const [
                  Color(0xFFE7E5F3),
                  Color(0xFFB8B8D8),
                  Color(0xFF9399C9),
                  Color(0xFF4D466E),
                ],
          stops: failed ? null : const [0, .34, .68, 1],
        ).createShader(bounds),
    );

    canvas.save();
    canvas.clipPath(silhouette);
    final drift = math.sin(phase) * radius * .06;
    // Broad curved ribbons look like milk folding into water; no nested glass discs.
    final ribbon = Path()
      ..moveTo(center.dx - radius * 1.1, center.dy + radius * .02)
      ..cubicTo(
        center.dx - radius * .5,
        center.dy + radius * .62 + drift,
        center.dx + radius * .14,
        center.dy - radius * .9,
        center.dx + radius * 1.1,
        center.dy - radius * .28,
      )
      ..lineTo(center.dx + radius * 1.1, center.dy + radius * 1.1)
      ..lineTo(center.dx - radius * 1.1, center.dy + radius * 1.1)
      ..close();
    canvas.drawPath(
      ribbon,
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            c.milk.withValues(alpha: .88),
            (connected ? const Color(0xFFAAE3E4) : const Color(0xFFB8BDE5))
                .withValues(alpha: .86),
            const Color(0xFF8C71B8).withValues(alpha: .62),
          ],
        ).createShader(bounds),
    );
    final fold = Path()
      ..moveTo(center.dx - radius, center.dy + radius * .36)
      ..cubicTo(
        center.dx - radius * .1,
        center.dy + radius * .92,
        center.dx + radius * .22,
        center.dy - radius * .24 + drift,
        center.dx + radius * 1.2,
        center.dy + radius * .08,
      )
      ..lineTo(center.dx + radius, center.dy + radius * 1.1)
      ..lineTo(center.dx - radius, center.dy + radius * 1.1)
      ..close();
    canvas.drawPath(
      fold,
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [c.milk.withValues(alpha: .52), tint.withValues(alpha: .08)],
        ).createShader(bounds),
    );
    canvas.restore();
    canvas.drawPath(
      silhouette,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.2
        ..shader = LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Colors.white.withValues(alpha: .8),
            Colors.white.withValues(alpha: .04),
            tint.withValues(alpha: .55),
          ],
        ).createShader(bounds),
    );

    // The same M/drop remains visible in all states; connection adds a small check.
    final markRect = Rect.fromCenter(
      center: center.translate(0, -radius * .08),
      width: radius * .72,
      height: radius * .78,
    );
    MilkyMark.paint(
      canvas,
      markRect,
      fill: const Color(0xFFF9F7F0).withValues(alpha: .92),
      glyph: const Color(0xFF61577F),
      glyphWeight: .08,
    );
    if (check > 0) {
      final badge = center.translate(radius * .52, radius * .55);
      canvas.drawCircle(
        badge,
        radius * .135,
        Paint()..color = const Color(0xFF173D41),
      );
      final path = Path()
        ..moveTo(badge.dx - radius * .065, badge.dy)
        ..lineTo(badge.dx - radius * .015, badge.dy + radius * .048)
        ..lineTo(badge.dx + radius * .072, badge.dy - radius * .052);
      final metric = path.computeMetrics().first;
      canvas.drawPath(
        metric.extractPath(0, metric.length * check),
        Paint()
          ..color = const Color(0xFFCDFFF2)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 2.2
          ..strokeCap = StrokeCap.round
          ..strokeJoin = StrokeJoin.round,
      );
    }
    canvas.restore();

    if (state == MilkyOrbState.connecting || connected) {
      final ring = Rect.fromCircle(center: center, radius: radius * 1.13);
      final start = state == MilkyOrbState.connecting ? phase : -math.pi * .65;
      canvas.drawArc(
        ring,
        start,
        connected ? math.pi * 1.5 : math.pi * (1.0 + .35 * math.sin(phase)),
        false,
        Paint()
          ..style = PaintingStyle.stroke
          ..strokeWidth = connected ? 1.2 : 2.0
          ..strokeCap = StrokeCap.round
          ..shader = SweepGradient(
            transform: GradientRotation(start),
            colors: [
              tint.withValues(alpha: .02),
              c.milk.withValues(alpha: .8),
              tint.withValues(alpha: .55),
              tint.withValues(alpha: 0),
            ],
          ).createShader(ring),
      );
    }
  }

  Path _contour(Offset center, double r, double phase) {
    final path = Path();
    const steps = 96;
    for (var i = 0; i <= steps; i++) {
      final a = i / steps * math.pi * 2;
      final wobble =
          1 + .018 * math.sin(a * 3 + phase) + .009 * math.cos(a * 2 - phase);
      final point = center + Offset(math.cos(a), math.sin(a)) * (r * wobble);
      if (i == 0) {
        path.moveTo(point.dx, point.dy);
      } else {
        path.lineTo(point.dx, point.dy);
      }
    }
    return path..close();
  }

  @override
  bool shouldRepaint(_OrbPainter old) =>
      old.t != t ||
      old.energy != energy ||
      old.check != check ||
      old.progress != progress ||
      old.state != state ||
      old.colors != colors;
}
