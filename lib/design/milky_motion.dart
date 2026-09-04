import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// True when the user asked the OS to reduce motion. Every ambient animation in
/// MilkyVPN collapses to a static frame in that case.
bool milkyReduceMotion(BuildContext context) {
  final mq = MediaQuery.maybeOf(context);
  if (mq == null) return false;
  return mq.disableAnimations || mq.accessibleNavigation;
}

/// Mixes an app-lifecycle pause into any animated state so nothing keeps rendering
/// (and draining battery) while MilkyVPN is in the background.
mixin MilkyAutoPause<T extends StatefulWidget> on State<T>, WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      resumeMilkyAnimations();
    } else {
      pauseMilkyAnimations();
    }
  }

  void pauseMilkyAnimations();
  void resumeMilkyAnimations();
}

/// Subtle haptics. Deliberately rare: connect, disconnect, selection, success.
abstract final class MilkyHaptics {
  static bool enabled = true;

  static void tap() {
    if (enabled) HapticFeedback.selectionClick();
  }

  static void select() {
    if (enabled) HapticFeedback.selectionClick();
  }

  static void connect() {
    if (enabled) HapticFeedback.mediumImpact();
  }

  static void disconnect() {
    if (enabled) HapticFeedback.lightImpact();
  }

  static void success() {
    if (enabled) HapticFeedback.mediumImpact();
  }

  static void error() {
    if (enabled) HapticFeedback.heavyImpact();
  }
}

/// Press feedback used by every custom control: the surface sinks slightly and dims.
class MilkyPressable extends StatefulWidget {
  const MilkyPressable({
    super.key,
    required this.child,
    this.onTap,
    this.onLongPress,
    this.scale = 0.975,
    this.dim = 0.86,
    this.borderRadius,
    this.behavior = HitTestBehavior.opaque,
  });

  final Widget child;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final double scale;
  final double dim;
  final BorderRadius? borderRadius;
  final HitTestBehavior behavior;

  @override
  State<MilkyPressable> createState() => _MilkyPressableState();
}

class _MilkyPressableState extends State<MilkyPressable> {
  bool _down = false;

  void _set(bool v) {
    if (_down == v) return;
    if (mounted) setState(() => _down = v);
  }

  @override
  Widget build(BuildContext context) {
    final active = widget.onTap != null || widget.onLongPress != null;
    return Listener(
      behavior: widget.behavior,
      onPointerDown: active ? (_) => _set(true) : null,
      onPointerCancel: (_) => _set(false),
      onPointerUp: (_) => _set(false),
      child: GestureDetector(
        behavior: widget.behavior,
        onTap: widget.onTap,
        onLongPress: widget.onLongPress,
        child: AnimatedScale(
          scale: _down && active ? widget.scale : 1,
          duration: const Duration(milliseconds: 120),
          curve: Curves.easeOut,
          child: AnimatedOpacity(
            opacity: _down && active ? widget.dim : 1,
            duration: const Duration(milliseconds: 120),
            child: widget.child,
          ),
        ),
      ),
    );
  }
}

/// Fades + slides a child in the first time it appears. Used for cards entering a screen.
class MilkyEnter extends StatelessWidget {
  const MilkyEnter({super.key, required this.child, this.delay = Duration.zero, this.distance = 14});

  final Widget child;
  final Duration delay;
  final double distance;

  @override
  Widget build(BuildContext context) {
    if (milkyReduceMotion(context)) return child;
    return TweenAnimationBuilder<double>(
      tween: Tween<double>(begin: 0, end: 1),
      duration: const Duration(milliseconds: 420) + delay,
      curve: Curves.easeOutCubic,
      builder: (context, t, c) => Opacity(
        opacity: t.clamp(0.0, 1.0),
        child: Transform.translate(offset: Offset(0, distance * (1 - t)), child: c),
      ),
      child: child,
    );
  }
}
