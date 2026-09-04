import 'package:flutter/material.dart';

import 'milky_aurora.dart';

/// A pushed screen with the Milky Glass backdrop behind a transparent scaffold.
///
/// Routes in MilkyVPN are opaque, so the aurora has to be painted by the route itself —
/// otherwise the area behind the app bar would be black.
class MilkyScreen extends StatelessWidget {
  const MilkyScreen({
    super.key,
    required this.child,
    this.appBar,
    this.intensity = 0.42,
    this.glowAnchor = Alignment.topCenter,
  });

  final Widget child;
  final PreferredSizeWidget? appBar;
  final double intensity;
  final Alignment glowAnchor;

  @override
  Widget build(BuildContext context) {
    return MilkyBackdrop(
      intensity: intensity,
      glowAnchor: glowAnchor,
      child: Scaffold(
        backgroundColor: Colors.transparent,
        appBar: appBar,
        body: child,
      ),
    );
  }
}
