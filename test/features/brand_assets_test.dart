import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/design/milky_brand.dart';

/// Reproducible legacy/store assets from the same brand vector as the real UI.
/// Explicit export only: flutter test --dart-define=MILKY_EXPORT_BRAND=true test/features/brand_assets_test.dart
void main() {
  test('brand geometry scales without leaving the launcher safe area', () {
    for (final size in [24.0, 48.0, 512.0]) {
      final bounds = MilkyMark.droplet(
        Rect.fromLTWH(0, 0, size, size),
      ).getBounds();
      expect(bounds.left, greaterThanOrEqualTo(0));
      expect(bounds.right, lessThanOrEqualTo(size));
      expect(bounds.top, greaterThanOrEqualTo(0));
      expect(bounds.bottom, lessThanOrEqualTo(size));
    }
  });

  testWidgets(
    'export launcher and store icons',
    (tester) async {
      final outputs = <String, int>{
        'assets/brand/app_icon_1024.png': 1024,
        'assets/brand/play_icon_512.png': 512,
        'assets/brand/app_icon.png': 512,
        for (final entry in {
          'mdpi': 48,
          'hdpi': 72,
          'xhdpi': 96,
          'xxhdpi': 144,
          'xxxhdpi': 192,
        }.entries)
          for (final name in ['ic_launcher', 'ic_launcher_round'])
            'android/app/src/main/res/mipmap-${entry.key}/$name.png':
                entry.value,
      };
      await tester.runAsync(() async {
        for (final entry in outputs.entries) {
          final recorder = ui.PictureRecorder();
          final canvas = Canvas(recorder);
          final size = entry.value.toDouble();
          final rect = Rect.fromLTWH(0, 0, size, size);
          canvas.drawRect(
            rect,
            Paint()
              ..shader = const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  Color(0xFF111728),
                  Color(0xFF3E3C64),
                  Color(0xFF86A4B9),
                ],
              ).createShader(rect),
          );
          MilkyMark.paint(
            canvas,
            Rect.fromLTWH(size * .2, size * .18, size * .6, size * .6),
            fill: const Color(0xFFF2EDF7),
            glyph: const Color(0xFF61577F),
            glyphWeight: .08,
          );
          final picture = recorder.endRecording();
          final image = await picture.toImage(entry.value, entry.value);
          final data = await image.toByteData(format: ui.ImageByteFormat.png);
          await File(entry.key).writeAsBytes(data!.buffer.asUint8List());
          image.dispose();
          picture.dispose();
        }
      });
    },
    skip: !const bool.fromEnvironment('MILKY_EXPORT_BRAND'),
  );
}
