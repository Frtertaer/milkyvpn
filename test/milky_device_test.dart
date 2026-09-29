import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/app/milky_device.dart';

void main() {
  // BUG-15 regression: Diagnostics labeled every non-Android platform
  // "Windows" — iOS sims showed "Windows 26.5".
  test('platformLabel maps every supported platform', () {
    const cases = {
      'android': 'Android',
      'ios': 'iOS',
      'macos': 'macOS',
      'windows': 'Windows',
    };
    for (final e in cases.entries) {
      expect(
        MilkyDevice(platform: e.key).platformLabel,
        e.value,
        reason: e.key,
      );
    }
  });

  test('platform defaults to android for channel-less devices', () {
    const d = MilkyDevice(osVersion: '13', sdkInt: 33);
    expect(d.platformLabel, 'Android');
    expect(d.osLabel, '13 (API 33)');
  });
}
