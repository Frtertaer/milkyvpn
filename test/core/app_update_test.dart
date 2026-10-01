import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/update/app_update.dart';

void main() {
  test('semver compare orders triples, ignores build suffix', () {
    expect(AppUpdate.compareVersion('v0.2.0', 'v0.1.0'), greaterThan(0));
    expect(AppUpdate.compareVersion('v0.1.0', 'v0.2.0'), lessThan(0));
    expect(AppUpdate.compareVersion('v1.0.0', 'v1.0.0'), 0);
    // Non-semver tags compare as 0.0.0 — never "newer".
    expect(AppUpdate.compareVersion('windows-test-49', 'v0.1.0'), lessThan(0));
    expect(AppUpdate.compareVersion('v0.1.0', 'windows-test-49'), greaterThan(0));
  });

  test('isSemverTag accepts only strict vX.Y.Z', () {
    expect(AppUpdate.isSemverTag('v1.2.3'), isTrue);
    expect(AppUpdate.isSemverTag('v1.2.3-beta'), isFalse);
    expect(AppUpdate.isSemverTag('windows-test-49'), isFalse);
    expect(AppUpdate.isSemverTag('1.2.3'), isFalse);
  });

  AppRelease rel(List<String> names) => AppRelease(
    tag: 'v9.9.9',
    assets: [
      for (final n in names)
        ReleaseAsset(name: n, url: 'https://example/$n'),
    ],
  );

  test('pickAsset matches Android ABI, falls back to arm64', () {
    final r = rel(const [
      'MilkyVPN-android-arm64-v8a.apk',
      'MilkyVPN-android-armeabi-v7a.apk',
      'MilkyVPN-android-x86_64.apk',
      'MilkyVPN-Setup.exe',
    ]);
    expect(
      AppUpdate.pickAsset(r, isAndroid: true, isWindows: false, abi: 'arm64-v8a')
          ?.name,
      'MilkyVPN-android-arm64-v8a.apk',
    );
    expect(
      AppUpdate.pickAsset(r, isAndroid: true, isWindows: false, abi: 'x86_64')
          ?.name,
      'MilkyVPN-android-x86_64.apk',
    );
    // Unknown ABI prefers arm64.
    expect(
      AppUpdate.pickAsset(r, isAndroid: true, isWindows: false, abi: 'mips')
          ?.name,
      'MilkyVPN-android-arm64-v8a.apk',
    );
  });

  test('pickAsset takes the Setup exe on Windows, null elsewhere', () {
    final r = rel(const ['MilkyVPN-Setup.exe', 'MilkyVPN-android-arm64-v8a.apk']);
    expect(
      AppUpdate.pickAsset(r, isAndroid: false, isWindows: true)?.name,
      'MilkyVPN-Setup.exe',
    );
    expect(
      AppUpdate.pickAsset(r, isAndroid: false, isWindows: false),
      isNull,
    );
  });
}
