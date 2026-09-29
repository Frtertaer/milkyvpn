import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/windows_vpn_bridge.dart';

VpnProfile kal2Profile({String? ech, String? pin, String? cover}) =>
    VpnProfile(
      id: 'p1',
      protocol: 'kal2',
      address: '23.133.88.167',
      port: 443,
      secret: 'psk',
      remark: 'r',
      sni: 'kal.mergescribe.dev',
      publicKey: 'PUBK',
      ech: ech,
      pin: pin,
      cover: cover,
    );

void main() {
  // BUG-2026-09-29-01: ech must reach the spawned client — the parser kept
  // it, but the flag was never passed, so the veil hello exposed the real
  // SNI. Pin the whole arg contract: -ech and -pin ride the command line.
  test('kal2 profile params reach the kal2-client command line', () {
    final b = WindowsProcessVpnBridge(logPath: r'C:\Logs\kal2-client.log');
    final args = b.argsForTesting(kal2Profile(ech: 'ECH64', pin: 'PIN64'));

    String? flagValue(String f) {
      final i = args.indexOf(f);
      return i < 0 ? null : args[i + 1];
    }

    expect(flagValue('-ech'), 'ECH64');
    expect(flagValue('-pin'), 'PIN64');
    expect(flagValue('-addr'), '23.133.88.167:443');
    expect(flagValue('-sni'), 'kal.mergescribe.dev');
    expect(flagValue('-pub'), 'PUBK');
  });

  // BUG-2026-09-29-02: the spawned core must be told where to persist its
  // log — otherwise its stderr vanishes (hidden child, and the elevated -tun
  // helper has no parent at all) and field diagnostics are impossible.
  test('client is spawned with -log under the app data dir', () {
    final b = WindowsProcessVpnBridge(logPath: r'C:\Logs\kal2-client.log');
    final args = b.argsForTesting(kal2Profile());

    final i = args.indexOf('-log');
    expect(i, greaterThanOrEqualTo(0), reason: '-log flag missing');
    expect(args[i + 1], r'C:\Logs\kal2-client.log');
  });

  test('default log path lands under %APPDATA%\\homes.milky\\milkyvpn', () {
    final b = WindowsProcessVpnBridge();
    final args = b.argsForTesting(kal2Profile());
    final i = args.indexOf('-log');
    expect(i, greaterThanOrEqualTo(0));
    expect(args[i + 1], endsWith(r'\homes.milky\milkyvpn\logs\kal2-client.log'));
  });
}
