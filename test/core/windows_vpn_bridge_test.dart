import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/windows_vpn_bridge.dart';

VpnProfile kal2Profile({String? ech, String? cover, String? path}) =>
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
      cover: cover,
      path: path,
    );

void main() {
  // BUG-2026-09-29-01 class: the spawned command line is the bridge's real
  // contract — a flag dropped here is a silent regression (ech= once was).
  test('kal2 profile params reach the kal2-client command line', () {
    final b = WindowsProcessVpnBridge(logPath: r'C:\Logs\kal2-client.log');
    final args = b.argsForTesting(kal2Profile(ech: 'ECH64'));

    String? flagValue(String f) {
      final i = args.indexOf(f);
      return i < 0 ? null : args[i + 1];
    }

    expect(flagValue('-ech'), 'ECH64');
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

  // BUG-2026-09-29-12: a flag with a '' value crashed the -tun elevated
  // spawn — PowerShell `Start-Process -ArgumentList` rejects empty elements
  // (ParameterBindingValidation) and the bridge mapped it to tun_uac_denied
  // for every profile without `path`. Optional flags must be omitted instead
  // of emitted empty; no element of the arg list may ever be ''.
  test('path-less profile drops -drift instead of passing an empty value', () {
    final b = WindowsProcessVpnBridge(logPath: r'C:\Logs\kal2-client.log');
    final args = b.argsForTesting(kal2Profile());

    expect(args.contains(''), isFalse, reason: 'empty arg: $args');
    expect(args.contains('-drift'), isFalse, reason: '-drift kept: $args');
  });

  test('drift path survives when set', () {
    final b = WindowsProcessVpnBridge(logPath: r'C:\Logs\kal2-client.log');
    final args = b.argsForTesting(kal2Profile(path: '/drift/x'));

    final i = args.indexOf('-drift');
    expect(i, greaterThanOrEqualTo(0));
    expect(args[i + 1], '/drift/x');
  });

  // BUG-2026-09-29-06: disconnect used to flatten the system proxy to
  // ProxyEnable=0 and leave our `socks=` ProxyServer behind — a user's own
  // proxy config was lost. The restore plan must put back what connect
  // captured (or delete our value when there was none).
  group('proxy restore plan (BUG-06)', () {
    test('clean box: deletes our ProxyServer and disables the proxy', () {
      final ops = WindowsProcessVpnBridge.restoreProxyPlan();
      expect(
        ops,
        orderedEquals([
          containsAllInOrder(['delete', '/v', 'ProxyServer', '/f']),
          containsAllInOrder(['add', 'ProxyEnable', '/d', '0', '/f']),
        ]),
      );
    });

    test('prior manual proxy is restored verbatim', () {
      final ops = WindowsProcessVpnBridge.restoreProxyPlan(
        prevProxyEnable: 1,
        prevProxyServer: 'proxy.corp.local:8080',
      );
      expect(ops, hasLength(2));
      expect(ops[0], containsAllInOrder(['add', 'ProxyServer', 'proxy.corp.local:8080']));
      expect(ops[1], containsAllInOrder(['add', 'ProxyEnable', '/d', '1']));
    });

    test('disabled-but-set ProxyServer is restored with enable=0', () {
      final ops = WindowsProcessVpnBridge.restoreProxyPlan(
        prevProxyEnable: 0,
        prevProxyServer: 'proxy.corp.local:8080',
      );
      expect(ops[0], containsAllInOrder(['add', 'ProxyServer', 'proxy.corp.local:8080']));
      expect(ops[1], containsAllInOrder(['add', 'ProxyEnable', '/d', '0']));
    });

    test('snapshot equal to our own socks value is a leaked marker: delete + disable', () {
      final ops = WindowsProcessVpnBridge.restoreProxyPlan(
        prevProxyEnable: 1,
        prevProxyServer: 'socks=127.0.0.1:11808',
        ourServer: 'socks=127.0.0.1:11808',
      );
      expect(
        ops,
        orderedEquals([
          containsAllInOrder(['delete', '/v', 'ProxyServer', '/f']),
          containsAllInOrder(['add', 'ProxyEnable', '/d', '0', '/f']),
        ]),
      );
    });
  });

  group('reg query output parsing', () {
    const sample = '\r\n'
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n'
        '    ProxyEnable    REG_DWORD    0x1\r\n'
        '    ProxyServer    REG_SZ    proxy.corp.local:8080\r\n\r\n';

    test('dword value parses as hex', () {
      expect(
        WindowsProcessVpnBridge.parseRegQueryValue(sample, 'ProxyEnable'),
        '0x1',
      );
    });

    test('sz value parses verbatim', () {
      expect(
        WindowsProcessVpnBridge.parseRegQueryValue(sample, 'ProxyServer'),
        'proxy.corp.local:8080',
      );
    });

    test('missing value returns null', () {
      expect(
        WindowsProcessVpnBridge.parseRegQueryValue(sample, 'AutoConfigURL'),
        isNull,
      );
      expect(WindowsProcessVpnBridge.parseRegQueryValue('', 'ProxyEnable'), isNull);
    });
  });
}
