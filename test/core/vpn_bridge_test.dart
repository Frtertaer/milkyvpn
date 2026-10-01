import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('homes.milky.vpn/vpn');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  const profile = VpnProfile(
    id: 'p1',
    protocol: 'kal2',
    address: '127.0.0.1',
    port: 443,
    secret: 'secret',
    remark: 'test',
    network: 'veil',
  );

  tearDown(() {
    messenger.setMockMethodCallHandler(channel, null);
  });

  test('connect resolves when the platform side reports success', () async {
    // Android answers `result.success(true)`; both Apple plugins used to answer
    // `result(nil)` — the bridge must accept either or a live core gets
    // reported as a failure and torn down.
    for (final reply in <bool?>[true, null]) {
      messenger.setMockMethodCallHandler(channel, (call) async {
        return call.method == 'connect' ? reply : null;
      });

      await MethodChannelVpnBridge().connect(profile);
    }
  });

  test(
    'connect propagates a PlatformException as VpnBridgeException',
    () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'error', message: 'boom');
      });

      expect(
        MethodChannelVpnBridge().connect(profile),
        throwsA(
          isA<VpnBridgeException>().having((e) => e.code, 'code', 'boom'),
        ),
      );
    },
  );
}
