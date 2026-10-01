import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/errors/milky_error.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';

class FakeBridge implements VpnBridge {
  final _ctrl = StreamController<VpnSnapshot>.broadcast();
  bool permission = true;
  Set<String> failIds = {};
  Set<String> unsupportedIds = {};
  bool hang = false;
  bool bridgeTimeout = false;
  bool silentDisconnect = false;
  List<String> connectCalls = [];
  int disconnectCalls = 0;
  VpnSnapshot _state = VpnSnapshot.initial;

  void emit(VpnSnapshot s) {
    _state = s;
    _ctrl.add(s);
  }

  @override
  Stream<VpnSnapshot> get states => _ctrl.stream;
  @override
  Future<VpnSnapshot> currentState() async => _state;
  @override
  Future<bool> isPrepared() async => permission;
  @override
  Future<bool> prepare() async => permission;
  @override
  Future<bool> isProfileSupported(VpnProfile p) async =>
      !unsupportedIds.contains(p.id);
  @override
  Future<void> connect(VpnProfile p) async {
    connectCalls.add(p.id);
    if (bridgeTimeout) throw VpnBridgeException('bridge_timeout:connect');
    emit(
      VpnSnapshot(
        state: VpnState.connecting,
        profileId: p.id,
        profileRemark: p.redactedRemark,
      ),
    );
    if (hang) return;
    await Future<void>.delayed(const Duration(milliseconds: 5));
    if (failIds.contains(p.id)) {
      emit(
        VpnSnapshot(
          state: VpnState.error,
          profileId: p.id,
          errorCode: 'tls_handshake',
        ),
      );
    } else {
      emit(
        VpnSnapshot(
          state: VpnState.connected,
          profileId: p.id,
          profileRemark: p.redactedRemark,
          connectedSince: DateTime.now(),
        ),
      );
    }
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    if (silentDisconnect) return;
    emit(const VpnSnapshot(state: VpnState.disconnected));
  }

  @override
  Future<void> clearActiveProfile() async {}
  @override
  Future<String> coreVersion() async => 'fake';
  @override
  Future<bool> openVpnSettings() async => true;
  @override
  Future<Map<String, Object?>> deviceInfo() async => {};
  @override
  Future<String?> getInitialLink() async => null;
  @override
  Future<bool> installUpdate(String localPath) async => false;
  @override
  Stream<String> get links => const Stream.empty();
}

VpnProfile p(String id, {String remark = 'Finland'}) => VpnProfile(
  id: id,
  protocol: 'vless',
  address: '$id.example.invalid',
  port: 443,
  secret: '00000001-0000-4000-8000-000000000001',
  remark: remark,
  security: 'reality',
  publicKey: 'FAKE',
);

void main() {
  test('connects to first candidate and reports connected', () async {
    final b = FakeBridge();
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
    );
    final ok = await c.connect([p('a'), p('b')], LocationChoice.auto);
    expect(ok, isTrue);
    expect(c.isConnected, isTrue);
    expect(c.state, VpnState.connected);
    expect(b.connectCalls, ['a']);
    expect(c.attemptsMade, 1);
    expect(c.attemptTotal, 2);
  });

  test(
    'falls back to next profile after failure, disconnects failed attempt',
    () async {
      final b = FakeBridge()..failIds = {'a'};
      final c = VpnController(
        bridge: b,
        attemptTimeout: const Duration(seconds: 1),
      );
      expect(await c.connect([p('a'), p('b')], LocationChoice.auto), isTrue);
      expect(b.connectCalls, ['a', 'b']);
      expect(b.disconnectCalls, 1);
      expect(c.attemptsMade, 2);
    },
  );

  test('all attempts fail -> bounded, error surfaced, not connected', () async {
    final b = FakeBridge()..failIds = {'a', 'b', 'c', 'd', 'e', 'f'};
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
      maxAttempts: 3,
    );
    expect(
      await c.connect(
        List.generate(6, (i) => p('abcdef'[i])),
        LocationChoice.auto,
      ),
      isFalse,
    );
    expect(b.connectCalls.length, 3);
    expect(c.attemptTotal, 3);
    expect(c.lastErrorClass, 'tls_handshake');
    expect(c.state, VpnState.disconnected);
  });

  test('timeout per attempt triggers fallback', () async {
    final b = FakeBridge()..hang = true;
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(milliseconds: 50),
      maxAttempts: 2,
    );
    expect(await c.connect([p('a'), p('b')], LocationChoice.auto), isFalse);
    expect(b.connectCalls, ['a', 'b']);
    expect(c.lastErrorClass, 'timeout');
  });

  test('dead core (bridge timeouts) fails fast, no full sweep', () async {
    // Regression: a wedged native core answered every platform call with a
    // timeout and the sweep ground through all candidates, holding the UI
    // busy ~8min. Now two consecutive bridge timeouts bail out as core_dead.
    final b = FakeBridge()..bridgeTimeout = true;
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(milliseconds: 50),
      maxAttempts: 4,
    );
    expect(
      await c.connect([p('a'), p('b'), p('c'), p('d')], LocationChoice.auto),
      isFalse,
    );
    expect(b.connectCalls, ['a', 'b']);
    expect(c.lastErrorClass, 'core_dead');
    expect(MilkyError.fromCode(c.lastErrorClass).diagnosticsCode,
        'CORE_UNRESPONSIVE');
  });

  test('failed sweep with silent teardown does not wedge UI busy', () async {
    // Regression: when the native side emitted 'connecting' but never
    // confirmed teardown, `state` stayed connecting forever — button read
    // «Подключаем…» and ate taps until force-stop (2nd wedge mechanism).
    final b = FakeBridge()
      ..hang = true
      ..silentDisconnect = true;
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
      maxAttempts: 2,
    );
    expect(await c.connect([p('a'), p('b')], LocationChoice.auto), isFalse);
    expect(c.state, VpnState.disconnected);
    expect(c.isBusy, isFalse);
    expect(c.lastErrorClass, isNotNull);
  });

  test('pinned-but-unsupported profile fails loudly, no silent fallback',
      () async {
    // Regression: pinning an unsupported profile used to silently sweep
    // another one — a VPN exiting through an unpicked country with no
    // user-visible signal.
    final b = FakeBridge()..unsupportedIds = {'rtc'};
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
    );
    expect(
      await c.connect([p('rtc'), p('b')], LocationChoice.auto,
          profileId: 'rtc'),
      isFalse,
    );
    expect(b.connectCalls, isEmpty);
    expect(c.lastErrorClass, 'unsupported_profile');
  });

  test('dead pin falls back within same location, sets pinnedFellBack',
      () async {
    final b = FakeBridge()..failIds = {'a'};
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
    );
    expect(
      await c.connect(
        [p('a'), p('b'), p('c', remark: 'USA-1')],
        LocationChoice.auto,
        profileId: 'a',
      ),
      isTrue,
    );
    // a failed -> same-location b served; usa profile c never tried.
    expect(b.connectCalls, ['a', 'b']);
    expect(c.pinnedFellBack, isTrue);
    expect(c.isConnected, isTrue);
  });

  test('live pin connects directly, pinnedFellBack stays false', () async {
    final b = FakeBridge();
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
    );
    expect(
      await c.connect(
        [p('a'), p('b')],
        LocationChoice.auto,
        profileId: 'a',
      ),
      isTrue,
    );
    expect(b.connectCalls, ['a']);
    expect(c.pinnedFellBack, isFalse);
  });

  test('dead pin with no same-location candidate fails, pin not crossed',
      () async {
    final b = FakeBridge()..failIds = {'a'};
    final c = VpnController(
      bridge: b,
      attemptTimeout: const Duration(seconds: 1),
    );
    expect(
      await c.connect(
        [p('a'), p('c', remark: 'USA-1')],
        LocationChoice.auto,
        profileId: 'a',
      ),
      isFalse,
    );
    // a retried once; the usa profile was never dialed behind the pin.
    expect(b.connectCalls, ['a']);
    expect(c.pinnedFellBack, isFalse);
    expect(c.lastErrorClass, isNotNull);
  });

  test('VPN permission denied stops before connecting', () async {
    final b = FakeBridge()..permission = false;
    final c = VpnController(bridge: b);
    expect(await c.connect([p('a')], LocationChoice.auto), isFalse);
    expect(c.lastErrorClass, 'vpn_permission_denied');
    expect(b.connectCalls, isEmpty);
  });

  test('VPN permission granted proceeds', () async {
    final b = FakeBridge()..permission = true;
    final c = VpnController(bridge: b);
    expect(await c.connect([p('a')], LocationChoice.auto), isTrue);
  });

  test('unsupported profiles are skipped; location filter applied', () async {
    final b = FakeBridge()..unsupportedIds = {'a'};
    final c = VpnController(bridge: b);
    expect(
      await c.connect([
        p('a'),
        p('b', remark: 'USA-1'),
      ], LocationChoice.finland),
      isFalse,
    );
    expect(c.lastErrorClass, 'no_compatible_profiles');
    expect(
      await c.connect([p('a'), p('b', remark: 'USA-1')], LocationChoice.usa),
      isTrue,
    );
    expect(b.connectCalls, ['b']);
  });

  test(
    'disconnect transitions to disconnected; system revoke/network loss propagates',
    () async {
      final b = FakeBridge();
      final c = VpnController(bridge: b);
      await c.connect([p('a')], LocationChoice.auto);
      await c.disconnect();
      await Future<void>.delayed(Duration.zero);
      expect(c.state, VpnState.disconnected);
      // network change / revoke reported by native
      await c.connect([p('a')], LocationChoice.auto);
      b.emit(
        const VpnSnapshot(
          state: VpnState.disconnected,
          errorCode: 'revoked_by_system',
        ),
      );
      await Future<void>.delayed(Duration.zero);
      expect(c.isConnected, isFalse);
      expect(c.lastErrorClass, 'revoked_by_system');
    },
  );
}
