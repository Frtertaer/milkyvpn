import 'dart:async';

import 'package:flutter/services.dart';

import '../subscription/vpn_profile.dart';

enum VpnState { disconnected, connecting, connected, disconnecting, error }

class VpnSnapshot {
  const VpnSnapshot({
    required this.state,
    this.profileId,
    this.profileRemark,
    this.connectedSince,
    this.errorCode,
  });

  final VpnState state;
  final String? profileId;
  final String? profileRemark;
  final DateTime? connectedSince;
  final String? errorCode;

  static const initial = VpnSnapshot(state: VpnState.disconnected);

  factory VpnSnapshot.fromMap(Map<dynamic, dynamic> m) {
    final s = (m['state'] as String? ?? 'disconnected');
    final since = m['connectedSince'];
    return VpnSnapshot(
      state: VpnState.values.firstWhere((e) => e.name == s, orElse: () => VpnState.disconnected),
      profileId: m['profileId'] as String?,
      profileRemark: m['profileRemark'] as String?,
      connectedSince: since is int ? DateTime.fromMillisecondsSinceEpoch(since) : null,
      errorCode: m['errorCode'] as String?,
    );
  }
}

class VpnBridgeException implements Exception {
  VpnBridgeException(this.code, [this.message]);
  final String code;
  final String? message;
  @override
  String toString() => 'VpnBridgeException($code)';
}

/// Platform bridge contract. Implemented by [MethodChannelVpnBridge] on Android and by fakes
/// in tests.
abstract class VpnBridge {
  Stream<VpnSnapshot> get states;
  Future<VpnSnapshot> currentState();
  Future<bool> isPrepared();

  /// Shows the system VPN consent dialog when needed. Returns true when permission is granted.
  Future<bool> prepare();
  Future<bool> isProfileSupported(VpnProfile profile);
  Future<void> connect(VpnProfile profile);
  Future<void> disconnect();
  Future<void> clearActiveProfile();
  Future<String> coreVersion();
  Future<bool> openVpnSettings();
  Future<Map<String, Object?>> deviceInfo();
  Future<String?> getInitialLink();
  Stream<String> get links;
}

class MethodChannelVpnBridge implements VpnBridge {
  MethodChannelVpnBridge()
      : _m = const MethodChannel('homes.milky.vpn/vpn'),
        _stateCh = const EventChannel('homes.milky.vpn/vpn_state'),
        _linkCh = const EventChannel('homes.milky.vpn/links');

  final MethodChannel _m;
  final EventChannel _stateCh;
  final EventChannel _linkCh;
  Stream<VpnSnapshot>? _states;
  Stream<String>? _links;

  @override
  Stream<VpnSnapshot> get states => _states ??= _stateCh
      .receiveBroadcastStream()
      .where((e) => e is Map)
      .map((e) => VpnSnapshot.fromMap(e as Map))
      .asBroadcastStream();

  @override
  Stream<String> get links =>
      _links ??= _linkCh.receiveBroadcastStream().where((e) => e is String).map((e) => e as String).asBroadcastStream();

  Future<T> _call<T>(String method, [Object? args]) async {
    try {
      final r = await _m.invokeMethod<T>(method, args);
      return r as T;
    } on PlatformException catch (e) {
      throw VpnBridgeException(normalizePlatformCode(e.code, e.message), e.message);
    } on MissingPluginException {
      throw VpnBridgeException('unsupported_platform');
    }
  }

  /// The native side reports the generic channel code `error` with the real reason in
  /// `message` (see `MainActivity`). Flatten that so the UI always gets a stable code.
  static String normalizePlatformCode(String code, String? message) {
    switch (code) {
      case 'permission':
        return 'vpn_permission_denied';
      case 'unsupported':
        return 'unsupported_profile';
      case 'busy':
        return 'busy';
      case 'error':
        final m = message?.trim() ?? '';
        return m.isEmpty ? 'bridge_error' : m;
      default:
        return code;
    }
  }

  @override
  Future<VpnSnapshot> currentState() async => VpnSnapshot.fromMap(await _call<Map<dynamic, dynamic>>('getState'));

  @override
  Future<bool> isPrepared() => _call<bool>('isPrepared');

  @override
  Future<bool> prepare() => _call<bool>('prepare');

  @override
  Future<bool> isProfileSupported(VpnProfile profile) => _call<bool>('isProfileSupported', profile.toBridgeMap());

  @override
  Future<void> connect(VpnProfile profile) => _call<bool>('connect', profile.toBridgeMap());

  @override
  Future<void> disconnect() => _call<bool>('disconnect');

  @override
  Future<void> clearActiveProfile() => _call<bool>('clearActiveProfile');

  @override
  Future<String> coreVersion() => _call<String>('coreVersion');

  @override
  Future<bool> openVpnSettings() => _call<bool>('openVpnSettings');

  @override
  Future<Map<String, Object?>> deviceInfo() async =>
      (await _call<Map<dynamic, dynamic>>('deviceInfo')).map((k, v) => MapEntry(k.toString(), v as Object?));

  @override
  Future<String?> getInitialLink() => _call<String?>('getInitialLink');
}
