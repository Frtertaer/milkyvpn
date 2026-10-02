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
    this.lastSuccessfulStage,
    this.firstFailedStage,
  });

  final VpnState state;
  final String? profileId;
  final String? profileRemark;
  final DateTime? connectedSince;
  final String? errorCode;
  final String? lastSuccessfulStage;
  final String? firstFailedStage;

  static const initial = VpnSnapshot(state: VpnState.disconnected);

  factory VpnSnapshot.fromMap(Map<dynamic, dynamic> m) {
    final s = (m['state'] as String? ?? 'disconnected');
    final since = m['connectedSince'];
    return VpnSnapshot(
      state: VpnState.values.firstWhere(
        (e) => e.name == s,
        orElse: () => VpnState.disconnected,
      ),
      profileId: m['profileId'] as String?,
      profileRemark: m['profileRemark'] as String?,
      connectedSince: since is int
          ? DateTime.fromMillisecondsSinceEpoch(since)
          : null,
      errorCode: m['errorCode'] as String?,
      lastSuccessfulStage: m['lastSuccessfulStage'] as String?,
      firstFailedStage: m['firstFailedStage'] as String?,
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

  /// Hands a downloaded installer to the OS (Android: package-manager intent
  /// via FileProvider; Windows: launches the Inno Setup exe). Platforms with
  /// no self-update path throw VpnBridgeException('unsupported_platform').
  Future<bool> installUpdate(String localPath);

  /// Per-app split tunneling (Android VpnService only).
  /// [listInstalledApps] returns launchable apps as {package,label} maps for
  /// the picker; [splitApps] reads the stored {mode,packages}; [setSplitApps]
  /// writes 'all'|'allow'|'block' + package list and restarts a live session.
  /// Other platforms throw VpnBridgeException('unsupported_platform').
  Future<List<InstalledApp>> listInstalledApps();
  Future<SplitAppsConfig> splitApps();
  Future<void> setSplitApps(SplitAppsConfig config);

  /// Android Private DNS (encrypted DNS) mode: 'hostname' | 'opportunistic' |
  /// 'off' | '' when unset or unsupported on the platform.
  Future<String> privateDnsMode();

  /// Private DNS hostname when mode is 'hostname', else ''.
  Future<String> privateDnsSpecifier();
}

/// One launchable app row for the split-tunneling picker.
class InstalledApp {
  const InstalledApp({required this.packageName, required this.label});
  final String packageName;
  final String label;
}

/// Stored split-tunneling selection: 'all' (default), 'allow' (only listed
/// apps through the VPN) or 'block' (listed apps bypass the VPN).
class SplitAppsConfig {
  const SplitAppsConfig({this.mode = 'all', this.packages = const []});
  final String mode;
  final List<String> packages;
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
  Stream<String> get links => _links ??= _linkCh
      .receiveBroadcastStream()
      .where((e) => e is String)
      .map((e) => e as String)
      .asBroadcastStream();

  Future<T> _call<T>(String method, [Object? args, Duration? timeout]) async {
    try {
      final r = await _m
          .invokeMethod<T>(method, args)
          .timeout(timeout ?? const Duration(seconds: 20));
      return r as T;
    } on TimeoutException {
      throw VpnBridgeException('bridge_timeout:$method');
    } on PlatformException catch (e) {
      throw VpnBridgeException(
        normalizePlatformCode(e.code, e.message),
        e.message,
      );
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
  Future<VpnSnapshot> currentState() async =>
      VpnSnapshot.fromMap(await _call<Map<dynamic, dynamic>>('getState'));

  @override
  Future<bool> isPrepared() => _call<bool>('isPrepared');

  @override
  Future<bool> prepare() =>
      _call<bool>('prepare', null, const Duration(seconds: 90));

  @override
  Future<bool> isProfileSupported(VpnProfile profile) =>
      _call<bool>('isProfileSupported', profile.toBridgeMap());

  @override
  Future<void> connect(VpnProfile profile) => _call<void>(
    'connect',
    profile.toBridgeMap(),
    // The core's own dial budget is ~25s (hedged carrier attempts); a shorter
    // bridge timeout would tear down a session that was about to come up.
    const Duration(seconds: 40),
  );

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
      (await _call<Map<dynamic, dynamic>>(
        'deviceInfo',
      )).map((k, v) => MapEntry(k.toString(), v as Object?));

  @override
  Future<String?> getInitialLink() => _call<String?>('getInitialLink');

  @override
  Future<bool> installUpdate(String localPath) =>
      _call<bool>('installApk', {'path': localPath});

  @override
  Future<List<InstalledApp>> listInstalledApps() async =>
      (await _call<List<dynamic>>('listApps'))
          .whereType<Map>()
          .map(
            (m) => InstalledApp(
              packageName: m['package']?.toString() ?? '',
              label: m['label']?.toString() ?? '',
            ),
          )
          .where((a) => a.packageName.isNotEmpty)
          .toList();

  @override
  Future<SplitAppsConfig> splitApps() async {
    final m = await _call<Map<dynamic, dynamic>>('getSplitApps');
    return SplitAppsConfig(
      mode: m['mode']?.toString() ?? 'all',
      packages:
          (m['packages'] as List?)?.map((e) => e.toString()).toList() ??
          const [],
    );
  }

  @override
  Future<void> setSplitApps(SplitAppsConfig config) => _call<bool>(
    'setSplitApps',
    {'mode': config.mode, 'packages': config.packages},
  );

  @override
  Future<String> privateDnsMode() async {
    final m = await _call<Map<dynamic, dynamic>>('privateDns');
    return m['mode']?.toString() ?? '';
  }

  @override
  Future<String> privateDnsSpecifier() async {
    final m = await _call<Map<dynamic, dynamic>>('privateDns');
    return m['specifier']?.toString() ?? '';
  }
}
