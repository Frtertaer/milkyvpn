import 'dart:async';

import 'package:flutter/foundation.dart';

import '../subscription/vpn_profile.dart';
import 'vpn_bridge.dart';

/// Picks candidate profiles for a location choice. Pure logic, unit tested.
class ProfileSelector {
  const ProfileSelector();

  /// Stability ranking: Reality TCP first, then XHTTP, then WS/TLS, then Hysteria2.
  static int rank(VpnProfile p) {
    switch (p.kind) {
      case ProfileKind.vlessRealityTcp:
        return 0;
      case ProfileKind.vlessXhttp:
        return 1;
      case ProfileKind.vlessWsTls:
        return 2;
      case ProfileKind.hysteria2:
        return 3;
      case ProfileKind.other:
        return 9;
    }
  }

  List<VpnProfile> candidates(List<VpnProfile> supported, LocationChoice choice, {int maxAttempts = 4}) {
    Iterable<VpnProfile> pool = supported.where((p) => p.kind != ProfileKind.other);
    switch (choice) {
      case LocationChoice.finland:
        pool = pool.where((p) => p.location == ServerLocation.finland);
        break;
      case LocationChoice.usa:
        pool = pool.where((p) => p.location == ServerLocation.usa);
        break;
      case LocationChoice.auto:
        break;
    }
    final list = pool.toList()..sort((a, b) => rank(a).compareTo(rank(b)));
    return list.take(maxAttempts).toList();
  }
}

/// High-level VPN state machine used by the UI.
///
/// Connect flow (bounded, no infinite loops):
///   for each candidate (max [maxAttempts]):
///     bridge.connect(profile) -> wait for native CONNECTED (tunnel verified by HTTPS through
///     the core) or ERROR/timeout -> on failure disconnect cleanly and try next.
class VpnController extends ChangeNotifier {
  VpnController({
    required VpnBridge bridge,
    ProfileSelector selector = const ProfileSelector(),
    this.attemptTimeout = const Duration(seconds: 40),
    this.maxAttempts = 4,
  })  : _bridge = bridge,
        _selector = selector {
    _sub = _bridge.states.listen(_onNative, onError: (_) {});
  }

  final VpnBridge _bridge;
  final ProfileSelector _selector;
  final Duration attemptTimeout;
  final int maxAttempts;

  StreamSubscription<VpnSnapshot>? _sub;
  VpnSnapshot _native = VpnSnapshot.initial;
  bool _autoConnecting = false;
  bool _cancelRequested = false;
  String? _lastErrorClass;
  int _attemptsMade = 0;
  int _compatibleCount = 0;
  Completer<VpnSnapshot>? _waiter;

  VpnSnapshot get native => _native;
  VpnState get state => _autoConnecting ? VpnState.connecting : _native.state;
  bool get isBusy => state == VpnState.connecting || state == VpnState.disconnecting;
  bool get isConnected => _native.state == VpnState.connected;
  String? get lastErrorClass => _lastErrorClass ?? _native.errorCode;
  int get attemptsMade => _attemptsMade;
  int get compatibleCount => _compatibleCount;
  String? get activeRemark => _native.profileRemark;
  DateTime? get connectedSince => _native.connectedSince;

  Future<void> init() async {
    try {
      _native = await _bridge.currentState();
    } catch (_) {}
    notifyListeners();
  }

  void _onNative(VpnSnapshot s) {
    _native = s;
    final w = _waiter;
    if (w != null && !w.isCompleted && (s.state == VpnState.connected || s.state == VpnState.error || s.state == VpnState.disconnected)) {
      w.complete(s);
    }
    notifyListeners();
  }

  /// Filters profiles the engine can genuinely execute.
  Future<List<VpnProfile>> supportedProfiles(List<VpnProfile> all) async {
    final out = <VpnProfile>[];
    for (final p in all) {
      if (p.kind == ProfileKind.other) continue;
      try {
        if (await _bridge.isProfileSupported(p)) out.add(p);
      } catch (_) {}
    }
    _compatibleCount = out.length;
    return out;
  }

  /// Returns true when a verified tunnel is up.
  Future<bool> connect(List<VpnProfile> all, LocationChoice choice) async {
    if (_autoConnecting) return false;
    _autoConnecting = true;
    _cancelRequested = false;
    _lastErrorClass = null;
    _attemptsMade = 0;
    notifyListeners();
    try {
      final granted = await _bridge.prepare();
      if (!granted) {
        _lastErrorClass = 'vpn_permission_denied';
        return false;
      }
      final supported = await supportedProfiles(all);
      final candidates = _selector.candidates(supported, choice, maxAttempts: maxAttempts);
      if (candidates.isEmpty) {
        _lastErrorClass = 'no_compatible_profiles';
        return false;
      }
      for (final p in candidates) {
        if (_cancelRequested) {
          _lastErrorClass = 'cancelled';
          return false;
        }
        _attemptsMade++;
        final ok = await _attempt(p);
        if (ok) {
          _lastErrorClass = null;
          return true;
        }
      }
      _lastErrorClass ??= 'all_attempts_failed';
      return false;
    } catch (e) {
      _lastErrorClass = e is VpnBridgeException ? e.code : 'bridge_error';
      return false;
    } finally {
      _autoConnecting = false;
      notifyListeners();
    }
  }

  Future<bool> _attempt(VpnProfile p) async {
    final waiter = Completer<VpnSnapshot>();
    _waiter = waiter;
    try {
      await _bridge.connect(p);
      final res = await waiter.future.timeout(attemptTimeout, onTimeout: () => const VpnSnapshot(state: VpnState.error, errorCode: 'timeout'));
      if (res.state == VpnState.connected) return true;
      _lastErrorClass = res.errorCode ?? 'connect_failed';
      await _bridge.disconnect();
      return false;
    } on VpnBridgeException catch (e) {
      _lastErrorClass = e.code;
      try {
        await _bridge.disconnect();
      } catch (_) {}
      return false;
    } finally {
      if (identical(_waiter, waiter)) _waiter = null;
    }
  }

  Future<void> disconnect() async {
    _cancelRequested = true;
    try {
      await _bridge.disconnect();
    } catch (e) {
      _lastErrorClass = e is VpnBridgeException ? e.code : 'bridge_error';
    }
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}
