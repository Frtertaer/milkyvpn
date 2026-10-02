import 'dart:async';

import 'package:flutter/foundation.dart';

import '../errors/milky_error.dart';
import '../subscription/vpn_profile.dart';
import 'vpn_bridge.dart';

/// Picks candidate profiles for a location choice. Pure logic, unit tested.
class ProfileSelector {
  const ProfileSelector();

  /// Transport preference within each diversity round. Actual reachability is
  /// still decided by connection verification; this ordering is country agnostic.
  static int rank(VpnProfile p) {
    switch (p.kind) {
      case ProfileKind.vlessXhttp:
        return 0;
      case ProfileKind.hysteria2:
        return 1;
      case ProfileKind.vlessWsTls:
        return 2;
      case ProfileKind.vlessRealityTcp:
        return 3;
      case ProfileKind.kal2:
        return 4;
      case ProfileKind.vmess:
        return 5;
      case ProfileKind.trojan:
        return 6;
      case ProfileKind.shadowsocks:
        return 7;
      case ProfileKind.other:
        return 9;
    }
  }

  List<VpnProfile> candidates(
    List<VpnProfile> supported,
    LocationChoice choice, {
    int maxAttempts = 4,
  }) {
    if (maxAttempts <= 0) return const [];

    final all = supported.where((p) => p.kind != ProfileKind.other).toList();
    Iterable<VpnProfile> pool;
    if (choice == locationAuto) {
      pool = all;
    } else {
      pool = _preferLocation(all, choice);
    }
    final families = <ProfileKind, List<VpnProfile>>{};
    for (final profile in pool) {
      families.putIfAbsent(profile.kind, () => <VpnProfile>[]).add(profile);
    }

    final orderedKinds = families.keys.toList()
      ..sort((a, b) {
        final aProfile = families[a]!.first;
        final bProfile = families[b]!.first;
        return rank(aProfile).compareTo(rank(bProfile));
      });
    final selected = <VpnProfile>[];
    final locationUse = <ServerLocation, int>{};
    while (selected.length < maxAttempts) {
      var addedInRound = false;
      for (final kind in orderedKinds) {
        final family = families[kind]!;
        if (family.isEmpty) continue;
        var candidateIndex = 0;
        if (choice == locationAuto) {
          var lowestUse = locationUse[family.first.location] ?? 0;
          for (var i = 1; i < family.length; i++) {
            final use = locationUse[family[i].location] ?? 0;
            if (use < lowestUse) {
              candidateIndex = i;
              lowestUse = use;
            }
          }
        }
        final candidate = family.removeAt(candidateIndex);
        selected.add(candidate);
        locationUse.update(
          candidate.location,
          (count) => count + 1,
          ifAbsent: () => 1,
        );
        addedInRound = true;
        if (selected.length == maxAttempts) break;
      }
      if (!addedInRound) break;
    }
    return selected;
  }

  /// Profiles in `location` first, then unknown-located ones. Profiles known to be
  /// in a different country are excluded — an unlabelled profile can still serve
  /// the choice and must never dead-end a single-profile subscription.
  static List<VpnProfile> _preferLocation(
    List<VpnProfile> profiles,
    String location,
  ) {
    return [
      ...profiles.where((p) => p.location == location),
      ...profiles.where((p) => p.location == null),
    ];
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
  }) : _bridge = bridge,
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
  VpnProfile? _activeProfile;
  VpnProfile? _attemptingProfile;
  bool _pinnedFellBack = false;
  int _attemptsMade = 0;
  int _attemptTotal = 0;
  int _compatibleCount = 0;
  Completer<VpnSnapshot>? _waiter;

  VpnSnapshot get native => _native;
  VpnState get state => _autoConnecting ? VpnState.connecting : _native.state;

  /// True when the last successful connect reached a profile other than the
  /// user's pin — the pinned entry was dead and a same-location fallback
  /// served. Reset on every connect; read after a successful one.
  bool get pinnedFellBack => _pinnedFellBack;
  bool get isBusy =>
      state == VpnState.connecting || state == VpnState.disconnecting;
  bool get isConnected => _native.state == VpnState.connected;
  String? get lastErrorClass => _lastErrorClass ?? _native.errorCode;

  /// The last failure as a user-safe, mapped error (never a raw class name).
  MilkyError? get lastError {
    final code = lastErrorClass;
    if (code == null) return null;
    return MilkyError.fromCode(code);
  }

  int get attemptsMade => _attemptsMade;

  /// Total number of profiles one connect run is allowed to try.
  int get attemptTotal => _attemptTotal;
  int get compatibleCount => _compatibleCount;
  String? get activeRemark => _native.profileRemark;

  /// The profile that produced the verified tunnel. Used to show a country name instead of
  /// a raw remark (which can contain protocol words we never surface).
  VpnProfile? get activeProfile => _activeProfile;

  /// Candidate currently being verified. Only its public country is exposed to the UI.
  /// ISO country code of the profile currently being attempted, or null.
  ServerLocation get attemptingLocation => _attemptingProfile?.location;

  /// Public, user-visible location of the connected server (ISO code or null).
  ServerLocation get activeLocation {
    final profile = _activeProfile;
    if (profile != null) return profile.location;
    final remark = _native.profileRemark;
    if (remark == null || remark.isEmpty) return null;
    return VpnProfile.locationFromRemark(remark);
  }

  DateTime? get connectedSince => _native.connectedSince;

  Future<void> init() async {
    try {
      _native = await _bridge.currentState();
    } catch (_) {}
    notifyListeners();
  }

  void _onNative(VpnSnapshot s) {
    // A late event for A must never complete the waiter for B. Native generations
    // independently guard same-profile retries and callbacks after cancellation.
    final candidate = _attemptingProfile;
    if (candidate != null &&
        s.profileId != null &&
        s.profileId!.isNotEmpty &&
        s.profileId != candidate.id) {
      return;
    }
    if (s.state == VpnState.connected &&
        (_cancelRequested ||
            (candidate != null && s.profileId != candidate.id))) {
      return;
    }
    _native = s;
    if (s.state != VpnState.connected && s.state != VpnState.connecting) {
      _activeProfile = null;
    }
    final w = _waiter;
    if (w != null &&
        !w.isCompleted &&
        (s.state == VpnState.connected ||
            s.state == VpnState.error ||
            s.state == VpnState.disconnected)) {
      w.complete(s);
    }
    notifyListeners();
  }

  /// Filters profiles the engine can genuinely execute.
  Future<List<VpnProfile>> supportedProfiles(List<VpnProfile> all) async {
    final out = <VpnProfile>[];
    var consecutiveErrors = 0;
    for (final p in all) {
      if (p.kind == ProfileKind.other) continue;
      try {
        if (await _bridge.isProfileSupported(p)) out.add(p);
        consecutiveErrors = 0;
      } catch (_) {
        // A wedged native core answers every call with a timeout — bail out
        // instead of grinding a 20s timeout through each remaining profile.
        if (++consecutiveErrors >= 3) break;
      }
    }
    _compatibleCount = out.length;
    return out;
  }

  /// Returns true when a verified tunnel is up.
  Future<bool> connect(
    List<VpnProfile> all,
    LocationChoice choice, {
    String? profileId,
  }) async {
    if (_autoConnecting) return false;
    _autoConnecting = true;
    _cancelRequested = false;
    _lastErrorClass = null;
    _pinnedFellBack = false;
    _attemptsMade = 0;
    _attemptTotal = 0;
    var connected = false;
    notifyListeners();
    try {
      final granted = await _bridge.prepare();
      if (!granted) {
        _lastErrorClass = 'vpn_permission_denied';
        return false;
      }
      final supported = await supportedProfiles(all);
      VpnProfile? pinned;
      if (profileId != null) {
        for (final p in supported) {
          if (p.id == profileId) {
            pinned = p;
            break;
          }
        }
      }
      // A pin that resolves to nothing executable must fail loudly — silently
      // sweeping another profile would exit the tunnel through a country the
      // user did not pick.
      if (profileId != null && pinned == null) {
        _lastErrorClass = 'unsupported_profile';
        return false;
      }
      final candidates = pinned != null
          ? [pinned]
          : _selector.candidates(
              supported,
              choice,
              maxAttempts: maxAttempts,
            );
      _attemptTotal = candidates.length;
      notifyListeners();
      if (candidates.isEmpty) {
        _lastErrorClass = 'no_compatible_profiles';
        return false;
      }
      var consecutiveBridgeTimeouts = 0;
      var fellBack = false;
      // Index-based: the fallback path appends same-location candidates while
      // iterating — a for-in iterator would throw on the mutation.
      for (var i = 0; i < candidates.length; i++) {
        final p = candidates[i];
        if (_cancelRequested) {
          _lastErrorClass = 'cancelled';
          return false;
        }
        _attemptsMade++;
        final ok = await _attempt(p);
        if (ok) {
          _lastErrorClass = null;
          _pinnedFellBack = fellBack;
          connected = true;
          return true;
        }
        // Bridge-call timeouts mean the native core is wedged, not that the
        // servers are down — fail fast rather than sweeping all candidates
        // (previously this could hold the UI busy for ~8min on a dead core).
        if (_lastErrorClass?.startsWith('bridge_timeout') ?? false) {
          if (++consecutiveBridgeTimeouts >= 2) {
            _lastErrorClass = 'core_dead';
            return false;
          }
        } else {
          consecutiveBridgeTimeouts = 0;
        }
        // A dead pin is retried first, then we fall back to other profiles
        // in the SAME location — the exit country stays the one the user
        // picked; a pin to a foreign country never silently crosses borders.
        if (pinned != null && !fellBack) {
          final fallback = _selector
              .candidates(
                supported
                    .where(
                      (x) =>
                          x.id != pinned!.id && x.location == pinned.location,
                    )
                    .toList(),
                locationAuto,
                maxAttempts: maxAttempts - 1,
              )
              .toList();
          if (fallback.isNotEmpty) {
            candidates.addAll(fallback);
            _attemptTotal = candidates.length;
            notifyListeners();
          }
          fellBack = true;
        }
      }
      _lastErrorClass ??= 'all_attempts_failed';
      return false;
    } catch (e) {
      _lastErrorClass = e is VpnBridgeException ? e.code : 'bridge_error';
      return false;
    } finally {
      _autoConnecting = false;
      // A failed sweep can leave _native stuck on a transitional snapshot:
      // the native side emitted 'connecting' for the last attempt but never
      // confirmed its teardown — then `state` stays `connecting` forever,
      // the button reads «Подключаем…» and taps are eaten until force-stop.
      // Confirm teardown ourselves, then drop the stale snapshot.
      if (!connected &&
          (_native.state == VpnState.connecting ||
              _native.state == VpnState.disconnecting)) {
        try {
          await _bridge.disconnect();
        } catch (_) {}
        if (!connected &&
            (_native.state == VpnState.connecting ||
                _native.state == VpnState.disconnecting)) {
          _native = VpnSnapshot(
            state: VpnState.disconnected,
            errorCode: _lastErrorClass,
          );
        }
      }
      notifyListeners();
    }
  }

  Future<bool> _attempt(VpnProfile p) async {
    final waiter = Completer<VpnSnapshot>();
    _waiter = waiter;
    _attemptingProfile = p;
    try {
      await _bridge.connect(p);
      final res = await waiter.future.timeout(
        attemptTimeout,
        onTimeout: () =>
            const VpnSnapshot(state: VpnState.error, errorCode: 'timeout'),
      );
      if (res.state == VpnState.connected &&
          !_cancelRequested &&
          res.profileId == p.id) {
        _activeProfile = p;
        return true;
      }
      _lastErrorClass = res.errorCode ?? 'connect_failed';
      try {
        await _bridge.disconnect();
      } catch (_) {
        // This is cleanup for an already failed attempt. Keep the native
        // connection error: it identifies the real failed stage, while a
        // teardown error is only secondary evidence.
      }
      return false;
    } on VpnBridgeException catch (e) {
      _lastErrorClass = e.code;
      try {
        await _bridge.disconnect();
      } catch (_) {}
      return false;
    } finally {
      if (identical(_waiter, waiter)) _waiter = null;
      if (identical(_attemptingProfile, p)) _attemptingProfile = null;
    }
  }

  Future<void> disconnect() async {
    _cancelRequested = true;
    final waiter = _waiter;
    if (waiter != null && !waiter.isCompleted) {
      waiter.complete(
        const VpnSnapshot(state: VpnState.disconnected, errorCode: 'cancelled'),
      );
    }
    _activeProfile = null;
    _attemptingProfile = null;
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
