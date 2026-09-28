import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:shared_preferences/shared_preferences.dart';

import '../subscription/vpn_profile.dart';
import 'milky_ffi.dart';
import 'vpn_bridge.dart';

/// Desktop bridge over the unified milky C ABI ([MilkyCore]): the core runs
/// in-process via `milky_start`, serves SOCKS5 on loopback, and the bridge
/// points the OS system proxy at it.
///
/// Used on Linux and macOS (and iOS once the xcframework ships — the FFI
/// surface is identical). Windows keeps [WindowsProcessVpnBridge]: UAC
/// elevation for TUN needs a separate elevated helper process.
/// On Android the same `milky_*` symbols live inside libcore.so, but the
/// `:kal2` service stays on JNI for lifecycle isolation.
class FfiVpnBridge implements VpnBridge {
  FfiVpnBridge({String? corePath, String? socksAddr, MilkyCore? core})
    : _corePath = corePath,
      _socksAddr = socksAddr ?? defaultSocksAddr,
      _core = core;

  static const String defaultSocksAddr = '127.0.0.1:11808';

  final String? _corePath;
  final String _socksAddr;
  MilkyCore? _core;

  final _states = StreamController<VpnSnapshot>.broadcast();
  final _links = StreamController<String>.broadcast();
  VpnSnapshot _snap = VpnSnapshot.initial;
  bool _proxySet = false;
  List<String> _proxyServices = const [];

  void _set(VpnSnapshot s) {
    _snap = s;
    if (!_states.isClosed) _states.add(s);
  }

  @override
  Stream<VpnSnapshot> get states => _states.stream;

  @override
  Stream<String> get links => _links.stream;

  @override
  Future<VpnSnapshot> currentState() async => _snap;

  @override
  Future<bool> isPrepared() async => true;

  @override
  Future<bool> prepare() async => true;

  @override
  Future<bool> isProfileSupported(VpnProfile profile) async =>
      profile.kind == ProfileKind.kal2 &&
      profile.publicKey != null &&
      profile.publicKey!.isNotEmpty;

  MilkyCore _openCore() {
    final c = _core ??= MilkyCore.open(path: _corePath);
    return c;
  }

  Map<String, Object?> _configFor(VpnProfile p, {required bool tun}) {
    final network = p.network.toLowerCase();
    return <String, Object?>{
      'addr': '${p.address}:${p.port}',
      'sni': p.sni ?? '',
      'pub': p.publicKey ?? '',
      'psk': p.secret,
      // 'relay' is its own carrier; everything else goes through the hedged
      // veil+drift dial so a blocked carrier still connects.
      'carrier': network == 'relay' ? 'relay' : 'auto',
      'path': p.path ?? '',
      'socks': _socksAddr,
      if (p.ech != null && p.ech!.isNotEmpty) 'ech': p.ech,
      if (p.cover == '0' || p.cover == 'false') 'cover': false,
      if (tun) 'tun': true,
    };
  }

  @override
  Future<void> connect(VpnProfile profile) async {
    if (_snap.state == VpnState.connected ||
        _snap.state == VpnState.connecting) {
      throw VpnBridgeException('busy');
    }
    if (!await isProfileSupported(profile)) {
      throw VpnBridgeException('unsupported_profile');
    }
    _set(
      VpnSnapshot(
        state: VpnState.connecting,
        profileId: profile.id,
        profileRemark: profile.redactedRemark,
      ),
    );

    final prefs = await SharedPreferences.getInstance();
    final tun = prefs.getBool('tun_mode') ?? false;

    MilkyCore core;
    int port;
    try {
      core = _openCore();
      core.setLogCallback((line) {
        if (!_links.isClosed) _links.add(line);
      });
      port = core.start(jsonEncode(_configFor(profile, tun: tun)));
    } on MilkyCoreException catch (e) {
      final code = e.detail.contains('permission') || e.detail.contains('EPERM')
          ? 'tun_needs_elevation'
          : 'core_start';
      _set(VpnSnapshot(state: VpnState.error, errorCode: code));
      throw VpnBridgeException(code, e.detail);
    }

    if (!tun) {
      await _applyProxy(port);
    }
    _set(
      VpnSnapshot(
        state: VpnState.connected,
        profileId: profile.id,
        profileRemark: profile.redactedRemark,
        connectedSince: DateTime.now(),
        lastSuccessfulStage: tun ? 'tun' : 'session',
      ),
    );
  }

  @override
  Future<void> disconnect() async {
    _set(
      VpnSnapshot(
        state: VpnState.disconnecting,
        profileId: _snap.profileId,
        profileRemark: _snap.profileRemark,
      ),
    );
    try {
      _core?.stop();
    } finally {
      await _restoreProxy();
      _set(VpnSnapshot.initial);
    }
  }

  @override
  Future<void> clearActiveProfile() async => disconnect();

  @override
  Future<String> coreVersion() async {
    try {
      return _openCore().version;
    } on MilkyCoreException {
      return 'missing';
    }
  }

  @override
  Future<bool> openVpnSettings() async {
    if (Platform.isMacOS) {
      final r = await Process.run('open', const [
        'x-apple.systempreferences:com.apple.preference.network',
      ]);
      return r.exitCode == 0;
    }
    if (Platform.isLinux) {
      // GNOME network proxy panel when present.
      final r = await Process.run('gnome-control-center', const ['network']);
      return r.exitCode == 0;
    }
    return false;
  }

  @override
  Future<Map<String, Object?>> deviceInfo() async => {
    'platform': Platform.operatingSystem,
    'osVersion': Platform.operatingSystemVersion,
    'localSocks': _socksAddr,
    'coreBinding': 'ffi',
    'corePresent': _core != null,
  };

  @override
  Future<String?> getInitialLink() async => null;

  // --- system proxy -------------------------------------------------------

  Future<void> _applyProxy(int port) async {
    final host = _socksAddr.split(':').first;
    if (Platform.isMacOS) {
      // Point every configured network service at the local SOCKS listener.
      final list = await Process.run('networksetup', const [
        '-listallnetworkservices',
      ]);
      final services = '${list.stdout}'
          .split('\n')
          .skip(1) // header line
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty && !s.startsWith('*'))
          .toList();
      for (final s in services) {
        await Process.run('networksetup', [
          '-setsocksfirewallproxy',
          s,
          host,
          '$port',
        ]);
        await Process.run('networksetup', [
          '-setsocksfirewallproxystate',
          s,
          'on',
        ]);
      }
      _proxyServices = services;
    } else if (Platform.isLinux) {
      // GNOME system proxy (no-op on other DEs — best effort).
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy',
        'mode',
        'manual',
      ]);
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy.socks',
        'host',
        host,
      ]);
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy.socks',
        'port',
        '$port',
      ]);
    }
    _proxySet = true;
  }

  Future<void> _restoreProxy() async {
    if (!_proxySet) return;
    _proxySet = false;
    if (Platform.isMacOS) {
      for (final s in _proxyServices) {
        await Process.run('networksetup', [
          '-setsocksfirewallproxystate',
          s,
          'off',
        ]);
      }
      _proxyServices = const [];
    } else if (Platform.isLinux) {
      await Process.run('gsettings', [
        'set',
        'org.gnome.system.proxy',
        'mode',
        'none',
      ]);
    }
  }
}
