import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../subscription/vpn_profile.dart';
import 'vpn_bridge.dart';

/// Windows desktop bridge: runs the bundled `kal2-client.exe` as a hidden
/// child process and points the system proxy at its local SOCKS5 listener.
///
/// There is no TUN on this path — Windows routes through the WinINet proxy
/// setting, which covers browsers and any app honouring the system proxy.
class WindowsProcessVpnBridge implements VpnBridge {
  WindowsProcessVpnBridge({String? clientPath, String? socksAddr})
    : _clientPath = clientPath ?? _defaultClientPath(),
      _socksAddr = socksAddr ?? defaultSocksAddr;

  static const String defaultSocksAddr = '127.0.0.1:11808';
  static const Duration _upTimeout = Duration(seconds: 25);

  final String _clientPath;
  final String _socksAddr;

  final _states = StreamController<VpnSnapshot>.broadcast();
  final _links = StreamController<String>.broadcast();
  Process? _proc;
  VpnSnapshot _snap = VpnSnapshot.initial;
  bool _proxySet = false;

  static String _defaultClientPath() {
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    return '$exeDir\\kal2\\kal2-client.exe';
  }

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

  List<String> _argsFor(VpnProfile p) {
    final network = p.network.toLowerCase();
    return <String>[
      '-addr',
      '${p.address}:${p.port}',
      '-sni',
      p.sni ?? '',
      '-pub',
      p.publicKey ?? '',
      '-psk',
      p.secret,
      '-carrier',
      (network == 'veil' || network == 'drift' || network == 'relay')
          ? network
          : 'auto',
      '-drift',
      p.path ?? '',
      '-socks',
      _socksAddr,
    ];
  }

  @override
  Future<void> connect(VpnProfile profile) async {
    if (_proc != null) throw VpnBridgeException('busy');
    if (!await isProfileSupported(profile)) {
      throw VpnBridgeException('unsupported_profile');
    }
    if (!File(_clientPath).existsSync()) {
      throw VpnBridgeException('core_missing', _clientPath);
    }
    _set(
      VpnSnapshot(
        state: VpnState.connecting,
        profileId: profile.id,
        profileRemark: profile.redactedRemark,
      ),
    );

    Process proc;
    try {
      proc = await Process.start(_clientPath, _argsFor(profile));
    } on ProcessException catch (e) {
      _set(const VpnSnapshot(state: VpnState.error, errorCode: 'core_start'));
      throw VpnBridgeException('core_start', e.message);
    }
    _proc = proc;

    final up = Completer<void>();
    final errLines = <String>[];
    void onLine(String line) {
      errLines.add(line);
      if (errLines.length > 40) errLines.removeAt(0);
      if (line.contains('session up') && !up.isCompleted) up.complete();
    }

    final sub = proc.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(onLine);
    // 'session up' goes through log.Printf → stderr, not stdout.
    final subErr = proc.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(onLine);
    unawaited(
      proc.exitCode.then((code) {
        _proc = null;
        unawaited(_restoreProxy());
        if (!up.isCompleted) up.completeError(VpnBridgeException('core_exit'));
        _set(
          _snap.state == VpnState.connected ||
                  _snap.state == VpnState.disconnecting
              ? VpnSnapshot.initial
              : VpnSnapshot(
                  state: VpnState.error,
                  errorCode: 'core_exit_$code',
                  lastSuccessfulStage: _snap.lastSuccessfulStage,
                ),
        );
      }),
    );

    try {
      await up.future.timeout(_upTimeout);
    } on Object {
      proc.kill();
      _proc = null;
      sub.cancel();
      subErr.cancel();
      _set(
        const VpnSnapshot(state: VpnState.error, errorCode: 'connect_timeout'),
      );
      throw VpnBridgeException(
        'connect_timeout',
        errLines.isEmpty ? null : errLines.join('\n'),
      );
    }
    sub.cancel();
    subErr.cancel();

    await _applyProxy();
    _set(
      VpnSnapshot(
        state: VpnState.connected,
        profileId: profile.id,
        profileRemark: profile.redactedRemark,
        connectedSince: DateTime.now(),
        lastSuccessfulStage: 'session',
      ),
    );
  }

  @override
  Future<void> disconnect() async {
    final p = _proc;
    _proc = null;
    _set(
      VpnSnapshot(
        state: VpnState.disconnecting,
        profileId: _snap.profileId,
        profileRemark: _snap.profileRemark,
      ),
    );
    p?.kill();
    await _restoreProxy();
    _set(VpnSnapshot.initial);
  }

  @override
  Future<void> clearActiveProfile() async => disconnect();

  @override
  Future<String> coreVersion() async {
    if (!File(_clientPath).existsSync()) return 'missing';
    try {
      final r = await Process.run(_clientPath, const ['-h']);
      final text = '${r.stdout}${r.stderr}';
      return text.contains('Usage') ? 'kal2/2 (mirage)' : 'unknown';
    } on Object {
      return 'unrunnable';
    }
  }

  @override
  Future<bool> openVpnSettings() async {
    try {
      await Process.run('cmd', const [
        '/c',
        'start',
        'ms-settings:network-proxy',
      ]);
      return true;
    } on Object {
      return false;
    }
  }

  @override
  Future<Map<String, Object?>> deviceInfo() async => {
    'platform': 'windows',
    'osVersion': Platform.operatingSystemVersion,
    'localSocks': _socksAddr,
    'corePath': _clientPath,
    'corePresent': File(_clientPath).existsSync(),
  };

  @override
  Future<String?> getInitialLink() async => null;

  static const _proxyKey =
      r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings';

  Future<void> _applyProxy() async {
    await Process.run('reg', [
      'add',
      _proxyKey,
      '/v',
      'ProxyEnable',
      '/t',
      'REG_DWORD',
      '/d',
      '1',
      '/f',
    ]);
    await Process.run('reg', [
      'add',
      _proxyKey,
      '/v',
      'ProxyServer',
      '/t',
      'REG_SZ',
      '/d',
      'socks=$_socksAddr',
      '/f',
    ]);
    _proxySet = true;
    await _refreshProxy();
  }

  Future<void> _restoreProxy() async {
    if (!_proxySet) return;
    _proxySet = false;
    await Process.run('reg', [
      'add',
      _proxyKey,
      '/v',
      'ProxyEnable',
      '/t',
      'REG_DWORD',
      '/d',
      '0',
      '/f',
    ]);
    await _refreshProxy();
  }

  Future<void> _refreshProxy() => Process.run('powershell', const [
    '-NoProfile',
    '-Command',
    r'''
$sig='[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h,int o,System.IntPtr b,int l);'
$t=Add-Type -MemberDefinition $sig -Name W -Namespace I -PassThru
[void]$t::InternetSetOption([System.IntPtr]::Zero,39,[System.IntPtr]::Zero,0)
[void]$t::InternetSetOption([System.IntPtr]::Zero,37,[System.IntPtr]::Zero,0)
''',
  ]);
}
