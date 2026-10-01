import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:shared_preferences/shared_preferences.dart';

import '../subscription/vpn_profile.dart';
import 'vpn_bridge.dart';

/// Windows desktop bridge: runs the bundled `kal2-client.exe` as a hidden
/// child process and points the system proxy at its local SOCKS5 listener.
///
/// Full-TUN mode (Settings → «Полный туннель») instead spawns the client
/// elevated (-tun -ctl): the UAC prompt appears once per connect, the client
/// creates the wintun adapter and routes all device traffic into the tunnel.
class WindowsProcessVpnBridge implements VpnBridge {
  WindowsProcessVpnBridge({
    String? clientPath,
    String? socksAddr,
    String? logPath,
  }) : _clientPath = clientPath ?? _defaultClientPath(),
       _socksAddr = socksAddr ?? defaultSocksAddr,
       _logPath = logPath ?? _defaultLogPath();

  static const String defaultSocksAddr = '127.0.0.1:11808';
  static const String _ctlAddr = '127.0.0.1:11909';
  static const Duration _upTimeout = Duration(seconds: 25);

  final String _clientPath;
  final String _socksAddr;
  final String _logPath;

  final _states = StreamController<VpnSnapshot>.broadcast();
  final _links = StreamController<String>.broadcast();
  Process? _proc;
  Socket? _ctl;
  VpnSnapshot _snap = VpnSnapshot.initial;
  bool _proxySet = false;
  // Proxy state captured before the first apply, so disconnect restores the
  // user's previous configuration instead of flattening it to "off".
  int? _prevProxyEnable;
  String? _prevProxyServer;

  static String _defaultClientPath() {
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    return '$exeDir\\kal2\\kal2-client.exe';
  }

  /// kal2-client -log target under the per-user app data dir — the core
  /// persists its own log there (stderr is invisible to us, and the elevated
  /// -tun helper has no parent to read it anyway).
  static String _defaultLogPath() {
    final appData = Platform.environment['APPDATA'] ?? '';
    return '$appData\\homes.milky\\milkyvpn\\logs\\kal2-client.log';
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
  Future<VpnSnapshot> currentState() async {
    unawaited(_healLeakedProxy());
    return _snap;
  }

  @override
  Future<bool> isPrepared() async => true;

  @override
  Future<bool> prepare() async {
    await _healLeakedProxy();
    return true;
  }

  bool _healAttempted = false;

  /// Self-heal for a leaked system proxy: a crash/kill/uninstall while
  /// connected leaves ProxyServer=socks=127.0.0.1:11808 enabled with no
  /// client behind it — every browser then dies with
  /// ERR_PROXY_CONNECTION_FAILED. Only ever touches our own value; a live
  /// listener on the socks port means the leak is not ours to fix.
  Future<void> _healLeakedProxy() async {
    if (_healAttempted) return;
    _healAttempted = true;
    if (_proc != null || _proxySet || _ctl != null) return;
    final server = await _queryRegValue('ProxyServer');
    final enabled = await _queryRegDword('ProxyEnable');
    final ops = leakedProxyPlan(
      currentServer: server,
      enabled: enabled,
      ourServer: 'socks=$_socksAddr',
    );
    if (ops == null) return;
    try {
      final s = await Socket.connect(
        '127.0.0.1',
        int.parse(_socksAddr.split(':').last),
        timeout: const Duration(milliseconds: 400),
      );
      s.destroy();
      return; // a live kal2-client owns the proxy — not a leak
    } catch (_) {}
    // Re-check after the awaits: a connect racing the heal may have claimed
    // the proxy — tearing it down now would break a live session.
    if (_proc != null || _proxySet || _ctl != null) return;
    try {
      for (final args in ops) {
        await Process.run('reg', args);
      }
      await _refreshProxy();
    } catch (_) {
      // self-heal is best-effort; a failed reg call must not break startup
    }
  }

  /// reg ops that undo a leaked proxy of ours, or null when the current
  /// registry state is not our leak (foreign proxy, proxy off, or no
  /// ProxyServer at all).
  static List<List<String>>? leakedProxyPlan({
    String? currentServer,
    int? enabled,
    required String ourServer,
    String key = _proxyKey,
  }) {
    if (currentServer != ourServer || enabled != 1) return null;
    return [
      ['delete', key, '/v', 'ProxyServer', '/f'],
      ['add', key, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f'],
    ];
  }

  @override
  Future<bool> isProfileSupported(VpnProfile profile) async =>
      profile.kind == ProfileKind.kal2 &&
      profile.publicKey != null &&
      profile.publicKey!.isNotEmpty;

  List<String> _argsFor(VpnProfile p) {
    final network = p.network.toLowerCase();
    // Carriers 'auto' cannot hedge — UDP (quasar/quic2) and relay — pass
    // through verbatim. TCP carriers keep the hedged veil+drift+cdn+mosaic
    // dial so a blocked carrier still connects (BUG-2026-10-02-01).
    const passThrough = {'quasar', 'quic2', 'relay'};
    final carrier = passThrough.contains(network) ? network : 'auto';
    // A flag with a '' value is fatal on the -tun path: `Start-Process
    // -ArgumentList` rejects empty elements, and Go's flag pkg would read the
    // NEXT token as the value. Every client flag defaults to "" anyway —
    // omit the pair.
    List<String> kv(String flag, String value) =>
        value.isEmpty ? const [] : [flag, value];
    return <String>[
      // altAddrs: extra entry points of the same server; kal2-client -addr
      // takes a comma list and fails over across them (multi-entry link).
      ...kv(
        '-addr',
        '${p.address}:${p.port}'
        '${p.altAddrs == null || p.altAddrs!.isEmpty ? '' : ',${p.altAddrs}'}',
      ),
      ...kv('-sni', p.sni ?? ''),
      ...kv('-pub', p.publicKey ?? ''),
      ...kv('-psk', p.secret),
      ...kv('-carrier', carrier),
      ...kv('-drift', p.path ?? ''),
      ...kv('-socks', _socksAddr),
      ...kv('-log', _logPath),
      ...kv('-ech', p.ech ?? ''),
      ...kv('-pin', p.pin ?? ''),
      ...kv('-front', p.fronts?.join(',') ?? p.front ?? ''),
      if (p.cover == '0' || p.cover == 'false') '-cover=false',
    ];
  }

  /// Visible seam for unit tests — the spawned command line is the bridge's
  /// real contract with kal2-client (flags dropped here are silent bugs).
  List<String> argsForTesting(VpnProfile p) => _argsFor(p);

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

    final prefs = await SharedPreferences.getInstance();
    if (prefs.getBool('tun_mode') ?? false) {
      return _connectTun(profile);
    }

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
    // The client can die mid-applyProxy (e.g. SOCKS bind failure races the
    // 'session up' line): its exit handler's _restoreProxy may already have
    // run as a no-op before _proxySet flipped — leaving our proxy pointing at
    // a dead listener. Re-check and undo synchronously.
    if (_proc == null) {
      await _restoreProxy();
      _set(
        const VpnSnapshot(state: VpnState.error, errorCode: 'core_exit'),
      );
      throw VpnBridgeException('core_exit');
    }
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
    final ctl = _ctl;
    _proc = null;
    _ctl = null;
    _set(
      VpnSnapshot(
        state: VpnState.disconnecting,
        profileId: _snap.profileId,
        profileRemark: _snap.profileRemark,
      ),
    );
    if (ctl != null) {
      try {
        ctl.writeln('stop');
        await ctl.flush();
        ctl.destroy();
      } catch (_) {}
    } else {
      p?.kill();
    }
    await _restoreProxy();
    _set(VpnSnapshot.initial);
  }

  /// Full-TUN connect: spawn kal2-client elevated via UAC and drive it over
  /// the -ctl socket. The system proxy is untouched — routes do the work.
  Future<void> _connectTun(VpnProfile profile) async {
    final args = <String>[
      ..._argsFor(profile),
      '-tun',
      'MilkyVPN-TUN',
      '-ctl',
      _ctlAddr,
    ];
    // A helper orphaned by a previous app run would already own the adapter;
    // ask it to stop before spawning a new one.
    await _stopCtl();

    final argLine = args.map((a) => "'$a'").join(', ');
    final res = await Process.run('powershell', [
      '-NoProfile',
      '-Command',
      'Start-Process -Verb RunAs -FilePath "$_clientPath" -ArgumentList $argLine',
    ]);
    if (res.exitCode != 0) {
      _set(
        const VpnSnapshot(state: VpnState.error, errorCode: 'tun_uac_denied'),
      );
      throw VpnBridgeException(
        'tun_uac_denied',
        '${res.stderr}${res.stdout}'.trim(),
      );
    }

    // The elevated helper binds the ctl socket once its session is up.
    Socket? ctl;
    for (var i = 0; i < 80 && ctl == null; i++) {
      try {
        ctl = await Socket.connect(
          '127.0.0.1',
          int.parse(_ctlAddr.split(':').last),
          timeout: const Duration(milliseconds: 300),
        );
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
    }
    if (ctl == null) {
      _set(
        const VpnSnapshot(state: VpnState.error, errorCode: 'connect_timeout'),
      );
      throw VpnBridgeException(
        'connect_timeout',
        'elevated helper never bound',
      );
    }
    _ctl = ctl;

    final up = Completer<void>();
    final errLines = <String>[];
    ctl
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(
          (line) {
            errLines.add(line);
            if (errLines.length > 40) errLines.removeAt(0);
            if ((line.contains('tun: adapter') ||
                    line.contains('session up')) &&
                !up.isCompleted) {
              up.complete();
            }
          },
          onDone: () {
            _ctl = null;
            if (!up.isCompleted) {
              up.completeError(VpnBridgeException('core_exit'));
            }
            _set(
              _snap.state == VpnState.connected ||
                      _snap.state == VpnState.disconnecting
                  ? VpnSnapshot.initial
                  : VpnSnapshot(
                      state: VpnState.error,
                      errorCode: 'core_exit',
                      lastSuccessfulStage: _snap.lastSuccessfulStage,
                    ),
            );
          },
        );

    try {
      await up.future.timeout(_upTimeout);
    } on Object {
      _ctl?.destroy();
      _ctl = null;
      _set(
        const VpnSnapshot(state: VpnState.error, errorCode: 'connect_timeout'),
      );
      throw VpnBridgeException(
        'connect_timeout',
        errLines.isEmpty ? null : errLines.join('\n'),
      );
    }

    _set(
      VpnSnapshot(
        state: VpnState.connected,
        profileId: profile.id,
        profileRemark: profile.redactedRemark,
        connectedSince: DateTime.now(),
        lastSuccessfulStage: 'tun',
      ),
    );
  }

  Future<void> _stopCtl() async {
    try {
      final s = await Socket.connect(
        '127.0.0.1',
        int.parse(_ctlAddr.split(':').last),
        timeout: const Duration(milliseconds: 400),
      );
      s.writeln('stop');
      await s.flush();
      s.destroy();
      await Future<void>.delayed(const Duration(milliseconds: 600));
    } catch (_) {
      // No stale helper listening — normal path.
    }
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
    _prevProxyEnable ??= await _queryRegDword('ProxyEnable');
    _prevProxyServer ??= await _queryRegValue('ProxyServer');
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

  /// reg arg lists that put the captured proxy state back: re-add the prior
  /// ProxyServer (or delete ours when there was none), then restore
  /// ProxyEnable. PAC/AutoConfigURL is never touched. A snapshot equal to
  /// [ourServer] is our own value leaked by a crashed run — restoring it
  /// would perpetuate the leak, so it counts as "no prior proxy".
  static List<List<String>> restoreProxyPlan({
    int? prevProxyEnable,
    String? prevProxyServer,
    String? ourServer,
    String key = _proxyKey,
  }) {
    final leaked = prevProxyServer != null && prevProxyServer == ourServer;
    final ops = <List<String>>[
      if (prevProxyServer == null || leaked)
        ['delete', key, '/v', 'ProxyServer', '/f']
      else
        ['add', key, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', prevProxyServer, '/f'],
      [
        'add',
        key,
        '/v',
        'ProxyEnable',
        '/t',
        'REG_DWORD',
        '/d',
        '${leaked ? 0 : (prevProxyEnable ?? 0)}',
        '/f',
      ],
    ];
    return ops;
  }

  /// Parses one `reg query` value line (`    Name    TYPE    VALUE`) into the
  /// raw value string; null when the name is absent from the output.
  static String? parseRegQueryValue(String output, String name) {
    for (final line in output.split('\n')) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length >= 3 && parts[0] == name) {
        return parts.sublist(2).join(' ');
      }
    }
    return null;
  }

  Future<String?> _queryRegValue(String name) async {
    try {
      final r = await Process.run('reg', ['query', _proxyKey, '/v', name]);
      if (r.exitCode != 0) return null;
      return parseRegQueryValue('${r.stdout}', name);
    } on Object {
      return null;
    }
  }

  Future<int?> _queryRegDword(String name) async {
    final raw = await _queryRegValue(name);
    if (raw == null) return null;
    return int.tryParse(raw.startsWith('0x') ? raw.substring(2) : raw, radix: 16) ??
        int.tryParse(raw);
  }

  Future<void> _restoreProxy() async {
    if (!_proxySet) return;
    _proxySet = false;
    final ops = restoreProxyPlan(
      prevProxyEnable: _prevProxyEnable,
      prevProxyServer: _prevProxyServer,
      ourServer: 'socks=$_socksAddr',
    );
    _prevProxyEnable = null;
    _prevProxyServer = null;
    for (final args in ops) {
      // A missing ProxyServer makes `reg delete` fail — that is the expected
      // state when the user never had one, so failures here are ignored.
      await Process.run('reg', args);
    }
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
