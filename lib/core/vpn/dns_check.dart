import 'dart:async';
import 'dart:io';

import 'vpn_bridge.dart';

/// DNS posture check: encrypted-DNS setting (Android Private DNS) plus a real
/// DNS query both through the tunnel's SOCKS inbound and directly.
/// A leak means a query resolved over the plain path while the tunnel is up —
/// if direct DNS answers, that path exists and could carry plaintext lookups.
class DnsCheckResult {
  const DnsCheckResult({
    required this.privateDnsMode,
    required this.privateDnsSpecifier,
    required this.dohViaTunnel,
    required this.dohDirect,
  });

  /// 'hostname' | 'opportunistic' | 'off' | '' (unsupported platform).
  final String privateDnsMode;
  final String privateDnsSpecifier;

  /// A DNS query answered through the VPN tunnel's SOCKS port.
  final bool dohViaTunnel;

  /// A DNS query answered over the direct (non-tunnel) path.
  final bool dohDirect;

  /// Suspicious when the tunnel should be carrying DNS but doesn't answer
  /// while the physical path does — i.e. a dead tunnel, not merely an open
  /// direct path. The app's own sockets always bypass TUN by design
  /// (loop-avoidance exclusion), so a working direct probe alone proves
  /// nothing about leaks — it is permanently true whenever the device is
  /// online, VPN or not.
  bool get leakSuspected => dohDirect && !dohViaTunnel;

  bool get privateDnsOff =>
      privateDnsMode.isNotEmpty && privateDnsMode != 'hostname';
}

/// Runs the whole check; never throws — a failed probe lands as false.
Future<DnsCheckResult> checkDns(VpnBridge bridge, {List<int>? socksPorts}) async {
  final mode = await bridge.privateDnsMode().catchError((_) => '');
  final spec = await bridge.privateDnsSpecifier().catchError((_) => '');
  final via = await _dohProbe(viaSocks: true, socksPorts: socksPorts);
  final direct = await _dohProbe(viaSocks: false);
  return DnsCheckResult(
    privateDnsMode: mode,
    privateDnsSpecifier: spec,
    dohViaTunnel: via,
    dohDirect: direct,
  );
}

/// Sends a wire-format DNS query for example.com/A over TCP to 1.1.1.1:53 and
/// treats a matching answer as a working resolver. Through the tunnel the TCP
/// connection is opened to the app's loopback SOCKS inbound and CONNECTs
/// onward; directly it is a plain session to Cloudflare. (Not DoH: a Socket
/// allows a single listen(), so a TLS layer could not be attached after the
/// manual SOCKS handshake — plain DNS still proves the tunnel carries DNS.)
Future<bool> _dohProbe({required bool viaSocks, List<int>? socksPorts}) async {
  const host = '1.1.1.1';
  // Which loopback SOCKS is live depends on the engine: xray binds 10808
  // always; the native kal2 core binds 11808. Try both.
  final ports = viaSocks ? (socksPorts ?? _socksPorts()) : const <int>[53];
  for (final port in ports) {
    if (await _probePort(viaSocks, port, host)) return true;
  }
  return false;
}

Future<bool> _probePort(bool viaSocks, int port, String host) async {
  Socket? tcp;
  try {
    tcp = await Socket.connect(
      viaSocks ? InternetAddress.loopbackIPv4.address : host,
      viaSocks ? port : 53,
      timeout: const Duration(seconds: 6),
    );
    final reader = _BufferedSocket(tcp);
    if (viaSocks) {
      // SOCKS5 greeting: v5, one method, no-auth.
      tcp.add(const [0x05, 0x01, 0x00]);
      final g = await _take(reader, 2);
      if (g.length != 2 || g[0] != 0x05 || g[1] != 0x00) return false;
      // CONNECT 1.1.1.1:53, ATYP=0x01 IPv4.
      tcp.add(const [0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35]);
      final rep = await _take(reader, 4);
      if (rep.length < 4 || rep[1] != 0x00) return false;
      final atyp = rep[3];
      final skip = atyp == 0x01
          ? 4 + 2
          : atyp == 0x03
          ? 1 + rep[4] + 2
          : 16 + 2;
      await _take(reader, skip);
    }
    // TCP DNS: 2-byte length prefix + wire query, ID 0x4D56, RD=1.
    const q = [
      0x4D, 0x56, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
      0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    tcp.add([0x00, q.length, ...q]);
    final lenBytes = await _take(reader, 2);
    if (lenBytes.length < 2) return false;
    final len = (lenBytes[0] << 8) | lenBytes[1];
    final msg = await _take(reader, len);
    if (msg.length < 12) return false;
    final id = (msg[0] << 8) | msg[1];
    final qr = msg[2] & 0x80;
    final rcode = msg[3] & 0x0F;
    final anCount = (msg[6] << 8) | msg[7];
    return id == 0x4D56 && qr != 0 && rcode == 0 && anCount > 0;
  } catch (_) {
    return false;
  } finally {
    try {
      await tcp?.close();
    } catch (_) {}
  }
}

Future<List<int>> _take(_BufferedSocket r, int n) =>
    r.take(n).timeout(const Duration(seconds: 6), onTimeout: () => []);

List<int> _socksPorts() =>
    Platform.isAndroid ? const [10808, 11808] : const [11808, 10808];

/// Single-subscription buffered reader — a Socket allows only one listen(),
/// so every handshake phase drains this buffer instead of re-listening.
class _BufferedSocket {
  _BufferedSocket(Socket s) {
    _sub = s.listen(
      (c) {
        _buf.addAll(c);
        _drainWaiters();
      },
      onDone: () {
        _closed = true;
        _drainWaiters();
      },
      onError: (Object e) {
        _error = e;
        _closed = true;
        _drainWaiters();
      },
    );
  }
  late final StreamSubscription<List<int>> _sub;
  final _buf = <int>[];
  Completer<List<int>>? _waiter;
  int _want = 0;
  bool _closed = false;
  Object? _error;

  Future<void> close() => _sub.cancel();

  /// Resolves with the next [n] bytes; fewer when the socket closes first.
  Future<List<int>> take(int n) {
    if (_buf.length >= n) {
      final out = _buf.sublist(0, n);
      _buf.removeRange(0, n);
      return Future.value(out);
    }
    if (_closed) {
      final out = List<int>.from(_buf);
      _buf.clear();
      return _error != null ? Future.error(_error!) : Future.value(out);
    }
    _want = n;
    _waiter = Completer<List<int>>();
    return _waiter!.future;
  }

  void _drainWaiters() {
    final w = _waiter;
    if (w == null || w.isCompleted) return;
    if (_buf.length >= _want) {
      final out = _buf.sublist(0, _want);
      _buf.removeRange(0, _want);
      _waiter = null;
      w.complete(out);
    } else if (_closed) {
      final out = List<int>.from(_buf);
      _buf.clear();
      _waiter = null;
      if (_error != null) {
        w.completeError(_error!);
      } else {
        w.complete(out);
      }
    }
  }
}
