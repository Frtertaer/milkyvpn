import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'vpn_bridge.dart';

/// DNS posture check: encrypted-DNS setting (Android Private DNS) plus a real
/// DNS-over-HTTPS probe both through the tunnel's SOCKS inbound and directly.
/// A leak means a query resolved over the plain path while the tunnel is up —
/// if direct DoH answers, that path exists and could carry plaintext lookups.
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

  /// A DoH query answered through the VPN tunnel's SOCKS port.
  final bool dohViaTunnel;

  /// A DoH query answered over the direct (non-tunnel) path.
  final bool dohDirect;

  /// Suspicious when the tunnel is supposed to carry everything but the plain
  /// path still resolves — DNS could leak past the VPN.
  bool get leakSuspected => dohDirect;

  bool get privateDnsOff =>
      privateDnsMode.isNotEmpty && privateDnsMode != 'hostname';
}

/// Runs the whole check; never throws — a failed probe lands as false.
Future<DnsCheckResult> checkDns(VpnBridge bridge) async {
  final mode = await bridge.privateDnsMode().catchError((_) => '');
  final spec = await bridge.privateDnsSpecifier().catchError((_) => '');
  final via = await _dohProbe(viaSocks: true);
  final direct = await _dohProbe(viaSocks: false);
  return DnsCheckResult(
    privateDnsMode: mode,
    privateDnsSpecifier: spec,
    dohViaTunnel: via,
    dohDirect: direct,
  );
}

/// GET https://1.1.1.1/dns-query?name=example.com&type=A and treat a JSON
/// answer with a "Status" field as a working resolver. Through the tunnel the
/// TCP connection is opened to the app's loopback SOCKS inbound and CONNECTs
/// onward; directly it is a plain TLS session to Cloudflare.
Future<bool> _dohProbe({required bool viaSocks}) async {
  const host = '1.1.1.1';
  Socket? tcp;
  try {
    tcp = await Socket.connect(
      viaSocks ? InternetAddress.loopbackIPv4.address : host,
      viaSocks ? _socksPort() : 443,
      timeout: const Duration(seconds: 6),
    );
    if (viaSocks) {
      // SOCKS5 greeting: v5, one method, no-auth.
      tcp.add(const [0x05, 0x01, 0x00]);
      final g = await _read(tcp, 2);
      if (g.length != 2 || g[0] != 0x05 || g[1] != 0x00) return false;
      // CONNECT 1.1.1.1:443, ATYP=0x01 IPv4.
      tcp.add(const [0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB]);
      final rep = await _read(tcp, 4);
      if (rep.length < 4 || rep[1] != 0x00) return false;
      final atyp = rep[3];
      final skip = atyp == 0x01
          ? 4 + 2
          : atyp == 0x03
          ? 1 + rep[4] + 2
          : 16 + 2;
      await _read(tcp, skip);
    }
    final tls = await SecureSocket.secure(
      tcp,
      host: host,
      supportedProtocols: const ['http/1.1'],
    );
    tcp = null;
    final req =
        'GET /dns-query?name=example.com&type=A HTTP/1.1\r\n'
        'Host: $host\r\n'
        'accept: application/dns-json\r\n'
        'connection: close\r\n\r\n';
    tls.add(ascii.encode(req));
    final body = StringBuffer();
    await for (final chunk in tls.timeout(const Duration(seconds: 8))) {
      body.write(utf8.decode(chunk, allowMalformed: true));
    }
    await tls.close();
    final s = body.toString();
    return s.contains('application/dns-json') || s.contains('"Status"');
  } catch (_) {
    return false;
  } finally {
    try {
      await tcp?.close();
    } catch (_) {}
  }
}

int _socksPort() => Platform.isAndroid ? 10808 : 11808;

Future<List<int>> _read(Socket s, int n) async {
  final out = <int>[];
  final c = Completer<List<int>>();
  late StreamSubscription<List<int>> sub;
  sub = s.listen(
    (d) {
      out.addAll(d);
      if (out.length >= n) {
        sub.cancel();
        if (!c.isCompleted) c.complete(out.sublist(0, n));
      }
    },
    onError: (_) {
      if (!c.isCompleted) c.complete(out);
    },
    onDone: () {
      if (!c.isCompleted) c.complete(out);
    },
    cancelOnError: true,
  );
  return c.future.timeout(const Duration(seconds: 6), onTimeout: () => out);
}
