import 'dart:convert';

import '../security/fnv_hash.dart';

import 'vpn_profile.dart';

/// Outcome of parsing one subscription payload.
class SubscriptionParseResult {
  const SubscriptionParseResult({
    required this.profiles,
    required this.totalLines,
    required this.malformedLines,
    this.expiresAt,
    this.headersUsed = false,
  });

  final List<VpnProfile> profiles;
  final int totalLines;
  final int malformedLines;

  /// Optional expiry parsed from `subscription-userinfo` (expire=unix) if the server sends it.
  final DateTime? expiresAt;
  final bool headersUsed;
}

/// Production parser for MilkyVPN subscription payloads.
///
/// Guarantees:
///  * Never throws on malformed input — bad lines are counted and skipped.
///  * Accepts Base64 (standard / url-safe, padded / unpadded, with whitespace) or plain text.
///  * Supports `vless://` (tcp/raw, ws, xhttp, grpc…; reality/tls/none) and `hysteria2://` / `hy2://`.
///  * Other schemes are kept as `protocol: other` so counts stay accurate but are never executed.
class SubscriptionParser {
  const SubscriptionParser();

  static const _uuidRe = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';

  SubscriptionParseResult parse(String body, {Map<String, String>? headers}) {
    final text = decodeBody(body);
    final lines = text
        .split(RegExp(r'\r?\n'))
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && !l.startsWith('#') && !l.startsWith('//'))
        .toList();

    final profiles = <VpnProfile>[];
    var malformed = 0;
    final seen = <String>{};
    for (final line in lines) {
      final p = parseLine(line);
      if (p == null) {
        malformed++;
        continue;
      }
      if (seen.add(p.id)) profiles.add(p);
    }

    DateTime? expires;
    var headersUsed = false;
    if (headers != null) {
      final ui = headers.entries
          .where((e) => e.key.toLowerCase() == 'subscription-userinfo')
          .map((e) => e.value)
          .firstOrNull;
      if (ui != null) {
        headersUsed = true;
        final m = RegExp(r'expire=(\d+)').firstMatch(ui);
        if (m != null) {
          final v = int.tryParse(m.group(1)!);
          if (v != null && v > 0) {
            expires = DateTime.fromMillisecondsSinceEpoch(v * 1000, isUtc: true);
          }
        }
      }
    }

    return SubscriptionParseResult(
      profiles: profiles,
      totalLines: lines.length,
      malformedLines: malformed,
      expiresAt: expires,
      headersUsed: headersUsed,
    );
  }

  /// Decodes a Base64 body (tolerant) or returns the input if it is already plain URI text.
  static String decodeBody(String body) {
    final trimmed = body.trim();
    if (trimmed.isEmpty) return '';
    if (RegExp(r'^[a-z0-9+.-]+://', caseSensitive: false).hasMatch(trimmed)) {
      return trimmed; // already plain text
    }
    final compact = trimmed.replaceAll(RegExp(r'\s+'), '');
    if (!RegExp(r'^[A-Za-z0-9+/_\-=]+$').hasMatch(compact)) return trimmed;
    var norm = compact.replaceAll('-', '+').replaceAll('_', '/').replaceAll('=', '');
    final pad = (4 - norm.length % 4) % 4;
    if (pad == 3) return trimmed; // impossible length for base64
    norm = norm + '=' * pad;
    try {
      final bytes = base64.decode(norm);
      final decoded = utf8.decode(bytes, allowMalformed: true);
      // Heuristic: a valid subscription contains at least one URI scheme.
      if (RegExp(r'[a-z0-9+.-]+://', caseSensitive: false).hasMatch(decoded)) return decoded;
      return trimmed;
    } on FormatException {
      return trimmed;
    }
  }

  /// Parses a single share link. Returns null when the line cannot be turned into a profile.
  VpnProfile? parseLine(String line) {
    try {
      final schemeEnd = line.indexOf('://');
      if (schemeEnd <= 0) return null;
      final scheme = line.substring(0, schemeEnd).toLowerCase();
      switch (scheme) {
        case 'vless':
          return _parseVless(line);
        case 'hysteria2':
        case 'hy2':
          return _parseHysteria2(line);
        case 'vmess':
        case 'trojan':
        case 'ss':
        case 'ssr':
        case 'tuic':
        case 'wireguard':
        case 'socks':
        case 'http':
        case 'https':
          return _parseOther(scheme, line);
        default:
          return null;
      }
    } catch (_) {
      return null;
    }
  }

  // ---------------------------------------------------------------- helpers

  /// Splits `scheme://userinfo@host:port?query#fragment` without relying on Uri (which rejects
  /// some real-world links, e.g. raw base64 in userinfo or `[v6]` hosts without a port).
  static _Parts? _split(String line) {
    final schemeEnd = line.indexOf('://');
    if (schemeEnd <= 0) return null;
    var rest = line.substring(schemeEnd + 3);
    String fragment = '';
    final hashIdx = rest.indexOf('#');
    if (hashIdx >= 0) {
      fragment = rest.substring(hashIdx + 1);
      rest = rest.substring(0, hashIdx);
    }
    String query = '';
    final qIdx = rest.indexOf('?');
    if (qIdx >= 0) {
      query = rest.substring(qIdx + 1);
      rest = rest.substring(0, qIdx);
    }
    // strip trailing path (some generators add "/")
    final slashIdx = rest.indexOf('/');
    if (slashIdx >= 0) rest = rest.substring(0, slashIdx);
    String userInfo = '';
    final atIdx = rest.lastIndexOf('@');
    if (atIdx >= 0) {
      userInfo = rest.substring(0, atIdx);
      rest = rest.substring(atIdx + 1);
    }
    // host:port ([v6]:port)
    String host;
    int? port;
    if (rest.startsWith('[')) {
      final close = rest.indexOf(']');
      if (close < 0) return null;
      host = rest.substring(1, close);
      final after = rest.substring(close + 1);
      if (after.startsWith(':')) port = int.tryParse(after.substring(1));
    } else {
      final colon = rest.lastIndexOf(':');
      if (colon < 0) return null;
      host = rest.substring(0, colon);
      port = int.tryParse(rest.substring(colon + 1));
    }
    if (host.isEmpty || port == null || port < 1 || port > 65535) return null;
    if (!_validHost(host)) return null;

    final params = <String, String>{};
    if (query.isNotEmpty) {
      for (final kv in query.split('&')) {
        if (kv.isEmpty) continue;
        final eq = kv.indexOf('=');
        final k = _dec(eq < 0 ? kv : kv.substring(0, eq)).toLowerCase();
        final v = eq < 0 ? '' : _dec(kv.substring(eq + 1));
        if (k.isNotEmpty && !params.containsKey(k)) params[k] = v;
      }
    }
    return _Parts(userInfo: _dec(userInfo), host: host, port: port, params: params, remark: _dec(fragment));
  }

  static String _dec(String s) {
    try {
      return Uri.decodeComponent(s.replaceAll('+', '%2B'));
    } catch (_) {
      return s;
    }
  }

  static bool _validHost(String h) {
    if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(h)) {
      return h.split('.').every((o) => (int.tryParse(o) ?? 999) <= 255);
    }
    if (h.contains(':')) {
      return RegExp(r'^[0-9a-fA-F:.]+$').hasMatch(h); // IPv6 literal
    }
    return RegExp(r'^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
        .hasMatch(h);
  }

  static String _id(String proto, String host, int port, String net, String sec, String? path) =>
      fnv1a64Hex('$proto|$host|$port|$net|$sec|${path ?? ''}');

  VpnProfile? _parseVless(String line) {
    final p = _split(line);
    if (p == null) return null;
    final uuid = p.userInfo;
    if (!RegExp(_uuidRe).hasMatch(uuid)) return null;
    final q = p.params;
    var network = (q['type'] ?? 'tcp').toLowerCase();
    if (network == 'raw') network = 'tcp';
    if (network == 'splithttp') network = 'xhttp';
    var security = (q['security'] ?? 'none').toLowerCase();
    if (security.isEmpty) security = 'none';
    final flow = q['flow'];
    final remark = p.remark.isEmpty ? '${p.host}:${p.port}' : p.remark;
    return VpnProfile(
      id: _id('vless', p.host, p.port, network, security, q['path']),
      protocol: 'vless',
      address: p.host,
      port: p.port,
      secret: uuid,
      remark: remark,
      network: network,
      security: security,
      sni: _nz(q['sni']) ?? _nz(q['servername']),
      fingerprint: _nz(q['fp']),
      publicKey: _nz(q['pbk']),
      shortId: q['sid'],
      spiderX: _nz(q['spx']),
      flow: _nz(flow),
      host: _nz(q['host']),
      path: _nz(q['path']),
      xhttpMode: _nz(q['mode']),
      alpn: _nz(q['alpn']),
      allowInsecure: q['allowinsecure'] == '1' || q['allowinsecure'] == 'true' || q['insecure'] == '1',
    );
  }

  VpnProfile? _parseHysteria2(String line) {
    final p = _split(line);
    if (p == null) return null;
    final password = p.userInfo;
    if (password.isEmpty) return null;
    final q = p.params;
    final remark = p.remark.isEmpty ? '${p.host}:${p.port}' : p.remark;
    return VpnProfile(
      id: _id('hysteria2', p.host, p.port, 'hysteria', 'tls', null),
      protocol: 'hysteria2',
      address: p.host,
      port: p.port,
      secret: password,
      remark: remark,
      network: 'hysteria',
      security: 'tls',
      sni: _nz(q['sni']),
      alpn: _nz(q['alpn']),
      allowInsecure: q['insecure'] == '1' || q['insecure'] == 'true',
      obfsPassword: (q['obfs'] ?? '').toLowerCase() == 'salamander' ? _nz(q['obfs-password']) : null,
    );
  }

  VpnProfile? _parseOther(String scheme, String line) {
    final p = _split(line);
    if (p == null) return null;
    return VpnProfile(
      id: _id(scheme, p.host, p.port, 'other', 'other', null),
      protocol: 'other',
      address: p.host,
      port: p.port,
      secret: p.userInfo,
      remark: p.remark.isEmpty ? scheme : p.remark,
      network: 'other',
      security: 'other',
    );
  }

  static String? _nz(String? s) => (s == null || s.isEmpty) ? null : s;
}

class _Parts {
  const _Parts({
    required this.userInfo,
    required this.host,
    required this.port,
    required this.params,
    required this.remark,
  });

  final String userInfo;
  final String host;
  final int port;
  final Map<String, String> params;
  final String remark;
}
