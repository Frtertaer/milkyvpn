import 'dart:convert';

import '../security/fnv_hash.dart';
import 'vpn_profile.dart';

/// Outcome of parsing one subscription payload.
class SubscriptionParseResult {
  const SubscriptionParseResult({
    required this.profiles,
    required this.totalLines,
    required this.malformedLines,
    this.duplicateEntries = 0,
    this.expiresAt,
    this.headersUsed = false,
  });

  final List<VpnProfile> profiles;
  final int totalLines;
  final int malformedLines;

  /// Entries that parsed successfully but exactly repeated a canonical profile identity.
  final int duplicateEntries;

  /// Optional expiry parsed from `subscription-userinfo` (`expire=unix`).
  final DateTime? expiresAt;
  final bool headersUsed;

  /// Non-empty, non-comment entries received from the subscription payload.
  int get receivedEntryCount => totalLines;

  /// Entries successfully parsed before exact duplicates were removed.
  int get parsedProfileCount => profiles.length + duplicateEntries;

  /// Profiles retained after exact deduplication.
  int get postDedupeProfileCount => profiles.length;

  /// Successfully parsed entries removed as exact duplicates.
  int get droppedDuplicateCount => duplicateEntries;

  /// Entries that could not be parsed into a recognized profile shape.
  int get malformedEntryCount => malformedLines;

  /// Retained profiles admitted by the current Dart/native selection contract.
  int get compatibleProfileCount =>
      profiles.where((profile) => profile.isStaticCompatible).length;

  bool get isAccounted =>
      receivedEntryCount == parsedProfileCount + malformedEntryCount;
}

/// Production parser for MilkyVPN subscription payloads.
///
/// Guarantees:
///  * Never throws on malformed input; bad entries are counted and skipped.
///  * Accepts Base64 (standard/url-safe, padded/unpadded, with whitespace) or plain text.
///  * Supports `vless://`, `hysteria2://`, and `hy2://`.
///  * Recognized unsupported schemes remain countable but are never executed.
class SubscriptionParser {
  const SubscriptionParser();

  static const _uuidRe =
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';

  SubscriptionParseResult parse(String body, {Map<String, String>? headers}) {
    final text = decodeBody(body);
    final lines = text
        .split(RegExp(r'\r?\n'))
        .map((line) => line.trim())
        .where(
          (line) =>
              line.isNotEmpty &&
              !line.startsWith('#') &&
              !line.startsWith('//'),
        )
        .toList();

    final profiles = <VpnProfile>[];
    var malformed = 0;
    var duplicates = 0;

    // Credential-bearing canonical identities exist only for this parse operation. They are
    // never returned, persisted, or logged; profile ids are opaque digests for correlation.
    final seen = <String>{};
    for (final line in lines) {
      final profile = parseLine(line);
      if (profile == null) {
        malformed++;
        continue;
      }
      if (seen.add(_canonicalIdentity(profile))) {
        profiles.add(profile);
      } else {
        duplicates++;
      }
    }

    DateTime? expires;
    var headersUsed = false;
    if (headers != null) {
      final userInfo = headers.entries
          .where((entry) => entry.key.toLowerCase() == 'subscription-userinfo')
          .map((entry) => entry.value)
          .firstOrNull;
      if (userInfo != null) {
        headersUsed = true;
        final match = RegExp(r'expire=(\d+)').firstMatch(userInfo);
        if (match != null) {
          final value = int.tryParse(match.group(1)!);
          if (value != null && value > 0) {
            expires = DateTime.fromMillisecondsSinceEpoch(
              value * 1000,
              isUtc: true,
            );
          }
        }
      }
    }

    return SubscriptionParseResult(
      profiles: profiles,
      totalLines: lines.length,
      malformedLines: malformed,
      duplicateEntries: duplicates,
      expiresAt: expires,
      headersUsed: headersUsed,
    );
  }

  /// Decodes a tolerant Base64 body or returns already-plain URI text unchanged.
  static String decodeBody(String body) {
    final trimmed = body.trim();
    if (trimmed.isEmpty) return '';
    if (RegExp(r'^[a-z0-9+.-]+://', caseSensitive: false).hasMatch(trimmed)) {
      return trimmed;
    }

    final compact = trimmed.replaceAll(RegExp(r'\s+'), '');
    if (!RegExp(r'^[A-Za-z0-9+/_\-=]+$').hasMatch(compact)) return trimmed;
    var normalized = compact
        .replaceAll('-', '+')
        .replaceAll('_', '/')
        .replaceAll('=', '');
    final padding = (4 - normalized.length % 4) % 4;
    if (padding == 3) return trimmed;
    normalized += '=' * padding;
    try {
      final bytes = base64.decode(normalized);
      final decoded = utf8.decode(bytes, allowMalformed: true);
      if (RegExp(r'[a-z0-9+.-]+://', caseSensitive: false).hasMatch(decoded)) {
        return decoded;
      }
      return trimmed;
    } on FormatException {
      return trimmed;
    }
  }

  /// Parses a single share link. Returns null for malformed or unknown schemes.
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

  /// Splits `scheme://userinfo@host:port?query#fragment` without relying on [Uri].
  static _Parts? _split(String line) {
    final schemeEnd = line.indexOf('://');
    if (schemeEnd <= 0) return null;
    var rest = line.substring(schemeEnd + 3);

    var fragment = '';
    final hashIndex = rest.indexOf('#');
    if (hashIndex >= 0) {
      fragment = rest.substring(hashIndex + 1);
      rest = rest.substring(0, hashIndex);
    }

    var query = '';
    final queryIndex = rest.indexOf('?');
    if (queryIndex >= 0) {
      query = rest.substring(queryIndex + 1);
      rest = rest.substring(0, queryIndex);
    }

    // Some generators append a slash after host:port.
    final slashIndex = rest.indexOf('/');
    if (slashIndex >= 0) rest = rest.substring(0, slashIndex);

    var userInfo = '';
    final atIndex = rest.lastIndexOf('@');
    if (atIndex >= 0) {
      userInfo = rest.substring(0, atIndex);
      rest = rest.substring(atIndex + 1);
    }

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
    if (host.isEmpty || port == null || port < 1 || port > 65535) {
      return null;
    }
    if (!_validHost(host)) return null;

    final params = <String, String>{};
    if (query.isNotEmpty) {
      for (final pair in query.split('&')) {
        if (pair.isEmpty) continue;
        final equals = pair.indexOf('=');
        final key = _dec(
          equals < 0 ? pair : pair.substring(0, equals),
        ).toLowerCase();
        final value = equals < 0 ? '' : _dec(pair.substring(equals + 1));
        if (key.isNotEmpty && !params.containsKey(key)) params[key] = value;
      }
    }

    return _Parts(
      userInfo: _dec(userInfo).trim(),
      host: host,
      port: port,
      params: params,
      remark: _dec(fragment).trim(),
    );
  }

  static String _dec(String value) {
    try {
      return Uri.decodeComponent(value.replaceAll('+', '%2B'));
    } catch (_) {
      return value;
    }
  }

  static bool _validHost(String host) {
    if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host)) {
      return host
          .split('.')
          .every((octet) => (int.tryParse(octet) ?? 999) <= 255);
    }
    if (host.contains(':')) {
      return RegExp(r'^[0-9a-fA-F:.]+$').hasMatch(host);
    }
    return RegExp(
      r'^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$',
    ).hasMatch(host);
  }

  /// Full semantic identity for exact duplicate detection.
  ///
  /// This covers all fields passed to the native builder and the remark/location semantics
  /// used by selection. Equivalent aliases/defaults are canonicalized before comparison.
  static String _canonicalIdentity(VpnProfile profile) {
    final rawProtocol = profile.protocol.trim().toLowerCase();
    final protocol = rawProtocol == 'hy2' ? 'hysteria2' : rawProtocol;
    final address = profile.address.trim().toLowerCase();
    final network = VpnProfile.normalizeNetwork(profile.network.trim());
    final security = profile.security.trim().toLowerCase();
    final transportHost = _canonicalHost(profile.host);
    final explicitSni = _canonicalHost(profile.sni);
    final fallbackSni =
        (network == 'ws' || network == 'xhttp') && transportHost.isNotEmpty
        ? transportHost
        : (_isIpLiteral(address) ? '' : address);
    final effectiveSni = explicitSni.isEmpty ? fallbackSni : explicitSni;
    final remark = profile.remark.trim();

    return jsonEncode([
      2, // identity schema
      protocol,
      address,
      profile.port,
      profile.secret,
      network,
      security,
      effectiveSni,
      (_nz(profile.fingerprint) ?? 'chrome').trim().toLowerCase(),
      profile.publicKey ?? '',
      profile.shortId ?? '',
      profile.spiderX ?? '',
      profile.flow ?? '',
      transportHost,
      _nz(profile.path) ?? '/',
      (_nz(profile.xhttpMode) ?? 'auto').trim().toLowerCase(),
      _canonicalAlpn(profile.alpn),
      profile.allowInsecure,
      profile.obfsPassword ?? '',
      remark,
      VpnProfile.locationFromRemark(remark).name,
    ]);
  }

  /// Assigns an opaque id without retaining the credential-bearing canonical string.
  static VpnProfile _identified(VpnProfile profile) => VpnProfile(
    id: fnv1a64Hex(_canonicalIdentity(profile)),
    protocol: profile.protocol,
    address: profile.address,
    port: profile.port,
    secret: profile.secret,
    remark: profile.remark,
    network: profile.network,
    security: profile.security,
    sni: profile.sni,
    fingerprint: profile.fingerprint,
    publicKey: profile.publicKey,
    shortId: profile.shortId,
    spiderX: profile.spiderX,
    flow: profile.flow,
    host: profile.host,
    path: profile.path,
    xhttpMode: profile.xhttpMode,
    alpn: profile.alpn,
    allowInsecure: profile.allowInsecure,
    obfsPassword: profile.obfsPassword,
  );

  VpnProfile? _parseVless(String line) {
    final parts = _split(line);
    if (parts == null) return null;
    final uuid = parts.userInfo;
    if (!RegExp(_uuidRe).hasMatch(uuid)) return null;

    final query = parts.params;
    final network = VpnProfile.normalizeNetwork(
      (query['type'] ?? 'tcp').trim(),
    );
    var security = (query['security'] ?? 'none').trim().toLowerCase();
    if (security.isEmpty) security = 'none';
    final remark = parts.remark.isEmpty
        ? '${parts.host}:${parts.port}'
        : parts.remark;

    return _identified(
      VpnProfile(
        id: '',
        protocol: 'vless',
        address: parts.host,
        port: parts.port,
        secret: uuid,
        remark: remark,
        network: network,
        security: security,
        sni: _trimmedNz(query['sni']) ?? _trimmedNz(query['servername']),
        fingerprint: _lowerNz(query['fp']),
        publicKey: _nz(query['pbk']),
        shortId: _nz(query['sid']),
        spiderX: _nz(query['spx']),
        flow: _nz(query['flow']),
        host: _trimmedNz(query['host']),
        path: _nz(query['path']),
        xhttpMode: _lowerNz(query['mode']),
        alpn: _canonicalAlpnOrNull(query['alpn']),
        allowInsecure:
            _flag(query['allowinsecure']) || _flag(query['insecure']),
      ),
    );
  }

  VpnProfile? _parseHysteria2(String line) {
    final parts = _split(line);
    if (parts == null) return null;
    final password = parts.userInfo;
    if (password.isEmpty) return null;

    final query = parts.params;
    final remark = parts.remark.isEmpty
        ? '${parts.host}:${parts.port}'
        : parts.remark;
    final obfsPassword =
        (query['obfs'] ?? '').trim().toLowerCase() == 'salamander'
        ? _nz(query['obfs-password'])
        : null;

    return _identified(
      VpnProfile(
        id: '',
        protocol: 'hysteria2',
        address: parts.host,
        port: parts.port,
        secret: password,
        remark: remark,
        network: 'hysteria',
        security: 'tls',
        sni: _trimmedNz(query['sni']),
        alpn: _canonicalAlpnOrNull(query['alpn']),
        allowInsecure:
            _flag(query['insecure']) || _flag(query['allowinsecure']),
        obfsPassword: obfsPassword,
      ),
    );
  }

  VpnProfile? _parseOther(String scheme, String line) {
    final parts = _split(line);
    if (parts == null) return null;
    return _identified(
      VpnProfile(
        id: '',
        protocol: scheme,
        address: parts.host,
        port: parts.port,
        secret: parts.userInfo,
        remark: parts.remark.isEmpty ? scheme : parts.remark,
        network: 'other',
        security: 'other',
      ),
    );
  }

  static String? _nz(String? value) =>
      value == null || value.isEmpty ? null : value;

  static String? _trimmedNz(String? value) {
    final normalized = value?.trim();
    return normalized == null || normalized.isEmpty ? null : normalized;
  }

  static String? _lowerNz(String? value) => _trimmedNz(value)?.toLowerCase();

  static String _canonicalHost(String? value) =>
      (_nz(value) ?? '').trim().toLowerCase();

  static String _canonicalAlpn(String? value) => (_nz(value) ?? '')
      .split(',')
      .map((part) => part.trim())
      .where((part) => part.isNotEmpty)
      .join(',');

  static String? _canonicalAlpnOrNull(String? value) {
    final normalized = _canonicalAlpn(value);
    return normalized.isEmpty ? null : normalized;
  }

  static bool _flag(String? value) {
    final normalized = value?.trim().toLowerCase();
    return normalized == '1' || normalized == 'true';
  }

  static bool _isIpLiteral(String value) {
    if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(value)) return true;
    return value.contains(':');
  }
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
