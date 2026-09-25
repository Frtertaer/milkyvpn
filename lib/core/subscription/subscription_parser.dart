import 'dart:convert';

import '../security/fnv_hash.dart';
import 'simple_yaml.dart';
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
///  * Fully parses `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`,
///    `hysteria2://`, `hy2://`, `tuic://`, `wireguard://` and `kal2://`.
///  * Accepts container payloads too: sing-box/v2ray JSON (`{outbounds: [...]}`
///    or a bare list/object) and YAML (`proxies:` clash lists or `outbounds:`).
///  * Recognized unsupported schemes (socks, http(s)) remain countable but are
///    never executed.
class SubscriptionParser {
  const SubscriptionParser();

  static const _uuidRe =
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';

  SubscriptionParseResult parse(String body, {Map<String, String>? headers}) {
    final text = decodeBody(body);
    final entries = <VpnProfile?>[];
    var totalLines = 0;

    if (_looksLikeContainer(text)) {
      entries.addAll(_parseContainerEntries(text));
      totalLines = entries.length;
    } else {
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
      totalLines = lines.length;
      for (final line in lines) {
        entries.add(parseLine(line));
      }
    }

    final profiles = <VpnProfile>[];
    var malformed = 0;
    var duplicates = 0;

    // Credential-bearing canonical identities exist only for this parse operation. They are
    // never returned, persisted, or logged; profile ids are opaque digests for correlation.
    final seen = <String>{};
    for (final profile in entries) {
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
      totalLines: totalLines,
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
      if (RegExp(r'[a-z0-9+.-]+://', caseSensitive: false).hasMatch(decoded) ||
          _looksLikeContainer(decoded)) {
        return decoded;
      }
      return trimmed;
    } on FormatException {
      return trimmed;
    }
  }

  /// True when the payload is a JSON or YAML container rather than share links.
  static bool _looksLikeContainer(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return false;
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) return true;
    return RegExp(
      r'^(proxies|outbounds|servers)\s*:',
      multiLine: true,
    ).hasMatch(trimmed);
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
          return _parseVmess(line);
        case 'trojan':
          return _parseTrojan(line);
        case 'ss':
          return _parseShadowsocks(line);
        case 'kal2':
          return _parseKal2(line);
        case 'ssr':
          return _parseSsr(line);
        case 'tuic':
          return _parseTuic(line);
        case 'wireguard':
        case 'wg':
          return _parseWireguard(line);
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
      profile.alterId,
      _nz(profile.cipher) ?? '',
      _nz(profile.plugin) ?? '',
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
    alterId: profile.alterId,
    cipher: profile.cipher,
    plugin: profile.plugin,
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

  /// `vmess://` is a single Base64-encoded JSON document (v2rayN share format).
  /// Some generators append `#name` after the payload.
  VpnProfile? _parseVmess(String line) {
    var payload = line.substring('vmess://'.length);
    var fragmentRemark = '';
    final hashIndex = payload.indexOf('#');
    if (hashIndex >= 0) {
      fragmentRemark = _dec(payload.substring(hashIndex + 1)).trim();
      payload = payload.substring(0, hashIndex);
    }
    final decoded = _b64decode(payload);
    if (decoded == null) return null;
    final Map<String, dynamic> m;
    try {
      final j = jsonDecode(decoded);
      if (j is! Map<String, dynamic>) return null;
      m = j;
    } catch (_) {
      return null;
    }
    String? s(String k) {
      final v = m[k];
      if (v == null) return null;
      return v.toString();
    }

    final host = s('add')?.trim();
    final port = int.tryParse(s('port') ?? '');
    final id = s('id')?.trim();
    if (host == null || host.isEmpty || !_validHost(host)) return null;
    if (port == null || port < 1 || port > 65535) return null;
    if (id == null || id.isEmpty) return null;

    final tls = (s('tls') ?? '').trim().toLowerCase();
    final security = (tls == 'tls' || tls == 'reality') ? 'tls' : 'none';
    var remark = (s('ps') ?? '').trim();
    if (remark.isEmpty) remark = fragmentRemark;
    return _identified(
      VpnProfile(
        id: '',
        protocol: 'vmess',
        address: host,
        port: port,
        secret: id,
        remark: remark.isEmpty ? '$host:$port' : remark,
        network: VpnProfile.normalizeNetwork((s('net') ?? 'tcp').trim()),
        security: security,
        sni: _trimmedNz(s('sni')),
        fingerprint: _lowerNz(s('fp')),
        host: _trimmedNz(s('host')),
        path: _nz(s('path')),
        alpn: _canonicalAlpnOrNull(s('alpn')),
        allowInsecure:
            _flag(s('allowInsecure')) || _flag(s('skip-cert-verify')),
        alterId: int.tryParse(s('aid') ?? '') ?? 0,
        cipher: _nz(s('scy')),
      ),
    );
  }

  /// `trojan://password@host:port?params#remark` — same URI shape as vless.
  VpnProfile? _parseTrojan(String line) {
    final parts = _split(line);
    if (parts == null) return null;
    final password = parts.userInfo;
    if (password.isEmpty) return null;

    final query = parts.params;
    // Trojan is TLS-by-design; generators that omit the param still mean TLS.
    var security = (query['security'] ?? 'tls').trim().toLowerCase();
    if (security.isEmpty) security = 'tls';
    var network = VpnProfile.normalizeNetwork(
      (query['type'] ?? 'tcp').trim(),
    );
    var path = _nz(query['path']);
    if (network == 'grpc') path ??= _nz(query['servicename']);
    final remark = parts.remark.isEmpty
        ? '${parts.host}:${parts.port}'
        : parts.remark;

    return _identified(
      VpnProfile(
        id: '',
        protocol: 'trojan',
        address: parts.host,
        port: parts.port,
        secret: password,
        remark: remark,
        network: network,
        security: security,
        sni: _trimmedNz(query['sni']) ?? _trimmedNz(query['peer']),
        fingerprint: _lowerNz(query['fp']),
        host: _trimmedNz(query['host']),
        path: path,
        alpn: _canonicalAlpnOrNull(query['alpn']),
        allowInsecure:
            _flag(query['allowinsecure']) || _flag(query['insecure']),
      ),
    );
  }

  /// Shadowsocks SIP002:
  ///   `ss://base64(method:password)@host:port?plugin=...#remark`
  ///   `ss://base64(method:password@host:port)#remark`        (legacy, no @)
  ///   `ss://method:password@host:port#remark`               (legacy plaintext)
  VpnProfile? _parseShadowsocks(String line) {
    var rest = line.substring('ss://'.length);
    var remark = '';
    final hashIndex = rest.indexOf('#');
    if (hashIndex >= 0) {
      remark = _dec(rest.substring(hashIndex + 1)).trim();
      rest = rest.substring(0, hashIndex);
    }
    var query = '';
    final queryIndex = rest.indexOf('?');
    if (queryIndex >= 0) {
      query = rest.substring(queryIndex + 1);
      rest = rest.substring(0, queryIndex);
    }

    String method;
    String password;
    String hostPort;
    if (rest.contains('@')) {
      final at = rest.lastIndexOf('@');
      var userPart = rest.substring(0, at);
      hostPort = rest.substring(at + 1);
      // userinfo is either plaintext `method:pass` or base64 of it.
      final decoded = _b64decode(userPart);
      if (decoded != null && decoded.contains(':')) userPart = decoded;
      userPart = _dec(userPart);
      final colon = userPart.indexOf(':');
      if (colon <= 0) return null;
      method = userPart.substring(0, colon).trim();
      password = userPart.substring(colon + 1);
    } else {
      // Whole payload is base64(method:pass@host:port)
      final decoded = _b64decode(rest);
      if (decoded == null) return null;
      final at = decoded.lastIndexOf('@');
      if (at < 0) return null;
      final userPart = decoded.substring(0, at);
      hostPort = decoded.substring(at + 1);
      final colon = userPart.indexOf(':');
      if (colon <= 0) return null;
      method = userPart.substring(0, colon).trim();
      password = userPart.substring(colon + 1);
    }
    if (method.isEmpty || password.isEmpty) return null;

    // hostPort may carry a trailing path in sloppy generators.
    final slashIndex = hostPort.indexOf('/');
    if (slashIndex >= 0) hostPort = hostPort.substring(0, slashIndex);

    String host;
    int? port;
    if (hostPort.startsWith('[')) {
      final close = hostPort.indexOf(']');
      if (close < 0) return null;
      host = hostPort.substring(1, close);
      final after = hostPort.substring(close + 1);
      if (after.startsWith(':')) port = int.tryParse(after.substring(1));
    } else {
      final colon = hostPort.lastIndexOf(':');
      if (colon < 0) return null;
      host = hostPort.substring(0, colon);
      port = int.tryParse(hostPort.substring(colon + 1));
    }
    if (host.isEmpty || port == null || port < 1 || port > 65535) return null;
    if (!_validHost(host)) return null;

    String? plugin;
    if (query.isNotEmpty) {
      for (final pair in query.split('&')) {
        final equals = pair.indexOf('=');
        final key = _dec(equals < 0 ? pair : pair.substring(0, equals))
            .toLowerCase();
        if (key == 'plugin') {
          plugin = equals < 0 ? '' : _dec(pair.substring(equals + 1));
        }
      }
    }

    return _identified(
      VpnProfile(
        id: '',
        protocol: 'ss',
        address: host,
        port: port,
        secret: password,
        remark: remark.isEmpty ? '$host:$port' : remark,
        network: 'tcp',
        security: 'none',
        cipher: method.toLowerCase(),
        plugin: _nz(plugin),
      ),
    );
  }

  /// `kal2://psk@host:port?sni=domain&pub=hex&carrier=veil|drift&path=/p#remark`
  VpnProfile? _parseKal2(String line) {
    final parts = _split(line);
    if (parts == null) return null;
    final psk = parts.userInfo;
    if (psk.isEmpty) return null;

    final query = parts.params;
    final carrier = (query['carrier'] ?? 'veil').trim().toLowerCase();
    if (carrier != 'veil' && carrier != 'drift' && carrier != 'relay') {
      return null;
    }
    final remark = parts.remark.isEmpty
        ? '${parts.host}:${parts.port}'
        : parts.remark;

    return _identified(
      VpnProfile(
        id: '',
        protocol: 'kal2',
        address: parts.host,
        port: parts.port,
        secret: psk,
        remark: remark,
        network: carrier,
        security: 'tls',
        sni: _trimmedNz(query['sni']),
        publicKey: _nz(query['pub']),
        path: _nz(query['path']),
      ),
    );
  }

  /// Tolerant Base64 decode: standard or URL-safe, padded or not. Returns null
  /// when the input is not valid base64 at all.
  static String? _b64decode(String input) {
    var s = input.trim().replaceAll(RegExp(r'\s+'), '');
    if (s.isEmpty) return null;
    if (!RegExp(r'^[A-Za-z0-9+/_\-=]+$').hasMatch(s)) return null;
    s = s.replaceAll('-', '+').replaceAll('_', '/').replaceAll('=', '');
    final padding = (4 - s.length % 4) % 4;
    if (padding == 3) return null;
    s += '=' * padding;
    try {
      return utf8.decode(base64.decode(s), allowMalformed: true);
    } on FormatException {
      return null;
    }
  }

  /// `ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=b64&
  /// protoparam=b64&remarks=b64&group=b64)`.
  ///
  /// The SSR protocol/obfs triplet has no dedicated profile field; it is packed
  /// into [VpnProfile.plugin] as `ssr:<protocol>:<obfs>:<obfsparam>:<protoparam>`
  /// so the exporter can reconstruct the link losslessly.
  VpnProfile? _parseSsr(String line) {
    var payload = line.substring('ssr://'.length).trim();
    // Some generators append a stray `#remark` after the payload.
    final hash = payload.indexOf('#');
    if (hash >= 0) payload = payload.substring(0, hash);
    final decoded = _b64decode(payload) ?? _dec(payload);
    var core = decoded;
    var remark = '';
    var obfsParam = '';
    var protoParam = '';
    final qIndex = core.indexOf('/?');
    if (qIndex >= 0) {
      final params = core.substring(qIndex + 2);
      core = core.substring(0, qIndex);
      for (final pair in params.split('&')) {
        final eq = pair.indexOf('=');
        if (eq < 0) continue;
        final key = pair.substring(0, eq).trim().toLowerCase();
        final raw = pair.substring(eq + 1);
        final value = _b64decode(raw) ?? _dec(raw);
        switch (key) {
          case 'remarks':
            remark = value;
          case 'obfsparam':
            obfsParam = value;
          case 'protoparam':
            protoParam = value;
          case 'group':
            if (remark.isEmpty) remark = value;
        }
      }
    }
    final segs = core.split(':');
    if (segs.length < 6) return null;
    final host = segs[0].trim();
    final port = int.tryParse(segs[1]);
    final ssrProtocol = segs[2].trim();
    final method = segs[3].trim();
    final obfs = segs[4].trim();
    final password = _b64decode(segs.sublist(5).join(':')) ??
        _dec(segs.sublist(5).join(':'));
    if (host.isEmpty || port == null || port < 1 || port > 65535) return null;
    if (!_validHost(host)) return null;
    if (method.isEmpty || password.isEmpty) return null;

    return _identified(
      VpnProfile(
        id: '',
        protocol: 'ssr',
        address: host,
        port: port,
        secret: password,
        remark: remark.isEmpty ? '$host:$port' : remark,
        network: 'tcp',
        security: 'none',
        cipher: method.toLowerCase(),
        plugin: 'ssr:$ssrProtocol:$obfs:$obfsParam:$protoParam',
      ),
    );
  }

  /// `tuic://uuid:password@host:port?congestion_control=&udp_relay_mode=&sni=&
  /// alpn=&allow_insecure=#remark` (TUIC v5 share form).
  ///
  /// `secret` packs `uuid:password`; transport extras are packed into
  /// [VpnProfile.plugin] as `key=value;key=value`.
  VpnProfile? _parseTuic(String line) {
    final parts = _split(line);
    if (parts == null) return null;
    final userInfo = parts.userInfo;
    final colon = userInfo.indexOf(':');
    if (colon <= 0) return null;
    final uuid = userInfo.substring(0, colon);
    final password = userInfo.substring(colon + 1);
    if (!RegExp(_uuidRe).hasMatch(uuid) || password.isEmpty) return null;

    final query = parts.params;
    final extras = <String>[
      if (_nz(query['congestion_control']) != null)
        'congestion_control=${query['congestion_control']}',
      if (_nz(query['udp_relay_mode']) != null)
        'udp_relay_mode=${query['udp_relay_mode']}',
      if (_nz(query['disable_sni']) != null)
        'disable_sni=${query['disable_sni']}',
      if (_nz(query['reduce_rtt']) != null)
        'reduce_rtt=${query['reduce_rtt']}',
    ];
    return _identified(
      VpnProfile(
        id: '',
        protocol: 'tuic',
        address: parts.host,
        port: parts.port,
        secret: '$uuid:$password',
        remark: parts.remark.isEmpty
            ? '${parts.host}:${parts.port}'
            : parts.remark,
        network: 'tuic',
        security: 'tls',
        sni: _trimmedNz(query['sni']),
        alpn: _canonicalAlpnOrNull(query['alpn']),
        allowInsecure:
            _flag(query['allow_insecure']) || _flag(query['insecure']),
        plugin: extras.isEmpty ? null : extras.join(';'),
      ),
    );
  }

  /// `wireguard://privkey@host:port?publickey=&presharedkey=&address=&mtu=&
  /// reserved=#remark` — the NekoBox/Throne share form. sing-box endpoint style
  /// (`wg://`) is accepted via the same shape.
  ///
  /// `secret` = private key, `publicKey` = peer public key; remaining parameters
  /// are packed into [VpnProfile.plugin] as `key=value;key=value`.
  VpnProfile? _parseWireguard(String line) {
    final parts = _split(line);
    if (parts == null) return null;
    final privateKey = parts.userInfo;
    if (privateKey.isEmpty) return null;
    final query = parts.params;
    final peerKey = _nz(query['publickey'] ?? query['peer_public_key']);
    if (peerKey == null) return null;
    final extras = <String>[
      for (final k in const [
        'presharedkey',
        'pre_shared_key',
        'address',
        'local_address',
        'ip',
        'mtu',
        'reserved',
        'workers',
        'keepalive',
      ])
        if (_nz(query[k]) != null) '${_wgCanonKey(k)}=${query[k]}',
    ];
    return _identified(
      VpnProfile(
        id: '',
        protocol: 'wireguard',
        address: parts.host,
        port: parts.port,
        secret: privateKey,
        remark: parts.remark.isEmpty
            ? '${parts.host}:${parts.port}'
            : parts.remark,
        network: 'wireguard',
        security: 'none',
        publicKey: peerKey,
        plugin: extras.isEmpty ? null : extras.join(';'),
      ),
    );
  }

  static String _wgCanonKey(String k) {
    switch (k) {
      case 'presharedkey':
        return 'pre_shared_key';
      case 'address':
      case 'local_address':
      case 'ip':
        return 'local_address';
      default:
        return k;
    }
  }

  // ------------------------------------------------------ container formats

  /// Parses a JSON or YAML container payload into nullable profile entries —
  /// one per outbound/proxy item, null for entries that did not map.
  List<VpnProfile?> _parseContainerEntries(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return const [];
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        return _entriesFromJson(jsonDecode(trimmed));
      } catch (_) {
        return const [null];
      }
    }
    try {
      final doc = SimpleYaml.parse(trimmed);
      return _entriesFromYaml(doc);
    } on FormatException {
      return const [null];
    }
  }

  List<VpnProfile?> _entriesFromJson(Object? doc) {
    if (doc is List) {
      return doc.map(_entryFromJsonItem).toList();
    }
    if (doc is Map<String, dynamic>) {
      final outbounds = doc['outbounds'] ?? doc['proxies'];
      if (outbounds is List) {
        return outbounds.map(_entryFromJsonItem).toList();
      }
      // Bare single outbound object.
      return [_profileFromOutbound(doc)];
    }
    return const [null];
  }

  VpnProfile? _entryFromJsonItem(Object? item) {
    if (item is String) return parseLine(item.trim());
    if (item is Map<String, dynamic>) return _profileFromOutbound(item);
    return null;
  }

  List<VpnProfile?> _entriesFromYaml(Map<String, Object?> doc) {
    final proxies = doc['proxies'] ?? doc['outbounds'];
    if (proxies is List) {
      return proxies
          .map(
            (item) => item is Map<String, Object?>
                ? _profileFromClash(item)
                : null,
          )
          .toList();
    }
    return const [null];
  }

  /// sing-box outbound `{type, server, server_port, ...}` plus the v2ray JSON
  /// `{protocol, settings.vnext[0], streamSettings}` shape.
  VpnProfile? _profileFromOutbound(Map<String, dynamic> m) {
    String? s(String k) {
      final v = m[k];
      return v == null ? null : v.toString();
    }

    Map<String, dynamic>? sub(String k) {
      final v = m[k];
      return v is Map<String, dynamic> ? v : null;
    }

    final type = (s('type') ?? s('protocol') ?? '').trim().toLowerCase();

    // v2ray JSON outbound: protocol + settings.vnext + streamSettings.
    if (m.containsKey('settings') && m['settings'] is Map<String, dynamic>) {
      return _profileFromV2rayOutbound(type, m, s, sub);
    }

    final host = s('server')?.trim();
    final port = int.tryParse(s('server_port') ?? s('port') ?? '');
    if (host == null || host.isEmpty || !_validHost(host)) return null;
    if (port == null || port < 1 || port > 65535) return null;

    final tls = sub('tls');
    final transport = sub('transport');
    String? tlsS(String k) => tls?[k]?.toString();
    bool tlsFlag(String k) => tls?[k] == true;
    final tlsEnabled = tlsFlag('enabled') || tls != null;
    final reality = sub('reality') ?? (tls == null ? null : sub('reality'));
    Map<String, dynamic>? realityMap;
    if (tls != null && tls['reality'] is Map<String, dynamic>) {
      realityMap = tls['reality'] as Map<String, dynamic>;
    } else {
      realityMap = reality;
    }
    final network = VpnProfile.normalizeNetwork(
      (transport?['type']?.toString() ?? 'tcp').trim(),
    );
    final transportHost = (transport?['headers'] is Map<String, dynamic>)
        ? (transport!['headers'] as Map<String, dynamic>)['Host']?.toString() ??
              (transport['headers'] as Map<String, dynamic>)['host']?.toString()
        : null;
    final remark = s('tag')?.trim();

    VpnProfile base({
      required String protocol,
      required String secret,
      String security = 'none',
      String? cipher,
      int alterId = 0,
      String? plugin,
      String? obfsPassword,
    }) {
      return VpnProfile(
        id: '',
        protocol: protocol,
        address: host,
        port: port,
        secret: secret,
        remark: (remark == null || remark.isEmpty) ? '$host:$port' : remark,
        network: network,
        security: security,
        sni: _trimmedNz(tlsS('server_name') ?? tlsS('servername')),
        fingerprint: _lowerNz(
          tls?['utls'] is Map<String, dynamic>
              ? (tls!['utls'] as Map<String, dynamic>)['fingerprint']?.toString()
              : tlsS('fingerprint'),
        ),
        publicKey: realityMap?['public_key']?.toString(),
        shortId: realityMap?['short_id']?.toString(),
        flow: s('flow'),
        host: _trimmedNz(transportHost),
        path: _nz(
          transport?['path']?.toString() ??
              transport?['service_name']?.toString(),
        ),
        alpn: _alpnFromValue(tls?['alpn']),
        allowInsecure: tlsFlag('insecure'),
        obfsPassword: obfsPassword,
        alterId: alterId,
        cipher: cipher,
        plugin: plugin,
      );
    }

    switch (type) {
      case 'vless':
        final uuid = s('uuid');
        if (uuid == null) return null;
        final security = realityMap != null
            ? 'reality'
            : tlsEnabled
            ? 'tls'
            : 'none';
        return _identified(
          base(protocol: 'vless', secret: uuid, security: security),
        );
      case 'vmess':
        final uuid = s('uuid');
        if (uuid == null) return null;
        return _identified(
          base(
            protocol: 'vmess',
            secret: uuid,
            security: tlsEnabled ? 'tls' : 'none',
            cipher: _nz(s('security')),
            alterId: int.tryParse(s('alter_id') ?? '') ?? 0,
          ),
        );
      case 'trojan':
        final password = s('password');
        if (password == null) return null;
        return _identified(
          base(
            protocol: 'trojan',
            secret: password,
            security: tlsEnabled ? 'tls' : 'none',
          ),
        );
      case 'shadowsocks':
      case 'ss':
        final password = s('password');
        final method = s('method');
        if (password == null || method == null) return null;
        final pluginName = s('plugin');
        final pluginOpts = s('plugin_opts');
        return _identified(
          base(
            protocol: 'ss',
            secret: password,
            cipher: method.toLowerCase(),
            plugin: _nz(
              pluginName == null
                  ? null
                  : pluginOpts == null
                  ? pluginName
                  : '$pluginName;$pluginOpts',
            ),
          ),
        );
      case 'hysteria2':
      case 'hy2':
        final password = s('password');
        if (password == null) return null;
        final obfs = sub('obfs');
        return _identified(
          base(
            protocol: 'hysteria2',
            secret: password,
            security: 'tls',
            obfsPassword: _nz(obfs?['password']?.toString()),
          ),
        );
      case 'tuic':
        final uuid = s('uuid');
        final password = s('password');
        if (uuid == null || password == null) return null;
        final extras = <String>[
          if (_nz(s('congestion_control')) != null)
            'congestion_control=${s('congestion_control')}',
          if (_nz(s('udp_relay_mode')) != null)
            'udp_relay_mode=${s('udp_relay_mode')}',
        ];
        return _identified(
          base(
            protocol: 'tuic',
            secret: '$uuid:$password',
            security: 'tls',
            plugin: extras.isEmpty ? null : extras.join(';'),
          ),
        );
      case 'wireguard':
      case 'wg':
        final priv = s('private_key');
        final peer = s('peer_public_key');
        if (priv == null || peer == null) return null;
        final extras = <String>[
          for (final k in const [
            'pre_shared_key',
            'local_address',
            'mtu',
            'reserved',
            'workers',
            'keepalive',
          ])
            if (_nz(s(k)) != null) '$k=${_joinableValue(m[k])}',
        ];
        return _identified(
          VpnProfile(
            id: '',
            protocol: 'wireguard',
            address: host,
            port: port,
            secret: priv,
            remark: (remark == null || remark.isEmpty)
                ? '$host:$port'
                : remark,
            network: 'wireguard',
            security: 'none',
            publicKey: peer,
            plugin: extras.isEmpty ? null : extras.join(';'),
          ),
        );
      default:
        return null;
    }
  }

  /// v2ray JSON outbound (`protocol`/`settings.vnext`/`streamSettings`).
  VpnProfile? _profileFromV2rayOutbound(
    String type,
    Map<String, dynamic> m,
    String? Function(String) s,
    Map<String, dynamic>? Function(String) sub,
  ) {
    final settings = sub('settings');
    if (settings == null) return null;
    final vnext = settings['vnext'];
    if (vnext is! List || vnext.isEmpty) return null;
    final first = vnext.first;
    if (first is! Map<String, dynamic>) return null;
    final host = first['address']?.toString().trim();
    final port = int.tryParse(first['port']?.toString() ?? '');
    if (host == null || host.isEmpty || !_validHost(host)) return null;
    if (port == null || port < 1 || port > 65535) return null;
    final users = first['users'];
    final user = users is List && users.isNotEmpty ? users.first : null;
    final userMap = user is Map<String, dynamic> ? user : const {};

    final stream = sub('streamSettings') ?? const <String, dynamic>{};
    Map<String, dynamic>? subS(String k) =>
        stream[k] is Map<String, dynamic>
            ? stream[k] as Map<String, dynamic>
            : null;
    final network = VpnProfile.normalizeNetwork(
      (stream['network']?.toString() ?? 'tcp').trim(),
    );
    final streamSec = (stream['security']?.toString() ?? 'none')
        .trim()
        .toLowerCase();
    final reality = subS('realitySettings') ?? const <String, dynamic>{};
    final tls = subS('tlsSettings') ?? const <String, dynamic>{};
    final ws = subS('wsSettings') ?? const <String, dynamic>{};
    final wsHeaders = ws['headers'] is Map<String, dynamic>
        ? ws['headers'] as Map<String, dynamic>
        : const <String, dynamic>{};
    final grpc = subS('grpcSettings') ?? const <String, dynamic>{};
    final remark = s('tag')?.trim();
    final id = userMap['id']?.toString() ?? userMap['password']?.toString();
    if (id == null || id.isEmpty) return null;

    return _identified(
      VpnProfile(
        id: '',
        protocol: type == 'shadowsocks' ? 'ss' : type,
        address: host,
        port: port,
        secret: id,
        remark: (remark == null || remark.isEmpty) ? '$host:$port' : remark,
        network: network,
        security: streamSec == 'reality'
            ? 'reality'
            : streamSec == 'tls'
            ? 'tls'
            : 'none',
        sni: _trimmedNz(
          reality['serverName']?.toString() ?? tls['serverName']?.toString(),
        ),
        fingerprint: _lowerNz(
          reality['fingerprint']?.toString() ??
              tls['fingerprint']?.toString(),
        ),
        publicKey: reality['publicKey']?.toString(),
        shortId: reality['shortId']?.toString(),
        flow: _nz(userMap['flow']?.toString()),
        host: _trimmedNz(
          wsHeaders['Host']?.toString() ?? wsHeaders['host']?.toString(),
        ),
        path: _nz(
          ws['path']?.toString() ?? grpc['serviceName']?.toString(),
        ),
        allowInsecure:
            tls['allowInsecure'] == true || tls['skip-cert-verify'] == true,
        alterId: int.tryParse(userMap['alterId']?.toString() ?? '') ?? 0,
        cipher: _nz(
          userMap['security']?.toString() ?? settings['method']?.toString(),
        ),
        plugin: _nz(
          settings['password'] != null && id != settings['password']
              ? null
              : settings['plugin']?.toString(),
        ),
      ),
    );
  }

  /// Clash/Clash-Meta `proxies:` map — also covers sing-box YAML outbounds,
  /// which share the same key names (`type`, `server`, `server_port`/`port`).
  VpnProfile? _profileFromClash(Map<String, Object?> m) {
    String? s(String k) => m[k]?.toString();
    bool flag(String k) => m[k] == true || s(k) == 'true';

    final type = (s('type') ?? '').trim().toLowerCase();
    final host = (s('server') ?? '').trim();
    final port = int.tryParse(s('port') ?? s('server_port') ?? '');
    if (host.isEmpty || port == null || port < 1 || port > 65535) return null;
    if (!_validHost(host)) return null;
    final remark = (s('name') ?? s('tag') ?? '').trim();

    Map<String, Object?>? sub(String k) =>
        m[k] is Map<String, Object?> ? m[k] as Map<String, Object?> : null;

    final wsOpts = sub('ws-opts');
    final wsHeaders = wsOpts?['headers'] is Map<String, Object?>
        ? wsOpts!['headers'] as Map<String, Object?>
        : null;
    final grpcOpts = sub('grpc-opts');
    final realityOpts = sub('reality-opts');
    final tlsEnabled =
        flag('tls') ||
        type == 'trojan' ||
        type == 'hysteria2' ||
        type == 'hy2' ||
        type == 'tuic';
    final network = VpnProfile.normalizeNetwork(
      (s('network') ?? 'tcp').trim(),
    );

    VpnProfile base({
      required String protocol,
      required String secret,
      String security = 'none',
      String? cipher,
      int alterId = 0,
      String? plugin,
      String? publicKey,
      String? shortId,
      String? obfsPassword,
      String? flow,
    }) {
      return VpnProfile(
        id: '',
        protocol: protocol,
        address: host,
        port: port,
        secret: secret,
        remark: remark.isEmpty ? '$host:$port' : remark,
        network: network,
        security: security,
        sni: _trimmedNz(
          s('sni') ?? s('servername') ?? s('server-name'),
        ),
        fingerprint: _lowerNz(
          s('client-fingerprint') ?? s('fingerprint'),
        ),
        publicKey: publicKey ?? realityOpts?['public-key']?.toString(),
        shortId: shortId ?? realityOpts?['short-id']?.toString(),
        flow: flow,
        host: _trimmedNz(
          wsHeaders?['Host']?.toString() ?? wsHeaders?['host']?.toString(),
        ),
        path: _nz(
          wsOpts?['path']?.toString() ??
              grpcOpts?['grpc-service-name']?.toString(),
        ),
        alpn: _alpnFromValue(m['alpn']),
        allowInsecure:
            flag('skip-cert-verify') || flag('allow-insecure'),
        obfsPassword: obfsPassword,
        alterId: alterId,
        cipher: cipher,
        plugin: plugin,
      );
    }

    switch (type) {
      case 'vless':
        final uuid = s('uuid');
        if (uuid == null) return null;
        return _identified(
          base(
            protocol: 'vless',
            secret: uuid,
            security: realityOpts != null
                ? 'reality'
                : tlsEnabled
                ? 'tls'
                : 'none',
            flow: _nz(s('flow')),
          ),
        );
      case 'vmess':
        final uuid = s('uuid');
        if (uuid == null) return null;
        return _identified(
          base(
            protocol: 'vmess',
            secret: uuid,
            security: tlsEnabled ? 'tls' : 'none',
            cipher: _nz(s('cipher')),
            alterId: int.tryParse(s('alterId') ?? s('alter_id') ?? '') ?? 0,
          ),
        );
      case 'trojan':
        final password = s('password');
        if (password == null) return null;
        return _identified(
          base(protocol: 'trojan', secret: password, security: 'tls'),
        );
      case 'ss':
      case 'shadowsocks':
        final password = s('password');
        final method = s('cipher') ?? s('method');
        if (password == null || method == null) return null;
        final pluginOpts = sub('plugin-opts');
        final pluginName = s('plugin');
        return _identified(
          base(
            protocol: 'ss',
            secret: password,
            cipher: method.toLowerCase(),
            plugin: _nz(
              pluginName == null
                  ? null
                  : pluginOpts == null
                  ? pluginName
                  : '$pluginName;${pluginOpts.entries.map((e) => '${e.key}=${e.value}').join(';')}',
            ),
          ),
        );
      case 'ssr':
        final password = s('password');
        final method = s('cipher') ?? s('method');
        if (password == null || method == null) return null;
        return _identified(
          base(
            protocol: 'ssr',
            secret: password,
            cipher: method.toLowerCase(),
            plugin:
                'ssr:${s('protocol') ?? 'origin'}:${s('obfs') ?? 'plain'}:${s('obfs-param') ?? ''}:${s('protocol-param') ?? ''}',
          ),
        );
      case 'hysteria2':
      case 'hy2':
        final password = s('password') ?? s('auth');
        if (password == null) return null;
        return _identified(
          base(
            protocol: 'hysteria2',
            secret: password,
            security: 'tls',
            obfsPassword: _nz(s('obfs-password')),
          ),
        );
      case 'tuic':
        final uuid = s('uuid');
        final password = s('password');
        if (uuid == null || password == null) return null;
        final extras = <String>[
          if (_nz(s('congestion-controller') ?? s('congestion_control')) !=
              null)
            'congestion_control=${s('congestion-controller') ?? s('congestion_control')}',
          if (_nz(s('udp-relay-mode') ?? s('udp_relay_mode')) != null)
            'udp_relay_mode=${s('udp-relay-mode') ?? s('udp_relay_mode')}',
        ];
        return _identified(
          base(
            protocol: 'tuic',
            secret: '$uuid:$password',
            security: 'tls',
            plugin: extras.isEmpty ? null : extras.join(';'),
          ),
        );
      case 'wireguard':
      case 'wg':
        final priv = s('private-key') ?? s('private_key');
        final peer = s('public-key') ??
            s('public_key') ??
            s('peer-public-key') ??
            s('peer_public_key');
        if (priv == null || peer == null) return null;
        final extras = <String>[
          for (final e in m.entries)
            if (const {
              'pre-shared-key',
              'pre_shared_key',
              'presharedkey',
              'ip',
              'ipv6',
              'mtu',
              'reserved',
              'workers',
              'keepalive',
            }.contains(e.key))
              '${_wgCanonKey(e.key)}=${_joinableValue(e.value)}',
        ];
        return _identified(
          VpnProfile(
            id: '',
            protocol: 'wireguard',
            address: host,
            port: port,
            secret: priv,
            remark: remark.isEmpty ? '$host:$port' : remark,
            network: 'wireguard',
            security: 'none',
            publicKey: peer,
            plugin: extras.isEmpty ? null : extras.join(';'),
          ),
        );
      case 'kal2':
        final psk = s('psk') ?? s('password');
        if (psk == null) return null;
        final carrier = (s('carrier') ?? 'veil').trim().toLowerCase();
        if (carrier != 'veil' && carrier != 'drift' && carrier != 'relay') {
          return null;
        }
        return _identified(
          VpnProfile(
            id: '',
            protocol: 'kal2',
            address: host,
            port: port,
            secret: psk,
            remark: remark.isEmpty ? '$host:$port' : remark,
            network: carrier,
            security: 'tls',
            sni: _trimmedNz(s('sni')),
            publicKey: _nz(s('pub') ?? s('public-key')),
            path: _nz(s('path')),
          ),
        );
      default:
        return null;
    }
  }

  static String _joinableValue(Object? v) =>
      v is List ? v.join(',') : v?.toString() ?? '';

  static String? _alpnFromValue(Object? v) {
    if (v == null) return null;
    final raw = v is List ? v.join(',') : v.toString();
    return _canonicalAlpnOrNull(raw);
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
