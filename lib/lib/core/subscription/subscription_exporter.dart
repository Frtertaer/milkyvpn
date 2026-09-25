import 'dart:convert';

import 'vpn_profile.dart';

/// Serializes profiles back into shareable subscription payloads — the inverse
/// of [SubscriptionParser]. Output is credential-bearing by definition: treat
/// it like the subscription URL itself (clipboard/file only on explicit user
/// action, never logged).
class SubscriptionExporter {
  const SubscriptionExporter();

  /// One canonical share link per profile, newline-joined. Profiles whose
  /// protocol cannot round-trip (`other`, socks, http) are skipped.
  String exportLinks(List<VpnProfile> profiles) => profiles
      .map(toShareLink)
      .whereType<String>()
      .join('\n');

  /// Standard subscription body: the joined links Base64-encoded, as returned
  /// by `X-Subscription-Format: base64` endpoints.
  String exportSubscription(List<VpnProfile> profiles) =>
      base64.encode(utf8.encode('${exportLinks(profiles)}\n'));

  /// Profiles skipped by [exportLinks] because their protocol is not
  /// share-link serializable.
  List<VpnProfile> unserializable(List<VpnProfile> profiles) =>
      profiles.where((p) => toShareLink(p) == null).toList();

  /// Canonical share link for [profile], or null when the protocol has no
  /// share-link form.
  String? toShareLink(VpnProfile profile) {
    switch (profile.protocol.toLowerCase()) {
      case 'vless':
        return _vless(profile);
      case 'vmess':
        return _vmess(profile);
      case 'trojan':
        return _trojan(profile);
      case 'ss':
      case 'shadowsocks':
        return _shadowsocks(profile);
      case 'ssr':
        return _ssr(profile);
      case 'hysteria2':
      case 'hy2':
        return _hysteria2(profile);
      case 'tuic':
        return _tuic(profile);
      case 'wireguard':
      case 'wg':
        return _wireguard(profile);
      case 'kal2':
        return _kal2(profile);
      default:
        return null;
    }
  }

  // ------------------------------------------------------------ protocols

  String _vless(VpnProfile p) {
    final q = _Q();
    q.put('type', VpnProfile.normalizeNetwork(p.network));
    q.put('security', p.security.isEmpty ? 'none' : p.security);
    q.put('encryption', 'none');
    q.put('sni', p.sni);
    q.put('fp', p.fingerprint);
    q.put('pbk', p.publicKey);
    q.put('sid', p.shortId);
    q.put('spx', p.spiderX);
    q.put('flow', p.flow);
    q.put('host', p.host);
    q.put('path', p.path);
    if (VpnProfile.normalizeNetwork(p.network) == 'xhttp') {
      q.put('mode', p.xhttpMode);
    }
    q.put('alpn', p.alpn);
    if (p.allowInsecure) q.put('allowInsecure', '1');
    return _uri('vless', p.secret, p.address, p.port, q, p.remark);
  }

  String _hysteria2(VpnProfile p) {
    final q = _Q();
    q.put('sni', p.sni);
    q.put('alpn', p.alpn);
    if (p.allowInsecure) q.put('insecure', '1');
    if (p.obfsPassword != null && p.obfsPassword!.isNotEmpty) {
      q.put('obfs', 'salamander');
      q.put('obfs-password', p.obfsPassword);
    }
    return _uri('hy2', p.secret, p.address, p.port, q, p.remark);
  }

  /// v2rayN vmess share form: single Base64 JSON document.
  String _vmess(VpnProfile p) {
    final security = p.security.toLowerCase();
    final doc = <String, Object?>{
      'v': '2',
      'ps': p.remark,
      'add': p.address,
      'port': p.port.toString(),
      'id': p.secret,
      'aid': p.alterId.toString(),
      'scy': p.cipher ?? 'auto',
      'net': VpnProfile.normalizeNetwork(p.network),
      'type': 'none',
      'host': p.host ?? '',
      'path': p.path ?? '',
      'tls': security == 'none' ? '' : security,
      'sni': p.sni ?? '',
      'alpn': p.alpn ?? '',
      'fp': p.fingerprint ?? '',
    };
    if (p.allowInsecure) {
      doc['skip-cert-verify'] = true;
    }
    return 'vmess://${base64.encode(utf8.encode(jsonEncode(doc)))}';
  }

  String _trojan(VpnProfile p) {
    final q = _Q();
    q.put('security', p.security.isEmpty ? 'tls' : p.security);
    q.put('sni', p.sni);
    q.put('type', VpnProfile.normalizeNetwork(p.network));
    q.put('host', p.host);
    q.put('path', p.path);
    q.put('alpn', p.alpn);
    q.put('fp', p.fingerprint);
    if (p.allowInsecure) q.put('allowInsecure', '1');
    return _uri('trojan', p.secret, p.address, p.port, q, p.remark);
  }

  /// SIP002: `ss://base64(method:pass)@host:port?plugin=...#remark`.
  String _shadowsocks(VpnProfile p) {
    final method = p.cipher ?? 'aes-256-gcm';
    final user = base64.encode(
      utf8.encode('$method:${p.secret}'),
    );
    final q = _Q()..put('plugin', p.plugin);
    return _uri('ss', user, p.address, p.port, q, p.remark, encodeUser: false);
  }

  /// `ssr://base64(host:port:proto:method:obfs:base64pass/?params)`.
  ///
  /// The parser packs the SSR triplet into [VpnProfile.plugin] as
  /// `ssr:<protocol>:<obfs>:<obfsparam>:<protoparam>`.
  String _ssr(VpnProfile p) {
    var proto = 'origin';
    var obfs = 'plain';
    var obfsParam = '';
    var protoParam = '';
    final packed = p.plugin;
    if (packed != null && packed.startsWith('ssr:')) {
      final segs = packed.substring(4).split(':');
      if (segs.isNotEmpty && segs[0].isNotEmpty) proto = segs[0];
      if (segs.length > 1 && segs[1].isNotEmpty) obfs = segs[1];
      if (segs.length > 2) obfsParam = segs[2];
      if (segs.length > 3) protoParam = segs.sublist(3).join(':');
    }
    final body = StringBuffer()
      ..write('${p.address}:${p.port}:$proto:${p.cipher ?? 'none'}:$obfs:')
      ..write(_b64Url(p.secret))
      ..write('/?');
    final params = <String>[
      'obfsparam=${_b64Url(obfsParam)}',
      'protoparam=${_b64Url(protoParam)}',
      'remarks=${_b64Url(p.remark)}',
    ];
    body.write(params.join('&'));
    return 'ssr://${_b64Url(body.toString())}';
  }

  /// `tuic://uuid:password@host:port?...#remark` — `secret` packs `uuid:pass`.
  String _tuic(VpnProfile p) {
    final q = _Q();
    q.put('sni', p.sni);
    q.put('alpn', p.alpn);
    if (p.allowInsecure) q.put('allow_insecure', '1');
    for (final extra in _extras(p.plugin)) {
      q.put(extra.key, extra.value);
    }
    return _uri('tuic', p.secret, p.address, p.port, q, p.remark);
  }

  /// `wireguard://privkey@host:port?publickey=...#remark` — NekoBox/Throne form.
  String _wireguard(VpnProfile p) {
    final q = _Q();
    q.put('publickey', p.publicKey);
    for (final extra in _extras(p.plugin)) {
      q.put(extra.key, extra.value);
    }
    return _uri('wireguard', p.secret, p.address, p.port, q, p.remark);
  }

  String _kal2(VpnProfile p) {
    final q = _Q();
    q.put('sni', p.sni);
    q.put('pub', p.publicKey);
    q.put('carrier', p.network.isEmpty ? 'veil' : p.network);
    q.put('path', p.path);
    return _uri('kal2', p.secret, p.address, p.port, q, p.remark);
  }

  // ------------------------------------------------------------ helpers

  /// Splits the `key=value;key=value` extras convention used by tuic/wireguard.
  static List<MapEntry<String, String>> _extras(String? plugin) {
    if (plugin == null || plugin.isEmpty) return const [];
    return plugin
        .split(';')
        .map((part) {
          final eq = part.indexOf('=');
          if (eq <= 0) return null;
          return MapEntry(part.substring(0, eq), part.substring(eq + 1));
        })
        .whereType<MapEntry<String, String>>()
        .toList();
  }

  static String _uri(
    String scheme,
    String userInfo,
    String host,
    int port,
    _Q query,
    String remark, {
    bool encodeUser = true,
  }) {
    final buf = StringBuffer('$scheme://')
      ..write(encodeUser ? Uri.encodeComponent(userInfo) : userInfo)
      ..write('@');
    if (host.contains(':')) {
      buf.write('[$host]');
    } else {
      buf.write(host);
    }
    buf.write(':$port');
    final qs = query.build();
    if (qs.isNotEmpty) buf.write('?$qs');
    if (remark.isNotEmpty) buf.write('#${Uri.encodeComponent(remark)}');
    return buf.toString();
  }

  static String _b64Url(String value) => base64
      .encode(utf8.encode(value))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
}

/// Ordered query builder preserving parameter order for stable output.
class _Q {
  final _pairs = <MapEntry<String, String>>[];

  void put(String key, String? value) {
    if (value == null || value.isEmpty) return;
    _pairs.add(MapEntry(key, value));
  }

  String build() => _pairs
      .map(
        (e) => '${Uri.encodeComponent(e.key)}=${Uri.encodeComponent(e.value)}',
      )
      .join('&');
}
