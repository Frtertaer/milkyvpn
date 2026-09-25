import 'package:flutter/foundation.dart';
import '../security/redactor.dart';

/// Server location exposed to the user (never protocol details).
enum ServerLocation { finland, usa, unknown }

/// Public, user-visible location selector.
enum LocationChoice { auto, finland, usa }

/// Transport family of a parsed profile.
enum ProfileKind {
  vlessRealityTcp,
  vlessWsTls,
  vlessXhttp,
  hysteria2,
  vmess,
  trojan,
  shadowsocks,
  kal2,
  other,
}

/// A parsed subscription entry.
///
/// [secret] (UUID / hysteria password), [publicKey], [shortId], and [obfsPassword]
/// are credential material: they must never be displayed, logged, or copied. Use
/// [redactedRemark] / [toDiagnosticString] for UI and diagnostics.
@immutable
class VpnProfile {
  const VpnProfile({
    required this.id,
    required this.protocol,
    required this.address,
    required this.port,
    required this.secret,
    required this.remark,
    this.network = 'tcp',
    this.security = 'none',
    this.sni,
    this.fingerprint,
    this.publicKey,
    this.shortId,
    this.spiderX,
    this.flow,
    this.host,
    this.path,
    this.xhttpMode,
    this.alpn,
    this.allowInsecure = false,
    this.obfsPassword,
    this.alterId = 0,
    this.cipher,
    this.plugin,
  });

  /// Opaque stable correlation id.
  ///
  /// The parser derives this from the complete canonical profile identity. Never render or
  /// log it: profile ids are implementation details, not user-facing server names.
  final String id;
  final String protocol; // vless | hysteria2 | original unsupported scheme
  final String address;
  final int port;
  final String secret;
  final String remark;
  final String network; // tcp | ws | xhttp | grpc | ...
  final String security; // reality | tls | none
  final String? sni;
  final String? fingerprint;
  final String? publicKey;
  final String? shortId;
  final String? spiderX;
  final String? flow;
  final String? host;
  final String? path;
  final String? xhttpMode;
  final String? alpn;
  final bool allowInsecure;
  final String? obfsPassword;

  /// VMess `aid` (0 for modern servers).
  final int alterId;

  /// Shadowsocks cipher (`method`) or VMess `scy` cipher name.
  final String? cipher;

  /// Shadowsocks SIP002 `plugin=` string, when present in the share link.
  final String? plugin;

  ProfileKind get kind {
    final proto = protocol.toLowerCase();
    final sec = security.toLowerCase();
    if (proto == 'hysteria2' || proto == 'hy2') return ProfileKind.hysteria2;
    if (proto == 'vmess') return ProfileKind.vmess;
    if (proto == 'trojan') return ProfileKind.trojan;
    if (proto == 'ss' || proto == 'shadowsocks') return ProfileKind.shadowsocks;
    if (proto == 'kal2') return ProfileKind.kal2;
    if (proto == 'vless') {
      final n = normalizeNetwork(network);
      if (n == 'tcp' && sec == 'reality') return ProfileKind.vlessRealityTcp;
      if (n == 'ws' && sec == 'tls') return ProfileKind.vlessWsTls;
      if (n == 'xhttp') return ProfileKind.vlessXhttp;
    }
    return ProfileKind.other;
  }

  ServerLocation get location => locationFromRemark(remark);

  /// Derives the public country selector value from a user-visible profile remark.
  ///
  /// Unicode escapes keep this source encoding-independent. This also recognizes Russian
  /// country/city names so selection does not depend on English-only profile remarks.
  static ServerLocation locationFromRemark(String remark) {
    final r = remark.toLowerCase().replaceAll('\u0451', '\u0435');
    if (r.contains('finland') ||
        r.contains('\u0444\u0438\u043d\u043b\u044f\u043d\u0434') ||
        r.contains('helsinki') ||
        r.contains('\u0445\u0435\u043b\u044c\u0441\u0438\u043d\u043a') ||
        r.contains('\u{1f1eb}\u{1f1ee}') ||
        RegExp(r'(^|[^a-z])fi([^a-z]|$)').hasMatch(r)) {
      return ServerLocation.finland;
    }
    if (r.contains('usa') ||
        r.contains('\u0441\u0448\u0430') ||
        r.contains('united states') ||
        r.contains('america') ||
        r.contains(
          '\u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u043d\u044b\u0435 \u0448\u0442\u0430\u0442\u044b',
        ) ||
        r.contains('\u{1f1fa}\u{1f1f8}') ||
        RegExp(r'(^|[^a-z])us([^a-z]|$)').hasMatch(r)) {
      return ServerLocation.usa;
    }
    return ServerLocation.unknown;
  }

  /// Payload sent to the native bridge. Contains credentials by design (in-process only).
  Map<String, Object?> toBridgeMap() => {
    'id': id,
    'remark': redactedRemark,
    'protocol': protocol,
    'address': address,
    'port': port,
    'secret': secret,
    'network': normalizeNetwork(network),
    'security': security,
    'sni': sni,
    'fingerprint': fingerprint,
    'publicKey': publicKey,
    'shortId': shortId,
    'spiderX': spiderX,
    'flow': flow,
    'host': host,
    'path': path,
    'xhttpMode': xhttpMode,
    'alpn': alpn,
    'allowInsecure': allowInsecure,
    'obfsPassword': obfsPassword,
    'alterId': alterId,
    'cipher': cipher,
    'plugin': plugin,
  };

  /// Remark with anything that looks like credential material removed.
  String get redactedRemark {
    var r = remark;
    r = r.replaceAll(
      RegExp(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
      ),
      '',
    );
    for (final value in [secret, publicKey, shortId, obfsPassword]) {
      if (value != null && value.isNotEmpty) r = r.replaceAll(value, '');
    }
    r = const Redactor().redact(r);
    // Remarks are untrusted labels. URLs have no place in notifications or diagnostics.
    r = r.replaceAll(RegExp(r'https?://\S+', caseSensitive: false), '<link>');
    return r.trim().isEmpty ? 'Server' : r.trim();
  }

  /// Safe for the diagnostics screen: no host, no credentials.
  String toDiagnosticString() =>
      '$redactedRemark [${kind.name}, ${location.name}]';

  /// Whether the current Dart selection pipeline can execute this profile.
  ///
  /// The authoritative check before connecting remains `VpnBridge.isProfileSupported`.
  bool get isStaticCompatible {
    if (address.trim().isEmpty || port < 1 || port > 65535 || secret.isEmpty) {
      return false;
    }
    final sec = security.toLowerCase();
    switch (kind) {
      case ProfileKind.vlessRealityTcp:
      case ProfileKind.vlessXhttp:
        if (sec != 'reality' && sec != 'tls' && sec != 'none') return false;
        if (sec == 'reality' && (publicKey == null || publicKey!.isEmpty)) {
          return false;
        }
        return true;
      case ProfileKind.vlessWsTls:
        return true;
      case ProfileKind.hysteria2:
        return true;
      case ProfileKind.vmess:
        const vmessNetworks = {'tcp', 'ws', 'xhttp', 'grpc'};
        if (!vmessNetworks.contains(normalizeNetwork(network))) return false;
        return sec == 'tls' || sec == 'none';
      case ProfileKind.trojan:
        const trojanNetworks = {'tcp', 'ws', 'grpc'};
        if (!trojanNetworks.contains(normalizeNetwork(network))) return false;
        return sec == 'tls' || sec == 'none';
      case ProfileKind.shadowsocks:
        const ciphers = {
          'aes-128-gcm',
          'aes-256-gcm',
          'chacha20-ietf-poly1305',
          'chacha20-poly1305',
          'xchacha20-ietf-poly1305',
          '2022-blake3-aes-128-gcm',
          '2022-blake3-aes-256-gcm',
          '2022-blake3-chacha20-poly1305',
          'none',
          'plain',
        };
        if (!ciphers.contains((cipher ?? '').toLowerCase())) return false;
        // SIP002 plugins (v2ray-plugin, obfs-local) have no engine equivalent.
        return plugin == null || plugin!.isEmpty;
      case ProfileKind.kal2:
        // Executable where the native core is present (Android: libcore.so in
        // the APK); requires the server public key alongside the PSK.
        return publicKey != null && publicKey!.isNotEmpty;
      case ProfileKind.other:
        return false;
    }
  }

  /// Canonical network name shared by parser identity, bridge payload, and compatibility.
  static String normalizeNetwork(String network) {
    switch (network.toLowerCase()) {
      case 'raw':
      case 'tcp':
        return 'tcp';
      case 'splithttp':
      case 'xhttp':
        return 'xhttp';
      default:
        return network.toLowerCase();
    }
  }

  @override
  String toString() => 'VpnProfile($id, ${kind.name})';
}
