import 'package:flutter/foundation.dart';

/// Server location exposed to the user (never protocol details).
enum ServerLocation { finland, usa, unknown }

/// Public, user-visible location selector.
enum LocationChoice { auto, finland, usa }

/// Transport family of a parsed profile.
enum ProfileKind { vlessRealityTcp, vlessWsTls, vlessXhttp, hysteria2, other }

/// A parsed subscription entry.
///
/// [secret] (UUID / hysteria password) and [publicKey] are credentials: they must never be
/// displayed, logged or copied. Use [redactedRemark] / [toDiagnosticString] for UI/diagnostics.
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
  });

  /// Stable id derived from the non-secret parts of the URI (address:port/network).
  final String id;
  final String protocol; // vless | hysteria2 | other
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

  ProfileKind get kind {
    if (protocol == 'hysteria2') return ProfileKind.hysteria2;
    if (protocol == 'vless') {
      final n = _normNet(network);
      if (n == 'tcp' && security == 'reality') return ProfileKind.vlessRealityTcp;
      if (n == 'ws' && security == 'tls') return ProfileKind.vlessWsTls;
      if (n == 'xhttp') return ProfileKind.vlessXhttp;
    }
    return ProfileKind.other;
  }

  ServerLocation get location {
    final r = remark.toLowerCase();
    if (r.contains('finland') ||
        r.contains('финлянд') ||
        r.contains('helsinki') ||
        r.contains('🇫🇮') ||
        RegExp(r'(^|[^a-z])fi([^a-z]|$)').hasMatch(r)) {
      return ServerLocation.finland;
    }
    if (r.contains('usa') ||
        r.contains('сша') ||
        r.contains('united states') ||
        r.contains('america') ||
        r.contains('🇺🇸') ||
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
        'network': _normNet(network),
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
      };

  /// Remark with anything that looks like a credential removed.
  String get redactedRemark {
    var r = remark;
    r = r.replaceAll(RegExp(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), '');
    if (secret.isNotEmpty) r = r.replaceAll(secret, '');
    if (publicKey != null && publicKey!.isNotEmpty) r = r.replaceAll(publicKey!, '');
    return r.trim().isEmpty ? 'Server' : r.trim();
  }

  /// Safe for the diagnostics screen: no host, no credentials.
  String toDiagnosticString() => '$redactedRemark [${kind.name}, ${location.name}]';

  static String _normNet(String n) {
    switch (n.toLowerCase()) {
      case 'raw':
      case 'tcp':
        return 'tcp';
      case 'splithttp':
      case 'xhttp':
        return 'xhttp';
      default:
        return n.toLowerCase();
    }
  }

  @override
  String toString() => 'VpnProfile($id, ${kind.name})';
}
