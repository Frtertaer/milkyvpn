import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../security/redactor.dart';
import '../security/subscription_url_policy.dart';
import '../storage/secure_store.dart';
import 'subscription_parser.dart';
import 'vpn_profile.dart';

/// Fetches subscription bodies. Abstracted so tests never hit the network.
abstract class SubscriptionFetcher {
  Future<FetchedSubscription> fetch(Uri url);
}

class FetchedSubscription {
  const FetchedSubscription({required this.body, required this.headers});
  final String body;
  final Map<String, String> headers;
}

class SubscriptionFetchException implements Exception {
  SubscriptionFetchException(this.errorClass);
  final String errorClass;
  @override
  String toString() => 'SubscriptionFetchException($errorClass)';
}

/// Dedicated HTTPS-only fetcher. Redirects are NOT followed (they could leave the allowlist).
class HttpsSubscriptionFetcher implements SubscriptionFetcher {
  HttpsSubscriptionFetcher({
    this.policy = const SubscriptionUrlPolicy(),
    this.timeout = const Duration(seconds: 20),
  });

  final SubscriptionUrlPolicy policy;
  final Duration timeout;
  static const _maxBodyBytes = 512 * 1024;

  @override
  Future<FetchedSubscription> fetch(Uri url) async {
    final safe = policy.validate(url.toString());
    if (safe == null) throw SubscriptionFetchException('url_not_allowed');
    final client = HttpClient()
      ..connectionTimeout = timeout
      ..badCertificateCallback = (cert, host, port) => false;
    try {
      final req = await client.getUrl(safe).timeout(timeout);
      req.followRedirects = false;
      req.headers.set(HttpHeaders.userAgentHeader, 'MilkyVPN-Android/0.1');
      req.headers.set(HttpHeaders.acceptHeader, 'text/plain, */*');
      final res = await req.close().timeout(timeout);
      if (res.statusCode != 200) {
        throw SubscriptionFetchException(
          res.statusCode == 404 || res.statusCode == 403
              ? 'subscription_not_found'
              : 'http_${res.statusCode}',
        );
      }
      final bytes = <int>[];
      await for (final chunk in res.timeout(timeout)) {
        bytes.addAll(chunk);
        if (bytes.length > _maxBodyBytes) {
          throw SubscriptionFetchException('body_too_large');
        }
      }
      final headers = <String, String>{};
      res.headers.forEach((k, v) => headers[k.toLowerCase()] = v.join(', '));
      return FetchedSubscription(
        body: utf8.decode(bytes, allowMalformed: true),
        headers: headers,
      );
    } on SubscriptionFetchException {
      rethrow;
    } catch (e) {
      throw SubscriptionFetchException(const Redactor().errorClass(e));
    } finally {
      client.close(force: true);
    }
  }
}

/// Persisted subscription snapshot (parsed profiles + metadata). Stored in secure storage
/// because it contains credentials.
@immutable
class SubscriptionSnapshot {
  const SubscriptionSnapshot({
    required this.profiles,
    required this.updatedAt,
    required this.totalEntries,
    required this.malformedEntries,
    this.duplicateEntries = 0,
    this.expiresAt,
    this.schemaVersion = currentSchemaVersion,
    bool countsTrusted = true,
  }) : _countsTrusted = countsTrusted;

  /// First persisted schema that records every count boundary explicitly.
  static const int currentSchemaVersion = 2;

  final List<VpnProfile> profiles;
  final DateTime updatedAt;

  /// Non-empty, non-comment lines in the payload.
  final int totalEntries;

  /// Lines that could not be parsed at all.
  final int malformedEntries;

  /// Lines that parsed but repeated an endpoint already present in the list.
  ///
  /// `totalEntries = profiles.length + malformedEntries + duplicateEntries`, which is what
  /// makes the parsed count explainable instead of mysteriously smaller than the file.
  final int duplicateEntries;
  final DateTime? expiresAt;
  final int schemaVersion;
  final bool _countsTrusted;

  int get receivedEntryCount => totalEntries;
  int get parsedProfileCount => profiles.length + duplicateEntries;
  int get postDedupeProfileCount => profiles.length;
  int get droppedDuplicateCount => duplicateEntries;
  int get malformedEntryCount => malformedEntries;
  int get compatibleProfileCount =>
      profiles.where((profile) => profile.isStaticCompatible).length;

  bool get isCountInvariantValid =>
      receivedEntryCount >= 0 &&
      malformedEntryCount >= 0 &&
      droppedDuplicateCount >= 0 &&
      receivedEntryCount == parsedProfileCount + malformedEntryCount;

  /// True only for a current-schema snapshot whose persisted counters reconcile exactly.
  bool get countsTrusted => _countsTrusted && isCountInvariantValid;

  /// Legacy snapshots can still provide profiles for connection, but their counts must not
  /// be presented as authoritative until an explicit refresh reparses the source payload.
  bool get needsRefresh => !countsTrusted;

  bool get isActive =>
      profiles.isNotEmpty &&
      (expiresAt == null || expiresAt!.isAfter(DateTime.now().toUtc()));
}

/// Owns the subscription credential (URL/token) and the parsed snapshot.
class SubscriptionRepository extends ChangeNotifier {
  SubscriptionRepository({
    required SecureStore store,
    required SubscriptionFetcher fetcher,
    SubscriptionParser parser = const SubscriptionParser(),
    SubscriptionUrlPolicy policy = const SubscriptionUrlPolicy(),
  }) : _store = store,
       _fetcher = fetcher,
       _parser = parser,
       _policy = policy;

  static const _kUrl = 'subscription_url';
  static const _kSnapshot = 'subscription_snapshot';

  final SecureStore _store;
  final SubscriptionFetcher _fetcher;
  final SubscriptionParser _parser;
  final SubscriptionUrlPolicy _policy;

  bool _loaded = false;
  Uri? _url;
  SubscriptionSnapshot? _snapshot;
  String? _lastError;

  bool get isLoaded => _loaded;
  /// Either a fetched subscription (has a URL) or a text-imported profile set
  /// (snapshot only, nothing to refresh).
  bool get hasSubscription =>
      _url != null || (_snapshot?.profiles.isNotEmpty ?? false);
  SubscriptionSnapshot? get snapshot => _snapshot;
  String? get lastErrorClass => _lastError;

  /// Whether the currently loaded count snapshot passed schema and invariant checks.
  bool get countsTrusted => _snapshot?.countsTrusted ?? false;

  /// A refresh is useful only when a subscription credential exists and counts are absent
  /// or untrusted. Loading never performs network I/O implicitly.
  bool get needsRefresh => _url != null && !countsTrusted;

  /// Redacted for UI. Never exposes the token.
  String? get redactedUrl =>
      _url == null ? null : SubscriptionUrlPolicy.redact(_url!);

  /// Full subscription URL, exposed ONLY for the explicit "copy link" advanced action.
  /// Never render this on normal screens.
  String? get urlForCopy => _url?.toString();

  Future<void> load() async {
    try {
      final u = await _store.read(_kUrl);
      if (u != null) _url = _policy.validate(u);
    } catch (_) {
      _url = null;
    }
    try {
      final s = await _store.read(_kSnapshot);
      if (s != null) _snapshot = _decodeSnapshot(s);
    } catch (_) {
      // A damaged cache must not discard the independently validated credential.
      _snapshot = null;
    }
    _loaded = true;
    notifyListeners();
  }

  /// Validates, fetches, parses and stores a new subscription. Returns the parse result.
  Future<SubscriptionSnapshot> importFromUrl(String rawUrl) async {
    final url = _policy.validate(rawUrl);
    if (url == null) throw SubscriptionFetchException('url_not_allowed');
    final snap = await _fetchAndParse(url);
    if (snap.profiles.isEmpty) throw SubscriptionFetchException('no_profiles');
    _url = url;
    _snapshot = snap;
    _lastError = null;
    await _store.write(_kUrl, url.toString());
    await _store.write(_kSnapshot, _encodeSnapshot(snap));
    notifyListeners();
    return snap;
  }

  /// Imports share links pasted directly (kal2://, vless://, ss://…): the text is
  /// parsed in place without a fetch, so there is no source URL to refresh against.
  Future<SubscriptionSnapshot> importFromText(String rawText) async {
    final result = _parser.parse(rawText);
    final snap = SubscriptionSnapshot(
      profiles: result.profiles,
      updatedAt: DateTime.now().toUtc(),
      totalEntries: result.receivedEntryCount,
      malformedEntries: result.malformedEntryCount,
      duplicateEntries: result.droppedDuplicateCount,
      expiresAt: result.expiresAt,
    );
    if (snap.profiles.isEmpty) throw SubscriptionFetchException('no_profiles');
    _url = null;
    _snapshot = snap;
    _lastError = null;
    await _store.delete(_kUrl);
    await _store.write(_kSnapshot, _encodeSnapshot(snap));
    notifyListeners();
    return snap;
  }

  Future<SubscriptionSnapshot?> refresh() async {
    final url = _url;
    if (url == null) return null;
    try {
      final snap = await _fetchAndParse(url);
      if (snap.profiles.isNotEmpty) {
        _snapshot = snap;
        await _store.write(_kSnapshot, _encodeSnapshot(snap));
      }
      _lastError = null;
      notifyListeners();
      return snap;
    } on SubscriptionFetchException catch (e) {
      _lastError = e.errorClass;
      notifyListeners();
      rethrow;
    }
  }

  Future<void> remove() async {
    _url = null;
    _snapshot = null;
    _lastError = null;
    await _store.delete(_kUrl);
    await _store.delete(_kSnapshot);
    notifyListeners();
  }

  Future<SubscriptionSnapshot> _fetchAndParse(Uri url) async {
    final fetched = await _fetcher.fetch(url);
    final result = _parser.parse(fetched.body, headers: fetched.headers);
    return SubscriptionSnapshot(
      profiles: result.profiles,
      updatedAt: DateTime.now().toUtc(),
      totalEntries: result.receivedEntryCount,
      malformedEntries: result.malformedEntryCount,
      duplicateEntries: result.droppedDuplicateCount,
      expiresAt: result.expiresAt,
    );
  }

  // ---------------------------------------------------------------- (de)serialisation

  static String _encodeSnapshot(SubscriptionSnapshot s) => jsonEncode({
    'schemaVersion': SubscriptionSnapshot.currentSchemaVersion,
    'receivedEntryCount': s.receivedEntryCount,
    'parsedProfileCount': s.parsedProfileCount,
    'postDedupeProfileCount': s.postDedupeProfileCount,
    'droppedDuplicateCount': s.droppedDuplicateCount,
    'malformedEntryCount': s.malformedEntryCount,
    'updatedAt': s.updatedAt.toIso8601String(),
    // Legacy aliases are retained so an older app can still read a newly written snapshot.
    'total': s.totalEntries,
    'malformed': s.malformedEntries,
    'duplicates': s.duplicateEntries,
    'expiresAt': s.expiresAt?.toIso8601String(),
    'profiles': s.profiles.map(_profileToJson).toList(),
  });

  static SubscriptionSnapshot _decodeSnapshot(String raw) {
    final m = jsonDecode(raw) as Map<String, dynamic>;
    final profiles = (m['profiles'] as List<dynamic>? ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(_profileFromJson)
        .whereType<VpnProfile>()
        .toList();

    final schemaVersion = _nonNegativeInt(m['schemaVersion']) ?? 0;
    final received = _nonNegativeInt(m['receivedEntryCount']);
    final parsed = _nonNegativeInt(m['parsedProfileCount']);
    final postDedupe = _nonNegativeInt(m['postDedupeProfileCount']);
    final dropped = _nonNegativeInt(m['droppedDuplicateCount']);
    final malformed = _nonNegativeInt(m['malformedEntryCount']);

    final countsTrusted =
        schemaVersion == SubscriptionSnapshot.currentSchemaVersion &&
        received != null &&
        parsed != null &&
        postDedupe != null &&
        dropped != null &&
        malformed != null &&
        postDedupe == profiles.length &&
        parsed == postDedupe + dropped &&
        received == parsed + malformed;

    return SubscriptionSnapshot(
      updatedAt:
          DateTime.tryParse(m['updatedAt'] as String? ?? '') ??
          DateTime.now().toUtc(),
      totalEntries: received ?? _nonNegativeInt(m['total']) ?? 0,
      malformedEntries: malformed ?? _nonNegativeInt(m['malformed']) ?? 0,
      duplicateEntries: dropped ?? _nonNegativeInt(m['duplicates']) ?? 0,
      expiresAt: m['expiresAt'] == null
          ? null
          : DateTime.tryParse(m['expiresAt'] as String),
      profiles: profiles,
      schemaVersion: schemaVersion,
      countsTrusted: countsTrusted,
    );
  }

  static int? _nonNegativeInt(Object? value) {
    if (value is! num || !value.isFinite) return null;
    final integer = value.toInt();
    if (integer < 0 || value != integer) return null;
    return integer;
  }

  static Map<String, Object?> _profileToJson(VpnProfile p) => {
    'id': p.id,
    'protocol': p.protocol,
    'address': p.address,
    'port': p.port,
    'secret': p.secret,
    'remark': p.remark,
    'network': p.network,
    'security': p.security,
    'sni': p.sni,
    'fingerprint': p.fingerprint,
    'publicKey': p.publicKey,
    'shortId': p.shortId,
    'spiderX': p.spiderX,
    'flow': p.flow,
    'host': p.host,
    'path': p.path,
    'xhttpMode': p.xhttpMode,
    'alpn': p.alpn,
    'allowInsecure': p.allowInsecure,
    'obfsPassword': p.obfsPassword,
    'alterId': p.alterId,
    'cipher': p.cipher,
    'plugin': p.plugin,
  };

  static VpnProfile? _profileFromJson(Map<String, dynamic> m) {
    try {
      String? s(String k) => m[k] as String?;
      return VpnProfile(
        id: s('id')!,
        protocol: s('protocol')!,
        address: s('address')!,
        port: (m['port'] as num).toInt(),
        secret: s('secret') ?? '',
        remark: s('remark') ?? '',
        network: s('network') ?? 'tcp',
        security: s('security') ?? 'none',
        sni: s('sni'),
        fingerprint: s('fingerprint'),
        publicKey: s('publicKey'),
        shortId: s('shortId'),
        spiderX: s('spiderX'),
        flow: s('flow'),
        host: s('host'),
        path: s('path'),
        xhttpMode: s('xhttpMode'),
        alpn: s('alpn'),
        allowInsecure: m['allowInsecure'] == true,
        obfsPassword: s('obfsPassword'),
        alterId: (m['alterId'] as num?)?.toInt() ?? 0,
        cipher: s('cipher'),
        plugin: s('plugin'),
      );
    } catch (_) {
      return null;
    }
  }
}
