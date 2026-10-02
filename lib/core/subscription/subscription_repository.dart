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

  // Legacy single-source keys are read once for migration, then deleted.
  static const _kUrl = 'subscription_url';
  static const _kSnapshot = 'subscription_snapshot';
  // Multi-source: ordered URL list + per-source parsed snapshots keyed by URL.
  static const _kUrls = 'subscription_urls';
  static const _kSnaps = 'subscription_snapshots';
  static const _kTextSnap = 'subscription_text_snapshot';

  final SecureStore _store;
  final SubscriptionFetcher _fetcher;
  final SubscriptionParser _parser;
  final SubscriptionUrlPolicy _policy;

  bool _loaded = false;
  List<Uri> _urls = const [];
  Map<String, SubscriptionSnapshot> _snaps = const {};
  SubscriptionSnapshot? _textSnapshot;
  String? _lastError;

  bool get isLoaded => _loaded;

  /// Either fetched subscriptions (has URLs) or a text-imported profile set
  /// (snapshot only, nothing to refresh).
  bool get hasSubscription =>
      _urls.isNotEmpty || (_merged()?.profiles.isNotEmpty ?? false);
  SubscriptionSnapshot? get snapshot => _merged();
  String? get lastErrorClass => _lastError;

  /// Whether the currently loaded count snapshot passed schema and invariant checks.
  bool get countsTrusted => _merged()?.countsTrusted ?? false;

  /// A refresh is useful only when a subscription credential exists and counts are absent
  /// or untrusted. Loading never performs network I/O implicitly.
  bool get needsRefresh => _urls.isNotEmpty && !countsTrusted;

  /// Redacted source URLs for UI. Never exposes tokens.
  List<String> get redactedUrls =>
      _urls.map(SubscriptionUrlPolicy.redact).toList();

  /// Redacted for UI — the first source. Never exposes the token.
  String? get redactedUrl =>
      _urls.isEmpty ? null : SubscriptionUrlPolicy.redact(_urls.first);

  /// Full subscription URL, exposed ONLY for the explicit "copy link" advanced action.
  /// Never render this on normal screens.
  String? get urlForCopy => _urls.isEmpty ? null : _urls.first.toString();

  /// Full URLs for the per-source management rows (remove/copy by the user only).
  List<Uri> get sourceUrls => List.unmodifiable(_urls);

  /// Union of per-source profiles, deduped by profile id, counts summed.
  SubscriptionSnapshot? _merged() {
    final all = <VpnProfile>[];
    final seen = <String>{};
    var received = 0, malformed = 0, dropped = 0;
    var trusted = true;
    DateTime? updatedAt;
    DateTime? expiresAt;
    var any = false;
    for (final s in [
      ..._urls.map((u) => _snaps[u.toString()]),
      _textSnapshot,
    ]) {
      if (s == null) continue;
      any = true;
      trusted = trusted && s.countsTrusted;
      received += s.receivedEntryCount;
      malformed += s.malformedEntryCount;
      dropped += s.droppedDuplicateCount;
      for (final p in s.profiles) {
        if (seen.add(p.id)) all.add(p);
      }
      if (updatedAt == null || s.updatedAt.isBefore(updatedAt)) {
        updatedAt = s.updatedAt;
      }
      if (s.expiresAt != null &&
          (expiresAt == null || s.expiresAt!.isBefore(expiresAt))) {
        expiresAt = s.expiresAt;
      }
    }
    if (!any) return null;
    return SubscriptionSnapshot(
      profiles: all,
      updatedAt: updatedAt ?? DateTime.now().toUtc(),
      totalEntries: received,
      malformedEntries: malformed,
      duplicateEntries: dropped,
      expiresAt: expiresAt,
      countsTrusted: trusted,
    );
  }

  Future<void> load() async {
    try {
      final raw = await _store.read(_kUrls);
      if (raw != null) {
        _urls = (jsonDecode(raw) as List<dynamic>)
            .whereType<String>()
            .map(_policy.validate)
            .whereType<Uri>()
            .toList();
      } else {
        // Migration: a single legacy URL becomes the first source.
        final u = await _store.read(_kUrl);
        if (u != null) {
          final url = _policy.validate(u);
          if (url != null) _urls = [url];
          await _store.delete(_kUrl);
        }
      }
    } catch (_) {
      _urls = const [];
    }
    try {
      final raw = await _store.read(_kSnaps);
      if (raw != null) {
        _snaps = {
          for (final e in (jsonDecode(raw) as Map<String, dynamic>).entries)
            e.key: _decodeSnapshot(e.value as String),
        };
      } else {
        final s = await _store.read(_kSnapshot);
        if (s != null && _urls.isNotEmpty) {
          _snaps = {_urls.first.toString(): _decodeSnapshot(s)};
        }
        await _store.delete(_kSnapshot);
      }
    } catch (_) {
      // A damaged cache must not discard the independently validated credentials.
      _snaps = const {};
    }
    try {
      final t = await _store.read(_kTextSnap);
      if (t != null) _textSnapshot = _decodeSnapshot(t);
    } catch (_) {
      _textSnapshot = null;
    }
    _loaded = true;
    notifyListeners();
  }

  /// Adds a new subscription source (or re-imports an existing one), fetches
  /// and parses it, and stores its snapshot. Other sources are untouched.
  Future<SubscriptionSnapshot> importFromUrl(String rawUrl) async {
    final url = _policy.validate(rawUrl);
    if (url == null) throw SubscriptionFetchException('url_not_allowed');
    final snap = await _fetchAndParse(url);
    if (snap.profiles.isEmpty) throw SubscriptionFetchException('no_profiles');
    if (!_urls.contains(url)) _urls = [..._urls, url];
    _snaps = {..._snaps, url.toString(): snap};
    _textSnapshot = null;
    _lastError = null;
    await _persistSources();
    notifyListeners();
    return snap;
  }

  /// Imports share links pasted directly (kal2://, vless://, ss://…): the text is
  /// parsed in place without a fetch, so there is no source URL to refresh
  /// against. Replaces any previous text-imported set; URL sources are kept.
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
    _textSnapshot = snap;
    _lastError = null;
    await _store.write(_kTextSnap, _encodeSnapshot(snap));
    notifyListeners();
    return snap;
  }

  /// Removes one subscription source and its cached profiles.
  Future<void> removeUrl(String url) async {
    _urls = _urls.where((u) => u.toString() != url).toList();
    _snaps = {..._snaps}..remove(url);
    await _persistSources();
    notifyListeners();
  }

  /// Re-fetches every source; a source that fails keeps its last good snapshot.
  Future<SubscriptionSnapshot?> refresh() async {
    if (_urls.isEmpty) return null;
    Object? firstError;
    for (final url in List<Uri>.of(_urls)) {
      try {
        final snap = await _fetchAndParse(url);
        if (snap.profiles.isNotEmpty) {
          _snaps = {..._snaps, url.toString(): snap};
        }
      } on SubscriptionFetchException catch (e) {
        firstError ??= e;
      }
    }
    await _persistSources();
    _lastError = firstError is SubscriptionFetchException
        ? firstError.errorClass
        : null;
    notifyListeners();
    if (firstError is SubscriptionFetchException) throw firstError;
    return _merged();
  }

  Future<void> remove() async {
    _urls = const [];
    _snaps = const {};
    _textSnapshot = null;
    _lastError = null;
    await _store.delete(_kUrls);
    await _store.delete(_kSnaps);
    await _store.delete(_kTextSnap);
    await _store.delete(_kUrl);
    await _store.delete(_kSnapshot);
    notifyListeners();
  }

  Future<void> _persistSources() async {
    await _store.write(
      _kUrls,
      jsonEncode(_urls.map((u) => u.toString()).toList()),
    );
    await _store.write(
      _kSnaps,
      jsonEncode({
        for (final e in _snaps.entries) e.key: _encodeSnapshot(e.value),
      }),
    );
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
    'ech': p.ech,
    'cover': p.cover,
    'pin': p.pin,
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
    'altAddrs': p.altAddrs,
    'front': p.front,
    'fronts': p.fronts,
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
        ech: s('ech'),
        cover: s('cover'),
        pin: s('pin'),
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
        altAddrs: s('altAddrs'),
        front: s('front'),
        fronts: (m['fronts'] as List?)?.map((e) => e.toString()).toList(),
      );
    } catch (_) {
      return null;
    }
  }
}
