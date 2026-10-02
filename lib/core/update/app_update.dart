import 'dart:convert';
import 'dart:io';

/// One release asset the app can self-update with. [altUrl] is the mirror
/// fallback used when the primary download itself is blocked/throttled.
class ReleaseAsset {
  const ReleaseAsset({required this.name, required this.url, this.altUrl});
  final String name;
  final String url;
  final String? altUrl;
}

/// A semver-tagged GitHub release (test/manual tags are skipped — only
/// `vX.Y.Z` counts as an update source).
class AppRelease {
  const AppRelease({required this.tag, required this.assets});
  final String tag;
  final List<ReleaseAsset> assets;
}

class AppUpdate {
  AppUpdate._();

  static const repo = 'Frtertaer/milkyvpn';
  static const _api = 'https://api.github.com/repos/$repo/releases?per_page=10';

  /// Release mirror on the panel box — a cron-synced copy of the latest
  /// release reachable even when github.com is throttled for the user.
  static const _mirror = 'https://panel.mergescribe.dev/releases';

  /// Latest semver release, or null when the API is unreachable / nothing
  /// semver-tagged has been published yet. Never throws. GitHub first, then
  /// the panel mirror as fallback.
  static Future<AppRelease?> latest() async {
    return await _latestGithub() ?? await _latestMirror();
  }

  static Future<AppRelease?> _latestGithub() async {
    try {
      final http = HttpClient()..connectionTimeout = const Duration(seconds: 8);
      try {
        final req = await http.getUrl(Uri.parse(_api));
        req.headers.set(HttpHeaders.userAgentHeader, 'milkyvpn-app');
        req.headers.set(HttpHeaders.acceptHeader, 'application/vnd.github+json');
        final res = await req.close().timeout(const Duration(seconds: 10));
        if (res.statusCode != 200) return null;
        final body = await res.transform(utf8.decoder).join();
        final list = jsonDecode(body);
        if (list is! List) return null;
        for (final r in list) {
          if (r is! Map) continue;
          final tag = (r['tag_name'] ?? '').toString();
          if (!isSemverTag(tag)) continue;
          if (r['draft'] == true || r['prerelease'] == true) continue;
          final assets = <ReleaseAsset>[
            for (final a in (r['assets'] as List? ?? const []))
              if (a is Map)
                ReleaseAsset(
                  name: (a['name'] ?? '').toString(),
                  url: (a['browser_download_url'] ?? '').toString(),
                  altUrl: '$_mirror/${Uri.encodeComponent(tag)}/${a['name']}',
                ),
          ];
          return AppRelease(tag: tag, assets: assets);
        }
        return null;
      } finally {
        http.close(force: true);
      }
    } on Object {
      return null;
    }
  }

  /// Mirror manifest written by deploy/release-mirror.sh:
  /// {"tag":"vX.Y.Z","assets":[{"name":..,"url":"/releases/<tag>/<name>"}]}.
  static Future<AppRelease?> _latestMirror() async {
    try {
      final http = HttpClient()..connectionTimeout = const Duration(seconds: 8);
      try {
        final req = await http.getUrl(Uri.parse('$_mirror/latest.json'));
        req.headers.set(HttpHeaders.userAgentHeader, 'milkyvpn-app');
        final res = await req.close().timeout(const Duration(seconds: 10));
        if (res.statusCode != 200) return null;
        final m = jsonDecode(await res.transform(utf8.decoder).join());
        if (m is! Map) return null;
        final tag = (m['tag'] ?? '').toString();
        if (!isSemverTag(tag)) return null;
        final assets = <ReleaseAsset>[
          for (final a in (m['assets'] as List? ?? const []))
            if (a is Map)
              ReleaseAsset(
                name: (a['name'] ?? '').toString(),
                url: '$_mirror/${Uri.encodeComponent(tag)}/${a['name']}',
              ),
        ];
        return AppRelease(tag: tag, assets: assets);
      } finally {
        http.close(force: true);
      }
    } on Object {
      return null;
    }
  }

  static bool isSemverTag(String tag) =>
      RegExp(r'^v\d+\.\d+\.\d+$').hasMatch(tag);

  /// Strict semver triple compare; returns >0 when [a] is newer. Tags that
  /// aren't `vX.Y.Z` compare as (0,0,0) — never an update.
  static int compareVersion(String a, String b) {
    List<int> parse(String t) {
      final v = t.startsWith('v') ? t.substring(1) : t;
      final parts = v.split('.');
      if (parts.length != 3) return const [0, 0, 0];
      final nums = parts.map(int.tryParse).toList();
      if (nums.any((n) => n == null)) return const [0, 0, 0];
      return nums.cast<int>();
    }

    final pa = parse(a);
    final pb = parse(b);
    for (var i = 0; i < 3; i++) {
      final d = pa[i].compareTo(pb[i]);
      if (d != 0) return d;
    }
    return 0;
  }

  /// Picks the installable asset for this platform. Android matches the
  /// device ABI (arm64→arm64, armv7→armeabi-v7a, x86_64→x86_64); Windows
  /// takes the Inno Setup installer; other platforms get null (no release
  /// artifacts exist for them today).
  static ReleaseAsset? pickAsset(
    AppRelease release, {
    required bool isAndroid,
    required bool isWindows,
    String abi = '',
  }) {
    if (isAndroid) {
      final want = abi.toLowerCase();
      final Map<String, List<String>> aliases = {
        'arm64-v8a': ['arm64-v8a'],
        'armeabi-v7a': ['armeabi-v7a'],
        'armeabi': ['armeabi-v7a'],
        'x86_64': ['x86_64'],
        'x86': ['x86_64'],
      };
      final keys = aliases[want] ?? const ['arm64-v8a', 'armeabi-v7a'];
      for (final key in keys) {
        for (final a in release.assets) {
          if (a.name.toLowerCase().contains(key) && a.name.endsWith('.apk')) {
            return a;
          }
        }
      }
      // ABI unknown — prefer arm64, the dominant Android target.
      for (final a in release.assets) {
        if (a.name.contains('arm64-v8a') && a.name.endsWith('.apk')) return a;
      }
      return null;
    }
    if (isWindows) {
      for (final a in release.assets) {
        if (a.name.endsWith('.exe')) return a;
      }
    }
    return null;
  }

  /// Downloads [asset] to [destPath], reporting 0..1 progress. Falls back
  /// to [ReleaseAsset.altUrl] (mirror) once the primary URL fails.
  static Future<void> download(
    ReleaseAsset asset,
    String destPath, {
    void Function(double progress)? onProgress,
  }) async {
    try {
      await _fetch(asset.url, destPath, onProgress: onProgress);
      return;
    } on Object {
      if (asset.altUrl == null) rethrow;
    }
    await _fetch(asset.altUrl!, destPath, onProgress: onProgress);
  }

  static Future<void> _fetch(
    String url,
    String destPath, {
    void Function(double progress)? onProgress,
  }) async {
    final http = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      final req = await http.getUrl(Uri.parse(url));
      req.headers.set(HttpHeaders.userAgentHeader, 'milkyvpn-app');
      final res = await req.close();
      if (res.statusCode != 200) {
        throw HttpException('download ${res.statusCode}', uri: Uri.parse(url));
      }
      final total = res.contentLength;
      final sink = File(destPath).openWrite();
      var got = 0;
      try {
        await for (final chunk in res) {
          sink.add(chunk);
          got += chunk.length;
          if (total > 0) onProgress?.call(got / total);
        }
      } finally {
        await sink.close();
      }
    } finally {
      http.close(force: true);
    }
  }
}
