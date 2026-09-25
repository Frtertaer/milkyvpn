/// URL policy for subscription URLs and deep links.
///
/// Any `http(s)` subscription URL is accepted so users can import third-party feeds.
/// The SSRF guard stays: no userinfo, no fragments, no localhost/private/link-local/
/// reserved IP literals, no non-http schemes (file:, javascript:, etc.). Redirects are
/// still not followed by the fetcher, so the validated origin is the only one fetched.
///
/// Caveat: the guard inspects the URL literal only. A public hostname that resolves to a
/// private address cannot be detected here; the fetcher only issues a plain GET and
/// treats the response as subscription text, which bounds the impact.
class SubscriptionUrlPolicy {
  const SubscriptionUrlPolicy();

  /// Legacy canonical feed (still fully supported).
  static const canonicalHost = 'sub.milky.homes';

  static const int maxUrlLength = 2048;

  /// Returns the normalized URL when it is allowed, otherwise `null`.
  Uri? validate(String raw) {
    final s = raw.trim();
    if (s.isEmpty || s.length > maxUrlLength) return null;
    if (RegExp(r'[\s\x00-\x1f\x7f]').hasMatch(s)) return null;
    final Uri u;
    try {
      u = Uri.parse(s);
    } on FormatException {
      return null;
    }
    final scheme = u.scheme.toLowerCase();
    if (scheme != 'https' && scheme != 'http') return null;
    if (u.userInfo.isNotEmpty) return null;
    if (u.hasFragment) return null;
    final host = u.host.toLowerCase();
    if (host.isEmpty) return null;
    if (_isBlockedHost(host)) return null;
    if (u.hasPort && (u.port < 1 || u.port > 65535)) return null;
    return Uri(
      scheme: scheme,
      host: u.host,
      port: u.hasPort ? u.port : null,
      path: u.path,
      query: u.hasQuery ? u.query : null,
    );
  }

  bool isAllowed(String raw) => validate(raw) != null;

  /// localhost / private / link-local / reserved destinations the fetcher must never
  /// reach from the device.
  static bool _isBlockedHost(String host) {
    if (host == 'localhost' ||
        host.endsWith('.localhost') ||
        host.endsWith('.local') ||
        host.endsWith('.internal') ||
        host.endsWith('.lan') ||
        host.endsWith('.home')) {
      return true;
    }
    final v4 = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
        .firstMatch(host);
    if (v4 != null) {
      final a = int.parse(v4.group(1)!);
      final b = int.parse(v4.group(2)!);
      if (a > 255 || b > 255) return true;
      // 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24,
      // 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224+/4
      if (a == 0 || a == 10 || a == 127 || a >= 224) return true;
      if (a == 100 && b >= 64 && b <= 127) return true;
      if (a == 169 && b == 254) return true;
      if (a == 172 && b >= 16 && b <= 31) return true;
      if (a == 192 && b == 168) return true;
      if (a == 192 && b == 0) return true;
      if (a == 198 && (b == 18 || b == 19 || b == 51)) return true;
      if (a == 203 && b == 0) return true;
      return false;
    }
    if (host.contains(':')) {
      final h = host.replaceAll('[', '').replaceAll(']', '');
      final lower = h.toLowerCase();
      if (lower == '::1' || lower == '::') return true;
      if (lower.startsWith('fe8') ||
          lower.startsWith('fe9') ||
          lower.startsWith('fea') ||
          lower.startsWith('feb')) {
        return true; // fe80::/10 link-local
      }
      if (lower.startsWith('fc') || lower.startsWith('fd')) {
        return true; // fc00::/7 unique local
      }
      if (lower.startsWith('::ffff:')) return _isBlockedV4Mapped(lower);
      return false;
    }
    return false;
  }

  static bool _isBlockedV4Mapped(String h) {
    final tail = h.substring('::ffff:'.length);
    return _isBlockedHost(tail);
  }

  /// Extracts the subscription URL from a `milkyvpn://import?url=...` deep link.
  /// Returns null if the link is not ours or the embedded URL is not allowed.
  Uri? fromDeepLink(String raw) {
    final Uri link;
    try {
      link = Uri.parse(raw.trim());
    } on FormatException {
      return null;
    }
    if (link.scheme.toLowerCase() != 'milkyvpn') return null;
    if (link.host.toLowerCase() != 'import') return null;
    final url = link.queryParameters['url'];
    if (url == null) return null;
    return validate(url);
  }

  /// Human-safe representation: host is shown, the last path segment (the token) is
  /// masked. Never shows the credential part of a subscription link.
  static String redact(Uri u) {
    final segments = u.pathSegments.where((s) => s.isNotEmpty).toList();
    final tail = segments.isEmpty ? '' : '/••••••';
    final head = segments.length > 1
        ? '/${segments.sublist(0, segments.length - 1).join('/')}'
        : '';
    final port = u.hasPort && u.port != 80 && u.port != 443 ? ':${u.port}' : '';
    return '${u.scheme}://${u.host}$port$head$tail';
  }
}
