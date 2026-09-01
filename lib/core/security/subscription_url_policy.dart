/// Strict allowlist for subscription URLs and deep links.
///
/// Only `https://sub.milky.homes/s/{token}` is accepted. Everything else (http, other hosts,
/// localhost, private IPs, file:, javascript:, userinfo tricks, path traversal) is rejected.
class SubscriptionUrlPolicy {
  const SubscriptionUrlPolicy();

  static const allowedHost = 'sub.milky.homes';
  static const allowedPathPrefix = '/s/';
  static final _tokenRe = RegExp(r'^[A-Za-z0-9_\-]{8,128}$');

  /// Returns the normalized URL when it is allowed, otherwise `null`.
  Uri? validate(String raw) {
    final s = raw.trim();
    if (s.isEmpty || s.length > 512) return null;
    // Refuse control chars / whitespace inside.
    if (RegExp(r'[\s\x00-\x1f\x7f]').hasMatch(s)) return null;
    final Uri u;
    try {
      u = Uri.parse(s);
    } on FormatException {
      return null;
    }
    if (u.scheme.toLowerCase() != 'https') return null;
    if (u.userInfo.isNotEmpty) return null;
    if (u.host.toLowerCase() != allowedHost) return null;
    if (u.hasPort && u.port != 443) return null;
    if (u.hasFragment) return null;
    if (u.hasQuery) return null;
    final path = u.path;
    if (!path.startsWith(allowedPathPrefix)) return null;
    final token = path.substring(allowedPathPrefix.length);
    if (token.contains('/') || token.contains('.') || !_tokenRe.hasMatch(token)) return null;
    return Uri(scheme: 'https', host: allowedHost, path: '$allowedPathPrefix$token');
  }

  bool isAllowed(String raw) => validate(raw) != null;

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

  /// Human-safe representation: never shows the token.
  static String redact(Uri u) => '${u.scheme}://${u.host}/s/••••••';
}
