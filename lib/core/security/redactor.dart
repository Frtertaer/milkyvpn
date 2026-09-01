/// Redacts credential-looking material from arbitrary strings (errors, diagnostics).
class Redactor {
  const Redactor();

  static final _uuid = RegExp(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');
  static final _subToken = RegExp(r'(sub\.milky\.homes/s/)[A-Za-z0-9_\-]+');
  static final _userInfo = RegExp(r'([a-z0-9]+)://[^@\s/]+@', caseSensitive: false);
  static final _queryCred = RegExp(r'([?&](pbk|sid|password|obfs-password|auth|token|url)=)[^&\s#]+', caseSensitive: false);
  static final _bearer = RegExp(r'(Bearer\s+)[A-Za-z0-9._\-]+', caseSensitive: false);
  static final _longBase64 = RegExp(r'[A-Za-z0-9+/_\-]{40,}={0,2}');

  String redact(String? input) {
    if (input == null) return '';
    var s = input;
    s = s.replaceAll(_uuid, '<uuid>');
    s = s.replaceAllMapped(_subToken, (m) => '${m[1]}<token>');
    s = s.replaceAllMapped(_userInfo, (m) => '${m[1]}://<cred>@');
    s = s.replaceAllMapped(_queryCred, (m) => '${m[1]}<redacted>');
    s = s.replaceAllMapped(_bearer, (m) => '${m[1]}<redacted>');
    s = s.replaceAll(_longBase64, '<blob>');
    return s;
  }

  /// Turns any exception into a short, credential-free error class for the UI/diagnostics.
  String errorClass(Object? error) {
    if (error == null) return 'unknown';
    final text = redact(error.toString()).toLowerCase();
    if (text.contains('timeout') || text.contains('timed out')) return 'timeout';
    if (text.contains('refused')) return 'connection_refused';
    if (text.contains('unreachable') || text.contains('no route') || text.contains('network is')) {
      return 'network_unreachable';
    }
    if (text.contains('handshake') || text.contains('certificate') || text.contains('tls')) return 'tls_handshake';
    if (text.contains('socket') || text.contains('failed host lookup')) return 'network_error';
    if (text.contains('permission')) return 'permission_denied';
    if (text.contains('format') || text.contains('parse')) return 'format_error';
    final type = error.runtimeType.toString().replaceAll(RegExp(r'[^A-Za-z0-9_]'), '_');
    return type.length > 40 ? type.substring(0, 40) : type;
  }
}
