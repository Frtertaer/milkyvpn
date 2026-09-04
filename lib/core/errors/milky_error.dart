/// Human-facing error model.
///
/// **Rule:** a technical code (`proxyerror`, `S`, `tls_handshake`, …) is never shown to a
/// customer. It is mapped to [MilkyErrorKind], which the UI renders as a short Russian
/// sentence, and to a stable [diagnosticsCode] that appears only on the Diagnostics screen.
library;

/// What the user is told. Deliberately few: users do not care about the failure taxonomy,
/// only about what to do next.
enum MilkyErrorKind {
  /// Android did not grant the VPN permission (or it was revoked).
  permissionDenied,

  /// The device itself has no usable network.
  noInternet,

  /// A server was reached but refused / timed out / failed the handshake.
  serverUnreachable,

  /// The tunnel could not be established (core, TUN, verification).
  tunnelFailed,

  /// No server from the subscription can be used.
  noServers,

  /// The subscription itself is missing, expired or unreadable.
  subscriptionProblem,

  /// The user cancelled the attempt. Not an error to surface.
  cancelled,

  /// Anything unmapped — still gets a calm, actionable message.
  unknown,
}

/// Failure taxonomy for Diagnostics only. Never rendered on a normal screen.
enum MilkyFailureCategory {
  emulatorFailure,
  realDeviceFailure,
  coreFailure,
  configFailure,
  permissionFailure,
  networkFailure,
  subscriptionFailure,
  none,
}

extension MilkyFailureCategoryX on MilkyFailureCategory {
  /// Stable, copy-pasteable token for the diagnostics report.
  String get diagnosticsToken {
    switch (this) {
      case MilkyFailureCategory.emulatorFailure:
        return 'EMULATOR_FAILURE';
      case MilkyFailureCategory.realDeviceFailure:
        return 'REAL_DEVICE_FAILURE';
      case MilkyFailureCategory.coreFailure:
        return 'CORE_FAILURE';
      case MilkyFailureCategory.configFailure:
        return 'CONFIG_FAILURE';
      case MilkyFailureCategory.permissionFailure:
        return 'PERMISSION_FAILURE';
      case MilkyFailureCategory.networkFailure:
        return 'NETWORK_FAILURE';
      case MilkyFailureCategory.subscriptionFailure:
        return 'SUBSCRIPTION_FAILURE';
      case MilkyFailureCategory.none:
        return 'NONE';
    }
  }
}

/// Which action buttons a failure sheet should offer.
enum MilkyErrorAction { retry, chooseServer, diagnostics, addSubscription, openVpnSettings, dismiss }

/// A resolved, user-safe error.
class MilkyError {
  const MilkyError({
    required this.kind,
    required this.diagnosticsCode,
    required this.category,
    this.rawCode,
  });

  final MilkyErrorKind kind;

  /// STABLE_UPPER_SNAKE token, e.g. `VPN_CORE_START_FAILED`.
  final String diagnosticsCode;

  /// Device-independent category. Refined by [withDeviceContext].
  final MilkyFailureCategory category;

  /// The original code as produced by Dart/Kotlin. Diagnostics only.
  final String? rawCode;

  bool get isCancelled => kind == MilkyErrorKind.cancelled;

  /// Actions shown in the failure sheet, in order.
  List<MilkyErrorAction> get actions {
    switch (kind) {
      case MilkyErrorKind.permissionDenied:
        return const [MilkyErrorAction.retry, MilkyErrorAction.openVpnSettings, MilkyErrorAction.diagnostics];
      case MilkyErrorKind.subscriptionProblem:
        return const [MilkyErrorAction.retry, MilkyErrorAction.addSubscription, MilkyErrorAction.diagnostics];
      case MilkyErrorKind.noServers:
        return const [MilkyErrorAction.addSubscription, MilkyErrorAction.diagnostics];
      case MilkyErrorKind.cancelled:
        return const [MilkyErrorAction.dismiss];
      default:
        return const [MilkyErrorAction.retry, MilkyErrorAction.chooseServer, MilkyErrorAction.diagnostics];
    }
  }

  /// TUN establishment and core startup are exactly what emulators get wrong, so the
  /// category is refined once we know what device we are on.
  MilkyError withDeviceContext({required bool isEmulator}) {
    if (category != MilkyFailureCategory.realDeviceFailure && category != MilkyFailureCategory.emulatorFailure) {
      return this;
    }
    return MilkyError(
      kind: kind,
      diagnosticsCode: diagnosticsCode,
      category: isEmulator ? MilkyFailureCategory.emulatorFailure : MilkyFailureCategory.realDeviceFailure,
      rawCode: rawCode,
    );
  }

  /// Maps any code — including raw JVM class names leaked by the native layer such as
  /// `proxyerror` or an R8-shortened `S` — onto a human error.
  static MilkyError fromCode(String? code) {
    final raw = (code ?? '').trim();
    if (raw.isEmpty) return const MilkyError(kind: MilkyErrorKind.unknown, diagnosticsCode: 'NO_ERROR_REPORTED', category: MilkyFailureCategory.none);

    final known = _table[raw.toLowerCase()];
    if (known != null) {
      return MilkyError(kind: known.$1, diagnosticsCode: known.$2, category: known.$3, rawCode: raw);
    }

    // HTTP status codes from the subscription fetcher: `http_404`, `http_503`, …
    final http = RegExp(r'^http_(\d{3})$').firstMatch(raw.toLowerCase());
    if (http != null) {
      return MilkyError(
        kind: MilkyErrorKind.subscriptionProblem,
        diagnosticsCode: 'SUBSCRIPTION_HTTP_${http.group(1)}',
        category: MilkyFailureCategory.subscriptionFailure,
        rawCode: raw,
      );
    }

    // Anything else is an implementation detail: a Go proxy error, an obfuscated class
    // name, a platform exception code. Never surface it — bucket it as a core failure.
    return MilkyError(
      kind: MilkyErrorKind.tunnelFailed,
      diagnosticsCode: 'VPN_CORE_START_FAILED',
      category: MilkyFailureCategory.coreFailure,
      rawCode: raw,
    );
  }

  /// Every raw code this mapper recognises. Exposed for tests and for diagnostics tooling.
  static List<String> get knownRawCodes => _table.keys.toList(growable: false);

  static const Map<String, (MilkyErrorKind, String, MilkyFailureCategory)> _table = {
    // --- permission -------------------------------------------------------
    'vpn_permission_denied': (MilkyErrorKind.permissionDenied, 'VPN_PERMISSION_DENIED', MilkyFailureCategory.permissionFailure),
    'vpn_permission_missing': (MilkyErrorKind.permissionDenied, 'VPN_PERMISSION_MISSING', MilkyFailureCategory.permissionFailure),
    'permission_denied': (MilkyErrorKind.permissionDenied, 'PERMISSION_DENIED', MilkyFailureCategory.permissionFailure),
    'permission': (MilkyErrorKind.permissionDenied, 'VPN_PERMISSION_DENIED', MilkyFailureCategory.permissionFailure),
    'revoked_by_system': (MilkyErrorKind.permissionDenied, 'VPN_REVOKED_BY_SYSTEM', MilkyFailureCategory.permissionFailure),

    // --- no usable server -------------------------------------------------
    'no_compatible_profiles': (MilkyErrorKind.noServers, 'NO_COMPATIBLE_PROFILES', MilkyFailureCategory.configFailure),
    'no_profile': (MilkyErrorKind.noServers, 'NO_ACTIVE_PROFILE', MilkyFailureCategory.configFailure),
    'unsupported_profile': (MilkyErrorKind.noServers, 'PROFILE_UNSUPPORTED', MilkyFailureCategory.configFailure),
    'unsupported': (MilkyErrorKind.noServers, 'PROFILE_UNSUPPORTED', MilkyFailureCategory.configFailure),
    'unsupported_platform': (MilkyErrorKind.noServers, 'PLATFORM_UNSUPPORTED', MilkyFailureCategory.configFailure),

    // --- subscription -----------------------------------------------------
    'no_profiles': (MilkyErrorKind.subscriptionProblem, 'SUBSCRIPTION_EMPTY', MilkyFailureCategory.subscriptionFailure),
    'url_not_allowed': (MilkyErrorKind.subscriptionProblem, 'SUBSCRIPTION_URL_REJECTED', MilkyFailureCategory.subscriptionFailure),
    'subscription_not_found': (MilkyErrorKind.subscriptionProblem, 'SUBSCRIPTION_NOT_FOUND', MilkyFailureCategory.subscriptionFailure),
    'body_too_large': (MilkyErrorKind.subscriptionProblem, 'SUBSCRIPTION_TOO_LARGE', MilkyFailureCategory.subscriptionFailure),
    'format_error': (MilkyErrorKind.subscriptionProblem, 'SUBSCRIPTION_PARSE_FAILED', MilkyFailureCategory.subscriptionFailure),
    'no_subscription': (MilkyErrorKind.subscriptionProblem, 'SUBSCRIPTION_MISSING', MilkyFailureCategory.subscriptionFailure),

    // --- network ----------------------------------------------------------
    'timeout': (MilkyErrorKind.serverUnreachable, 'SERVER_TIMEOUT', MilkyFailureCategory.networkFailure),
    'connection_refused': (MilkyErrorKind.serverUnreachable, 'SERVER_REFUSED', MilkyFailureCategory.networkFailure),
    'network_unreachable': (MilkyErrorKind.noInternet, 'NETWORK_UNAVAILABLE', MilkyFailureCategory.networkFailure),
    'network_error': (MilkyErrorKind.noInternet, 'NETWORK_ERROR', MilkyFailureCategory.networkFailure),
    'dns_failure': (MilkyErrorKind.noInternet, 'DNS_FAILURE', MilkyFailureCategory.networkFailure),
    'offline': (MilkyErrorKind.noInternet, 'OFFLINE', MilkyFailureCategory.networkFailure),

    // --- tunnel / core ----------------------------------------------------
    'tls_handshake': (MilkyErrorKind.serverUnreachable, 'TLS_HANDSHAKE_FAILED', MilkyFailureCategory.coreFailure),
    'reality_handshake': (MilkyErrorKind.serverUnreachable, 'TLS_HANDSHAKE_FAILED', MilkyFailureCategory.coreFailure),
    'tun_establish_failed': (MilkyErrorKind.tunnelFailed, 'TUN_ESTABLISH_FAILED', MilkyFailureCategory.realDeviceFailure),
    'tunnel_unverified': (MilkyErrorKind.tunnelFailed, 'TUNNEL_NOT_VERIFIED', MilkyFailureCategory.realDeviceFailure),
    'core_start_failed': (MilkyErrorKind.tunnelFailed, 'VPN_CORE_START_FAILED', MilkyFailureCategory.coreFailure),
    'core_failure': (MilkyErrorKind.tunnelFailed, 'VPN_CORE_START_FAILED', MilkyFailureCategory.coreFailure),
    'config_invalid': (MilkyErrorKind.tunnelFailed, 'VPN_CONFIG_INVALID', MilkyFailureCategory.configFailure),
    'proxyerror': (MilkyErrorKind.tunnelFailed, 'VPN_CORE_START_FAILED', MilkyFailureCategory.coreFailure),
    'bridge_error': (MilkyErrorKind.tunnelFailed, 'BRIDGE_ERROR', MilkyFailureCategory.coreFailure),
    'bridge_failure': (MilkyErrorKind.tunnelFailed, 'BRIDGE_ERROR', MilkyFailureCategory.coreFailure),
    'connect_failed': (MilkyErrorKind.serverUnreachable, 'SERVER_CONNECT_FAILED', MilkyFailureCategory.coreFailure),
    'all_attempts_failed': (MilkyErrorKind.serverUnreachable, 'ALL_SERVERS_FAILED', MilkyFailureCategory.coreFailure),
    'busy': (MilkyErrorKind.unknown, 'BUSY', MilkyFailureCategory.none),

    // --- user ------------------------------------------------------------
    'cancelled': (MilkyErrorKind.cancelled, 'CANCELLED_BY_USER', MilkyFailureCategory.none),
  };
}
