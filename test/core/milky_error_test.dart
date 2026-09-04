import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/errors/milky_error.dart';
import 'package:milkyvpn/l10n/milky_strings.dart';

void main() {
  const ru = S(Locale('ru'));
  const en = S(Locale('en'));

  group('MilkyError mapping', () {
    test('raw native class names never reach the user', () {
      for (final code in ['proxyerror', 'S', 'ProxyError', 'a', 'zz', 'SomeWeirdClass']) {
        final e = MilkyError.fromCode(code);
        expect(e.kind, MilkyErrorKind.tunnelFailed, reason: code);
        // The explicit Go wrapper maps to the core token; anything unrecognised becomes
        // the normalized UNKNOWN bucket. Neither ever shows the raw class name.
        expect(
          e.diagnosticsCode,
          code == 'proxyerror' ? 'VPN_CORE_START_FAILED' : 'UNKNOWN_CONNECTION_ERROR',
          reason: code,
        );
        for (final s in [ru, en]) {
          final title = s.errorTitle(e.kind);
          final body = s.errorBody(e.kind);
          expect(title.toLowerCase(), isNot(contains(code.toLowerCase())), reason: '$code / $title');
          expect(body.toLowerCase(), isNot(contains(code.toLowerCase())), reason: '$code / $body');
        }
      }
    });

    test('the legacy template "Не удалось выполнить операцию (code)" is gone', () {
      expect(ru.errorText('proxyerror'), isNot(contains('(')));
      expect(ru.errorText('S'), isNot(contains('(S)')));
      expect(ru.errorText('proxyerror'), 'Туннель не поднялся. Попробуйте ещё раз или выберите другой сервер.');
    });

    test('known codes map onto stable diagnostics tokens', () {
      expect(MilkyError.fromCode('vpn_permission_denied').diagnosticsCode, 'PERMISSION_DENIED');
      expect(MilkyError.fromCode('tun_establish_failed').diagnosticsCode, 'TUN_FAILED');
      expect(MilkyError.fromCode('core_start_failed').diagnosticsCode, 'VPN_CORE_START_FAILED');
      expect(MilkyError.fromCode('network_unreachable').diagnosticsCode, 'NETWORK_UNAVAILABLE');
      expect(MilkyError.fromCode('all_attempts_failed').diagnosticsCode, 'SERVER_UNREACHABLE');
      expect(MilkyError.fromCode('timeout').kind, MilkyErrorKind.serverUnreachable);
      expect(MilkyError.fromCode('network_unreachable').kind, MilkyErrorKind.noInternet);
      expect(MilkyError.fromCode('no_compatible_profiles').kind, MilkyErrorKind.noServers);
      expect(MilkyError.fromCode('subscription_not_found').kind, MilkyErrorKind.subscriptionProblem);
      expect(MilkyError.fromCode('cancelled').isCancelled, isTrue);
      expect(MilkyError.fromCode(null).diagnosticsCode, 'NO_ERROR_REPORTED');
      expect(MilkyError.fromCode('http_503').diagnosticsCode, 'SUBSCRIPTION_HTTP_503');
    });

    test('every diagnostics token is upper snake case', () {
      for (final code in MilkyError.knownRawCodes) {
        final token = MilkyError.fromCode(code).diagnosticsCode;
        expect(token, matches(RegExp(r'^[A-Z][A-Z0-9_]*$')), reason: '$code -> $token');
      }
    });

    test('device context separates emulator from real device failures', () {
      final tun = MilkyError.fromCode('tun_establish_failed');
      expect(tun.withDeviceContext(isEmulator: true).category.diagnosticsToken, 'EMULATOR_FAILURE');
      expect(tun.withDeviceContext(isEmulator: false).category.diagnosticsToken, 'REAL_DEVICE_FAILURE');
      // A permission failure is never relabelled as a device problem.
      expect(
        MilkyError.fromCode('vpn_permission_denied').withDeviceContext(isEmulator: true).category,
        MilkyFailureCategory.permissionFailure,
      );
    });

    test('every kind has a RU and an EN title, body and at least one action', () {
      for (final kind in MilkyErrorKind.values) {
        expect(ru.errorTitle(kind), isNotEmpty);
        expect(ru.errorBody(kind), isNotEmpty);
        expect(en.errorTitle(kind), isNotEmpty);
        expect(en.errorBody(kind), isNotEmpty);
      }
      for (final code in MilkyError.knownRawCodes) {
        expect(MilkyError.fromCode(code).actions, isNotEmpty, reason: code);
      }
    });

    test('action labels exist for every action', () {
      for (final action in MilkyErrorAction.values) {
        expect(ru.errorAction(action), isNotEmpty);
        expect(en.errorAction(action), isNotEmpty);
      }
    });
  });

  group('Russian pluralisation', () {
    test('profile counts read naturally', () {
      expect(ru.profilesFound(1), '1 профиль найден');
      expect(ru.profilesFound(2), '2 профиля найдено');
      expect(ru.profilesFound(10), '10 профилей найдено');
      expect(ru.profilesFound(16), '16 профилей найдено');
      expect(ru.profilesFound(21), '21 профиль найден');
      expect(ru.profilesFound(11), '11 профилей найдено');
      expect(ru.profilesCompatible(16), '16 совместимых с приложением');
      expect(ru.profilesShort(10), '10 профилей');
      expect(ru.compatibleShort(1), '1 совместимый');
      expect(en.profilesFound(1), '1 profile found');
      expect(en.profilesFound(16), '16 profiles found');
    });

    test('dates render without intl locale data', () {
      expect(ru.dateLong(DateTime(2100, 1, 1)), '1 января 2100');
      expect(en.dateLong(DateTime(2100, 1, 1)), 'Jan 1, 2100');
    });
  });
}
