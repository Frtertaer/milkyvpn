import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/country_codes.dart';

void main() {
  group('locationCodeFromRemark', () {
    test('leading code before a hyphen', () {
      for (final r in [
        'fi-reality', 'fi-reality-2', 'fi-cdn', 'fi-hy2',
        'us-reality', 'us-cdn', 'us-cdn-alt', 'us-hy2', 'de-3', 'us-east',
      ]) {
        expect(locationCodeFromRemark(r), r.startsWith('us') ? 'us' : r.substring(0, 2), reason: r);
      }
    });
    test('flag emoji detected via code points', () {
      expect(locationCodeFromRemark('🇫🇮 сервер'), 'fi');
      expect(locationCodeFromRemark('🇺🇸 us'), 'us');
      expect(locationCodeFromRemark('x 🇳🇬 y'), 'ng');
    });
    test('free-boundary tokens', () {
      expect(locationCodeFromRemark('Node US'), 'us');
      expect(locationCodeFromRemark('[NL] ams'), 'nl');
      expect(locationCodeFromRemark('the fi tag'), 'fi');
    });
    test('id-suffix salad does not parse', () {
      expect(locationCodeFromRemark('unknown-ws'), isNull);
      expect(locationCodeFromRemark('node-us-east'), isNull);
      expect(locationCodeFromRemark('relay-fr'), isNull);
    });
    test('names and aliases', () {
      expect(locationCodeFromRemark('Финляндия'), 'fi');
      expect(locationCodeFromRemark('США сервер'), 'us');
      expect(locationCodeFromRemark('Nigeria'), 'ng');
      expect(locationCodeFromRemark('Unknown'), isNull);
    });
  });
  test('flagEmoji / countryName', () {
    expect(flagEmoji('fi'), '🇫🇮');
    expect(flagEmoji('zz'), '🌐');
    expect(countryName('ng', ru: false), 'Nigeria');
    expect(countryName('ng', ru: true), 'Нигерия');
    expect(countryName('zw', ru: false), 'ZW');
  });
  test('isValidLocationCode', () {
    expect(isValidLocationCode('auto'), isTrue);
    expect(isValidLocationCode('fi'), isTrue);
    expect(isValidLocationCode('removed-enum'), isFalse);
  });
}
