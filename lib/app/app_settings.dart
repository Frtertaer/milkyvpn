import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/subscription/country_codes.dart';
import '../core/subscription/vpn_profile.dart';

/// Non-secret preferences only (theme, onboarding flag, location choice, auto-connect).
class AppSettings extends ChangeNotifier {
  AppSettings(this._prefs);

  static Future<AppSettings> load() async =>
      AppSettings(await SharedPreferences.getInstance());

  final SharedPreferences _prefs;

  bool get onboardingDone => _prefs.getBool('onboarding_done') ?? false;
  ThemeMode get themeMode =>
      _enumValue(ThemeMode.values, _prefs.get('theme_mode'));
  /// 'auto' or an ISO country code. The pre-country-code build stored the
  /// picker enum index — map it once ({0:auto, 1:fi, 2:us}) then rewrite.
  /// Junk strings (removed enum names etc.) fall back to auto.
  LocationChoice get location {
    final raw = _prefs.get('location');
    if (raw is String && raw.isNotEmpty && isValidLocationCode(raw)) {
      return raw;
    }
    if (raw is int) {
      final legacy = switch (raw) { 1 => 'fi', 2 => 'us', _ => locationAuto };
      _prefs.setString('location', legacy);
      return legacy;
    }
    return locationAuto;
  }

  static T _enumValue<T>(List<T> values, Object? index) =>
      index is int && index >= 0 && index < values.length
      ? values[index]
      : values.first;
  bool get autoConnect => _prefs.getBool('auto_connect') ?? false;

  /// Windows only: route all device traffic through a wintun adapter instead
  /// of the SOCKS system proxy. Ignored elsewhere.
  bool get fullTunnel => _prefs.getBool('tun_mode') ?? false;

  Future<void> setOnboardingDone() async {
    await _prefs.setBool('onboarding_done', true);
    notifyListeners();
  }

  Future<void> setThemeMode(ThemeMode m) async {
    await _prefs.setInt('theme_mode', m.index);
    notifyListeners();
  }

  Future<void> setLocation(LocationChoice c) async {
    await _prefs.setString('location', c);
    notifyListeners();
  }

  /// A specific profile pinned by the user in the server sheet — overrides
  /// [location] on connect until cleared (changing location clears it).
  String? get selectedProfileId => _prefs.getString('selected_profile');

  Future<void> setSelectedProfile(String? id) async {
    if (id == null || id.isEmpty) {
      await _prefs.remove('selected_profile');
    } else {
      await _prefs.setString('selected_profile', id);
    }
    notifyListeners();
  }

  Future<void> setAutoConnect(bool v) async {
    await _prefs.setBool('auto_connect', v);
    notifyListeners();
  }

  /// Periodic subscription refetch — fresh entry links arrive without
  /// re-importing. Default on; the user can switch it off in settings.
  bool get autoUpdateSub => _prefs.getBool('auto_update_sub') ?? true;

  Future<void> setAutoUpdateSub(bool v) async {
    await _prefs.setBool('auto_update_sub', v);
    notifyListeners();
  }

  Future<void> setFullTunnel(bool v) async {
    await _prefs.setBool('tun_mode', v);
    notifyListeners();
  }
}
