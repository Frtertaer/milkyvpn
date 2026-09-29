import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

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
  LocationChoice get location =>
      _enumValue(LocationChoice.values, _prefs.get('location'));

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
    await _prefs.setInt('location', c.index);
    notifyListeners();
  }

  Future<void> setAutoConnect(bool v) async {
    await _prefs.setBool('auto_connect', v);
    notifyListeners();
  }

  Future<void> setFullTunnel(bool v) async {
    await _prefs.setBool('tun_mode', v);
    notifyListeners();
  }
}
