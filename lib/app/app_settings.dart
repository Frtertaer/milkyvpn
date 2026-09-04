import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/subscription/vpn_profile.dart';

/// Non-secret preferences only (theme, onboarding flag, location choice, auto-connect).
class AppSettings extends ChangeNotifier {
  AppSettings(this._prefs);

  static Future<AppSettings> load() async => AppSettings(await SharedPreferences.getInstance());

  final SharedPreferences _prefs;

  bool get onboardingDone => _prefs.getBool('onboarding_done') ?? false;
  ThemeMode get themeMode => ThemeMode.values[_prefs.getInt('theme_mode') ?? 0];
  LocationChoice get location => LocationChoice.values[_prefs.getInt('location') ?? 0];
  bool get autoConnect => _prefs.getBool('auto_connect') ?? false;

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
}
