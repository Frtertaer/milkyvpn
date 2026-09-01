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

/// Minimal RU/EN localization (RU primary). Structure ready to move into ARB later.
class S {
  const S(this.locale);
  final Locale locale;
  bool get ru => locale.languageCode == 'ru';

  static S of(BuildContext context) => S(Localizations.localeOf(context));

  String t(String ru, String en) => this.ru ? ru : en;

  String get appName => 'MilkyVPN';
  String get tagline => t('Простой VPN без ручной настройки серверов.', 'Simple VPN with no manual server setup.');
  String get cont => t('Продолжить', 'Continue');
  String get disclosureTitle => t('Как работает VPN', 'How the VPN works');
  String get disclosureBody => t(
      'Для работы MilkyVPN использует системную функцию Android VpnService. После вашего согласия Android направляет трафик устройства через зашифрованный VPN-туннель к выбранному серверу MilkyVPN.\n\nПриложение не ведёт историю сайтов, DNS-запросов и не содержит рекламных SDK. VPN не делает вас полностью анонимным и не гарантирует обход всех ограничений.',
      'MilkyVPN uses the Android VpnService system feature. After your consent Android routes the device traffic through an encrypted VPN tunnel to the selected MilkyVPN server.\n\nThe app keeps no browsing or DNS history and contains no advertising SDKs. A VPN does not make you fully anonymous and does not guarantee bypassing every restriction.');
  String get understood => t('Понятно, продолжить', 'Got it, continue');
  String get addSubscription => t('Добавить подписку', 'Add subscription');
  String get noSubscriptionYet => t('У меня пока нет подписки', "I don't have a subscription yet");
  String get pasteFromClipboard => t('Вставить из буфера обмена', 'Paste from clipboard');
  String get subscriptionUrlHint => t('Ссылка на подписку', 'Subscription link');
  String get import => t('Импортировать', 'Import');
  String get importOk => t('Подписка добавлена', 'Subscription added');
  String get urlNotAllowed => t('Допустимы только ссылки вида https://sub.milky.homes/s/…', 'Only https://sub.milky.homes/s/… links are accepted');
  String get notConnected => t('Не подключено', 'Not connected');
  String get connecting => t('Подключение…', 'Connecting…');
  String get connected => t('Подключено', 'Connected');
  String get connect => t('Подключить', 'Connect');
  String get disconnect => t('Отключить', 'Disconnect');
  String get auto => t('Авто', 'Auto');
  String get finland => t('Финляндия', 'Finland');
  String get usa => t('США', 'USA');
  String get subscription => t('Подписка', 'Subscription');
  String get settings => t('Настройки', 'Settings');
  String get status => t('Статус', 'Status');
  String get active => t('Активна', 'Active');
  String get unavailable => t('Недоступна', 'Unavailable');
  String get expires => t('Дата окончания', 'Expires');
  String get serversCount => t('Количество доступных серверов', 'Available servers');
  String get refreshSubscription => t('Обновить подписку', 'Refresh subscription');
  String get removeSubscription => t('Удалить подписку', 'Remove subscription');
  String get removeConfirm => t('Удалить подписку с этого устройства? Вы сможете добавить её снова.', 'Remove the subscription from this device? You can add it again later.');
  String get cancel => t('Отмена', 'Cancel');
  String get remove => t('Удалить', 'Remove');
  String get autoConnect => t('Автоподключение при запуске', 'Auto-connect on launch');
  String get theme => t('Тема', 'Theme');
  String get themeSystem => t('Системная', 'System');
  String get themeLight => t('Светлая', 'Light');
  String get themeDark => t('Тёмная', 'Dark');
  String get checkSubscriptionUpdate => t('Проверить обновление подписки', 'Check subscription update');
  String get diagnostics => t('Диагностика', 'Diagnostics');
  String get privacy => t('Конфиденциальность', 'Privacy');
  String get about => t('О приложении', 'About');
  String get support => t('Поддержка и помощь с аккаунтом', 'Support & account help');
  String get alwaysOn => t('Настройки VPN Android (Always-on)', 'Android VPN settings (Always-on)');
  String get copyDiagnostics => t('Скопировать диагностику', 'Copy diagnostics');
  String get copied => t('Скопировано', 'Copied');
  String get addSubscriptionQuestion => t('Добавить подписку MilkyVPN?', 'Add MilkyVPN subscription?');
  String get deepLinkBody => t('Ссылка получена из другого приложения. Подписка будет сохранена на устройстве. Подключение не начнётся автоматически.', 'The link was received from another app. The subscription will be stored on this device. No connection will start automatically.');
  String get add => t('Добавить', 'Add');
  String get noSubscription => t('Подписка не добавлена', 'No subscription');
  String get error => t('Ошибка', 'Error');
  String get privacyBody => t(
      'Приложение не собирает историю посещений, DNS-запросы, содержимое трафика и не содержит аналитики или рекламы. Ссылка на подписку хранится в защищённом хранилище Android Keystore и не покидает устройство, кроме запроса к sub.milky.homes для загрузки списка серверов. Диагностика копируется только по вашему действию и не содержит учётных данных.',
      'The app does not collect browsing history, DNS queries or traffic contents and has no analytics or ads. The subscription link is stored in Android Keystore-backed secure storage and never leaves the device except for requests to sub.milky.homes to download the server list. Diagnostics are copied only by your action and contain no credentials.');

  String errorText(String? code) {
    switch (code) {
      case 'vpn_permission_denied':
        return t('Вы не разрешили создание VPN-подключения.', 'VPN permission was not granted.');
      case 'no_compatible_profiles':
        return t('Нет совместимых серверов для выбранной локации.', 'No compatible servers for this location.');
      case 'timeout':
        return t('Сервер не ответил вовремя.', 'The server did not respond in time.');
      case 'all_attempts_failed':
        return t('Не удалось подключиться ни к одному серверу.', 'Could not connect to any server.');
      case 'url_not_allowed':
        return urlNotAllowed;
      case 'no_profiles':
        return t('Подписка не содержит серверов.', 'The subscription contains no servers.');
      case 'subscription_not_found':
        return t('Подписка не найдена или отключена.', 'Subscription not found or disabled.');
      case null:
        return '';
      default:
        return t('Не удалось выполнить операцию ($code).', 'Operation failed ($code).');
    }
  }
}
