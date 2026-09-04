import 'package:flutter/material.dart';

import '../core/errors/milky_error.dart';

/// RU/EN strings for MilkyVPN (RU is the product language).
///
/// Kept as a plain class rather than ARB so the build needs no code generation; the API
/// (`S.of(context)`) is stable and every user-visible string lives here.
class S {
  const S(this.locale);

  final Locale locale;

  bool get ru => locale.languageCode == 'ru';

  static S of(BuildContext context) => S(Localizations.localeOf(context));

  String t(String ru, String en) => this.ru ? ru : en;

  /// Russian pluralisation (1 профиль / 2 профиля / 5 профилей).
  String plural(int n, String one, String few, String many) {
    if (!ru) return '$n ${n == 1 ? one : many}';
    final m10 = n % 10;
    final m100 = n % 100;
    if (m10 == 1 && m100 != 11) return '$n $one';
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return '$n $few';
    return '$n $many';
  }

  /// Count phrase with Russian pluralisation and a plain English fallback.
  String counted(int n, String ruOne, String ruFew, String ruMany, String enOne, String enMany) =>
      ru ? plural(n, ruOne, ruFew, ruMany) : '$n ${n == 1 ? enOne : enMany}';

  // ---------------------------------------------------------------- brand

  String get appName => 'MilkyVPN';
  String get tagline => t('VPN без сложных настроек', 'VPN without the setup');
  String get taglineBody => t(
        'Одно нажатие — и трафик идёт через зашифрованный туннель. Сервер выбирается сам.',
        'One tap and your traffic travels through an encrypted tunnel. The server is picked for you.',
      );

  // ---------------------------------------------------------------- onboarding

  String get cont => t('Продолжить', 'Continue');
  String get understood => t('Понятно, продолжить', 'Got it, continue');
  String get disclosureTitle => t('Защищённое VPN-соединение', 'An encrypted VPN connection');
  String get disclosureBody => t(
        'MilkyVPN использует системную функцию Android VpnService: после вашего согласия Android направляет трафик устройства через зашифрованный туннель к серверу MilkyVPN.\n\nПриложение не ведёт историю сайтов и DNS-запросов, не содержит рекламных SDK. VPN не делает вас полностью анонимным и не гарантирует обход всех ограничений.',
        'MilkyVPN uses the Android VpnService system feature. After your consent Android routes the device traffic through an encrypted VPN tunnel to the selected MilkyVPN server.\n\nThe app keeps no browsing or DNS history and contains no advertising SDKs. A VPN does not make you fully anonymous and does not guarantee bypassing every restriction.',
      );
  String get importTitle => t('Добавьте подписку', 'Add your subscription');
  String get importBody => t(
        'Вставьте ссылку MilkyVPN — приложение само найдёт серверы.',
        'Paste your MilkyVPN link — the app finds the servers for you.',
      );
  String get addSubscription => t('Добавить подписку', 'Add subscription');
  String get noSubscriptionYet => t('У меня пока нет подписки', "I don't have a subscription yet");
  String get help => t('Помощь', 'Help');
  String get internet => t('Интернет', 'Internet');
  String get devicePhone => t('Телефон', 'Phone');

  // ---------------------------------------------------------------- home

  String get protectionOff => t('Защита выключена', 'Protection off');
  String get protectionOn => t('VPN подключён', 'VPN connected');
  String get protectionConnecting => t('Подключаем…', 'Connecting…');
  String get notConnected => t('Не подключено', 'Not connected');
  String get connecting => t('Подключаем…', 'Connecting…');
  String get connected => t('Подключено', 'Connected');
  String get protectedShort => t('Защищено', 'Protected');
  String get connect => t('Подключить', 'Connect');
  String get disconnect => t('Отключить', 'Disconnect');
  String get searchingServer => t('Ищем лучший сервер…', 'Finding the best server…');
  String attemptOf(int i, int n) => t('$i из $n', '$i of $n');
  String get auto => t('Авто', 'Auto');
  String get finland => t('Финляндия', 'Finland');
  String get usa => t('США', 'USA');
  String get autoHint => t('Лучший сервер', 'Best server');
  String get tapToConnect => t('Нажмите, чтобы подключиться', 'Tap to connect');
  String get tapToDisconnect => t('Нажмите, чтобы отключить', 'Tap to disconnect');
  String get needSubscription => t('Сначала добавьте подписку', 'Add a subscription first');
  String locationLabel(String name) => name;

  // ---------------------------------------------------------------- nav

  String get home => t('Главная', 'Home');
  String get subscription => t('Подписка', 'Subscription');
  String get settings => t('Настройки', 'Settings');

  // ---------------------------------------------------------------- subscription

  String get status => t('Статус', 'Status');
  String get active => t('Активна', 'Active');
  String get unavailable => t('Недоступна', 'Unavailable');
  String get expired => t('Истекла', 'Expired');
  String get expires => t('Действует до', 'Valid until');
  String get noExpiry => t('Бессрочно', 'No expiry');
  String get profiles => t('Профили', 'Profiles');
  String profilesFound(int n) =>
      counted(n, 'профиль найден', 'профиля найдено', 'профилей найдено', 'profile found', 'profiles found');
  String profilesCompatible(int n) =>
      counted(n, 'совместим с приложением', 'совместимы с приложением', 'совместимых с приложением', 'compatible with the app', 'compatible with the app');
  String profilesIncompatible(int n) =>
      counted(n, 'не поддерживается', 'не поддерживаются', 'не поддерживаются', 'not supported', 'not supported');
  String linesParsed(int n) =>
      counted(n, 'строка в подписке', 'строки в подписке', 'строк в подписке', 'line in the subscription', 'lines in the subscription');
  String duplicatesSkipped(int n) =>
      counted(n, 'повтор пропущен', 'повтора пропущено', 'повторов пропущено', 'duplicate skipped', 'duplicates skipped');
  String malformedSkipped(int n) =>
      counted(n, 'строка повреждена', 'строки повреждены', 'строк повреждено', 'broken line', 'broken lines');

  /// Short count phrases for dense lines: "16 профилей", "16 совместимых".
  String profilesShort(int n) => counted(n, 'профиль', 'профиля', 'профилей', 'profile', 'profiles');
  String compatibleShort(int n) => counted(n, 'совместимый', 'совместимых', 'совместимых', 'compatible', 'compatible');

  /// "1 января 2100" — no intl locale data needed, so it cannot fail at runtime.
  String dateLong(DateTime d) {
    final local = d.toLocal();
    if (ru) {
      const months = ['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'];
      return '${local.day} ${months[local.month - 1]} ${local.year}';
    }
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return '${months[local.month - 1]} ${local.day}, ${local.year}';
  }

  String dateTimeShort(DateTime d) {
    final local = d.toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${dateLong(local)}, ${two(local.hour)}:${two(local.minute)}';
  }

  String get compatibility => t('Совместимость', 'Compatibility');
  String get lastUpdated => t('Обновлено', 'Updated');
  String get refresh => t('Обновить', 'Refresh');
  String get refreshSubscription => t('Обновить подписку', 'Refresh subscription');
  String get removeSubscription => t('Удалить подписку', 'Remove subscription');
  String get removeConfirm => t('Удалить подписку с этого устройства? Вы сможете добавить её снова.', 'Remove the subscription from this device? You can add it again later.');
  String get remove => t('Удалить', 'Remove');
  String get cancel => t('Отмена', 'Cancel');
  String get noSubscription => t('Подписка не добавлена', 'No subscription');
  String get subscriptionHint => t('Подписка хранится только на этом устройстве.', 'The subscription is stored on this device only.');
  String get advanced => t('Дополнительно', 'Advanced');
  String get copyLink => t('Скопировать ссылку', 'Copy link');
  String get linkCopied => t('Ссылка скопирована', 'Link copied');
  String get subscriptionEmptyTitle => t('Подписки пока нет', 'No subscription yet');
  String get subscriptionEmptyBody => t('Добавьте ссылку MilkyVPN, чтобы подключить защиту.', 'Add your MilkyVPN link to enable protection.');

  // ---------------------------------------------------------------- import

  String get pasteFromClipboard => t('Вставить из буфера', 'Paste from clipboard');
  String get pasted => t('Вставлено из буфера обмена', 'Pasted from the clipboard');
  String get clipboardEmpty => t('В буфере обмена нет ссылки', 'No link in the clipboard');
  String get subscriptionUrlHint => t('Ссылка на подписку', 'Subscription link');
  String get import => t('Добавить', 'Add');
  String get importing => t('Загружаем…', 'Loading…');
  String get importOk => t('Подписка добавлена', 'Subscription added');
  String get goToConnect => t('Перейти к подключению', 'Go to connect');
  String get deepLinkTitle => t('Добавить подписку MilkyVPN?', 'Add MilkyVPN subscription?');
  String get deepLinkBody => t(
        'Ссылка получена из другого приложения. Подписка будет сохранена только на этом устройстве. Подключение не начнётся автоматически.',
        'The link came from another app. The subscription is stored on this device only. No connection starts automatically.',
      );
  String get add => t('Добавить', 'Add');
  String get urlNotAllowed => t('Допустимы только ссылки вида https://sub.milky.homes/s/…', 'Only https://sub.milky.homes/s/… links are accepted');
  String serversReady(int n) => counted(n, 'сервер готов', 'сервера готовы', 'серверов готово', 'server ready', 'servers ready');

  // ---------------------------------------------------------------- settings

  String get groupConnection => t('Подключение', 'Connection');
  String get groupApp => t('Приложение', 'App');
  String get groupHelp => t('Помощь', 'Help');
  String get groupAbout => t('О приложении', 'About');
  String get autoConnect => t('Автоподключение', 'Auto-connect');
  String get autoConnectHint => t('Подключаться при запуске приложения', 'Connect when the app starts');
  String get alwaysOn => t('Always-on VPN', 'Always-on VPN');
  String get alwaysOnHint => t('Системные настройки Android', 'Android system settings');
  String get theme => t('Тема', 'Theme');
  String get themeSystem => t('Системная', 'System');
  String get themeLight => t('Светлая', 'Light');
  String get themeDark => t('Тёмная', 'Dark');
  String get checkSubscriptionUpdate => t('Обновить подписку', 'Refresh subscription');
  String get diagnostics => t('Диагностика', 'Diagnostics');
  String get diagnosticsHint => t('Технические коды для поддержки', 'Technical codes for support');
  String get privacy => t('Конфиденциальность', 'Privacy');
  String get about => t('О приложении', 'About');
  String get version => t('Версия', 'Version');
  String get support => t('Поддержка', 'Support');
  String get supportHint => t('Telegram @MilkyVPNbot', 'Telegram @MilkyVPNbot');
  String get copyDiagnostics => t('Скопировать диагностику', 'Copy diagnostics');
  String get copied => t('Скопировано', 'Copied');
  String get privacyBody => t(
        'Приложение не собирает историю посещений, DNS-запросы и содержимое трафика, не содержит аналитики и рекламы. Ссылка на подписку хранится в защищённом хранилище Android Keystore и не покидает устройство, кроме запроса к sub.milky.homes для загрузки списка серверов. Диагностика копируется только по вашему действию и не содержит учётных данных.',
        'The app does not collect browsing history, DNS queries or traffic contents and has no analytics or ads. The subscription link is stored in Android Keystore-backed secure storage and never leaves the device except for requests to sub.milky.homes to download the server list. Diagnostics are copied only by your action and contain no credentials.',
      );
  String get aboutBody => t(
        'MilkyVPN — клиент для подписки Milky. Трафик проходит через зашифрованный туннель к выбранному серверу, приложение не видит содержимое ваших запросов.',
        'MilkyVPN is a client for the Milky subscription. Traffic travels through an encrypted tunnel to the selected server; the app never sees the contents of your requests.',
      );

  // ---------------------------------------------------------------- diagnostics

  String get diagDevice => t('Устройство', 'Device');
  String get diagDeviceType => t('Тип устройства', 'Device type');
  String get diagEmulator => t('Эмулятор', 'Emulator');
  String get diagRealDevice => t('Реальное устройство', 'Real device');
  String get diagCore => t('Ядро', 'Core');
  String get diagState => t('Состояние', 'State');
  String get diagProfile => t('Профиль', 'Profile');
  String get diagAttempts => t('Попытки', 'Attempts');
  String get diagLastError => t('Последняя ошибка', 'Last error');
  String get diagCategory => t('Категория', 'Category');
  String get diagCode => t('Код диагностики', 'Diagnostics code');
  String get diagSubscription => t('Подписка', 'Subscription');
  String get diagNone => t('Нет', 'None');
  String get diagHint => t(
        'Эти коды не показываются на основных экранах. Отправьте их в поддержку, если подключение не работает.',
        'These codes never appear on the main screens. Send them to support if the connection fails.',
      );

  // ---------------------------------------------------------------- errors

  String errorTitle(MilkyErrorKind kind) {
    switch (kind) {
      case MilkyErrorKind.permissionDenied:
        return t('Нужно разрешение VPN', 'VPN permission needed');
      case MilkyErrorKind.noInternet:
        return t('Нет соединения', 'No connection');
      case MilkyErrorKind.serverUnreachable:
        return t('Не удалось подключиться', 'Could not connect');
      case MilkyErrorKind.tunnelFailed:
        return t('Не удалось подключиться', 'Could not connect');
      case MilkyErrorKind.noServers:
        return t('Нет подходящих серверов', 'No suitable servers');
      case MilkyErrorKind.subscriptionProblem:
        return t('Проблема с подпиской', 'Subscription problem');
      case MilkyErrorKind.cancelled:
        return t('Подключение отменено', 'Connection cancelled');
      case MilkyErrorKind.unknown:
        return t('Не удалось подключиться', 'Could not connect');
    }
  }

  String errorBody(MilkyErrorKind kind) {
    switch (kind) {
      case MilkyErrorKind.permissionDenied:
        return t(
          'Android не разрешил создать VPN-туннель. Разрешите подключение и попробуйте снова.',
          'Android did not allow the VPN tunnel. Grant the permission and try again.',
        );
      case MilkyErrorKind.noInternet:
        return t('Проверьте интернет и попробуйте снова.', 'Check your internet connection and try again.');
      case MilkyErrorKind.serverUnreachable:
        return t('Сервер не отвечает. Попробуем другой сервер.', 'The server did not respond. Let us try another one.');
      case MilkyErrorKind.tunnelFailed:
        return t('Туннель не поднялся. Попробуйте ещё раз или выберите другой сервер.', 'The tunnel did not start. Try again or pick another server.');
      case MilkyErrorKind.noServers:
        return t('В подписке нет серверов, которые поддерживает приложение. Обновите подписку.', 'The subscription has no servers this app can run. Refresh it.');
      case MilkyErrorKind.subscriptionProblem:
        return t('Не удалось загрузить подписку. Проверьте ссылку и попробуйте снова.', 'The subscription could not be loaded. Check the link and try again.');
      case MilkyErrorKind.cancelled:
        return t('Вы отменили подключение.', 'You cancelled the connection.');
      case MilkyErrorKind.unknown:
        return t('Попробуем другой сервер.', 'Let us try another server.');
    }
  }

  String errorAction(MilkyErrorAction action) {
    switch (action) {
      case MilkyErrorAction.retry:
        return t('Попробовать снова', 'Try again');
      case MilkyErrorAction.chooseServer:
        return t('Другой сервер', 'Another server');
      case MilkyErrorAction.diagnostics:
        return t('Диагностика', 'Diagnostics');
      case MilkyErrorAction.addSubscription:
        return t('Добавить подписку', 'Add subscription');
      case MilkyErrorAction.openVpnSettings:
        return t('Настройки VPN', 'VPN settings');
      case MilkyErrorAction.dismiss:
        return t('Закрыть', 'Close');
    }
  }

  /// Human text for a raw code. Kept for call sites that only need one line.
  String errorText(String? code) {
    final e = MilkyError.fromCode(code);
    if (e.isCancelled) return '';
    return errorBody(e.kind);
  }
}
