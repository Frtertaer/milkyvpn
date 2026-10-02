/// Country detection and rendering for the location selector.
///
/// A profile's country is an ISO-3166 alpha-2 code ('fi', 'us', 'ng'...), never
/// a closed enum — any country a subscription carries must surface in the
/// picker. Detection order: flag emoji in the remark → EN/RU country name →
/// a 2-letter ISO token at a word boundary (the `fi-`, ` us ` convention).
library;

/// All ISO-3166 alpha-2 codes — used to gate bare 2-letter tokens so words
/// like "relay" can't parse as a country.
const Set<String> kIsoCodes = {
  'ad','ae','af','ag','ai','al','am','ao','aq','ar','as','at','au','aw','ax','az',
  'ba','bb','bd','be','bf','bg','bh','bi','bj','bl','bm','bn','bo','bq','br','bs',
  'bt','bv','bw','by','bz','ca','cc','cd','cf','cg','ch','ci','ck','cl','cm','cn',
  'co','cr','cu','cv','cw','cx','cy','cz','de','dj','dk','dm','do','dz','ec','ee',
  'eg','eh','er','es','et','fi','fj','fk','fm','fo','fr','ga','gb','gd','ge','gf',
  'gg','gh','gi','gl','gm','gn','gp','gq','gr','gs','gt','gu','gw','gy','hk','hm',
  'hn','hr','ht','hu','id','ie','il','im','in','io','iq','ir','is','it','je','jm',
  'jo','jp','ke','kg','kh','ki','km','kn','kp','kr','kw','ky','kz','la','lb','lc',
  'li','lk','lr','ls','lt','lu','lv','ly','ma','mc','md','me','mf','mg','mh','mk',
  'ml','mm','mn','mo','mp','mq','mr','ms','mt','mu','mv','mw','mx','my','mz','na',
  'nc','ne','nf','ng','ni','nl','no','np','nr','nu','nz','om','pa','pe','pf','pg',
  'ph','pk','pl','pm','pn','pr','ps','pt','pw','py','qa','re','ro','rs','ru','rw',
  'sa','sb','sc','sd','se','sg','sh','si','sj','sk','sl','sm','sn','so','sr','ss',
  'st','sv','sx','sy','sz','tc','td','tf','tg','th','tj','tk','tl','tm','tn','to',
  'tr','tt','tv','tw','tz','ua','ug','um','us','uy','uz','va','vc','ve','vg','vi',
  'vn','vu','wf','ws','ye','yt','za','zm','zw',
};

/// code → (English name, Russian name) for the countries seen in practice.
/// Anything absent still renders — the picker falls back to the uppercased code.
const Map<String, (String en, String ru)> kCountryNames = {
  'al': ('Albania', 'Албания'), 'ae': ('UAE', 'ОАЭ'),
  'ar': ('Argentina', 'Аргентина'), 'at': ('Austria', 'Австрия'),
  'au': ('Australia', 'Австралия'), 'az': ('Azerbaijan', 'Азербайджан'),
  'be': ('Belgium', 'Бельгия'), 'bg': ('Bulgaria', 'Болгария'),
  'br': ('Brazil', 'Бразилия'), 'by': ('Belarus', 'Беларусь'),
  'ca': ('Canada', 'Канада'), 'ch': ('Switzerland', 'Швейцария'),
  'cz': ('Czechia', 'Чехия'), 'de': ('Germany', 'Германия'),
  'dk': ('Denmark', 'Дания'), 'ee': ('Estonia', 'Эстония'),
  'eg': ('Egypt', 'Египет'), 'es': ('Spain', 'Испания'),
  'fi': ('Finland', 'Финляндия'), 'fr': ('France', 'Франция'),
  'gb': ('United Kingdom', 'Великобритания'),
  'ge': ('Georgia', 'Грузия'), 'gr': ('Greece', 'Греция'),
  'hk': ('Hong Kong', 'Гонконг'), 'hu': ('Hungary', 'Венгрия'),
  'id': ('Indonesia', 'Индонезия'), 'ie': ('Ireland', 'Ирландия'),
  'il': ('Israel', 'Израиль'), 'in': ('India', 'Индия'),
  'ir': ('Iran', 'Иран'), 'is': ('Iceland', 'Исландия'),
  'it': ('Italy', 'Италия'), 'jp': ('Japan', 'Япония'),
  'ke': ('Kenya', 'Кения'), 'kg': ('Kyrgyzstan', 'Киргизия'),
  'kr': ('South Korea', 'Южная Корея'), 'kz': ('Kazakhstan', 'Казахстан'),
  'lv': ('Latvia', 'Латвия'), 'lt': ('Lithuania', 'Литва'),
  'lu': ('Luxembourg', 'Люксембург'), 'md': ('Moldova', 'Молдова'),
  'mx': ('Mexico', 'Мексика'), 'my': ('Malaysia', 'Малайзия'),
  'ng': ('Nigeria', 'Нигерия'), 'nl': ('Netherlands', 'Нидерланды'),
  'no': ('Norway', 'Норвегия'), 'pl': ('Poland', 'Польша'),
  'pt': ('Portugal', 'Португалия'), 'ro': ('Romania', 'Румыния'),
  'rs': ('Serbia', 'Сербия'), 'ru': ('Russia', 'Россия'),
  'se': ('Sweden', 'Швеция'), 'sg': ('Singapore', 'Сингапур'),
  'th': ('Thailand', 'Таиланд'), 'tr': ('Türkiye', 'Турция'),
  'tw': ('Taiwan', 'Тайвань'), 'ua': ('Ukraine', 'Украина'),
  'us': ('USA', 'США'), 'vn': ('Vietnam', 'Вьетнам'),
  'za': ('South Africa', 'ЮАР'),
};

/// Bare 2-letter tokens only count at "free" boundaries — start/end, spaces
/// and explicit delimiters. A hyphen binds a token only before digits
/// (`de-3`) — otherwise id-shaped remarks like `unknown-ws` would parse
/// their suffix as Samoa.
final RegExp _tokenRe = RegExp(
  r'(?:^|[\s\[\]({}|_,;:#@])([a-z]{2})(?=[\s\]\[)({}|_,;:#@]|$|-\d)',
);

/// Aliases beyond kCountryNames values: cities and alternate spellings that
/// only map one way (checked as lowercase substrings).
const Map<String, String> _countryAliases = {
  'helsinki': 'fi', 'хельсинки': 'fi',
  'united states': 'us', 'america': 'us', 'сша': 'us',
  'соединенные штаты': 'us', 'new york': 'us', 'нью-йорк': 'us',
  'great britain': 'gb', 'england': 'gb', 'англия': 'gb', 'london': 'gb',
  'лондон': 'gb', 'united kingdom': 'gb',
  'holland': 'nl', 'голландия': 'nl', 'amsterdam': 'nl', 'амстердам': 'nl',
  'south korea': 'kr', 'южная корея': 'kr', 'корея': 'kr',
  'turkey': 'tr', 'турция': 'tr', 'istanbul': 'tr', 'стамбул': 'tr',
  'hong kong': 'hk', 'гонконг': 'hk',
  'uae': 'ae', 'дубай': 'ae', 'dubai': 'ae',
  'moldova': 'md', 'молдова': 'md', 'кишинев': 'md',
  'рф': 'ru',
};

/// Whether [code] is a usable location value ('auto' or an ISO alpha-2).
bool isValidLocationCode(String code) =>
    code == 'auto' || kIsoCodes.contains(code.toLowerCase());

/// Detects the country code from a profile remark, or null when unknown.
String? locationCodeFromRemark(String remark) {
  for (var i = 0; i + 1 < remark.length; i++) {
    final a = remark.codeUnitAt(i), b = remark.codeUnitAt(i + 1);
    if (a >= 0x1F1E6 && a <= 0x1F1FF && b >= 0x1F1E6 && b <= 0x1F1FF) {
      return '${String.fromCharCode(a - 0x1F1E6 + 0x61)}'
          '${String.fromCharCode(b - 0x1F1E6 + 0x61)}';
    }
  }
  final r = remark.toLowerCase().replaceAll('ё', 'е');
  for (final e in _countryAliases.entries) {
    if (r.contains(e.key)) return e.value;
  }
  for (final e in kCountryNames.entries) {
    if (r.contains(e.value.$1.toLowerCase()) ||
        r.contains(e.value.$2.toLowerCase())) {
      return e.key;
    }
  }
  for (final m in _tokenRe.allMatches(r)) {
    final t = m.group(1)!;
    if (kIsoCodes.contains(t)) return t;
  }
  return null;
}

/// 🇫🇮-style flag for a code, or a neutral marker when the code isn't valid.
String flagEmoji(String code) {
  if (code.length != 2 ||
      !kIsoCodes.contains(code.toLowerCase())) {
    return '🌐';
  }
  final c = code.toLowerCase();
  return String.fromCharCode(c.codeUnitAt(0) - 0x61 + 0x1F1E6) +
      String.fromCharCode(c.codeUnitAt(1) - 0x61 + 0x1F1E6);
}

/// Display name: the localized country when known, the uppercased code
/// otherwise — the picker never hides a country for lack of a table row.
String countryName(String code, {required bool ru}) {
  final names = kCountryNames[code.toLowerCase()];
  if (names == null) return code.toUpperCase();
  return ru ? names.$2 : names.$1;
}
