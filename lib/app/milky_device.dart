import '../core/vpn/vpn_bridge.dart';

/// Static facts about the device, used only by Diagnostics to label a failure as
/// `EMULATOR_FAILURE` or `REAL_DEVICE_FAILURE`. Never shown as a customer-facing error.
class MilkyDevice {
  const MilkyDevice({
    this.isEmulator = false,
    this.model = '',
    this.manufacturer = '',
    this.osVersion = '',
    this.sdkInt = 0,
    this.abi = '',
    this.platform = 'android',
  });

  final bool isEmulator;
  final String model;
  final String manufacturer;
  final String osVersion;
  final int sdkInt;
  final String abi;

  /// 'android', 'windows', … — absent on the Android channel (defaults to android).
  final String platform;

  String get platformLabel => platform == 'android' ? 'Android' : 'Windows';

  /// `13 (API 33)` on Android, the raw OS version elsewhere.
  String get osLabel {
    if (osVersion.isEmpty) return '?';
    return sdkInt > 0 ? '$osVersion (API $sdkInt)' : osVersion;
  }

  factory MilkyDevice.fromMap(Map<String, Object?> m) {
    bool b(String k) => m[k] == true;
    int i(String k) => (m[k] as num?)?.toInt() ?? 0;
    String s(String k) => (m[k] as String?) ?? '';
    final rel = s('release');
    return MilkyDevice(
      isEmulator: b('isEmulator'),
      model: s('model'),
      manufacturer: s('manufacturer'),
      osVersion: rel.isEmpty ? s('osVersion') : rel,
      sdkInt: i('sdkInt'),
      abi: s('abi'),
      platform: s('platform').isEmpty ? 'android' : s('platform'),
    );
  }

  static Future<MilkyDevice> load(VpnBridge bridge) async {
    try {
      return MilkyDevice.fromMap(await bridge.deviceInfo());
    } catch (_) {
      return const MilkyDevice();
    }
  }

  String get summary {
    final parts = <String>[
      if (manufacturer.isNotEmpty) manufacturer,
      if (model.isNotEmpty) model,
    ];
    return parts.isEmpty ? 'unknown' : parts.join(' ');
  }
}
