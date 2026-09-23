// Real-device test entry point, never referenced by lib/main.dart or normal builds.
// Uses the installed app's real encrypted subscription and the production bridge.
// Build with -t tool/device001_main.dart
//   --dart-define=DEVICE001_PROFILE=FI\ Helsinki-4
// No credential, URL or endpoint is printed. No CONNECTED state is synthesized.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:milkyvpn/app/app_settings.dart';
import 'package:milkyvpn/app/milky_device.dart';
import 'package:milkyvpn/core/storage/secure_store.dart';
import 'package:milkyvpn/core/subscription/subscription_repository.dart';
import 'package:milkyvpn/core/subscription/subscription_stats.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/main.dart' show MilkyApp;

class ExactDeviceProfileSelector extends ProfileSelector {
  const ExactDeviceProfileSelector(this.remark);
  final String remark;

  @override
  List<VpnProfile> candidates(
    List<VpnProfile> supported,
    LocationChoice choice, {
    int maxAttempts = 4,
  }) {
    // Fails closed: a missing/ambiguous requested remark never falls back to a
    // different profile and therefore cannot make this reproduction look passed.
    final exact = supported.where((p) => p.remark == remark).toList();
    return exact.length == 1 ? exact : const [];
  }
}

class DeviceTransportSelector extends ProfileSelector {
  const DeviceTransportSelector(this.kind);
  final String kind;
  @override
  List<VpnProfile> candidates(
    List<VpnProfile> supported,
    LocationChoice choice, {
    int maxAttempts = 4,
  }) => super.candidates(
    supported.where((p) => p.kind.name == kind).toList(),
    choice,
    maxAttempts: maxAttempts,
  );
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  final settings = await AppSettings.load();
  final bridge = MethodChannelVpnBridge();
  final repo = SubscriptionRepository(
    store: KeystoreSecureStore(),
    fetcher: HttpsSubscriptionFetcher(),
  );
  await repo.load();
  final stats = SubscriptionStats.from(repo.snapshot);
  debugPrint(
    'DEVICE001_COUNTS received=${stats.receivedEntryCount} '
    'parsed=${stats.parsedProfileCount} deduped=${stats.postDedupeProfileCount} '
    'compatible=${stats.compatibleProfileCount} trusted=${stats.countsTrusted}',
  );
  final groups = <String, int>{};
  for (final p in repo.snapshot?.profiles ?? <VpnProfile>[]) {
    final group = '${p.location.name}/${p.kind.name}';
    groups.update(group, (n) => n + 1, ifAbsent: () => 1);
  }
  debugPrint('DEVICE001_TRANSPORT_COUNTS $groups');
  if (const bool.fromEnvironment('DEVICE001_PREFLIGHT')) {
    await endpointPreflight(repo.snapshot?.profiles ?? <VpnProfile>[]);
  }
  const remark = String.fromEnvironment('DEVICE001_PROFILE');
  const kind = String.fromEnvironment('DEVICE001_KIND');
  final vpn = VpnController(
    bridge: bridge,
    selector: remark.isNotEmpty
        ? const ExactDeviceProfileSelector(remark)
        : kind.isNotEmpty
        ? const DeviceTransportSelector(kind)
        : const ProfileSelector(),
  );
  await vpn.init();
  final device = await MilkyDevice.load(bridge);
  runApp(
    MilkyApp(
      settings: settings,
      repo: repo,
      vpn: vpn,
      bridge: bridge,
      device: device,
    ),
  );
}

/// Read-only uplink experiment. Never used as VPN verification and never prints
/// an endpoint, resolved address, credential, subscription URL or profile ID.
Future<void> endpointPreflight(List<VpnProfile> profiles) async {
  final endpoints = <String, VpnProfile>{};
  for (final p in profiles) {
    // Hysteria uses UDP; a TCP check would misrepresent that contract.
    if (p.protocol == 'vless') {
      endpoints.putIfAbsent('${p.address}:${p.port}', () => p);
    }
  }
  await Future.wait(
    endpoints.values.indexed.map((item) async {
      final (index, profile) = item;
      final watch = Stopwatch()..start();
      var resolved = false;
      var tcp = false;
      var ipv4 = 0;
      var ipv6 = 0;
      var failure = 'none';
      try {
        final addresses = await InternetAddress.lookup(
          profile.address,
        ).timeout(const Duration(seconds: 8));
        resolved = addresses.isNotEmpty;
        ipv4 = addresses
            .where((a) => a.type == InternetAddressType.IPv4)
            .length;
        ipv6 = addresses
            .where((a) => a.type == InternetAddressType.IPv6)
            .length;
        // Use the normal resolver/socket choice, just as the application's uplink.
        final socket = await Socket.connect(
          profile.address,
          profile.port,
          timeout: const Duration(seconds: 8),
        );
        tcp = true;
        socket.destroy();
      } catch (e) {
        failure = e is SocketException ? 'socket_error' : 'deadline_or_lookup';
      }
      debugPrint(
        'DEVICE001_UPLINK endpoint=${index + 1} '
        'country=${profile.location.name} kind=${profile.kind.name} '
        'dns=$resolved ipv4Count=$ipv4 ipv6Count=$ipv6 tcp=$tcp '
        'elapsedMs=${watch.elapsedMilliseconds} code=$failure',
      );
    }),
  );
}
