import 'dart:io';

import 'vpn_profile.dart';

/// Result of one profile reachability probe.
class ProfileProbe {
  const ProfileProbe({this.ms, this.udp = false, this.dead = false});

  /// TCP round-trip to the dialed endpoint in milliseconds. Null when the
  /// carrier isn't TCP-probeable ([udp]) or the endpoint didn't answer
  /// ([dead]).
  final int? ms;
  final bool udp;
  final bool dead;
}

/// TCP-connect probes for the profile list. The target is whatever the
/// client actually dials: the front relay host:port when `front=` is set,
/// else `address:port` of the entry. UDP carriers (quic2/rtc/quasar) can't
/// be probed over TCP — they report `udp` instead of a misleading "dead".
class ProfileHealth {
  const ProfileHealth._();

  static const udpCarriers = {'quic2', 'rtc', 'quasar'};

  static Future<Map<String, ProfileProbe>> measure(
    List<VpnProfile> profiles, {
    Duration timeout = const Duration(seconds: 4),
  }) async {
    final out = <String, ProfileProbe>{};
    await Future.wait(
      profiles.map((p) async => out[p.id] = await probe(p, timeout: timeout)),
    );
    return out;
  }

  static Future<ProfileProbe> probe(
    VpnProfile p, {
    Duration timeout = const Duration(seconds: 4),
  }) async {
    if (udpCarriers.contains(p.network.trim().toLowerCase())) {
      return const ProfileProbe(udp: true);
    }
    final (host, port) = dialTarget(p);
    final sw = Stopwatch()..start();
    try {
      final sock = await Socket.connect(host, port, timeout: timeout);
      sw.stop();
      sock.destroy();
      return ProfileProbe(ms: sw.elapsedMilliseconds);
    } on Object {
      return const ProfileProbe(dead: true);
    }
  }

  /// What the client dials for this profile: the front relay when front= is
  /// set (scheme default port applies), else the entry address:port.
  static (String, int) dialTarget(VpnProfile p) {
    final front =
        p.front ??
        (p.fronts != null && p.fronts!.isNotEmpty ? p.fronts!.first : null);
    if (front != null && front.trim().isNotEmpty) {
      final f = front.trim();
      final uri = Uri.tryParse(f.contains('://') ? f : 'https://$f');
      if (uri != null && uri.host.isNotEmpty) {
        return (uri.host, uri.port == 0 ? 443 : uri.port);
      }
    }
    return (p.address, p.port);
  }
}
