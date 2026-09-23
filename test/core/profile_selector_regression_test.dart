import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';

void main() {
  const selector = ProfileSelector();

  VpnProfile profile(
    String id,
    ProfileKind kind, {
    ServerLocation location = ServerLocation.finland,
  }) {
    final country = switch (location) {
      ServerLocation.finland => 'Finland',
      ServerLocation.usa => 'USA',
      ServerLocation.unknown => 'Unknown',
    };
    return VpnProfile(
      id: id,
      protocol: kind == ProfileKind.hysteria2 ? 'hysteria2' : 'vless',
      address: '$id.example.invalid',
      port: 443,
      secret: 'test-credential',
      remark: '$country $id',
      network: switch (kind) {
        ProfileKind.vlessRealityTcp => 'tcp',
        ProfileKind.vlessWsTls => 'ws',
        ProfileKind.vlessXhttp => 'xhttp',
        ProfileKind.hysteria2 || ProfileKind.other => 'tcp',
      },
      security: switch (kind) {
        ProfileKind.vlessRealityTcp => 'reality',
        ProfileKind.vlessWsTls => 'tls',
        ProfileKind.vlessXhttp => 'reality',
        ProfileKind.hysteria2 || ProfileKind.other => 'none',
      },
      publicKey:
          kind == ProfileKind.vlessRealityTcp || kind == ProfileKind.vlessXhttp
          ? 'test-public-key'
          : null,
    );
  }

  group('ProfileSelector transport diversity regression', () {
    test(
      'bounded retry budget reaches alternatives previously starved by TCP',
      () {
        final profiles = [
          for (var i = 1; i <= 5; i++)
            profile('reality-$i', ProfileKind.vlessRealityTcp),
          profile('xhttp-1', ProfileKind.vlessXhttp),
          profile('ws-1', ProfileKind.vlessWsTls),
          profile('hy2-1', ProfileKind.hysteria2),
        ];

        final legacy = [...profiles]
          ..sort((a, b) {
            int oldRank(VpnProfile p) => switch (p.kind) {
              ProfileKind.vlessRealityTcp => 0,
              ProfileKind.vlessXhttp => 1,
              ProfileKind.vlessWsTls => 2,
              ProfileKind.hysteria2 => 3,
              ProfileKind.other => 9,
            };
            return oldRank(a).compareTo(oldRank(b));
          });
        expect(
          legacy.take(4).every((p) => p.kind == ProfileKind.vlessRealityTcp),
          isTrue,
          reason: 'Control reproduces the previous four-attempt starvation.',
        );

        final selected = selector.candidates(profiles, LocationChoice.auto);
        expect(selected.map((p) => p.kind), [
          ProfileKind.vlessXhttp,
          ProfileKind.hysteria2,
          ProfileKind.vlessWsTls,
          ProfileKind.vlessRealityTcp,
        ]);
      },
    );

    test('round robin preserves input order within every family', () {
      final profiles = [
        profile('reality-1', ProfileKind.vlessRealityTcp),
        profile('ws-1', ProfileKind.vlessWsTls),
        profile('xhttp-1', ProfileKind.vlessXhttp),
        profile('reality-2', ProfileKind.vlessRealityTcp),
        profile('xhttp-2', ProfileKind.vlessXhttp),
        profile('ws-2', ProfileKind.vlessWsTls),
      ];

      expect(
        selector
            .candidates(profiles, LocationChoice.auto, maxAttempts: 6)
            .map((p) => p.id),
        ['xhttp-1', 'ws-1', 'reality-1', 'xhttp-2', 'ws-2', 'reality-2'],
      );
    });

    test('auto balances locations while covering the first family round', () {
      final profiles = [
        profile('fi-xhttp', ProfileKind.vlessXhttp),
        profile('fi-hy2', ProfileKind.hysteria2),
        profile('fi-ws', ProfileKind.vlessWsTls),
        profile('fi-reality', ProfileKind.vlessRealityTcp),
        profile(
          'us-xhttp',
          ProfileKind.vlessXhttp,
          location: ServerLocation.usa,
        ),
        profile(
          'us-hy2',
          ProfileKind.hysteria2,
          location: ServerLocation.usa,
        ),
        profile(
          'us-ws',
          ProfileKind.vlessWsTls,
          location: ServerLocation.usa,
        ),
        profile(
          'us-reality',
          ProfileKind.vlessRealityTcp,
          location: ServerLocation.usa,
        ),
      ];

      final priorFamilyRound = [
        profiles.firstWhere((p) => p.kind == ProfileKind.vlessXhttp),
        profiles.firstWhere((p) => p.kind == ProfileKind.hysteria2),
        profiles.firstWhere((p) => p.kind == ProfileKind.vlessWsTls),
        profiles.firstWhere((p) => p.kind == ProfileKind.vlessRealityTcp),
      ];
      expect(
        priorFamilyRound.every(
          (p) => p.location == ServerLocation.finland,
        ),
        isTrue,
        reason: 'Control reproduces the previous Auto location starvation.',
      );

      final selected = selector.candidates(profiles, LocationChoice.auto);
      expect(
        selected.map((p) => p.id),
        ['fi-xhttp', 'us-hy2', 'fi-ws', 'us-reality'],
      );
      expect(
        selected.map((p) => p.location),
        [
          ServerLocation.finland,
          ServerLocation.usa,
          ServerLocation.finland,
          ServerLocation.usa,
        ],
      );
    });

    test('large budget returns all executable profiles without duplicates', () {
      final profiles = [
        profile('reality-1', ProfileKind.vlessRealityTcp),
        profile('xhttp-1', ProfileKind.vlessXhttp),
        profile('ws-1', ProfileKind.vlessWsTls),
        profile('hy2-1', ProfileKind.hysteria2),
        profile('unsupported', ProfileKind.other),
      ];

      final selected = selector.candidates(
        profiles,
        LocationChoice.auto,
        maxAttempts: 99,
      );
      expect(selected.map((p) => p.id).toSet(), {
        'reality-1',
        'xhttp-1',
        'ws-1',
        'hy2-1',
      });
      expect(selected.map((p) => p.id).toSet().length, selected.length);
    });

    test('skips unavailable families and keeps remaining preference order', () {
      final profiles = [
        profile('hy2-1', ProfileKind.hysteria2),
        profile('reality-1', ProfileKind.vlessRealityTcp),
        profile('hy2-2', ProfileKind.hysteria2),
      ];

      expect(
        selector
            .candidates(profiles, LocationChoice.auto, maxAttempts: 3)
            .map((p) => p.id),
        ['hy2-1', 'reality-1', 'hy2-2'],
      );
    });

    test('auto handles empty input, unknown locations, and missing families', () {
      expect(
        selector.candidates(const [], LocationChoice.auto),
        isEmpty,
      );
      final profiles = [
        profile(
          'unknown-xhttp',
          ProfileKind.vlessXhttp,
          location: ServerLocation.unknown,
        ),
        profile('fi-reality', ProfileKind.vlessRealityTcp),
      ];

      expect(
        selector
            .candidates(profiles, LocationChoice.auto)
            .map((p) => p.id),
        ['unknown-xhttp', 'fi-reality'],
      );
    });

    test('country choice is strict and auto remains country agnostic', () {
      final profiles = [
        profile('fi-xhttp', ProfileKind.vlessXhttp),
        profile(
          'us-xhttp',
          ProfileKind.vlessXhttp,
          location: ServerLocation.usa,
        ),
        profile(
          'unknown-ws',
          ProfileKind.vlessWsTls,
          location: ServerLocation.unknown,
        ),
      ];

      expect(
        selector
            .candidates(profiles, LocationChoice.finland, maxAttempts: 9)
            .map((p) => p.id),
        ['fi-xhttp'],
      );
      expect(
        selector
            .candidates(profiles, LocationChoice.usa, maxAttempts: 9)
            .map((p) => p.id),
        ['us-xhttp'],
      );
      expect(
        selector
            .candidates(profiles, LocationChoice.auto, maxAttempts: 9)
            .map((p) => p.id)
            .toSet(),
        {'fi-xhttp', 'us-xhttp', 'unknown-ws'},
      );
    });

    test('non-positive budgets are empty and input remains unchanged', () {
      final profiles = [
        profile('reality-1', ProfileKind.vlessRealityTcp),
        profile('xhttp-1', ProfileKind.vlessXhttp),
        profile('ws-1', ProfileKind.vlessWsTls),
      ];
      final originalIds = profiles.map((p) => p.id).toList();

      expect(
        selector.candidates(profiles, LocationChoice.auto, maxAttempts: 0),
        isEmpty,
      );
      expect(
        selector.candidates(profiles, LocationChoice.auto, maxAttempts: -1),
        isEmpty,
      );
      selector.candidates(profiles, LocationChoice.auto, maxAttempts: 3);
      expect(profiles.map((p) => p.id), originalIds);
    });
  });
}
