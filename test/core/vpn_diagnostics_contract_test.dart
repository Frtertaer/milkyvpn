import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:milkyvpn/core/errors/milky_error.dart';
import 'package:milkyvpn/core/subscription/vpn_profile.dart';
import 'package:milkyvpn/core/vpn/vpn_bridge.dart';
import 'package:milkyvpn/core/vpn/vpn_controller.dart';
import 'package:milkyvpn/features/settings/diagnostics_screen.dart';

import 'vpn_controller_test.dart' show FakeBridge, p;

class _CleanupFailureBridge extends FakeBridge {
  @override
  Future<void> connect(VpnProfile profile) async {
    connectCalls.add(profile.id);
    emit(
      VpnSnapshot(
        state: VpnState.error,
        profileId: profile.id,
        errorCode: 'core_start_failed',
      ),
    );
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    throw VpnBridgeException('disconnect_failed');
  }
}

void main() {
  test('native lifecycle stages survive the bridge map', () {
    final snapshot = VpnSnapshot.fromMap(<String, Object?>{
      'state': 'error',
      'errorCode': 'config_asset_missing',
      'lastSuccessfulStage': 'TUN_FD_RECEIVED',
      'firstFailedStage': 'CONFIG_VALIDATED',
    });

    expect(snapshot.state, VpnState.error);
    expect(snapshot.lastSuccessfulStage, 'TUN_FD_RECEIVED');
    expect(snapshot.firstFailedStage, 'CONFIG_VALIDATED');
  });

  test('missing config asset has a stable safe classification', () {
    final error = MilkyError.fromCode('config_asset_missing');

    expect(error.kind, MilkyErrorKind.tunnelFailed);
    expect(error.diagnosticsCode, 'CONFIG_ASSET_MISSING');
    expect(error.category, MilkyFailureCategory.configFailure);
  });

  test(
    'attempt cleanup failure preserves the native connection error',
    () async {
      final bridge = _CleanupFailureBridge();
      final controller = VpnController(bridge: bridge, maxAttempts: 1);

      expect(
        await controller.connect([p('fi')], LocationChoice.finland),
        isFalse,
      );
      expect(bridge.disconnectCalls, 1);
      expect(controller.lastErrorClass, 'core_start_failed');
      controller.dispose();
    },
  );

  test(
    'explicit user disconnect still reports its own bridge failure',
    () async {
      final bridge = _CleanupFailureBridge();
      final controller = VpnController(bridge: bridge);

      await controller.disconnect();

      expect(controller.lastErrorClass, 'disconnect_failed');
      controller.dispose();
    },
  );

  testWidgets(
    'long diagnostic code remains selectable on one scrollable line',
    (tester) async {
      const code = 'CONFIG_ASSET_MISSING_FROM_PACKAGED_ANDROID_APPLICATION';
      await tester.pumpWidget(
        const MaterialApp(
          home: MediaQuery(
            data: MediaQueryData(textScaler: TextScaler.linear(2)),
            child: Scaffold(
              body: Center(
                child: SizedBox(
                  width: 180,
                  child: DiagnosticsCodeLine(
                    value: code,
                    style: TextStyle(fontSize: 14),
                  ),
                ),
              ),
            ),
          ),
        ),
      );

      expect(tester.takeException(), isNull);
      final codeText = find.byType(SelectableText);
      final selectable = tester.widget<SelectableText>(codeText);
      expect(selectable.maxLines, 1);
      final scroller = tester.widget<SingleChildScrollView>(
        find.ancestor(
          of: codeText,
          matching: find.byType(SingleChildScrollView),
        ),
      );
      expect(scroller.scrollDirection, Axis.horizontal);
      final scrollables = tester.stateList<ScrollableState>(
        find.descendant(
          of: find.byType(SingleChildScrollView),
          matching: find.byType(Scrollable),
        ),
      );
      expect(
        scrollables.any((state) => state.position.maxScrollExtent > 0),
        isTrue,
      );
      expect(
        tester
            .getRect(find.byType(EditableText))
            .overlaps(tester.getRect(find.byType(SingleChildScrollView))),
        isTrue,
      );
    },
  );
}
