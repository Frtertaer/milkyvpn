import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';

import '../../app/app_info.dart';
import '../../core/update/app_update.dart';
import '../../core/vpn/vpn_bridge.dart';
import '../../l10n/milky_strings.dart';

/// Self-update via GitHub Releases: checks for a newer `vX.Y.Z` tag, offers
/// to download the platform asset (per-ABI APK / Inno Setup exe) and hands
/// it to the OS installer. Silent when nothing newer exists or the platform
/// has no asset — [manual] forces the result to surface either way.
class UpdateFlow {
  UpdateFlow._();

  static bool _checked = false;

  /// One silent check per launch — call from the home screen's first frame.
  /// Shows the update dialog only when a newer release has an asset for
  /// this platform.
  static Future<void> checkOnLaunch(BuildContext context) async {
    if (_checked) return;
    _checked = true;
    await check(context, manual: false);
  }

  /// Checks for an update; when [manual], also reports "already latest" and
  /// network failures. Safe to call repeatedly — the result is cached.
  static Future<void> check(BuildContext context, {required bool manual}) async {
    final bridge = context.read<VpnBridge>();
    final t = S.of(context);
    final release = await AppUpdate.latest();
    if (!context.mounted) return;
    if (release == null) {
      if (manual) _snack(context, t.updateCheckFailed);
      return;
    }
    final current = 'v${kAppVersion.split('+').first}';
    if (AppUpdate.compareVersion(release.tag, current) <= 0) {
      if (manual) _snack(context, t.updateLatest);
      return;
    }
    String abi = '';
    if (Platform.isAndroid) {
      try {
        abi = (await bridge.deviceInfo())['abi']?.toString() ?? '';
      } on Object {
        // A wedged bridge just means "unknown ABI" — the picker then
        // prefers arm64, the dominant target.
      }
    }
    if (!context.mounted) return;
    final asset = AppUpdate.pickAsset(
      release,
      isAndroid: Platform.isAndroid,
      isWindows: Platform.isWindows,
      abi: abi,
    );
    if (asset == null) {
      // No artifact for this platform (macOS/Linux today) — stay silent on
      // auto-check; on manual check say "latest" rather than lying.
      if (manual) _snack(context, t.updateLatest);
      return;
    }
    if (!context.mounted) return;
    final go = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(t.updateAvailableTitle),
        content: Text(t.updateAvailableBody(release.tag, current)),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: Text(t.updateLater),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(t.updateNow),
          ),
        ],
      ),
    );
    if (go != true || !context.mounted) return;
    await _downloadAndInstall(context, bridge, asset);
  }

  static Future<void> _downloadAndInstall(
    BuildContext context,
    VpnBridge bridge,
    ReleaseAsset asset,
  ) async {
    final t = S.of(context);
    final progress = ValueNotifier<double>(0);
    // Progress dialog — dismissed when install intent is handed off or on
    // failure.
    unawaited(
      showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => AlertDialog(
          title: Text(t.updateDownloading),
          content: ValueListenableBuilder<double>(
            valueListenable: progress,
            builder: (_, v, __) => LinearProgressIndicator(value: v == 0 ? null : v),
          ),
        ),
      ),
    );
    String? errorCode;
    try {
      final dir = await getTemporaryDirectory();
      final updates = Directory('${dir.path}/updates');
      await updates.create(recursive: true);
      final dest = '${updates.path}/${asset.name}';
      await AppUpdate.download(
        asset,
        dest,
        onProgress: (v) => progress.value = v,
      );
      final ok = await bridge.installUpdate(dest);
      if (!ok) errorCode = 'unsupported_platform';
    } on VpnBridgeException catch (e) {
      errorCode = e.code;
    } on Object {
      errorCode = 'download_failed';
    }
    if (context.mounted) {
      Navigator.of(context, rootNavigator: true).pop();
      if (errorCode != null) {
        _snack(
          context,
          errorCode == 'install_unknown_apps'
              ? t.updateNeedPerm
              : t.updateFailed,
        );
      }
    }
  }

  static void _snack(BuildContext context, String text) {
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(text)));
  }
}
