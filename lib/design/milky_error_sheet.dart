import 'package:flutter/material.dart';

import '../core/errors/milky_error.dart';
import '../l10n/milky_strings.dart';
import 'milky_buttons.dart';
import 'milky_colors.dart';
import 'milky_sheet.dart';
import 'milky_theme.dart';
import 'milky_tokens.dart';

/// The failure surface. It never contains a raw exception name or code — only a calm
/// Russian explanation and the three things the user can actually do.
class MilkyErrorSheet extends StatelessWidget {
  const MilkyErrorSheet({
    super.key,
    required this.error,
    this.subtitle,
    this.onRetry,
    this.onChooseServer,
    this.onOpenDiagnostics,
    this.onAddSubscription,
    this.onOpenVpnSettings,
  });

  final MilkyError error;

  /// Optional extra line, e.g. "Ищем лучший сервер… 3 из 4".
  final String? subtitle;

  final VoidCallback? onRetry;
  final VoidCallback? onChooseServer;
  final VoidCallback? onOpenDiagnostics;
  final VoidCallback? onAddSubscription;
  final VoidCallback? onOpenVpnSettings;

  static Future<void> show(
    BuildContext context, {
    required MilkyError error,
    String? subtitle,
    VoidCallback? onRetry,
    VoidCallback? onChooseServer,
    VoidCallback? onOpenDiagnostics,
    VoidCallback? onAddSubscription,
    VoidCallback? onOpenVpnSettings,
  }) {
    return showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: context.milky.scrim,
      builder: (_) => MilkyErrorSheet(
        error: error,
        subtitle: subtitle,
        onRetry: onRetry,
        onChooseServer: onChooseServer,
        onOpenDiagnostics: onOpenDiagnostics,
        onAddSubscription: onAddSubscription,
        onOpenVpnSettings: onOpenVpnSettings,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final tone =
        error.kind == MilkyErrorKind.subscriptionProblem ||
            error.kind == MilkyErrorKind.noServers
        ? c.warning
        : c.danger;

    return MilkySheetFrame(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Center(
            child: Container(
              width: 64,
              height: 64,
              decoration: BoxDecoration(
                color: tone.withValues(alpha: .14),
                shape: BoxShape.circle,
              ),
              child: Icon(Icons.wifi_off_rounded, size: 28, color: tone),
            ),
          ),
          const SizedBox(height: 20),
          Text(
            t.errorTitle(error.kind),
            textAlign: TextAlign.center,
            style: MilkyType.headline.copyWith(color: c.text),
          ),
          const SizedBox(height: 10),
          Text(
            t.errorBody(error.kind),
            textAlign: TextAlign.center,
            style: MilkyType.body.copyWith(color: c.textMuted),
          ),
          if (subtitle != null) ...[
            const SizedBox(height: 12),
            Text(
              subtitle!,
              textAlign: TextAlign.center,
              style: MilkyType.bodySmall.copyWith(color: c.textMuted),
            ),
          ],
          const SizedBox(height: 24),
          ..._buttons(context, t),
          if (onOpenDiagnostics != null) ...[
            const SizedBox(height: 12),
            MilkyLinkButton(
              label: t.diagnostics,
              color: c.textMuted,
              onPressed: () {
                Navigator.of(context).pop();
                onOpenDiagnostics!();
              },
            ),
          ],
        ],
      ),
    );
  }

  List<Widget> _buttons(BuildContext context, S t) {
    final out = <Widget>[];
    void add(MilkyErrorAction a) {
      switch (a) {
        case MilkyErrorAction.retry:
          out.add(
            MilkyPrimaryButton(
              label: t.errorAction(a),
              onPressed: onRetry == null
                  ? null
                  : () {
                      Navigator.of(context).pop();
                      onRetry!();
                    },
            ),
          );
          break;
        case MilkyErrorAction.chooseServer:
          out.add(
            MilkyGhostButton(
              label: t.errorAction(a),
              icon: Icons.public_rounded,
              onPressed: onChooseServer == null
                  ? null
                  : () {
                      Navigator.of(context).pop();
                      onChooseServer!();
                    },
            ),
          );
          break;
        case MilkyErrorAction.addSubscription:
          out.add(
            MilkyPrimaryButton(
              label: t.errorAction(a),
              icon: Icons.link_rounded,
              onPressed: onAddSubscription == null
                  ? null
                  : () {
                      Navigator.of(context).pop();
                      onAddSubscription!();
                    },
            ),
          );
          break;
        case MilkyErrorAction.openVpnSettings:
          out.add(
            MilkyGhostButton(
              label: t.errorAction(a),
              icon: Icons.settings_rounded,
              onPressed: onOpenVpnSettings == null
                  ? null
                  : () {
                      Navigator.of(context).pop();
                      onOpenVpnSettings!();
                    },
            ),
          );
          break;
        case MilkyErrorAction.diagnostics:
        case MilkyErrorAction.dismiss:
          break;
      }
    }

    for (final a in error.actions) {
      add(a);
    }
    if (out.isEmpty) {
      out.add(
        MilkyGhostButton(
          label: t.errorAction(MilkyErrorAction.dismiss),
          onPressed: () => Navigator.of(context).pop(),
        ),
      );
    }
    return [
      for (var i = 0; i < out.length; i++) ...[
        if (i > 0) const SizedBox(height: MilkySpace.md),
        out[i],
      ],
    ];
  }
}

/// Neutral confirmation sheet (used for destructive actions such as removing a subscription).
Future<bool> showMilkyConfirmSheet(
  BuildContext context, {
  required String title,
  required String body,
  required String confirmLabel,
  required String cancelLabel,
  bool danger = true,
}) async {
  final c = context.milky;
  final result = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    barrierColor: c.scrim,
    builder: (ctx) => MilkySheetFrame(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(title, style: MilkyType.headline.copyWith(color: c.text)),
          const SizedBox(height: 12),
          Text(body, style: MilkyType.body.copyWith(color: c.textMuted)),
          const SizedBox(height: 24),
          MilkyPrimaryButton(
            label: confirmLabel,
            tone: danger ? MilkyButtonTone.danger : MilkyButtonTone.accent,
            onPressed: () => Navigator.of(ctx).pop(true),
          ),
          const SizedBox(height: 12),
          MilkyGhostButton(
            label: cancelLabel,
            onPressed: () => Navigator.of(ctx).pop(false),
          ),
        ],
      ),
    ),
  );
  return result ?? false;
}
