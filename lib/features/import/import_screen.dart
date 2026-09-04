import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../core/security/redactor.dart';
import '../../core/security/subscription_url_policy.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../core/subscription/subscription_stats.dart';
import '../../design/milky_brand.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_screen.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// Subscription import: paste a link, watch it parse, get a real count back.
class ImportScreen extends StatefulWidget {
  const ImportScreen({super.key, this.initialValue = ''});

  final String initialValue;

  @override
  State<ImportScreen> createState() => _ImportScreenState();
}

class _ImportScreenState extends State<ImportScreen> {
  late final TextEditingController _ctrl = TextEditingController(text: widget.initialValue);
  bool _busy = false;
  String? _error;
  SubscriptionSnapshot? _result;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim() ?? '';
    if (!mounted) return;
    final t = S.of(context);
    if (text.isEmpty) {
      setState(() => _error = t.clipboardEmpty);
      return;
    }
    setState(() {
      _ctrl.text = text;
      _error = null;
      _result = null;
    });
    MilkyHaptics.tap();
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t.pasted)));
  }

  Future<void> _import() async {
    final t = S.of(context);
    final repo = context.read<SubscriptionRepository>();
    setState(() {
      _busy = true;
      _error = null;
      _result = null;
    });
    try {
      final snap = await repo.importFromUrl(_ctrl.text);
      if (!mounted) return;
      MilkyHaptics.success();
      setState(() => _result = snap);
    } on SubscriptionFetchException catch (e) {
      if (!mounted) return;
      setState(() => _error = t.errorText(e.errorClass));
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = t.errorText(const Redactor().errorClass(e)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);

    return MilkyScreen(
      appBar: AppBar(
        title: Text(t.addSubscription, style: MilkyType.title),
        leading: MilkyIconButton(
          icon: Icons.close_rounded,
          size: 38,
          tooltip: t.cancel,
          onPressed: () => Navigator.of(context).pop(),
        ),
      ),
      child: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(MilkySpace.screen, MilkySpace.sm, MilkySpace.screen, MilkySpace.xxl),
          child: MilkyColumn(
            child: _result != null ? _success(context, t, c) : _form(context, t, c),
          ),
        ),
      ),
    );
  }

  Widget _form(BuildContext context, S t, MilkyColors c) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SizedBox(height: MilkySpace.md),
        MilkyGlassCard(
          padding: const EdgeInsets.all(MilkySpace.xl),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(t.subscriptionUrlHint, style: MilkyType.label.copyWith(color: c.textFaint)),
              const SizedBox(height: MilkySpace.md),
              TextField(
                controller: _ctrl,
                obscureText: true,
                enableSuggestions: false,
                autocorrect: false,
                keyboardType: TextInputType.url,
                onChanged: (_) {
                  if (_error != null) setState(() => _error = null);
                },
                decoration: InputDecoration(
                  hintText: 'https://sub.milky.homes/s/…',
                  errorText: _error,
                  suffixIcon: _ctrl.text.isEmpty
                      ? null
                      : IconButton(
                          icon: const Icon(Icons.close_rounded, size: 18),
                          onPressed: () => setState(() {
                            _ctrl.clear();
                            _error = null;
                          }),
                        ),
                ),
              ),
              const SizedBox(height: MilkySpace.md),
              MilkyGhostButton(label: t.pasteFromClipboard, icon: Icons.content_paste_rounded, height: 48, onPressed: _busy ? null : _paste),
              const SizedBox(height: MilkySpace.md),
              Text(t.subscriptionHint, style: MilkyType.bodySmall.copyWith(color: c.textFaint)),
            ],
          ),
        ),
        const SizedBox(height: MilkySpace.xl),
        MilkyPrimaryButton(
          label: _busy ? t.importing : t.import,
          loading: _busy,
          onPressed: _busy ? null : _import,
        ),
      ],
    );
  }

  Widget _success(BuildContext context, S t, MilkyColors c) {
    final stats = SubscriptionStats.from(_result);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SizedBox(height: MilkySpace.huge),
        Center(
          child: TweenAnimationBuilder<double>(
            tween: Tween<double>(begin: 0.6, end: 1),
            duration: MilkyMotion.slow,
            curve: MilkyMotion.pop,
            builder: (context, v, child) => Transform.scale(scale: v, child: child),
            child: Container(
              width: 108,
              height: 108,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: c.positiveSoft,
                border: Border.all(color: c.positive.withValues(alpha: 0.4), width: 1.4),
                boxShadow: [BoxShadow(color: c.positive.withValues(alpha: 0.25), blurRadius: 40, spreadRadius: -6)],
              ),
              child: Icon(Icons.check_rounded, size: 52, color: c.positive),
            ),
          ),
        ),
        const SizedBox(height: MilkySpace.xxl),
        Text(t.importOk, textAlign: TextAlign.center, style: MilkyType.display.copyWith(fontSize: 28)),
        const SizedBox(height: MilkySpace.sm),
        Text(
          '${t.profilesFound(stats.profiles)}\n${t.profilesCompatible(stats.compatible)}',
          textAlign: TextAlign.center,
          style: MilkyType.body.copyWith(color: c.textMuted),
        ),
        if (stats.hasDroppedEntries) ...[
          const SizedBox(height: MilkySpace.md),
          MilkyGlassCard(
            tone: MilkyGlassTone.muted,
            padding: const EdgeInsets.all(MilkySpace.lg),
            child: Text(
              [
                t.linesParsed(stats.totalLines),
                if (stats.duplicates > 0) t.duplicatesSkipped(stats.duplicates),
                if (stats.malformed > 0) t.malformedSkipped(stats.malformed),
              ].join(' · '),
              textAlign: TextAlign.center,
              style: MilkyType.bodySmall.copyWith(color: c.textFaint),
            ),
          ),
        ],
        const SizedBox(height: MilkySpace.huge),
        MilkyPrimaryButton(
          label: t.goToConnect,
          icon: Icons.bolt_rounded,
          onPressed: () => Navigator.of(context).pop(true),
        ),
      ],
    );
  }
}

/// Confirmation for a subscription received through a `milkyvpn://import` deep link.
class DeepLinkConfirmScreen extends StatelessWidget {
  const DeepLinkConfirmScreen({super.key, required this.url});

  final Uri url;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    return MilkyScreen(
      child: SafeArea(
        child: Center(
          child: MilkyColumn(
            padding: const EdgeInsets.all(MilkySpace.screen),
            child: MilkyGlassCard(
              radius: MilkyRadius.sheet,
              padding: const EdgeInsets.all(MilkySpace.xxl),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Center(child: MilkyLogoMark(size: 56)),
                  const SizedBox(height: MilkySpace.lg),
                  Text(t.deepLinkTitle, textAlign: TextAlign.center, style: MilkyType.headline),
                  const SizedBox(height: MilkySpace.md),
                  Text(t.deepLinkBody, textAlign: TextAlign.center, style: MilkyType.body.copyWith(color: c.textMuted)),
                  const SizedBox(height: MilkySpace.xxl),
                  MilkyPrimaryButton(
                    label: t.add,
                    onPressed: () async {
                      final repo = context.read<SubscriptionRepository>();
                      final nav = Navigator.of(context);
                      final messenger = ScaffoldMessenger.of(context);
                      try {
                        await repo.importFromUrl(url.toString());
                        messenger.showSnackBar(SnackBar(content: Text(t.importOk)));
                        if (nav.canPop()) nav.pop(true);
                      } on SubscriptionFetchException catch (e) {
                        messenger.showSnackBar(SnackBar(content: Text(t.errorText(e.errorClass))));
                      }
                    },
                  ),
                  const SizedBox(height: MilkySpace.md),
                  MilkyGhostButton(label: t.cancel, onPressed: () => Navigator.of(context).pop()),
                  const SizedBox(height: MilkySpace.lg),
                  Center(
                    child: Text(
                      // Redacted host only: the token is a credential and is never rendered.
                      SubscriptionUrlPolicy.redact(url),
                      style: MilkyType.bodySmall.copyWith(color: c.textFaint),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
