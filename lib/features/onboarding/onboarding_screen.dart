import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../app/app_info.dart';
import '../../app/app_settings.dart';
import '../../core/subscription/subscription_repository.dart';
import '../../design/milky_aurora.dart';
import '../../design/milky_brand.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_connect_orb.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_motion.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';
import '../import/import_screen.dart';

/// Three screens, no walls of text: what it is, how it works, add your subscription.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  int _page = 0;

  @override
  Widget build(BuildContext context) {
    final t = S.of(context);
    final c = context.milky;
    final repo = context.watch<SubscriptionRepository>();

    return MilkyBackdrop(
      intensity: 0.8,
      glowAnchor: const Alignment(0, -0.2),
      child: Scaffold(
        backgroundColor: Colors.transparent,
        body: SafeArea(
          child: MilkyColumn(
            child: Column(
              children: [
                Expanded(
                  child: AnimatedSwitcher(
                    duration: MilkyMotion.base,
                    switchInCurve: MilkyMotion.standard,
                    transitionBuilder: (child, anim) => FadeTransition(
                      opacity: anim,
                      child: SlideTransition(
                        position: Tween<Offset>(begin: const Offset(0.06, 0), end: Offset.zero).animate(anim),
                        child: child,
                      ),
                    ),
                    child: _buildPage(context, t, repo),
                  ),
                ),
                _Dots(index: _page),
                const SizedBox(height: MilkySpace.lg),
              ],
            ),
          ),
        ),
        bottomNavigationBar: SafeArea(
          top: false,
          child: MilkyColumn(
            padding: const EdgeInsets.fromLTRB(MilkySpace.screen, 0, MilkySpace.screen, MilkySpace.lg),
            child: _footer(context, t, repo),
          ),
        ),
      ),
    );
  }

  Widget _buildPage(BuildContext context, S t, SubscriptionRepository repo) {
    switch (_page) {
      case 0:
        return _PageOne(key: const ValueKey('ob1'), t: t);
      case 1:
        return _PageTwo(key: const ValueKey('ob2'), t: t);
      default:
        return _PageThree(key: const ValueKey('ob3'), t: t, hasSubscription: repo.hasSubscription);
    }
  }

  Widget _footer(BuildContext context, S t, SubscriptionRepository repo) {
    switch (_page) {
      case 0:
        return MilkyPrimaryButton(
          label: t.cont,
          onPressed: () {
            MilkyHaptics.tap();
            setState(() => _page = 1);
          },
        );
      case 1:
        return MilkyPrimaryButton(
          label: t.understood,
          onPressed: () {
            MilkyHaptics.tap();
            if (repo.hasSubscription) {
              _finish();
            } else {
              setState(() => _page = 2);
            }
          },
        );
      default:
        return Column(
          children: [
            MilkyPrimaryButton(
              label: t.addSubscription,
              icon: Icons.link_rounded,
              onPressed: () async {
                final ok = await Navigator.of(context).push<bool>(MaterialPageRoute<bool>(builder: (_) => const ImportScreen()));
                if (ok == true && context.mounted) _finish();
              },
            ),
            const SizedBox(height: MilkySpace.sm),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                MilkyLinkButton(label: t.help, icon: Icons.help_outline_rounded, color: context.milky.textMuted, onPressed: _openSupport),
                const SizedBox(width: MilkySpace.lg),
                MilkyLinkButton(label: t.noSubscriptionYet, color: context.milky.textFaint, onPressed: _finish),
              ],
            ),
          ],
        );
    }
  }

  Future<void> _openSupport() async {
    final uri = Uri.parse(kSupportUrl);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  void _finish() => context.read<AppSettings>().setOnboardingDone();
}

// ------------------------------------------------------------------ pages

class _PageOne extends StatelessWidget {
  const _PageOne({super.key, required this.t});

  final S t;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: MilkySpace.xxl),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const MilkyConnectOrb(state: MilkyOrbState.idle, onTap: null, enabled: false, size: 190, semanticLabel: 'MilkyVPN'),
          const SizedBox(height: MilkySpace.huge),
          Text(t.tagline, textAlign: TextAlign.center, style: MilkyType.display),
          const SizedBox(height: MilkySpace.md),
          Text(t.taglineBody, textAlign: TextAlign.center, style: MilkyType.body.copyWith(color: c.textMuted)),
        ],
      ),
    );
  }
}

class _PageTwo extends StatelessWidget {
  const _PageTwo({super.key, required this.t});

  final S t;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: MilkySpace.xxl),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const SizedBox(height: MilkySpace.md),
          _FlowStep(icon: Icons.smartphone_rounded, label: t.devicePhone),
          const _FlowArrow(),
          _FlowStep(icon: null, label: t.appName, hero: true),
          const _FlowArrow(),
          _FlowStep(icon: Icons.public_rounded, label: t.internet),
          const SizedBox(height: MilkySpace.xxl),
          Text(t.disclosureTitle, textAlign: TextAlign.center, style: MilkyType.headline),
          const SizedBox(height: MilkySpace.md),
          Text(t.disclosureBody, textAlign: TextAlign.center, style: MilkyType.bodySmall.copyWith(color: c.textMuted)),
          const SizedBox(height: MilkySpace.xxl),
        ],
      ),
    );
  }
}

class _FlowStep extends StatelessWidget {
  const _FlowStep({super.key, required this.icon, required this.label, this.sublabel, this.hero = false});

  final IconData? icon;
  final String label;
  final String? sublabel;
  final bool hero;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return MilkyGlassCard(
      padding: EdgeInsets.symmetric(horizontal: MilkySpace.xl, vertical: hero ? MilkySpace.md : MilkySpace.md),
      tone: hero ? MilkyGlassTone.accent : MilkyGlassTone.neutral,
      child: Row(
        children: [
          if (hero)
            const MilkyLogoMark(size: 34)
          else
            Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(color: c.accentSoft, borderRadius: BorderRadius.circular(12)),
              child: Icon(icon, size: 19, color: c.accent),
            ),
          const SizedBox(width: MilkySpace.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: MilkyType.subtitle),
                if (sublabel != null) Text(sublabel!, style: MilkyType.bodySmall.copyWith(color: c.textMuted)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _FlowArrow extends StatelessWidget {
  const _FlowArrow({super.key});

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: MilkySpace.sm),
      child: Column(
        children: [
          Container(width: 1.5, height: 12, color: c.strokeStrong),
          Icon(Icons.arrow_downward_rounded, size: 14, color: c.accent),
        ],
      ),
    );
  }
}

class _PageThree extends StatelessWidget {
  const _PageThree({super.key, required this.t, required this.hasSubscription});

  final S t;
  final bool hasSubscription;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: MilkySpace.xxl),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(t.importTitle, textAlign: TextAlign.center, style: MilkyType.display.copyWith(fontSize: 30)),
          const SizedBox(height: MilkySpace.md),
          Text(t.importBody, textAlign: TextAlign.center, style: MilkyType.body.copyWith(color: c.textMuted)),
          const SizedBox(height: MilkySpace.xxl),
          MilkyGlassCard(
            padding: const EdgeInsets.all(MilkySpace.xl),
            tone: MilkyGlassTone.accent,
            child: Column(
              children: [
                Container(
                  width: 56,
                  height: 56,
                  decoration: BoxDecoration(color: c.accentSoft, borderRadius: BorderRadius.circular(18)),
                  child: Icon(Icons.link_rounded, size: 26, color: c.accent),
                ),
                const SizedBox(height: MilkySpace.md),
                Text('https://sub.milky.homes/s/…', style: MilkyType.bodySmall.copyWith(color: c.textFaint, fontFamily: 'monospace')),
                const SizedBox(height: MilkySpace.md),
                Text(
                  hasSubscription ? t.importOk : t.subscriptionHint,
                  textAlign: TextAlign.center,
                  style: MilkyType.bodySmall.copyWith(color: c.textMuted),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _Dots extends StatelessWidget {
  const _Dots({required this.index});

  final int index;

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        for (var i = 0; i < 3; i++)
          AnimatedContainer(
            duration: MilkyMotion.base,
            curve: MilkyMotion.standard,
            margin: const EdgeInsets.symmetric(horizontal: 3),
            width: i == index ? 20 : 6,
            height: 6,
            decoration: BoxDecoration(
              color: i == index ? c.accent : c.strokeStrong,
              borderRadius: MilkyRadius.pillRadius,
            ),
          ),
      ],
    );
  }
}
