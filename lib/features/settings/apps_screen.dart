import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/vpn/vpn_bridge.dart';
import '../../design/milky_buttons.dart';
import '../../design/milky_colors.dart';
import '../../design/milky_glass.dart';
import '../../design/milky_screen.dart';
import '../../design/milky_theme.dart';
import '../../design/milky_tokens.dart';
import '../../l10n/milky_strings.dart';

/// Per-app split tunneling (Android VpnService): pick which apps' traffic
/// enters the tunnel. The native side applies the filter on (re)connect.
class AppsScreen extends StatefulWidget {
  const AppsScreen({super.key});

  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  List<InstalledApp> _apps = const [];
  String _mode = 'all';
  final Set<String> _selected = {};
  String _query = '';
  bool _loading = true;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final bridge = context.read<VpnBridge>();
    try {
      final apps = await bridge.listInstalledApps();
      final cfg = await bridge.splitApps();
      if (!mounted) return;
      setState(() {
        _apps = apps;
        _mode = cfg.mode;
        _selected
          ..clear()
          ..addAll(cfg.packages);
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _save() async {
    final bridge = context.read<VpnBridge>();
    final t = S.of(context);
    setState(() => _saving = true);
    try {
      await bridge.setSplitApps(
        SplitAppsConfig(mode: _mode, packages: _selected.toList()),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(t.splitApplied)));
      Navigator.of(context).pop();
    } catch (_) {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.milky;
    final t = S.of(context);
    final filtered = _query.isEmpty
        ? _apps
        : _apps
              .where(
                (a) =>
                    a.label.toLowerCase().contains(_query) ||
                    a.packageName.toLowerCase().contains(_query),
              )
              .toList();

    return MilkyScreen(
      appBar: AppBar(
        title: Text(t.splitApps, style: MilkyType.title),
        leading: MilkyIconButton(
          icon: Icons.arrow_back_rounded,
          size: 38,
          onPressed: () => Navigator.of(context).pop(),
        ),
        actions: [
          TextButton(
            onPressed: _saving || _loading ? null : _save,
            child: Text(
              t.save,
              style: MilkyType.label.copyWith(color: c.accent),
            ),
          ),
        ],
      ),
      child: SafeArea(
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: MilkySpace.screen,
                    ),
                    child: MilkyGlassCard(
                      padding: const EdgeInsets.all(MilkySpace.md),
                      child: Column(
                        children: [
                          _modeRow(t.splitModeAll, 'all', c, t),
                          _modeRow(t.splitModeAllow, 'allow', c, t),
                          _modeRow(t.splitModeBlock, 'block', c, t),
                        ],
                      ),
                    ),
                  ),
                  if (_mode != 'all')
                    Padding(
                      padding: const EdgeInsets.fromLTRB(
                        MilkySpace.screen,
                        MilkySpace.sm,
                        MilkySpace.screen,
                        MilkySpace.xs,
                      ),
                      child: TextField(
                        decoration: InputDecoration(
                          hintText: t.searchApps,
                          prefixIcon: const Icon(Icons.search_rounded),
                          isDense: true,
                        ),
                        onChanged: (v) =>
                            setState(() => _query = v.trim().toLowerCase()),
                      ),
                    ),
                  Expanded(
                    child: _mode == 'all'
                        ? Center(
                            child: Padding(
                              padding: const EdgeInsets.all(MilkySpace.xl),
                              child: Text(
                                t.splitAllHint,
                                textAlign: TextAlign.center,
                                style: MilkyType.bodySmall.copyWith(
                                  color: c.textMuted,
                                ),
                              ),
                            ),
                          )
                        : ListView.builder(
                            padding: const EdgeInsets.fromLTRB(
                              MilkySpace.screen,
                              0,
                              MilkySpace.screen,
                              MilkySpace.xxl,
                            ),
                            itemCount: filtered.length,
                            itemBuilder: (context, i) {
                              final a = filtered[i];
                              final on = _selected.contains(a.packageName);
                              return CheckboxListTile(
                                dense: true,
                                controlAffinity:
                                    ListTileControlAffinity.leading,
                                title: Text(
                                  a.label,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: MilkyType.body,
                                ),
                                subtitle: Text(
                                  a.packageName,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: MilkyType.mono.copyWith(
                                    fontSize: 11,
                                    color: c.textMuted,
                                  ),
                                ),
                                value: on,
                                onChanged: (v) => setState(() {
                                  if (v ?? false) {
                                    _selected.add(a.packageName);
                                  } else {
                                    _selected.remove(a.packageName);
                                  }
                                }),
                              );
                            },
                          ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _modeRow(String label, String value, MilkyColors c, S t) {
    final on = _mode == value;
    return ListTile(
      dense: true,
      leading: Icon(
        on
            ? Icons.radio_button_checked_rounded
            : Icons.radio_button_off_rounded,
        size: 20,
        color: on ? c.accent : c.textMuted,
      ),
      title: Text(label, style: MilkyType.body),
      subtitle: value == 'allow'
          ? Text(
              t.splitAllowHint,
              style: MilkyType.bodySmall.copyWith(color: c.textMuted),
            )
          : value == 'block'
          ? Text(
              t.splitBlockHint,
              style: MilkyType.bodySmall.copyWith(color: c.textMuted),
            )
          : null,
      onTap: () => setState(() => _mode = value),
    );
  }
}
