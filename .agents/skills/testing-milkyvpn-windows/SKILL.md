---
name: testing-milkyvpn-windows
description: Run and UI-test the MilkyVPN Flutter app (Android-first codebase) on a Windows box — toolchain setup, local subscription fixtures that pass the SSRF URL guard, and the app's key UI paths/strings.
---

# Testing MilkyVPN on Windows

## Toolchain
- Flutter is at `C:/Users/Administrator/flutter`. Invoke `flutter.bat` (e.g. `"C:/Users/Administrator/flutter/bin/flutter.bat" test`) — the unix `flutter` script fails on this Windows box.
- `flutter run -d windows` needs: (a) a `windows/` runner — scaffold once via `flutter create --platforms=windows .` (untracked temp files, don't commit); (b) Visual Studio Build Tools with the **VC.ATL component** — `flutter_secure_storage_windows` includes `atlstr.h` and fails without it:
  - `choco install visualstudio2022buildtools -y --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"`
  - `vs_BuildTools.exe modify --installPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" --add Microsoft.VisualStudio.Component.VC.ATL --passive --norestart --wait` (bootstrapper: https://aka.ms/vs/17/release/vs_BuildTools.exe; args may be mangled by Git Bash — run via `cmd //c`).
- Web target is impossible: `subscription_repository.dart` imports `dart:io`.
- Golden/widget tests require machine TZ = Russian Standard Time (UTC+3).

## App behavior on Windows desktop (expected, not bugs)
- `MissingPluginException` on `homes.milky.vpn/vpn_state` and `.../links` channels at boot — handled gracefully, safe to ignore.
- `flutter_secure_storage` (KeystoreSecureStore), `shared_preferences`, `url_launcher` all work on Windows — imports persist.
- Connect orb → `unsupported_platform` → error sheet "Нет подходящих серверов" (noServers). Expected: no VPN engine exists off-Android. Diagnostics Ядро = `unavailable`.
- UI is Russian-locale (`locale: 'ru'` hardcoded). Key strings: "Добавить подписку" (import title + button), "Добавить" (import CTA), "Подписка добавлена" (success), "N профилей найдено" / "N совместимых с приложением", "Не удалось загрузить подписку. Проверьте ссылку и попробуйте снова." (all import errors incl. SSRF rejects).
- Import TextField has `obscureText: true` — typed URLs show as dots; an X suffix icon clears field+error and removes focus (re-click the field before typing).
- Boot flow: 3-page onboarding (Продолжить → Понятно, продолжить → Добавить подписку) → MilkyShell tabs Главная/Подписка/Настройки. No per-profile protocol labels exist anywhere in UI — protocol-layer proof is only via counts (success sheet, card Профилей получено/Совместимо, diagnostics "parsed/deduped/compatible").

## Local subscription fixtures vs the SSRF guard
`SubscriptionUrlPolicy` rejects localhost/.local/.internal/.lan/.home suffixes and private/loopback/link-local IP *literals* — it inspects the URL string only, so `http://127.0.0.1:port/...` is rejected but a public-looking hostname mapped in `C:\Windows\System32\drivers\etc\hosts` to 127.0.0.1 passes (`feed.testfixture-example.com` works; the code documents this caveat). Serve fixtures with a tiny python HTTP server (`python` = C:\Python314\python.exe) and send `Subscription-Userinfo: expire=<unix>` to exercise the expiry path. Feed bodies may be plaintext URI lists or base64 — both decode.
- Real feed for end-to-end: `https://sub.example.com/s/EXAMPLE_TOKEN_REPLACE_WITH_YOURS` → 16 profiles, all compatible, expiry ~2100.
- Crafted mixed fixture: `test/fixtures/mixed_formats.txt` + server `C:\Users\Administrator\sub_server.py` (port 8811) → 9 parsed / 6 compatible / 1 malformed (covers vmess/trojan/ss/kal2 + tuic + plugin + garbage).