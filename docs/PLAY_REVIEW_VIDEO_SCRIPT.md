# Play Review Video Script (≤ 90 s)

Purpose: demonstrate VpnService usage, FGS `specialUse` justification, and the in‑app disclosure for Google Play review. Record on a real device (screen recording + status bar visible). No narration required; on‑screen captions in English.

| Time | Action | Caption |
|---|---|---|
| 0–8 s | Launch MilkyVPN, onboarding screen 1 (logo, tagline) → Next | "MilkyVPN — a VPN client" |
| 8–18 s | Screen 2: VPN disclosure text, tap "Понятно, продолжить" | "In‑app disclosure: the app creates a VPN tunnel and will ask Android for permission" |
| 18–28 s | Screen 3 → "Добавить подписку" → paste subscription URL → "Импортировать" → list loaded (e.g. "16 серверов") | "User adds their own subscription; stored encrypted on device" |
| 28–40 s | Home: tap "Подключить" → **Android system VPN consent dialog** appears → tap OK | "Standard VpnService.prepare() consent" |
| 40–52 s | State "Подключение…" → "Подключено", timer starts; pull down shade: **persistent notification with Disconnect** | "Foreground service (specialUse) with persistent notification while the tunnel is active" |
| 52–62 s | Open browser → https://ifconfig.me shows server country | "Traffic really goes through the tunnel; status is only green after a real check" |
| 62–72 s | Back to app, tap "Отключить" → "Не подключено", notification disappears | "Clean disconnect; service stops, notification removed" |
| 72–82 s | Settings → Diagnostics → "Скопировать диагностику" → show text with `••••••` redactions | "No analytics; diagnostics only on demand and redacted" |
| 82–90 s | Settings → Privacy policy link | "Privacy policy linked in‑app" |

## Reviewer notes (paste into "App access" instructions)
```
MilkyVPN requires a subscription URL to connect.
Test subscription (review only, limited validity): https://sub.milky.homes/s/<REVIEW_TOKEN>   <- OWNER MUST PROVIDE
Steps: Open app → onboarding → "Добавить подписку" → paste URL → "Импортировать" → "Подключить" → accept the Android VPN dialog.
The status shows "Подключено" only after an HTTPS check through the tunnel succeeds.
No account, no billing, no ads, no analytics.
```
