# VpnService Declaration (Google Play — Play Console → App content → VPN)

> Fill the Play Console "VpnService" declaration form with the statements below. Keep them truthful; update if behaviour changes.

## Core functionality

MilkyVPN's **primary and only purpose** is to provide a VPN: it creates a device‑wide tunnel (`android.net.VpnService`) and routes the device's traffic to a remote VPN server chosen from the user's subscription (VLESS + Reality / TLS / XHTTP, Hysteria2 via the Xray‑core engine). The VPN is not a side feature of another product.

## How VpnService is used

- `VpnService.prepare()` is called before every connection; the user sees the standard Android consent dialog and can decline.
- The service runs as a **foreground service** (`foregroundServiceType="specialUse"`, subtype `vpn`) with a persistent notification that shows the state and offers a "Disconnect" action.
- TUN interface: address `10.10.14.1/30`, default route `0.0.0.0/0`, DNS `1.1.1.1`/`8.8.8.8` sent through the tunnel; the app itself is excluded (`addDisallowedApplication`) to avoid a routing loop.
- `onRevoke()` tears the tunnel down immediately when another VPN app or the user revokes permission.
- The app supports **Always‑on VPN** (`android.net.VpnService.SUPPORTS_ALWAYS_ON`) and offers a shortcut to the system VPN settings.
- The connection is reported as "Connected" **only after** an HTTPS probe succeeds through the tunnel.

## Data handling

- No traffic logging, no DNS logging, no browsing history.
- No analytics, advertising IDs, trackers or third‑party SDKs.
- Subscription URL and server credentials are stored encrypted with Android Keystore and excluded from backups.
- No user accounts, no personal data collected by the app. See `PRIVACY_POLICY_EN.md`.

## Not used for

- Not used to collect or sell user data, inject ads, modify traffic, or track users.
- Not a proxy/"unblocker" hidden inside another app.
- Not used for monetisation via user traffic.

## Compliance statements (checkboxes in the form)

- [x] Uses VpnService for core VPN functionality.
- [x] Discloses VPN usage in‑app before first use (onboarding screen "Понятно, продолжить").
- [x] Privacy policy is published and linked in the store listing and in‑app (Settings → Privacy).
- [x] Does not manipulate or inject into user traffic.
- [x] Does not collect sensitive data via the tunnel.
- [x] Foreground service with persistent notification while connected.

## Accessing the disclosure

Onboarding, screen 2 of 3 — text explains that the app will request VPN permission, that a system dialog will appear, and that all traffic will go through the tunnel while connected.
