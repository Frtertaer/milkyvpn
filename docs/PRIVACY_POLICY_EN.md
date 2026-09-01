# MilkyVPN Privacy Policy

**Version:** 0.1.0 · **Effective date:** _(set on publication)_
**App:** MilkyVPN (Android, package `homes.milky.vpn`)
**Operator:** _(legal entity / individual and contact e-mail — OWNER MUST FILL IN)_
**Support:** https://t.me/MilkyVPNbot

## 1. Summary

MilkyVPN is a VPN client that connects your device to the servers of your own subscription. The app:

- contains **no** analytics, advertising, trackers or third‑party data‑collection SDKs;
- keeps **no logs** of visited sites, DNS queries or traffic contents;
- requires **no** account, e‑mail or phone number;
- shares data with **no** third parties other than the subscription/VPN servers you add yourself.

## 2. Data processed

| Data | Where stored | Purpose | Leaves the device? |
|---|---|---|---|
| Subscription URL (`https://sub.milky.homes/s/…`) | On device only, encrypted storage (Android Keystore) | Fetching the server list | Yes — only to `sub.milky.homes` over HTTPS |
| Server parameters (address, port, access keys) | On device only, encrypted; excluded from backups | Establishing the VPN tunnel | Yes — only to the selected VPN server |
| Preferences (theme, auto‑connect, region) | On device only | UI behaviour | No |
| Diagnostics (app version, Android version, connection state, error class) | Generated on demand, not persisted | Helping support | Only if you copy and send it yourself |

Diagnostics **automatically redact** secrets: subscription tokens, user IDs, keys and passwords are replaced with `••••••`.

## 3. Network traffic

While the VPN is active, all device traffic (except MilkyVPN itself, to avoid a routing loop) is sent through an encrypted tunnel to a VPN server from your subscription. The app does not inspect, filter or store that traffic. DNS queries inside the tunnel are resolved through the VPN server.

Server‑side handling of traffic is governed by the policy of the operator of your subscription's servers.

## 4. Android permissions

- **VPN (BIND_VPN_SERVICE)** — creating the tunnel; granted through the Android system dialog on first connect.
- **INTERNET** — reaching subscription and VPN servers.
- **FOREGROUND_SERVICE / FOREGROUND_SERVICE_SPECIAL_USE** — keeping the connection alive with a persistent notification.
- **POST_NOTIFICATIONS** — VPN status notification.
- **ACCESS_NETWORK_STATE** — detecting network changes (Wi‑Fi ↔ cellular).

The app does not request location, contacts, camera, files or microphone.

## 5. Retention and deletion

All data is stored locally. Google backup of app data is disabled (`allowBackup=false`, exclusion rules for Android 12+). Data can be removed via "Remove subscription" in the app or by uninstalling it.

## 6. Children

The app is not directed at persons under 16 and does not collect data about them.

## 7. Changes

The current policy is published at: _(URL — OWNER MUST FILL IN)_.

## 8. Contact

Privacy questions: https://t.me/MilkyVPNbot or _(e‑mail)_.
