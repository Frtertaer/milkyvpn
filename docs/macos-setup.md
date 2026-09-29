# macOS setup — MilkyVPN

Status: the macOS target builds and produces a working app —
`milkyvpn.app` starts the kal2 core in-process and opens the local SOCKS5
proxy (`127.0.0.1:11808`). No paid Apple account is required to run it;
Developer-ID signing/notarization is only needed for distribution.

## What exists

| Piece | Where |
|---|---|
| kal2 core | `apple/Frameworks/Mirage.xcframework` (vendored; ios, ios-sim, macos slices — the macos slice is what this target links) |
| App target | `macos/Runner` — bundle id `homes.milky.vpn`, `milkyvpn://` URL scheme |
| Core bindings | `macos/Runner/VpnPlugin.swift` — calls `Kal2mobileStart/Stop/Alive/SetLogSink` directly on a background queue |
| Flutter channel | same contract as Android: `homes.milky.vpn/vpn` (MethodChannel) + `vpn_state` / `links` (EventChannels) |
| Entitlements | `DebugProfile.entitlements` / `Release.entitlements` — sandbox + `network.client` + `network.server` |
| Project wiring | `tool/macos_wire_mirage.py` (embeds Mirage, adds VpnPlugin.swift, sets `FRAMEWORK_SEARCH_PATHS`) |

Deployment target is macOS 13.0 — the vendored Mirage slice requires it.

## Building

```sh
flutter build macos            # or: flutter build macos --debug
```

Output: `build/macos/Build/Products/{Debug,Release}/milkyvpn.app` —
`Contents/Frameworks/Mirage.framework` embedded, ad-hoc signed
(`Identifier=homes.milky.vpn`, `TeamIdentifier=not set`).

## How the VPN works here

`connect` on the Flutter channel builds the same `kal2` JSON the Android
client produces (`addr`, `sni`, `carrier`, `path`, `pub`, `psk`,
`socks: "127.0.0.1:11808"`) and calls `Kal2mobileStart`. The core then
listens on 127.0.0.1:11808 as a SOCKS5 proxy — no system consent needed
because it is a loopback listener. `disconnect` calls `Kal2mobileStop`;
`getState`/`vpn_state` emit the same VpnSnapshot shape as Android.
`openVpnSettings` opens System Settings ▸ Network ▸ Proxies so the user
can point the system at the SOCKS proxy; `isProfileSupported` returns
true only for `protocol: kal2` (no Xray core on Apple platforms yet).

## Remaining steps for distribution

1. **Team + signing.** Open `macos/Runner.xcodeproj`, set your Team on the
   Runner target; Xcode produces a Development profile. For outside
   distribution use *Developer ID Application* signing then notarize:
   `xcrun notarytool submit milkyvpn.zip --keychain-profile <profile>`.
2. **Hardened runtime.** Release entitlements keep the sandbox on; add
   `com.apple.security.cs.disable-library-validation` only if the Go
   runtime trips it (it did not in testing).

## What a "real" system VPN would take

The scaffold deliberately exposes SOCKS instead of a system tun:

- `NETransparentProxyProvider` (system extension) — needs
  `com.apple.developer.networking.networkextension` plus the
  `com.apple.developer.system-extension.install` entitlement, a Developer
  Program team, and user approval in System Settings ▸ Login Items &
  Extensions. The extension would run the same `MirageBridge` +
  tun2socks path described in `docs/ios-setup.md`.
- Transparent proxy without an extension is not possible on modern
  macOS — `networksetup -setsocksfirewallproxy Wi-Fi localhost 11808`
  covers most apps manually today.
