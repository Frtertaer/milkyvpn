# iOS setup — MilkyVPN

Status: the iOS target builds end-to-end and produces a real `.app`
(Runner + `PacketTunnel.appex` + `Mirage.framework`). Everything that does
not require a paid Apple Developer account is done. What remains is
capability/provisioning enablement plus the userspace tun2socks seam in
`TunSocksBridge.swift`.

## What exists

| Piece | Where |
|---|---|
| kal2 core | `apple/Frameworks/Mirage.xcframework` (vendored; ios, ios-sim, macos slices) |
| App target | `ios/Runner` — bundle id `homes.milky.vpn`, `milkyvpn://` URL scheme |
| Tunnel extension | `ios/PacketTunnel` — `homes.milky.vpn.PacketTunnel`, `NEPacketTunnelProvider` |
| Cross-process state | `ios/Shared/SharedTunnelState.swift` (app-group JSON snapshot) |
| Core bindings | `ios/PacketTunnel/MirageBridge.swift` — `Kal2mobileStart/Stop/Alive/SetLogSink` |
| TUN pump | `ios/PacketTunnel/TunSocksBridge.swift` — packet pump + ICMP echo replies; TCP/UDP currently counted and dropped |
| Flutter channel | `ios/Runner/VpnPlugin.swift` — same contract as Android (`homes.milky.vpn/vpn` + `vpn_state` + `links`) |
| Project wiring | `tool/ios_add_packet_tunnel.py` (deterministic pbxproj injector) |

## Rebuilding Mirage.xcframework

```sh
cd milky-core
gomobile bind -target ios,iossimulator,macos \
  -o build/Mirage.xcframework ./pkg/kal2mobile
rsync -a --delete build/Mirage.xcframework ../apple/Frameworks/
```

Tree digest of the vendored copy:
`183226d7638a8a77c1de415023fd77cc79e1dd2b438a94c54a1b0820b06863d9`
(`find Mirage.xcframework -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256`;
first 12 chars are hard-coded in `VpnPlugin.swift` as `coreVersion`).

## Building without a paid account (simulator)

```sh
export LANG=en_US.UTF-8
cd ios && pod install
xcodebuild -workspace Runner.xcworkspace -scheme Runner \
  -configuration Debug -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro' \
  CODE_SIGNING_ALLOWED=NO
```

Produces `Debug-iphonesimulator/Runner.app` under DerivedData, with
`PlugIns/PacketTunnel.appex` and `Frameworks/Mirage.framework` inside.
Verified on Xcode 27.0 (iOS 27 simulator runtime); deployment target is
iOS 15.0 (`platform :ios, '15.0'` in `ios/Podfile`, pod targets forced to
15.0 in `post_install`).

## Remaining steps (need an Apple Developer account)

1. **App IDs.** In Certificates, Identifiers & Profiles register
   `homes.milky.vpn` and `homes.milky.vpn.PacketTunnel`. Enable the
   *Network Extensions* capability on both and the *App Groups*
   capability, adding `group.homes.milky.vpn` to both.
2. **App Group.** Register `group.homes.milky.vpn` under App Groups.
3. **Xcode signing.** In each target's *Signing & Capabilities*, pick your
   Team; Xcode generates provisioning profiles. The committed entitlements
   files (`Runner.entitlements`, `PacketTunnel.entitlements`) already
   declare `com.apple.developer.networking.networkextension =
   [packet-tunnel-provider]` and `com.apple.security.application-groups`.
4. **Device install.** `flutter run` on a real device (the simulator does
   not load packet-tunnel providers end-to-end; the `.app` above is the
   compile-time artifact).
5. **Approve the VPN.** `NETunnelProviderManager.saveToPreferences` pops
   the iOS consent sheet on first `connect`; subsequent starts are silent.

## The tun2socks seam

`PacketTunnelProvider` brings the interface up (198.18.0.2/30, default
route, DNS 1.1.1.1) and `TunSocksBridge` pumps `packetFlow.readPackets`.
Today it answers ICMPv4 echo requests directly (a working smoke test for
the full path: app → extension → TUN → reply) and counts/drops TCP and
UDP with periodic `os_log` summaries.

To pass real traffic, implement the TODO in `TunSocksBridge.swift` —
forward TCP/UDP flows to the SOCKS5 listener the core opens (`Start`
returns `socksPort`, e.g. `127.0.0.1:11808`). The intended route is to
extend `pkg/kal2mobile`/`pkg/kal2core` with a `PacketIO` hook (gomobile
binds interfaces fine, e.g. `SetLogSink`), then feed
`packetFlow.readPackets`/`writePackets` through it — the Go side already
owns dial/TLS/carrier logic, so only a stream-per-flow adaptor is needed.
Alternatives: vendoring a tun2socks library (go-tun2socks, sing-tun) as a
second xcframework, or a pure-Swift TCP/IP stack.

## Checking it on device

`log stream --predicate 'subsystem BEGINSWITH "homes.milky.vpn"'` shows
`kal2:` lines from `MirageLogSink`, tunnel bring-up, and the drop/echo
counters. `VpnPlugin.getState` also reads the extension's app-group
snapshot (`tunnel_state.json`) so the UI reflects extension state even if
the Flutter isolate restarts.
