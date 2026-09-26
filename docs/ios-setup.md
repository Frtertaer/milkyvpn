# iOS setup — MilkyVPN

Status: the iOS target builds end-to-end and produces a real `.app`
(Runner + `PacketTunnel.appex` + `Mirage.framework`), and the userspace
tun2socks stack is implemented and proven by an injected-packet harness
(16/16 checks: ICMP echo, full TCP handshake + HTTP over SOCKS5, DNS over
SOCKS5 TCP, FIN teardown). What remains is capability/provisioning
enablement for on-device verification.

## What exists

| Piece | Where |
|---|---|
| kal2 core | `apple/Frameworks/Mirage.xcframework` (vendored; ios, ios-sim, macos slices) |
| App target | `ios/Runner` — bundle id `homes.milky.vpn`, `milkyvpn://` URL scheme |
| Tunnel extension | `ios/PacketTunnel` — `homes.milky.vpn.PacketTunnel`, `NEPacketTunnelProvider` |
| Cross-process state | `ios/Shared/SharedTunnelState.swift` (app-group JSON snapshot) |
| Core bindings | `ios/PacketTunnel/MirageBridge.swift` — `Kal2mobileStart/Stop/Alive/SetLogSink` |
| TUN pump | `ios/PacketTunnel/TunSocksBridge.swift` — orchestrator over `bridgeQueue` |
| tun2socks | `IPCodec.swift` (v4/v6 + checksums), `Socks5.swift` (CONNECT/UDP ASSOCIATE), `TcpFlow.swift` (seq/ack state machine + retransmit), `UdpRelay.swift` (DNS-over-TCP :53 + UDP ASSOCIATE NAT) |
| Harness | `tool/tun2socks-test/main.swift` — fake `PacketChannel` + fake SOCKS relay; compile+run commands below |
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

## The tun2socks stack

`PacketTunnelProvider` brings the interface up (198.18.0.2/30, default
route, DNS 1.1.1.1) and `TunSocksBridge` pumps `packetFlow.readPackets`
through a minimal userspace TCP/IP stack — all flow state is confined to
`bridgeQueue` (a serial `DispatchQueue`):

- **ICMPv4/ICMPv6 echo** answered locally (liveness smoke test).
- **TCP**: `TcpFlow` terminates the tunnel-side connection — SYN →
  SYN|ACK, strict seq tracking with wrap-safe comparisons, overlapping-
  segment reassembly, payload → SOCKS5 CONNECT stream via `NWConnection`
  to `127.0.0.1:<socksPort>`, remote bytes → MSS-clamped packets,
  FIN/RST teardown, and a 1 s retransmit tick for unacked segments.
  SOCKS dial failures answer with RST|ACK.
- **UDP :53**: each datagram is relayed over a one-shot SOCKS5 CONNECT
  to the resolver's TCP/53 (2-byte length framing) — works with any
  CONNECT-only SOCKS5 server.
- **other UDP**: a lazily-created shared SOCKS5 UDP ASSOCIATE with a
  NAT table keyed on the remote endpoint (best effort; SOCKS5 associate
  inherently can't disambiguate two flows to the same remote).
- IPv6 packets parse and use the same engines; the active settings only
  route IPv4, so v6 support is present but dormant.

Known limits (correctness-over-performance design): no receive buffer
for out-of-order segments (client retransmits on dup-ACK), advertised
window fixed at 65535, no PMTU discovery, single UDP-associate NAT.

## Packet-injection harness

`tool/tun2socks-test/main.swift` compiles the *real* bridge sources
with a fake `PacketChannel` and a real-socket fake SOCKS5 relay
(CONNECT → dials loopback targets, ASSOCIATE → UDP echo) — no
NetworkExtension needed since `NEPacketTunnelFlow` conformance lives
behind `#if canImport` in `PacketChannel.swift`:

```sh
swiftc -O -o /tmp/tuntest \
  tool/tun2socks-test/main.swift \
  ios/PacketTunnel/{IPCodec,PacketChannel,Socks5,TcpFlow,UdpRelay,TunSocksBridge}.swift
/tmp/tuntest
```

16 checks: ICMPv4 echo; TCP SYN/SYN-ACK/ACK, HTTP GET → `HTTP/1.0 200` +
body through the SOCKS wire protocol; UDP/53 query → TCP-framed response
UDP packet; FIN teardown.

Manual end-to-end check on device (once provisioned): enable the VPN,
then open any https URL in Safari — the DNS answer and TCP stream both
traverse the tunnel. `log stream
--predicate 'subsystem BEGINSWITH "homes.milky.vpn"'` shows `tcp_flows=`,
`icmp_echo=`, `retransmits=` counters.

A deeper alternative remains open: a `PacketIO` hook in
`pkg/kal2mobile`/`pkg/kal2core` (gomobile binds interfaces fine, e.g.
`SetLogSink`) so the Go side owns the stream stack — the Swift stack
here would then become the reference client.

## Checking it on device

`log stream --predicate 'subsystem BEGINSWITH "homes.milky.vpn"'` shows
`kal2:` lines from `MirageLogSink`, tunnel bring-up, and the
`tcp_flows=`/`icmp_echo=`/`retransmits=` counters. `VpnPlugin.getState` also reads the extension's app-group
snapshot (`tunnel_state.json`) so the UI reflects extension state even if
the Flutter isolate restarts.
