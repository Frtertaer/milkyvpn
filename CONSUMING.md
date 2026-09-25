# Consuming Mirage core

Mirage core (module `github.com/Frtertaer/milkyvpn/milky-core`, package `kal2core`)
is the KAL/2 tunnel engine. This is the embedder's guide: three surfaces — the
Go API, the `gomobile`-built JNI library, and the CLI client — all driving the
same session semantics.

## Go API — `pkg/kal2core`

```go
cfg := kal2core.ClientConfig{
    Addr:   "203.0.113.10:443",         // or Addrs: []string for endpoint rotation
    SNI:    "kal.example.dev",          // server domain (real cert, never borrowed SNI)
    ServerPub: pubBytes,                // server Ed25519 public key, 32 bytes (see DecodeKey)
    PSK:       pskBytes,                // per-user pre-shared key, 32 bytes
    Carrier: "auto",                    // "veil" | "drift" | "auto" (hedged) | "a,b" list
    DriftPath: "/api/v2/stream",        // secret path when drift is in use
}
cli, err := kal2core.Dial(ctx, cfg)
```

- `kal2core.DecodeKey(s)` accepts hex or base64 (std or raw-url) and returns 32 bytes.
- `cli.EnableReconnect()` starts the watchdog: on carrier death (TSPU reset,
  idle kill, roaming) it re-dials down `Addrs` with backoff+jitter and swaps in
  the new session. Read the live session only through `cli.Session()` — it is
  nil during a reconnect gap.
- `cli.ServeSocks("127.0.0.1:10808")` exposes a local SOCKS5 that survives
  reconnects; `cli.Ping(ctx)` is the liveness check; `cli.Close()` stops
  everything, idempotent.
- **Proxying**: `ClientConfig.DialContext` overrides the base TCP dial —
  point it at an HTTP-CONNECT or SOCKS5 dialer to chain the tunnel through an
  upstream proxy (residential exit, corporate proxy).
- Server side: `kal2core.Serve(ServerConfig)` — `Listen`, `Domain`, cert via
  `CertFile`/`KeyFile` or `AutocertDir` (LE HTTP-01 on `AutocertHTTPAddr`),
  `Identity` (64B Ed25519 private), `Users []User{ID, PSK}`, `StealAddr`
  (decoy upstream for foreign SNI), `DriftPath`, `DecoyDir`.

## Android JNI — `libcore.so` (`cmd/kal2native`)

Built `-buildmode=c-shared` per ABI, NDK clang targeting API 23:

```
GOOS=android GOARCH=<arm64|arm|amd64> CGO_ENABLED=1 \
  CC=<ndk>/toolchains/llvm/prebuilt/<host>/bin/<triplet>23-clang \
  garble -literals build -trimpath -buildmode=c-shared -o libcore.so ./cmd/kal2native
```

Triplets: `aarch64-linux-android23-clang` (arm64-v8a),
`armv7a-linux-androideabi23-clang` (armeabi-v7a),
`x86_64-linux-android23-clang` (x86_64). Minimum platform is **API 23
(Android 6)** — raise the clang suffix only if you deliberately bump `minSdk`.

JNI contract (package `homes.milky.vpn.bridge`, class `NativeBridge`):

| Export | Signature | Semantics |
|---|---|---|
| `Java_homes_milky_vpn_bridge_NativeBridge_nativeStart` | `(String cfg) → int` | starts the tunnel, returns local SOCKS port, `-1` on failure |
| `Java_homes_milky_vpn_bridge_NativeBridge_nativeStop` | `() → void` | tears down, idempotent |
| `Java_homes_milky_vpn_bridge_NativeBridge_nativeAlive` | `() → boolean` | session currently connected |
| `Java_homes_milky_vpn_bridge_NativeBridge_nativeLastError` | `() → String` | last Start failure text |

`nativeStart` config JSON (all values strings):

```json
{
  "addr":    "ip:443[,ip2:443,...]",   // endpoints, tried in rotating order
  "sni":     "kal.example.dev",
  "carrier": "auto|veil|drift",
  "path":    "/api/v2/stream",          // drift path
  "pub":     "<hex|base64 32B>",        // server public key
  "psk":     "<hex|base64 32B>",        // user PSK
  "socks":   "127.0.0.1:10808"          // local SOCKS listen addr, default shown
}
```

Required: `addr`, `pub`, `psk`. `sni` should match the server domain. Route app
traffic at the returned SOCKS port (VpnService → local SOCKS). Core logs go to
`__android_log_write` under tag `core`.

## CLI — `cmd/kal2-client`

`/tmp/kal2-client -addr host:443 -sni <domain> -pub <hex> -psk <hex>
-carrier auto|veil|drift -drift <path> -socks 127.0.0.1:10808
-proxy <http://user:pass@host:port> -fetch <url> [-fetchmax <bytes>]`

`-fetch` issues a bounded read (default cap 32 MiB, `-fetchmax`) through the
tunnel — the canonical smoke check is an ip-lookup URL confirming tunnel egress.

## Deployment notes

- The server must terminate **its own** TLS 1.3 to a real domain with a real
  cert and a decoy site — borrowed-SNI REALITY-style fronts are detected by
  IP-ASN mismatch. `-steal` forwards foreign SNI to a decoy upstream.
- `drift` is HTTP-shaped traffic on a secret path for throttling windows;
  `auto` hedges veil+drift and keeps whichever completes.
- Endpoint agility is the anti-blocking contract: prefer `Addrs`/`addr` lists
  over a single IP; re-dial rotates starting index.
- License: same terms as this repository; no warranties — this is research
  networking code, audit before shipping.
