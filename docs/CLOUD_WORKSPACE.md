# Cloud workspace

This repo is the cloud-dev mirror of the `D:\vpnapp` workspace.

## Layout

| Path | What |
| --- | --- |
| `happ/` | Submodule — github.com/Happ-proxy/happ-desktop @ `1f6b0d1` (4.1.3) |
| `hiddify-app/` | Submodule — github.com/hiddify/hiddify-app @ `276a7eff` |
| `.remember/` | Agent autosave logs |
| `.semgrep/` | Semgrep guardian config |

## After cloning

```bash
git submodule update --init
```

`hiddify-app` has a nested submodule `hiddify-core` whose `.gitmodules` uses an
`ssh://` URL. In a cloud env without SSH keys, rewrite it to HTTPS first:

```bash
git config --global url."https://github.com/".insteadOf ssh://git@github.com/
git submodule update --init --recursive   # inside hiddify-app, if core is needed
```

## Build binaries (APK/AAB)

The ~690 MB of APK/AAB builds are not in git (GitHub rejects files >100 MB).
They are attached to the **`dev-assets`** release:

```bash
gh release view dev-assets --repo Frtertaer/milkyvpn
gh release download dev-assets --repo Frtertaer/milkyvpn --dir binaries/
```

Local toolchain SDKs (`.toolchains/`: Android SDK, Flutter, JDK17, Blender)
are intentionally excluded — provision them in the cloud env instead.
