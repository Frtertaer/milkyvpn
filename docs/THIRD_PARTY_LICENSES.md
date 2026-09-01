# Third‑party licenses

| Component | Version | License | Use |
|---|---|---|---|
| [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite) (`libv2ray.aar`) | v26.8.20 | **LGPL‑3.0** | Android JNI wrapper around Xray‑core; linked dynamically as a separate AAR (`android/app/libs/libv2ray.aar`). Source: https://github.com/2dust/AndroidLibXrayLite |
| [Xray‑core](https://github.com/XTLS/Xray-core) | v1.260327.1 (bundled in the AAR) | **MPL‑2.0** | VPN engine: VLESS/Reality/XHTTP/Hysteria2 outbounds, built‑in `tun` inbound (gVisor netstack) |
| gVisor netstack (via Xray tun) | bundled | Apache‑2.0 | Userspace TCP/IP stack |
| Flutter SDK | 3.35.4 | BSD‑3‑Clause | UI framework |
| provider | 6.1.5+1 | MIT | State management |
| flutter_secure_storage | 10.3.1 | BSD‑3‑Clause | Keystore‑backed secure storage |
| shared_preferences | 2.5.3 | BSD‑3‑Clause | Non‑secret settings |
| url_launcher | (see pubspec.lock) | BSD‑3‑Clause | Opening support/privacy links |
| intl / flutter_localizations | 0.20.2 | BSD‑3‑Clause | Localisation |
| AndroidX / Kotlin stdlib | via Gradle | Apache‑2.0 | Android platform libs |

## LGPL‑3.0 compliance (AndroidLibXrayLite)
- The library is used **unmodified** as a dynamically linked AAR (`libgojni.so` loaded at runtime); the app's own code is not a derivative of it.
- This notice, the license text and the source URL are shipped with the app documentation; the in‑app "О приложении" screen names the engine and links here.
- Users may replace `libv2ray.aar` with their own build: drop a new AAR into `android/app/libs/` and rebuild.
- Full license texts: https://www.gnu.org/licenses/lgpl-3.0.txt , https://www.mozilla.org/MPL/2.0/

## Icon & brand
The milk‑drop icon (`assets/brand/*`, `res/drawable/ic_launcher_foreground.xml`) is original artwork created for this project.

## Flutter package licenses
The complete license texts of all Dart packages can be generated with `flutter pub deps` / `LicenseRegistry` (Flutter's built‑in `showLicensePage`).
