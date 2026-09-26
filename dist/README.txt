Milky VPN — dist contents
=========================

milky-arm64-v8a.apk / milky-armeabi-v7a.apk / milky-x86_64.apk
    Android app (release APKs). Install: adb install <file> or copy to phone.

kal2-client-linux-x64 / kal2-client-windows-x64.exe
    CLI tunnel client (advanced users / scripting). NOT the GUI app.
    Usage: kal2-client -addr <server:443> -sni <sni> -pub <pubkey> -psk <psk>
           -socks 127.0.0.1:1080 [-carrier veil|drift|cdn|auto] [-ech <b64>]

WINDOWS APP (GUI):
    The installable Windows app is NOT in this folder — get
    MilkyVPN-Setup.exe from GitHub Releases:
    https://github.com/Frtertaer/milkyvpn/releases  (latest windows-test-*)
    It installs the Flutter app + bundled kal2 engine; no admin rights needed.
