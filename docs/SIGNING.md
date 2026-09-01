# Signing — upload key & Play App Signing

The repository never contains a production key. The build uses **debug signing** unless `android/key.properties` exists.

## 1. Create an upload keystore (once, on the owner's machine)
```bash
keytool -genkeypair -v \
  -keystore ~/keys/milkyvpn-upload.jks \
  -alias upload -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=MilkyVPN, O=Milky, C=FI"
```
Store the `.jks` and both passwords in a password manager. Losing the upload key is recoverable via Play Console (key reset), losing the **app signing key** is not — so always enrol in Play App Signing (default for new apps).

## 2. `android/key.properties` (git‑ignored)
```properties
storeFile=/absolute/path/to/milkyvpn-upload.jks
storePassword=********
keyAlias=upload
keyPassword=********
```
`android/app/build.gradle.kts` picks this file up automatically (`hasReleaseKeystore`) and uses `signingConfigs.release`; otherwise it falls back to the debug config and prints a warning.

## 3. Build
```bash
flutter build appbundle --release
jarsigner -verify -verbose -certs build/app/outputs/bundle/release/app-release.aab | head
```

## 4. Play Console
- First upload → "Use Google‑generated key" (Play App Signing). The uploaded AAB must be signed with the upload key from step 1.
- Note the SHA‑256 of the *app signing* certificate shown by Play (not needed by the app — no Firebase/Google Sign‑In — but keep it).

## 5. Rotation / loss
Play Console → Setup → App signing → "Request upload key reset". Requires a new PEM exported with `keytool -export -rfc`.

## Never
- Never commit `key.properties`, `*.jks`, `*.keystore` (already in `.gitignore`).
- Never paste passwords into CI logs; use CI secrets and write `key.properties` at build time.
