# Building

Use Rust 1.90 or newer, Node.js 22.12+, npm and the native build tools for your target.
Run the Rust library tests and frontend checks from README.md first.
Configure your own HTTPS relay in the two locations listed there before building.

## Windows x64

Install Visual Studio Build Tools with Desktop development with C++, a Windows SDK
and WebView2. Run `build-windows.cmd` from the repository root. Alternatively:

```sh
npm --prefix apps/desktop ci
npm --prefix apps/desktop/frontend ci
npm --prefix apps/desktop run build -- --locked
```

The build uses the checked-in Tauri configuration. Release signing is your own
responsibility; no author certificates or signing passwords are supplied.

## Android

Install JDK 21, Android SDK platform/build tools 37 and NDK 29.0.14206865.
Set JAVA_HOME, ANDROID_HOME and NDK_HOME, install the Rust Android target
`aarch64-linux-android`, then install both npm projects as above.

```sh
cd apps/desktop
npm run tauri -- android build --target aarch64 --apk --ci -- --locked
```

Use your own signing key for distribution. Independently signed builds cannot
update an installed build signed by another key. Do not remove a working profile
to test an unsigned or independently signed build; use a spare test device/profile.
Check the finished APK with `deploy/android/verify-workmanager-apk.py`.

The generated Android native project is intentionally included because it contains
the scanner, background runtime, profile-file picker and Keystore integration.
Do not regenerate it over those integrations without reviewing the diff.
