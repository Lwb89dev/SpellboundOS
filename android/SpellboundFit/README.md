# SpellboundFit Android Companion

Independently authored Android companion app for SpellboundOS (minSdk 26, compileSdk/targetSdk 35).

## Components

- `dev.spellboundfit.protocol.Protocol`: SpellboundFit v1 binary framed codec (`"SB"`, IEEE CRC-32, `StreamDecoder`), wire-compatible byte-for-byte with `kernel/proto.c`.
- `dev.spellboundfit.protocol.SecureLink`: RFC 8439 ChaCha20-Poly1305 AEAD + HKDF-SHA256 authenticated encrypted session with monotonic anti-replay, wire-compatible byte-for-byte with `kernel/secure_link.c`.
- `dev.spellboundfit.roadstr.RoadstrParser`: English and Italian Roadstr turn-by-turn notification parser.
- `dev.spellboundfit.ble.BleWatchClient`: Android BLE GATT client with MTU negotiation, secure handshake and telemetry/action callbacks.
- `dev.spellboundfit.service.WatchNotificationListener`: `NotificationListenerService` forwarding phone alerts and Roadstr navigation instructions to the watch and executing watch-triggered `PendingIntent` actions.
- `dev.spellboundfit.MainActivity`: Companion dashboard for status, telemetry, notification-bridge setup and test senders.

## Build & Verification

Build a signed, zipaligned debug APK completely offline (requires JDK 17+ and Android SDK 35 + build-tools):

```sh
make android-apk
adb install -r build/android/SpellboundFit-debug.apk
```

Or run the automated compile, JVM unit, live Java ↔ C encrypted interop and APK packaging/signature verification test from the repo root:

```sh
python3 -m unittest tests.test_android_companion -v
```
