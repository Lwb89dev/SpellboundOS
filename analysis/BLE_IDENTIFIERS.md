# Bluetooth GATT identifiers and the notification contract

Static string scan on 2026-11-15 of `META/firmware_sign.bin` inside the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The
inspector is `analysis_scripts/ble_identifiers.py`; its reproducible output is
[ble-identifiers.json](ble-identifiers.json). These are literal UUID strings
present in the firmware member, not proof that any service is advertised,
enabled or reachable on a running device. The same UUID set also appears in the
factory-test image `META/extfw/fct_test_sign.bin`.

This defines the device-side Bluetooth contract an Android companion or a
standalone OS would interoperate with, and complements the JS-side ABI and
message framing in [JS_RUNTIME_API.md](JS_RUNTIME_API.md).

## UUID inventory

27 distinct 128-bit UUID strings were found and classified:

| Category | Count | Meaning |
| --- | ---: | --- |
| huami | 14 | Zepp/Huami custom base `…-0000-3512-2118-0009af100700` |
| ancs | 4 | Apple Notification Center Service |
| ams | 4 | Apple Media Service |
| bt-sig | 1 | Bluetooth SIG base (Serial Port Profile) |
| custom | 4 | unclassified 128-bit UUIDs |

### Huami/Zepp custom services

All share the base `-0000-3512-2118-0009af100700`; the leading field is the
short id. Observed: `0x0001`, `0x0002`, `0x0004`, `0x0005`, `0x0006`, `0x0016`,
`0x0017`, `0x0022`, `0x0023`, `0x0024`, `0x0025`, and the firmware-update group
`0x1530`, `0x1531`, `0x1532`. This is the proprietary channel the Zepp phone app
uses; the `1530/1531/1532` triplet is the Huami OTA/DFU control, data and
version pattern. The framed message protocol in
[JS_RUNTIME_API.md](JS_RUNTIME_API.md) rides above this transport.

### Apple services (device acts as consumer)

The firmware embeds the published ANCS and AMS UUIDs and an ANCS client state
machine, so against an iOS phone the watch is the **consumer** of notifications
and media info:

- ANCS service `7905f431-…`, Notification Source `9fbf120d-…` (notify),
  Control Point `69d1d8f3-…` (write), Data Source `22eac6e9-…` (notify).
- AMS service `89d3502b-…`, Remote Command `9b3c81d8-…`,
  Entity Update `2f7cabce-…`, Entity Attribute `c6b2f38c-…`.

Firmware strings confirm an ANCS context carrying `app_id`, `title`,
`sub_title`, `message`, `date`, and `positive_action_label` /
`negative_action_label`, a state machine (`BX_ANCS_STATE_INIT` …
`SUBSCRIBE_SUCCESS`), stored peer address, retry/error timers, and a quick-reply
asset `images/notification/ic_reply_64px.png`. AMS strings reference
`player_name`, `title`, `artist`, `album`. SMS item assembly is also present.

### Standard and unclassified

`00001101-0000-1000-8000-00805f9b34fb` is the classic Serial Port Profile. Four
custom UUIDs remain unclassified: `7e78aa18-…` and `7e78aa19-…` (a
service/characteristic pair), `c551c36a-…`, and `cc353442-…`. Their roles are
not established here.

## Notification contract summary

- **iOS phone → watch:** standard ANCS/AMS. The watch subscribes to the phone's
  Notification Source and pulls attributes over the Control Point / Data Source.
  A compatible companion is not required for basic notifications.
- **Android phone ↔ watch:** the Huami custom GATT services carry the Zepp
  app's framed messages (see the 16-byte header in JS_RUNTIME_API.md), including
  notification push and the `hmBle` file transfer. This is the channel a
  SpellboundFit companion would implement.

## Reproduction

```sh
python3 analysis_scripts/ble_identifiers.py firmware/bip6-4.6.0.3.zip \
  > analysis/ble-identifiers.json
python3 -m unittest tests/test_ble_identifiers.py -v
```

The inspector reads the archive member directly, matches UUID string literals,
classifies them against the Huami and Bluetooth-SIG bases and the published
ANCS/AMS assignments, and reports short ids for base-relative UUIDs. The tests
use synthetic inputs. JSON regenerates deterministically from the archive.

## Limitations

A string scan cannot prove a service is advertised, which role is active, or
which characteristics are actually used; it also cannot order the GATT table or
recover handles. The custom UUIDs are unclassified, and the native ANCS/AMS and
Huami-channel handlers have not been decompiled into a reusable implementation.
No Bluetooth connection was made.
