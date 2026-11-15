# Bluetooth GATT identifiers and the notification contract

Static string scan on 2026-11-15 of `META/firmware_sign.bin` inside the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The
inspector is `analysis_scripts/ble_identifiers.py`; its reproducible output is
[ble-identifiers.json](ble-identifiers.json). These are literal UUID strings
present in the firmware member, not proof that any service is advertised,
enabled or reachable on a running device. The same UUID set also appears in the
factory-test image `META/extfw/fct_test_sign.bin`.

This is an initial Bluetooth identifier inventory. The subsequent native
builder investigation in [GATT_REGISTRATION.md](GATT_REGISTRATION.md) recovers
eight service registration attempts, 31 characteristic specs and concrete
transport bindings. It complements the JS-side ABI and framing in
[JS_RUNTIME_API.md](JS_RUNTIME_API.md); the complete phone contract is unresolved.

## UUID inventory

27 distinct 128-bit UUID strings were found and classified:

| Category | Count | Meaning |
| --- | ---: | --- |
| huami | 14 | Zepp/Huami custom base `…-0000-3512-2118-0009af100700` |
| ancs | 4 | Apple Notification Center Service |
| ams | 4 | Apple Media Service |
| bt-sig | 1 | Bluetooth SIG base (Serial Port Profile) |
| custom | 4 | unclassified 128-bit UUIDs |

### Huami/Zepp custom identifiers

All share the base `-0000-3512-2118-0009af100700`; the leading field is the
short id. Observed: `0x0001`, `0x0002`, `0x0004`, `0x0005`, `0x0006`, `0x0016`,
`0x0017`, `0x0022`, `0x0023`, `0x0024`, `0x0025`, and the firmware-update group
`0x1530`, `0x1531`, `0x1532`. The later builder analysis confirms a `1530`
service containing `1531`, `1532`, `0023` and `0024`, and a `fee0` service with
`0016`, `0017` and other custom characteristics. Their complete OTA/data
contracts still need recovery. Identifier `0022` is used by an RFCOMM BT_PORT
registration, and `0025` is absent from that builder. The initial string scan
alone did not establish which identifiers were GATT services or characteristics.

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
- **Android phone ↔ watch:** native custom `0016`/`0017` channel bindings and
  the separate JS runtime framing are mapped. The complete nesting,
  authentication and notification/file-transfer payload contract still needs
  tracing before a SpellboundFit implementation can interoperate reliably.

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
recover handles. The follow-up native builder recovers a conditional order,
but live handles and active state remain unobserved. The four non-Huami custom
UUIDs remain unclassified, and the native ANCS/AMS and
Huami-channel handlers have not been decompiled into a reusable implementation.
No Bluetooth connection was made.
