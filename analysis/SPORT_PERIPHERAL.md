# Sports-peripheral client and the four custom BLE UUIDs

Static investigation on 2026-11-15 of the main image `META/firmware_sign.bin`
(base `0x70160000`) and the factory-test image `META/extfw/fct_test_sign.bin`
(base `0x70000000`) in the Bip 6 OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/sport_peripheral.py`; its output is
[sport-peripheral.json](sport-peripheral.json). No device was contacted and no
vendor code was run.

This closes the four custom 128-bit UUIDs that
[BLE_IDENTIFIERS.md](BLE_IDENTIFIERS.md) left unclassified.

## Result

| UUID | Role | Evidence |
| --- | --- | --- |
| `7e78aa18-72cd-d3b8-a81f-5b7e589bea0f` | Stryd sensor service; the watch is the client | service table slot and service classifier in `bx_sport_peripheral` |
| `7e78aa19-72cd-d3b8-a81f-5b7e589bea0f` | Stryd cadence-sensor measurement characteristic | subscribe/unsubscribe and parse paths logged as `stryd_cadence_sensor` |
| `cc353442-be58-4ea2-876e-11d8d6976366` | service slot of the factory-test UUID table | referenced only in the factory image |
| `c551c36a-0377-4a29-9657-74ffb655a188` | characteristic slot of the factory-test UUID table | referenced only in the factory image |

## The UUID pointer table

Both images reach their UUID strings through one contiguous table of string
pointers. The tool finds the single pointer to the Huami `1530` string and
extends the run in both directions while each word points at a UUID-shaped
string. The table holds characteristics and descriptors first, then services.

| Image | Table start | Entries |
| --- | --- | ---: |
| main | `0x70a5b094` | 66 |
| factory | `0x702faf78` | 48 |

Compared with the factory build, the main build adds the sports and
notification entries: the Stryd pair, Running Speed and Cadence (`1814`,
`2A53`), Cycling Power (`1818`, `2A63`, `2A5B`), `1809`, `1826`, `1816`, the
ANCS service and characteristics, and Huami `0025`. The factory build alone
has `cc353442`, `c551c36a`, `4A02` and `3802`.

In the main image `cc353442` and `c551c36a` are present as strings, but nothing
uses them. No data word points at either string, and no `auipc`/`lui` +
`addi`/load pair in the code materializes either address. Neither appears in
the main exports. They are residual constants there. In the factory image each
is referenced exactly once, from its table slot. Their behavior in that build
has not been traced.

## The sports-peripheral module

Log and assertion strings name the module `bx_sport_peripheral`. The watch
discovers external sensors as a GATT client, reads Device Information and
battery, and subscribes to measurements: `subscribe_rsc_measurement`,
`subscribe_cycling_power_measurement`, `subscribe_battery_level`, and
`subscribe_stryd_cadence_sensor_measurement`. The reviewed functions:

| Function | Role |
| --- | --- |
| `0x703bd2c0` | `bx_uuid_is_equal(uuid1, uuid2)`, from its assertion strings |
| `0x7039f55a` | service classifier: `180A` → 6; `180F`, `1818`, `1814`, `7e78aa18` → 1; otherwise 0 |
| `0x7039f28c` | characteristic classifier: `2A19`, `2A63`, `2A53`, `7e78aa19` → 1; otherwise 0 |
| `0x7039f3c8` | creates a Stryd instance when the device name matches `"Stryd"` and an RSC service is present |
| `0x7039ecf6` / `0x7039ec4c` | subscribe / unsubscribe the Stryd measurement characteristic |
| `0x7039f5c2` | characteristic handler: battery, cycling power and Stryd message parsing |

The classifier return values are reproduced from the reviewed code. What value
6 means relative to 1 is not established.

## Stryd measurement message

The handler reads Stryd notifications with a little-endian byte reader
(`bx_decoder`: `u8`, `u16`, `u32`, `u64`, with a sticky error flag). The first
byte selects one of two layouts; any other value is logged as ignored. Both
layouts are exactly 20 bytes, the payload of a default-MTU notification.

| Type `0x32` | Type `0x36` |
| --- | --- |
| `u8` type | `u8` type |
| `u8` b1 | `u8` (read, discarded) |
| `u8` b2 | `u16` w1 |
| `u8` (read, discarded) | `u16` w2 |
| `u16` w1 | `u16` w3 |
| `u16` w2 | `u16` w4 |
| `u16` w3 | `u16` w5 |
| `u8` b3 | `u64` (read, discarded) |
| `u8` (read, discarded) | |
| `u32` d1 | |
| `u16` w4 | |
| `u16` w5 | |

A short message sets the reader's error flag, and the handler logs
`cannot parse stryd cadence sensor…`. The field meanings (cadence, stride,
power and so on) are not established from the firmware, so the host model
keeps generic names. `decode_stryd` reproduces the layouts, returns `None` for
ignored types and rejects short payloads.

## Reproduction

```sh
python3 analysis_scripts/sport_peripheral.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/main > analysis/sport-peripheral.json
python3 -m unittest tests/test_sport_peripheral.py -v
```

`--decompiled` only adds SHA-256 hashes of the twelve reviewed local exports;
the tables and reference counts come from the archive alone. The tests use a
synthetic pointer table and synthetic messages.

## Limitations

The roles come from the firmware's use of the UUIDs, not from vendor
documentation. The Stryd field semantics, the full subscription state machine
and connection policy, and the factory build's use of `cc353442`/`c551c36a`
remain open. Address-reference scans cover pointers and `auipc`/`lui` pairs; a
reference computed in another way, such as `gp`-relative addressing, would not
be found.
