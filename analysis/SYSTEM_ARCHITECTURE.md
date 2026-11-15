# System architecture from firmware symbol families

Static inventory on 2026-11-15 of C symbol strings embedded in
`META/firmware_sign.bin` of the Bip 6 OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The
inspector is `analysis_scripts/firmware_symbols.py`; its reproducible output is
[firmware-symbols.json](firmware-symbols.json). These are log tags, assertion
expressions and registration names compiled into the image, not a disassembled
call graph. Presence of a symbol does not prove the code path runs.

This sketches the subsystem structure a standalone OS would have to replace or
reimplement, and ties the JS-side BLE calls to native handlers (see
[JS_RUNTIME_API.md](JS_RUNTIME_API.md) and
[BLE_IDENTIFIERS.md](BLE_IDENTIFIERS.md)).

## Inter-processor RPC (rpmsg-lite)

The main firmware talks to co-processors over an rpmsg-lite transport wrapped by
a `zrpc` layer: named **links** (`zrpc_link_send`, `zrpc_link_pkt_checksum_check`,
`zrpc_link_recv_cb_set`, `zrpc_link_alloc_tx_buffer`) and **channels**
(`zrpc_channel_module_register`, `zrpc_channel_pkt_alloc`, `_zrpc_channel_send_inner`),
with short backing names `zrpc.lk`, `zrpc.ch`, `zrpc.rl`. Modules register
against the channel and exchange checksummed packets with send/wait-reply
semantics. This confirms a multi-core SoC with a message-passing fabric rather
than a single flat image; the sensor-hub and radio images analyzed earlier are
separate processors on this fabric.

## Audio DSP

A dedicated audio DSP is driven over its own IPC command set
(`AUD_IPC_CMD_PLAY_START`/`PLAY_STOP`, `REC_START`/`REC_STOP`, `HFP_START`,
`VOLUME_SET_VOLUME`) with DSP lifecycle strings ("Audio DSP Start/Stop", "DSP
init finished"). Playback, recording and hands-free paths all route through it.

## Bluetooth host stack (`bx_core`, dual-mode)

104 `bx_core_*` symbols implement a dual-mode Bluetooth host:

- **GAP** — LE and classic: `connect_le_device`/`disconnect_le_device`,
  `gap_bt_start_inquiry`/`stop_inquiry`, `enter_sniff`/`exit_sniff`,
  `change_connection_speed`, `get_all_conn_infor`,
  `get_conn_id_by_remote_addr`, encryption-change events.
- **GATT server** — `gatt_register_service`, `gatt_send_notification`,
  `gatt_send_service_change`, `gatt_enable_function_unit` (serves the Huami
  custom services).
- **GATT client** — `gattc_build_profile_instance` and the profile machinery
  the JS `ble.mst*` master-role calls map onto.

Classic-BT profile layers are present by name frequency: HFP (calls), A2DP and
AVRCP (media streaming and control), RFCOMM/SPP (serial), with BLE ATT/GATT/SMP
below. The device therefore supports phone-call audio and media control over
classic Bluetooth in addition to the BLE data channel.

## App command handlers and companion modules

A small app-layer command set appears as `app_handle_*_cmd`
(`read_description`, `set_sensor`, `start_transfer`, `stop_transfer`). Phone-
facing data modules are present as symbol groups: weather (53 symbols,
including allergy/city-tip variants), world clock (15), contacts (9), find-device
(6) and music (1). The cloud endpoint strings `api-mifit.huami.com` /
`Anhui Huami Information Technology` identify the vendor backend.

## Inventory

| Family | Symbols |
| --- | ---: |
| `bt_host` (bx_core) | 104 |
| `zrpc_rpmsg` | 15 |
| `audio_dsp_ipc` | 6 |
| `app_cmd_handlers` | 4 |

Companion modules (presence): weather, world_clock, contacts, find_device,
music. Full lists are in [firmware-symbols.json](firmware-symbols.json).

## Reproduction

```sh
python3 analysis_scripts/firmware_symbols.py firmware/bip6-4.6.0.3.zip \
  > analysis/firmware-symbols.json
python3 -m unittest tests/test_firmware_symbols.py -v
```

The inspector reads the archive member directly and groups embedded symbol
strings by prefix. The tests use synthetic inputs. JSON regenerates
deterministically from the archive.

## Limitations

Symbol strings are log/assert artifacts, not a call graph; counts depend on what
the vendor left in strings and are not an architecture spec. Core identities,
rpmsg endpoint addresses, memory maps and the exact profile configurations still
need corroboration from the decompiled code and independent hardware evidence.
No device was queried.
