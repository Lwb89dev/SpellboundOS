# ZeppOS runtime native ABI and BLE application protocol

Static investigation on 2026-11-15 of `META/js_apps/framework.js` inside the
Bip 6 OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The file is
the shipped JavaScript runtime, not executed here. The independent inspector is
`analysis_scripts/js_runtime_api.py`; its reproducible output is
[js-runtime-api.json](js-runtime-api.json). All names are kept exactly as the
minified source spells them. Native module objects and the BLE wrapper are
unmangled because the runtime references those native globals by their real
names; everything else in the file is minified.

This matters for the project because the runtime's call sites define the
boundary a standalone OS would have to provide to run the same apps, and the
message protocol below is the contract an Android companion would have to speak.
None of this is a validated implementation or a device observation.

## Runtime identity

`META/js_apps/framework.js` is 129,578 bytes, SHA-256
`015e05053b2b4dc516e31398711e2c3fffb6db57d6a2080638d42fc8d1e5e7f6`. Its banner
declares the Zepp `device-runtime-core`, version `v4.2.0-release.1`, API level
`4.2`, build date `2025-09-19`, commit `b3cc2d2`. The watchfaces ship as
separate `META/js_watchfaces/*/index.js` members.

## Native module surface (the JS→firmware boundary)

The runtime reaches native code through global module objects. Optional modules
(`hmCrypto`, `hmSysApi`, `hmVAD`) are referenced only behind `typeof` guards and
have no observed call sites in this file. `hmTimer` is exposed to apps as
`timer`. The method names below are every distinct call site, not a vendor
header.

| Module | Observed methods |
| --- | --- |
| `hmApp` | `startApp`, `startService`, `stopService`, `getServiceList`, `exit`, `gotoPage`, `redirectPage`, `setLayerY`, `getPackageInfo`, `queryPermission`, `postNotification`, `deleteNotification`, `getNotificationList`, `newAlarm`, `alarmNew`, `cancelAlarm`, `getAlarmList` |
| `hmUI` | `widget`, `deleteWidget`, `prop`, `setScrollView`, `setLayerScrolling`, `scrollToPage`, `getRtlLayout`, `relayoutRtl`, `getTextLayout`, `createDialog`, `showToast`, `redraw`, `align`, `event`, `sp`, `text_style`, `sport_type` |
| `hmFS` | `open`, `close`, `read`, `write`, `seek`, `stat`, `remove`, `readdir`, `open_asset`, `stat_asset`, flags `O_RDONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`/`SEEK_SET`, and a `SysPro*` key/value store (`SysProGet/Set/Delete` for `Bool`/`Int`/`Int64`/`Double`/`Chars`, plus `SysProGetValueSize`, `SysProReset`) |
| `hmSetting` | `getDeviceInfo`, `getLanguage`, `getFontSizeInfo`, `setBrightScreen`, `stopPalmOff`, `stopWristDownOff` |
| `hmSensor` | `createSensor`, `checkAvailable`, `id`, `event` |
| `hmBle` | `transferFile`, `cancelTransferFile` (the runtime also wraps the broader native object; see below) |
| `hmMedia` | `create` |

The `hmFS.SysPro*` family is a typed persistent property store separate from
file I/O. One of its backing namespaces appears as the string
`device:os.local_storage`.

## Permission namespaces

The runtime gates capabilities with these literal permission strings, consumed
through `hmApp.queryPermission`:

`device:os.accelerometer`, `device:os.gyroscope`, `device:os.compass`,
`device:os.barometer`, `device:os.geolocation`, `device:os.mic`,
`device:os.alarm`, `device:os.notification`, `device:os.bg_service`,
`device:os.local_storage`, and `data:os.device.info`.

## BLE native surface (`hmBle`, wrapped as `ble`)

The runtime wraps the native BLE object and calls 37 distinct methods. They fall
into a GATT **master/central** role (`mst*`), a connection layer, a generic
`send`, and a file-transfer channel:

- Connection / adapter: `createConnect`, `disConnect`, `connectStatus`,
  `getAddress`, `getBTSwitch`, `addListener`, `removeListener`, `send`.
- GATT master: `mstStartScan`, `mstStopScan`, `mstConnect`, `mstDisconnect`,
  `mstPair`, `mstPrepare`, `mstBuildProfile`, `mstGetProfileInstance`,
  `mstDestoryProfileInstance` (vendor spelling), `mstGetConnIdByRemoteAddr`,
  `mstReadCharacteristic`, `mstWriteCharacteristic`, `mstReadDescriptor`,
  `mstWriteDescriptor`, and callback registrars `mstOnPrepare`,
  `mstOnCharaNotification`, `mstOnCharaValueArrived`, `mstOnCharaReadComplete`,
  `mstOnCharaWriteComplete`, `mstOnDescValueArrived`, `mstOnDescReadComplete`,
  `mstOnDescWriteComplete`, `mstOnServiceChangeBegin`, `mstOnServiceChangeEnd`,
  `mstOffAllCb`.
- File transfer: `transferFile`, `listenTransferFile`, `cancelTransferFile`,
  `abortTransferFile`.

## Framed message protocol

Above `ble.send`, the runtime frames application messages. `getProtocolHeader`
parses a fixed 16-byte little-endian header, followed by a payload of up to
3584 bytes (total message size 3600 bytes):

| Offset | Bytes | Field | Type |
| ---: | ---: | --- | --- |
| 0 | 1 | `flag` | uint8 |
| 1 | 1 | `version` | uint8 |
| 2 | 2 | `type` | uint16 LE |
| 4 | 2 | `port1` | uint16 LE |
| 6 | 2 | `port2` | uint16 LE |
| 8 | 4 | `appId` | uint32 LE |
| 12 | 4 | `extra` | uint32 LE |

Two protocol predicates are defined over these constants (`M=0`, `G=1`, `k=2`,
`W=1`):

- **Invoke**: `flag == 0 && type == 1 && version == 1`.
- **Close**: `flag == 0 && type == 2 && version == 1`.

The `port1`/`port2` fields correspond to the `devicePort`/`sidePort` pairing in
the message dispatcher (the watch-side and phone-side service ports), and
`appId` selects the destination mini-program. This is the shape the bytes are
read in; field semantics beyond that (exact invoke/close payload layouts,
error codes) are not fully reconstructed here.

## File-transfer state machine

The transfer object exposes a `readyState` that moves through `pending`,
`transferring`, `transferred`, and `canceled`, emitting `change`
(`readyStateChanged`) and `progress` events with `{fileSize, loadedSize}`.
Transfers are keyed by a numeric `session_id` and carry `file_name`,
`file_size`, and a `url` whose query string provides `params`. A receiver path
(`recv_func`) and a `progress_func` update the same object. The runtime also has
a `local-transfer-file` path (`jsapp://file_transfer`) distinct from the online
BLE transfer. Both `hmBle.transferFile` and a "Transfer File Module not
implemented" fallback are present, so transfer availability is build-dependent.

## Reproduction

```sh
python3 analysis_scripts/js_runtime_api.py firmware/bip6-4.6.0.3.zip \
  > analysis/js-runtime-api.json
python3 -m unittest tests/test_js_runtime_api.py -v
```

The inspector reads the archive member directly, extracts module call sites,
permission strings, the BLE wrapper surface, the framed-message sizes and the
header layout parsed from the `getProtocolHeader` read sequence, and the
protocol constants. The tests use a synthetic fragment, not vendor code. JSON
regenerates deterministically from the original archive.

## Limitations

These are static observations of one runtime build. Method lists are call sites,
not a complete or stable API, and absence here does not prove a method is
unavailable on device. The protocol header layout is read from the parser, but
invoke/close payload encodings, the full dispatch semantics and the native
implementations behind every `hm*`/`ble.*` method remain to be reconstructed.
No Bluetooth exchange, file transfer or app launch was performed.
