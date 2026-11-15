# The `@zos/*` API table and its native bindings

Static investigation on 2026-11-15 of `META/js_apps/framework.js` (SHA-256
`015e05053b2b4dc516e31398711e2c3fffb6db57d6a2080638d42fc8d1e5e7f6`) in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/zos_api_table.py`; its output is
[zos-api-table.json](zos-api-table.json). Nothing was evaluated.

## How apps reach the API

The compiled apps load modules with `__$$R$$__('@zos/<name>')` (see
[APP_BYTECODE.md](APP_BYTECODE.md)). `framework.js` creates that loader when an
app is created:

1. `beforeAppCreate` sets `currentApp.__globals__.__$$R$$__ = Hr(apiObject)`.
   It also sets `__scopedGlobals__ = {__ZEPPOS__: 1, process}` and gives each
   module a `__$$G$$__` sandbox proxy. That proxy is the `with` object seen in
   the bytecode.
2. The loader applies one alias (`@zos/storage/localStorage` → `@zos/storage`),
   splits the specifier on `/` and, when the first part is `@zos`, walks the
   API object by the remaining parts. Any other specifier throws
   `API NOT EXIST`.
3. The API object is built by `gt()` from a single declarative configuration,
   `{modules:{router:…, fs:…, ui:…, …}}`. Every method entry has a `main`
   binding, an optional `permissionCode` and a `version` map. When a
   permission is present, each call is gated through
   `hmApp.queryPermission([code])`. A `main` binding of the form
   `{func:["hmApp","newAlarm"], arg:[…], opts:{argType}}` is a direct call
   into a native object. Otherwise `main` is a JavaScript function.
4. Seven modules are not tables but reflections. `ge(ae.hmUI,"hmUI","2.0")`
   turns every function property of the native object into a method bound to
   it, and every other property into a constant, at runtime.

The `@zos/*` modules therefore need no native resolver: the whole layer is in
`framework.js`, on top of the `hm*` native objects. That is why neither the main
image nor `framework.js` contains the `@zos/` specifier strings used by the
apps.

## Modules

| Module | Methods | Native-bound | JavaScript | Reflected native object | Classes |
| --- | ---: | ---: | ---: | --- | --- |
| `_internals` | 3 | 2 | 1 | — | — |
| `@zos/ai-flex` | 0 | 0 | 0 | `hmVAD` (3.0), `hmSysApi` (3.0) | — |
| `@zos/alarm` | 3 | 3 | 0 | — | — |
| `@zos/app` | 10 | 9 | 1 | — | — |
| `@zos/app-access` | 1 | 0 | 1 | `hmSysApi` (3.0) | — |
| `@zos/app-service` | 6 | 6 | 0 | — | — |
| `@zos/ble` | 1 | 1 | 0 | `hmBle` (2.0) | LocalTransferFile, TransferFile |
| `@zos/crypto` | 0 | 0 | 0 | `hmCrypto` (3.0) | — |
| `@zos/device` | 2 | 2 | 0 | — | — |
| `@zos/display` | 13 | 10 | 3 | — | — |
| `@zos/fs` | 13 | 5 | 8 | — | — |
| `@zos/interaction` | 9 | 6 | 3 | — | — |
| `@zos/media` | 1 | 0 | 1 | `hmMedia` (3.0) | — |
| `@zos/notification` | 3 | 3 | 0 | — | — |
| `@zos/page` | 6 | 2 | 4 | — | — |
| `@zos/router` | 10 | 6 | 4 | — | — |
| `@zos/sensor` | 1 | 0 | 1 | — | 29 sensor classes (below) |
| `@zos/settings` | 11 | 11 | 0 | — | — |
| `@zos/share-storage` | 0 | 0 | 0 | — | FileSystem, LocalStorage, TypedStorage |
| `@zos/storage` | 4 | 0 | 4 | — | LocalStorage, SessionStorage, ShareLocalStorage, ShareTypedStorage, TypedStorage |
| `@zos/system` | 1 | 0 | 1 | — | — |
| `@zos/timer` | 9 | 3 | 6 | — | — |
| `@zos/ui` | 0 | 0 | 0 | `hmUI` (2.0) | — |
| `@zos/user` | 2 | 2 | 0 | — | — |
| `@zos/vad` | 0 | 0 | 0 | `hmVAD` (3.0) | — |

In total there are 109 declared methods. 71 are bound directly to 70 distinct
native targets: `hmApp` 35, `hmSetting` 25, `hmFS` 5, `timer` 3, `hmBle` 1 and
`hmUI` 1. The other 38 are JavaScript wrappers. Each method's native target,
argument list, `argType` and earliest declared API version (from 2.0 to 4.1) are
in the JSON.

A few bindings rename across the boundary. `settings.getDistanceUnit` calls
`hmSetting.getMileageUnit`. `alarm.set` calls `hmApp.newAlarm`. `ble` adds a
correctly spelled `mstDestroyProfileInstance` that forwards to the native
`hmBle.mstDestoryProfileInstance`.

`@zos/sensor` exposes these classes: Accelerometer, Barometer, Battery,
BloodOxygen, BloodPress, BodyComposition, BodyTemperature, Buzzer, Calorie,
Compass, Distance, FatBurning, Geolocation, Gyroscope, HeartRate, Music, Pai,
Screen, Sleep, Stand, Step, Stress, SystemSounds, Time, Vibrator, Wear,
Weather, Workout and WorldClock.

## Permission model

The table declares 24 permission codes. Physical sensors use `device:os.*`,
and health data uses `data:user.hd.*`, one code per data type:

| Permission | Gated API |
| --- | --- |
| `device:os.accelerometer`, `.gyroscope`, `.compass`, `.barometer`, `.geolocation` | the matching `@zos/sensor` classes |
| `data:user.hd.heart_rate`, `.spo2`, `.sleep`, `.stress`, `.step`, `.distance`, `.calorie`, `.pai`, `.stand`, `.fat_burning`, `.body_temp`, `.blood_pressure`, `.body_composition`, `.workout` | the matching `@zos/sensor` classes; `.workout` also gates `app-access.getSportData` |
| `data:user.info` | `user.getProfile` |
| `data:os.device.info` | `device.getDeviceInfo` |
| `device:os.alarm` | `alarm.set`, `alarm.cancel`, `alarm.getAllAlarms` |
| `device:os.notification` | `notification.notify`, `notification.cancel`, `notification.getAllNotifications` |
| `device:os.local_storage` | `storage.getItem`/`setItem`/`removeItem`/`clear`, `LocalStorage`, `ShareLocalStorage` |

## Consequences for a standalone OS

Apps written against `@zos/*` could run on a reimplementation that keeps
`framework.js` unchanged and provides the native `hm*` objects with the 70
directly bound methods listed here. It would also have to provide the full
property sets of the six reflected objects (`hmUI`, `hmBle`, `hmMedia`,
`hmCrypto`, `hmVAD`, `hmSysApi`) and `hmApp.queryPermission` for the permission
gate. The reflected objects' method lists cannot be read from `framework.js`.
They are defined by the native registration code in the main image, which is
the next thing to map.

## Reproduction

```sh
python3 analysis_scripts/zos_api_table.py firmware/bip6-4.6.0.3.zip \
  > analysis/zos-api-table.json
python3 -m unittest tests/test_zos_api_table.py -v
```

The reader understands object and array literals, strings, numbers,
`!0`/`!1`, spreads, method shorthand, `Object.assign(...)`, `()=>X` getters and
the `ge()` reflection pattern. It skips strings, template literals and regular
expressions when stepping over code. Anything else is recorded as opaque. The
tests use a synthetic fragment. The output regenerates deterministically from
the archive.

## Limitations

This is the declared table, not a trace of runtime behavior. JavaScript method
bodies were not analyzed, so their native calls are not attributed here. Their
call sites are among those in [JS_RUNTIME_API.md](JS_RUNTIME_API.md). Version
maps also carry per-version option lists, which are kept only as the earliest
version. Top-level identifiers are resolved to the first matching literal
definition. Minified names reused in another scope could in principle resolve
to the wrong literal. The spot checks against the source (alarm, device,
notification, settings, app-service, ble) matched.
