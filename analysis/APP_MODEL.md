# App-loading contract and lifecycle model

Static read on 2026-11-15 of the packaged JavaScript app bundles in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The
inspector is `analysis_scripts/app_model.py`; its reproducible output is
[app-model.json](app-model.json). Unlike the minified `framework.js` runtime,
the ten `META/js_watchfaces/*/*.js` members are readable source bundled by
"huamiOS bundle tool v1.0.17", so the host contract is directly observable.

This sits above the native ABI in [JS_RUNTIME_API.md](JS_RUNTIME_API.md): it is
what a standalone OS must provide to *load and run* a ZeppOS app, as opposed to
the native calls the runtime itself makes.

## Injected host globals

Each app bundle is wrapped in a `try { (() => { ... })() } catch` and begins
from native-injected globals:

- `__$$hmAppManager$$__` — the native app manager; `.currentApp` gives the
  running app, which carries `.pid` and `.current` (the current page/module).
- `__$$app$$__` — the current app object the bundle populates.
- `__$$module$$__` — the current module/page object.

A host that runs these bundles must define these three globals before
evaluating the bundle, plus the `DeviceRuntimeCore` object below.

## Runtime entry points the apps construct

The shipped bundles build the UI and app objects through these
`DeviceRuntimeCore` entry points:

- `App(...)` — declares the application and its lifecycle.
- `WatchFace(...)` — declares a watchface and its widgets.
- `WidgetFactory(...)` and `HmDomApi(app, module)` — the widget/DOM layer the
  face uses to create and update widgets.
- `HmLogger` — logging.

The broader `DeviceRuntimeCore` export set (App, Page, AppService, AppWidget,
DataWidget, BleConnector, FileTransfer, HmSetting, HmUtils, Buffer,
ProxySandbox, SensorWidgetFactory and more) is visible in the runtime but is not
enumerated with a precise count here: the minified `framework.js` reuses the
exports identifier `e` as an ordinary function parameter, so a reliable static
export list cannot be extracted by scanning assignments. Only the entry points
the apps actually use are reported.

## Lifecycle hooks

The `App`/`WatchFace` objects define these hooks (vendor spelling preserved,
including `onDestory`):

`onInit`, `onCreate`, `onReady`, `onShow`, `onHide`, `onDestory`, `onError`,
`onPageNotFound`, `onUnhandledRejection`.

A standalone OS would call these at the corresponding points of an app's life
(initialize, create, become ready, foreground, background, destroy) and route
errors, missing-page and unhandled-rejection conditions to the last three.

## Reproduction

```sh
python3 analysis_scripts/app_model.py firmware/bip6-4.6.0.3.zip \
  > analysis/app-model.json
python3 -m unittest tests/test_app_model.py -v
```

The inspector reads the watchface bundles from the archive and extracts the
injected globals, the constructed `DeviceRuntimeCore` entry points and the
lifecycle hooks. The tests use a synthetic fragment. JSON regenerates
deterministically from the archive.

## Limitations

This covers the five shipped watchface bundles, not every app type (pages,
services, widgets) the runtime supports; those may use additional entry points
and hooks not present here. Nothing was executed, and the exact arguments,
ordering and semantics of each hook are not established from these bundles
alone.
