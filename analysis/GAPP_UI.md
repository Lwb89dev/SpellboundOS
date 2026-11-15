# GAPP compiled UI: complete decode of Application.bin

Static investigation on 2026-11-15 of `META/resources/Application.bin` (size
2,533,862 bytes, SHA-256
`611f52629c71e1cc92d0175301f5022d921937e834b5ee9b1a7b10cd51650bb0`) in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/gapp_ui.py`; its output is [gapp-ui.json](gapp-ui.json).
Nothing is rendered and no callback is executed.

This extends the top-level RIFF/GAPP walk in [APP_FORMATS.md](APP_FORMATS.md).
All six sections are now decoded: the application header, the UI node trees,
the easing curves and the data model. Together they are the built-in user
interface of the watch: screens, reusable layers, controls, drawables, event
handlers, animations and the state their properties are bound to.

**Correction.** The first version of this report (commit `cdd14ba`) undercounted
the trees: 25,342 nodes instead of 37,261. Its validation rejected two kinds of
real nodes: a last child followed by its parent's alignment byte, and the last
root of each section, which is followed by the `LEND` marker. Both rules are
described below. The cross-check against the APP header now matches exactly.

## Sections

| Section | Bytes | Content |
| --- | ---: | --- |
| APP | 3,054 | header plus 28 application-level `ACT` handlers |
| LAYR | 1,815,002 | 1,049 layer trees, closed by `LEND` |
| SCEN | 196,626 | 461 screens, closed by `LEND` |
| ANIM | 12,916 | 35 animations, closed by `LEND` |
| RATE | 200 | 5 easing curves, closed by `LEND` |
| DAMR | 505,988 | data model: 7,922 entries |

## Node format and validation

A node is a 4-byte tag, a little-endian `uint32` size and a body. Bodies begin
with primitive header words and length-prefixed names (a `uint16` length, then
the bytes including a terminating NUL), then hold child nodes. Three rules,
each confirmed on the whole file, make the parse exact:

1. **Alignment.** Every node size is even. When the body data is odd-sized, one
   zero byte is appended, and it is counted in the size. All 14,295 `ARGS`
   bodies either fill their size exactly (4,790) or leave one zero byte (9,505).
2. **`ARGS` structure.** An `ARGS` body is a `uint16` count followed by that
   many key/value string pairs, which must fill the body up to that padding.
3. **Section terminator.** Each LIST body ends with the 8-byte marker
   `LEND` + `uint32 0`, so the last root node ends where `LEND` begins.

The reader finds tags by scanning, keeps even-sized candidates that end on
another node's start, a node's end, the section's content end, or one padding
byte before one of these, and nests them by byte range. Every forest passes a
containment check (siblings disjoint, children inside parents). Each section
then has exactly as many roots as top-level nodes of its kind.

| Tag | Count | Role |
| --- | ---: | --- |
| `ARGS` | 14,295 | key/value property list |
| `REXT` | 7,134 | drawable primitive attached to a control |
| `ACT` | 6,688 | event handler: event class, event name, `ARGS` callback |
| `CNTL` | 4,726 | control (widget) with geometry and a name |
| `INST` | 1,437 | layer instance inside a screen |
| `LAYR` | 1,049 | reusable layer; its header carries the 390×450 screen size |
| `GRUP` | 815 | group of controls |
| `SCRL` | 473 | scroll container |
| `SCEN` | 461 | named screen |
| `STEP` | 120 | animation keyframe |
| `ANIM` | 35 | named animation |
| `TAB` | 28 | tab container |

37,261 nodes in total, nesting to depth 5.

## Application header

The APP body starts with fixed fields, then the application name and version:

| Field | Value |
| --- | --- |
| words 0–1 | `0`, `1` (format word) |
| `uint32` | `0x07888820` (meaning unknown) |
| width × height | 390 × 450 |
| three `uint32` counts | 461, 1,049, 35 |
| name / version | `Application` / `3.0` |

The three counts equal the decoded numbers of screens, layers and animations
exactly. That independently confirms the tree parse. After the header come 28
`ACT` handlers for application events, such as `gre.init` → `_onAppStart`.

## Drawables, events and properties

`REXT` types (all 7,134): text 2,849, image 2,002, fill 1,567, circle 391,
rectangle 258, canvas 56, gradient 7, poly 4.

`ACT` nodes bind one of 131 event types to a JavaScript callback named in their
`ARGS` (`function` → for example `_handleEvent`). The most frequent are
`gre.press` (1,534), `gre.touch` (1,291), `gre.release` (1,283), `gre.outbound`
(595), `gre.motion` (528), `gre.gesture.right` (458), `scroll_change` (257),
`gre.keypress` (183) and `gre.keyrelease` (181). There are also
`gre.gesture.up/down/left`, focus, scroll and table events and
`gre.animate.complete.<name>` callbacks.

`ARGS` use 109 distinct keys, mainly `function`, `halign`, `valign`, `name`,
`alpha`, `x`, `y`, `width`, `height`, `scale`, `color`, `font`, `size`,
`line-height`, `style`, `text`, `overflow`, `rotation` and `linewidth`.
1,589 distinct `${scope:path}` binding expressions occur, by scope:

| Scope | Occurrences |
| --- | ---: |
| `control` | 7,176 |
| `app` | 461 |
| `layer` | 257 |
| `cell` | 162 |
| `group` | 136 |

## Screens and instances

The 461 `SCEN` screens (for example `AlarmEditScreen`, `AppListScreen`,
`Bind_QRCodeScreen`) compose layers through `INST` nodes. An `INST` body is a
19-byte header, then the instanced layer's name. Optional children such as
`SCRL` follow. All 1,437 instances name one of the 1,049 layers (1,044 distinct
targets). The first header byte is `0xff` in every instance. Byte 1 is a small
flag, byte 3 a small index, and the 16-bit values at offsets 11 and 13 are
mostly zero and consistent with an x/y placement. Those three interpretations
are candidates.

## Animations, keyframes and easing curves

Each of the 35 `ANIM` nodes has a name, such as `BallFallsAnimation`,
`DeepStageAnimation` or `REMStageAnimation`, and `STEP` children. A `STEP` body
is two `uint16` words (`1,0` in 117 steps and `1,4` in 3), followed by six
strings:

| Field | Example |
| --- | --- |
| target property | `${app:CompassAppLayer.CalibrationScreen.Tips.tips_txt_alpha}` |
| from | `0` |
| to | `255`, or another binding |
| duration (ms) | `500` |
| easing | `linear` |
| start offset (ms) | `400` |

114 of the 120 targets are `${app:…}` bindings. The easing is the built-in
`linear` (113) or `easeinout` (2), or a curve defined in RATE (`BallDown` 3,
`CustomRate1` 2). Every easing name resolves.

A RATE node holds four `float32` values, the control points of a cubic Bézier
easing curve, and a name:

| Curve | x1, y1, x2, y2 |
| --- | --- |
| `BallDown` | 0.646154, 0.438462, 1.0, 1.0 |
| `CustomRate` | 0.753846, 0.292308, 1.0, 1.0 |
| `CustomRate1` | 0.284615, 0.723077, 1.0, 1.0 |
| `hm_screen_in` | 0.84, 0.0, 0.16, 1.0 |
| `hm_screen_out` | 0.66, 0.0, 0.34, 1.0 |

## Data model (DAMR)

DAMR is a `uint32` count (7,922) followed by that many entries. Each entry is a
`uint16` type, then three length-prefixed strings: key, value and change event.
The entries consume the section exactly, leaving one zero padding byte. Types
are named here by the observed value shapes:

| Type | Entries | Observed values |
| ---: | ---: | --- |
| 1 | 4,172 | strings, including 765 `translations.*` keys |
| 4 | 3,327 | numbers: decimal (`255`) and hex colors (`0xffffff`) |
| 0 | 285 | always empty |
| 10 | 131 | small integers such as angles |
| 8 | 7 | always `0` |

Keys are app-state paths such as `_g_post_screen`, `PickerLayer.baseGroup.
TitleControl.text` or `translations.id_cd_recent`. There are 7,858 distinct
keys and 64 repeats. The change-event string is usually empty. 22 distinct
events are used, most often `scroll_change` (233), `yoffset_change` (17) and
`yoffset_event` (13).

DAMR is the backing store for the `${app:…}` bindings. Of the 344 distinct
`${app:…}` paths used by properties and keyframes, 275 have an initial value
here. The other 69 are under screens such as `StressMeasuringScreen` and
`hr_setting_Layer`, and include 18 translation keys. They have no initial value
in this file and are presumably set at runtime, which has not been verified.

## Consequences

This is the full resource model a standalone OS needs to run the stock UI:

- a layer/control tree with eight drawable primitives;
- screens built from layer instances;
- an event model that dispatches to JavaScript callbacks;
- keyframe animations with Bézier easing;
- a typed data model that controls bind to through `${scope:path}`.

The callbacks named here are the same `_handle*` functions the app bytecode
defines ([APP_BYTECODE.md](APP_BYTECODE.md)).

## Reproduction

```sh
python3 analysis_scripts/gapp_ui.py firmware/bip6-4.6.0.3.zip > analysis/gapp-ui.json
python3 -m unittest tests/test_gapp_ui.py -v
```

The eleven tests build synthetic GAPP bytes. They cover header names,
UTF-8 `ARGS` values, a last child before its parent's padding, the rejection of
tags embedded in strings (odd sizes, overruns and malformed `ARGS`), the `LEND`
terminator, RATE curves, DAMR rows and padding, STEP and INST bodies, the APP
header, and the section walk. The JSON regenerates deterministically from the
archive.

## Limitations

The grammar is recovered from the bytes, not from vendor documentation. Header
words other than names, the 390×450 geometry, the APP counts and the INST
fields above are not interpreted. Neither are the APP word `0x07888820` and the
meaning of the DAMR type codes beyond their value shapes, or the STEP header's
second word. The RIFF size declared at offset 4 still does not match the file.
Arithmetically, it equals the `GAPP` form type plus the APP, LAYR, SCEN and DAMR
chunks plus 2, leaving out the ANIM and RATE chunks. That is a single
observation, not an explained rule. No image, font or glyph data was
extracted, and nothing was rendered.
