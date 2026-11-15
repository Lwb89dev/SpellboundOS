# GAPP compiled UI tree: layers, scenes, animations and drawables

Static investigation on 2026-11-15 of `META/resources/Application.bin` (size
2,533,862 bytes, SHA-256
`611f52629c71e1cc92d0175301f5022d921937e834b5ee9b1a7b10cd51650bb0`) in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/gapp_ui.py`; its output is [gapp-ui.json](gapp-ui.json).
Nothing is rendered and no callback is executed.

This extends the top-level RIFF/GAPP walk in [APP_FORMATS.md](APP_FORMATS.md),
which stopped at the section boundaries, by decoding the node tree inside the
LAYR, SCEN and ANIM sections. That tree is the built-in user interface of the
watch: the screens, reusable layers, controls, drawables, event handlers and
their bound properties.

## Node format

Every node is a 4-byte tag, a little-endian `uint32` body size, then the body.
A body starts with primitive header words (16-bit geometry and flags) and
length-prefixed ASCII names, then holds child nodes. The reader finds nodes by
tag and keeps only those whose declared size ends on another node's start or on
the section end, which rejects tag bytes that fall inside string data. The
surviving nodes nest strictly by their byte ranges; the LAYR and SCEN forests
pass a containment check (siblings disjoint, every child inside its parent).

| Tag | Role |
| --- | --- |
| `LAYR` | a reusable layer, with a 16-bit type and the 390×450 screen size in its header |
| `GRUP` | a group of controls |
| `CNTL` | a control (widget) with geometry and a name |
| `REXT` | a drawable primitive attached to a control |
| `ACT` | an event handler: an event class, an event name and an `ARGS` callback |
| `ARGS` | a `uint16` count followed by that many key/value string pairs |
| `SCEN` | a named screen that instances layers |
| `INST` | an instance reference inside a scene |
| `ANIM` / `STEP` | an animation and its keyframe steps |
| `SCRL` / `TAB` | scroll and tab containers |

## Section tree

| Section | Bytes | Roots |
| --- | ---: | ---: |
| LAYR | 1,815,002 | 1,058 |
| SCEN | 196,626 | 460 |
| ANIM | 12,916 | 38 |

25,342 nodes were decoded in total, nesting to depth 5:

| Tag | Count | Tag | Count |
| --- | ---: | --- | ---: |
| ACT | 6,475 | LAYR | 1,048 |
| ARGS | 6,540 | GRUP | 721 |
| REXT | 4,480 | SCEN | 460 |
| CNTL | 4,026 | SCRL | 215 |
| INST | 1,215 | STEP | 102 |
| ANIM | 34 | TAB | 26 |

The RATE (200 bytes) and DAMR (505,988 bytes) sections are not node trees and
remain undecoded here.

## Drawable primitives

`REXT` nodes name their primitive type. The eight observed types account for all
4,480 of them:

| Type | Count |
| --- | ---: |
| text | 1,676 |
| image | 1,296 |
| fill | 1,030 |
| circle | 267 |
| rectangle | 169 |
| canvas | 32 |
| gradient | 6 |
| poly | 4 |

## Event handlers

`ACT` nodes bind an event to a JavaScript callback named in their `ARGS`
(`function` → a handler name such as `_handleEvent`). 102 distinct event types
occur. The most frequent are the generic gesture/touch events, plus many
app-specific named events:

`gre.press` (1,520), `gre.touch` (1,267), `gre.release` (1,259),
`gre.outbound` (593), `gre.motion` (515), `gre.gesture.right/left/up/down`,
`gre.keypress` (183), `gre.keyrelease`, `scroll_change` (185),
`gre.scroll.complete`, `gre.gotfocus`/`gre.lostfocus`, and
`gre.animate.complete.<name>` callbacks.

## Property arguments and data binding

`ARGS` pairs carry the control properties. The most common keys are `function`,
`halign`, `valign`, `name`, `alpha`, `height`, `scale`, `x`, `y`, `width`,
`color`, `linewidth`, `rotation`, `aspect` and font paths such as
`fonts/allfont-Regular.ttf`. Many values are data-binding expressions of the
form `${scope:path}`, resolved at runtime against the app, the layer, the
control or a table cell:

`${control:alpha}` (576), `${control:image}` (257), `${control:alpha1}` (94),
`${layer:pos_line_alpha}` (52), `${control:color}` (34),
`${app:color_text_button}`, `${app:translations.id_public_unit_bpm}`,
`${cell:control:songItemAlpha}` and deep paths such as
`${app:RunningLayer.startButton.alpha}`.

## Screens and animations

The SCEN section names 460 screens, including `AlarmEditScreen`,
`AlarmInfoScreen`, `AppListScreen`, `AvaliableOtaScreen` (vendor spelling),
`Bind_QRCodeScreen`, `BioChargeDataDetailScreen` and many more. Each composes
layers through `INST` instances. The ANIM section names 34 animations such as
`BallFallsAnimation`, `DeepStageAnimation`, `LightStageAnimation`,
`REMStageAnimation` and `OfflineASRAnimationPopup`, each with `STEP` keyframes.
Complete name lists are in [gapp-ui.json](gapp-ui.json).

## Consequences

This is the resource model a standalone OS must render to run the stock watch
UI: a tree of layers and controls, eight drawable primitives, a gesture/event
model with JavaScript callbacks, and a `${scope:path}` data-binding system that
connects controls to app state. The callbacks named here are the same
`_handle*` functions the app bytecode defines ([APP_BYTECODE.md](APP_BYTECODE.md)).

## Reproduction

```sh
python3 analysis_scripts/gapp_ui.py firmware/bip6-4.6.0.3.zip > analysis/gapp-ui.json
python3 -m unittest tests/test_gapp_ui.py -v
```

The reader walks the RIFF/GAPP sections, parses each node tree by flat scan and
size containment, and tallies tags, drawable types, event types, property keys,
binding expressions, container names and the scene and animation names. The
tests build synthetic GAPP bytes, including a poisoned string that must not be
mistaken for a node. The JSON regenerates deterministically from the archive.

## Limitations

The node grammar is recovered from the bytes, not from vendor documentation.
Header fields beyond the recognized geometry words and names are not fully
interpreted, and `INST` instance targets, `STEP` keyframe parameters, the exact
coordinate semantics and the RATE and DAMR sections are not decoded. Tag counts
are of nodes that pass the containment check; a pathological size that happened
to land on a boundary could in principle be admitted. No image, font or glyph
data was extracted, and nothing was rendered.
