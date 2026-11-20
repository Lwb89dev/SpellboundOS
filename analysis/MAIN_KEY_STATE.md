# gpio_key state machine (dispatch + states 0..6)

`gpio_key_state_machine` (`0x701e923e`) is the key event handler. On each event
it decodes the GPIO level (`0x702bd6c8` writes a press/release flag onto the
stack) and dispatches on the per-key state byte through a 7-entry jump table.
This scope executes the dispatch and **all seven states**, including the two-key
combo pairing of state 1; the configuration it reads is the one written by
[drv_key_init](MAIN_KEY_INIT.md). Executed in `main-runtime`; the evidence is in
[main-key-state.json](main-key-state.json). All **26 native cases pass** and the
runtime context writes are recorded.

## Dispatch and context

- The message has `[0]` = event struct (`[0]` key index, `[2]` event code) and
  `[4]` = config base (`0x70f92bf4`).
- `0x702bd6c8(event_code, &flag)` decodes the level and must return 0.
- Runtime context at `0x70f92b74 + key*0x18`: `+0` state byte, `+4` press
  counter, `+8` repeat counter, `+0xc` flag byte.
- Config at `0x70f92bf4 + key*0x30`: flags `+0x50`; thresholds `+0x58`/`+0x5c`/
  `+0x60`/`+0x64` (press), `+0x68` (hold window), `+0x6c` (repeat max), `+0x70`
  (release).
- A **zero decode flag** is the press/hold edge; a **non-zero flag** is release.

## States (single-key paths)

| State | Press | Release |
| --- | --- | --- |
| 0 (idle) | build counter; store state 1/2 at the threshold (flag `+0x50` bit 4) | clear counter |
| 1 (combo) | within the combo window, debounce; past it, upload bit 0x10 + store 2; a pending combo stores 2 | upload bit 0x10 (unless combo pending) + store 2 |
| 2 | store state 4/5 (bit 5), upload bit 2 | upload bit 8, then hold (store 3) or end (upload bit 1, store 0) |
| 3 | upload bits 0x10 / 0x4, store state 5 | repeat → upload bit 1, store 0 |
| 4 | store state 6, upload bit 0x20 | upload bit 8, store 0 |
| 5 | count only | upload bit 8, store 0 |
| 6 | upload bit 0x40, store state 5 | upload bit 8, store 0 |

The event bits (`0x1`..`0x400`) are the key gestures posted to the input queue
by the upload helper `0x701e8b40`; the next state is written by the store helper
`0x701e90be`; the idle/finalize handler is `0x701e8dba` and the debounce timer
is `0x701e8afc`.

## Reproduction

```sh
python3 -m analysis_scripts.main_key_state --vectors-output firmware/main-key-state-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-key-state-vectors.json firmware/main-key-state-validation.json
python3 -m analysis_scripts.main_key_state firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-key-state-vectors.json \
  --validation firmware/main-key-state-validation.json > analysis/main-key-state.json
python3 -m unittest tests.test_main_key_state -q
```

## Two-key combo (state 1 pairing)

When both keys are active, state 1 clears the combo-key-1 index, records both
combo indices at `0x70f8e0da`/`0db`, logs `combo_key_1=%d, combo_key_2=%d`, and
compares the two keys' states and press counters: if both states are at most the
current one and the inter-press time is within the combo window (config `+0x74`)
with both counters above the press threshold (`+0x58`), it sets the combo-pending
flag `0x70f8e0dc` and posts the combo event (**bit 0x400**); otherwise it posts
bit 0x10. Both resolve to state 2.

The whole gpio_key handler — driver init, dispatch and all seven states
including the combo pairing — is now executed. This completes the key driver.
