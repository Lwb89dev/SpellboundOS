# gpio_key state machine (dispatch + state 0)

`gpio_key_state_machine` (`0x701e923e`) is the key event handler. On each event
it decodes the GPIO level (`0x702bd6c8` writes a press/release flag onto the
stack) and dispatches on the per-key state byte through a 7-entry jump table.
This scope executes the dispatch and **state 0 (idle)**; the configuration it
reads is the one written by [drv_key_init](MAIN_KEY_INIT.md). Executed in
`main-runtime`; the evidence is in [main-key-state.json](main-key-state.json).
All **5 native cases pass** and the runtime counter writes are recorded.

## Dispatch

- The message has `[0]` = event struct (`[0]` key index, `[2]` event code) and
  `[4]` = config base (`0x70f92bf4`).
- `0x702bd6c8(event_code, &flag)` decodes the level and must return 0.
- The runtime context at `0x70f92b74 + key*0x18` holds the state byte (`+0`) and
  the press counter (`+4`); the state byte indexes the jump table (states 0..6).
- Config is read at `0x70f92bf4 + key*0x30`: press threshold `+0x58`, flags
  `+0x50`.

## State 0 (idle)

- A **zero decode flag** is the press/hold edge: increment the press counter
  (`+4`). While it stays at or below the threshold (`+0x58`), just run the timer
  check (`0x701e8afc`). Once it exceeds the threshold, store the next state
  (`0x701e90be`) — **state 1 if config `+0x50` bit 4 is set, else state 2** —
  then run the timer check.
- A **non-zero decode flag** is the release edge: clear the press counter and
  run the idle handler (`0x701e8dba`).

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

## Remaining

- States **1..6** (combo, long press, double click, repeat): they read both
  keys' runtime contexts and the combo globals at `0x70f8e0da`/`0db`/`0dc` and
  raise event uploads (`0x701e8b40`) with event bits `0x1`..`0x400`. Mapped (see
  the handoff) but not yet executed — the next gpio_key blocks.
