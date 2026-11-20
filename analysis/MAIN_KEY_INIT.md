# gpio_key driver initialisation (`drv_key_init`)

`drv_key_init` (`0x701e9cbe`) sets up the keyboard driver: it finds the board
record `gpio_key` (`0x702b4f3e`), fills the driver object at `0x70f92bf4` with
the per-key timing thresholds and the operations table `0x70f60e2c`, then
registers the driver as `keyboard` (`0x703192ca`). Executed in `main-runtime`;
the evidence is in [main-key-init.json](main-key-init.json). All **3 native
cases pass** and every configuration write is recorded.

## Configuration

Two per-key configuration blocks (stride `0x30`, the second at object `+0x80`)
hold the timing windows that the key state machine (`0x701e923e`) reads:

| Field | Value | Meaning |
| --- | --- | --- |
| debounce | `0x7f` | debounce / press count |
| press | `10` | |
| hold | `3` | |
| release | `0x50` (80) | |
| long press | `0x1f4` (500) | long-press window (ms) |
| repeat | `0x1e` (30) | repeat interval |
| double window | `0x320` (800) | double / combo window (ms) |
| double count | `0x0f` (15) | |

The driver object also stores the board record at `+0x48`, the operations table
`0x70f60e2c` at `+0x28`, and a self-pointer at `+0x4c` / `+0x7c`.

## Return codes (observed natively)

| Case | Return |
| --- | --- |
| register ok | `0` (OS_EOK) |
| board record missing | `1` |
| register fails | the service error (`-11`); the firmware then asserts |

## Reproduction

```sh
python3 -m analysis_scripts.main_key_init --vectors-output firmware/main-key-init-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-key-init-vectors.json firmware/main-key-init-validation.json
python3 -m analysis_scripts.main_key_init firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-key-init-vectors.json \
  --validation firmware/main-key-init-validation.json > analysis/main-key-init.json
python3 -m unittest tests.test_main_key_init -q
```

## Remaining

- The board record holds the two key GPIO pins (pins 19 and 54 per the board
  scan in [MAIN_BOARD_RECORDS.md](MAIN_BOARD_RECORDS.md)); `drv_key_init` only
  wires the timing thresholds.
- The key **state machine** `0x701e923e` that consumes this configuration
  (7 states: debounce, combo, long press, double click, repeat) is mapped but
  not yet executed — the next gpio_key block, state by state from state 0.
