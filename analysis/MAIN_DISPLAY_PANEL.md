# ICNA3311 display panel: DCS read-id, probe and command-table player

All **9 native cases** pass in **565 instruction steps**. This scope executes
three original main-image bodies in the `main-runtime` project and establishes
the display driver's command contract. The evidence is in
[main-display-panel.json](main-display-panel.json). It supersedes the
preliminary static notes in [DISPLAY_AND_LIGHT.md](DISPLAY_AND_LIGHT.md).

## Panel identity

The panel is a **Chipone ICNA3311 AMOLED** driven over a **MIPI DCS** command
interface. The firmware strings `drv_display_init`, `display_panel_read_id`,
`icna3311_probe_success`, `icna3311_read_38_gamma` and `icna3311_vg_3a_gamma`
name it directly, and the id-read commands are the MIPI DCS set.

## What executes

| Body | Address | Role |
| --- | --- | --- |
| `display_panel_read_id` | `0x702c8238` | Issues DCS `0xDA/0xDB/0xDC` and accumulates the 24-bit id |
| panel probe | `0x702c82d8` | Reads the id, matches it against a 9-entry variant table |
| DCS command-table player | `0x702c8314` | Plays a `{type, nargs, payload}` sequence |

The DCS transfers, the delay and the logger are supplied. A `transfer` stub
captures the exact command bytes the code writes and injects scripted response
bytes, so the DCS framing is verified rather than assumed.

### Read id

`display_panel_read_id` sends three one-byte DCS commands — `0xDA`, `0xDB`,
`0xDC`, the standard MIPI DCS **RDID1/RDID2/RDID3** — reading one byte for each,
and returns `b0 << 16 | b1 << 8 | b2`. Any transfer error logs and returns 0.
The executed case confirms the three commands in order and the 24-bit
accumulation (e.g. responses `1b 09 09` → `0x1b0909`).

### Probe

The probe reads the id and walks a table of nine ICNA3311 variant descriptors
(runtime `0x70f62398`), each descriptor's first word being its id. It returns
the descriptor whose id matches the full 24-bit read id, or null. The nine real
ids embedded in the firmware are:

```
0x250905 0x5a0905 0x250906 0x1b0909 0x4b090d 0x5c0913 0x5b0913 0x250914 0x2c0914
```

The executed cases match a real id (`0x1b0909`, the fourth descriptor) and
return null for an unknown id or a failed read.

### Command-table player

`0x702c8314(table, length)` walks a byte sequence of entries `{type, nargs,
payload...}`, advancing by `nargs + 2` each time:

- **type 0** — a DCS write of the `nargs` payload bytes (DCS command + args),
  through the device write op at `device + 0xc`;
- **type 1** — a `delay(payload[0])` in milliseconds.

A null table or zero length returns the error code `0xfffffff6`. The executed
cases play realistic sequences — sleep-out `11 00`, a 120 ms delay, display-on
`29`; and a brightness bring-up `51 ff` (DCS `write_display_brightness`), `53
20` (`write_control_display`), a 10 ms delay, display-on `29` — and the player
issues exactly those DCS writes and delays.

The DCS read op is at `device + 0x10` and the write op at `device + 0xc`, both
behind the display device handle `0x70f8e694`; the physical bus underneath is
not exercised here.

## Cases

| Case | Result |
| --- | --- |
| `read_id_accumulates_rdid` | commands `da db dc`, id `0x1b0909` |
| `read_id_transfer_error_returns_zero` | stops after the first transfer, returns 0 |
| `probe_matches_icna3311_variant` | returns the `0x1b0909` descriptor |
| `probe_unknown_id_returns_null` | returns 0 |
| `probe_read_id_failure_returns_null` | returns 0 |
| `interp_writes_and_delays` | DCS `1100`, delay 120 ms, DCS `29` |
| `interp_brightness_then_on` | DCS `51ff`, `5320`, delay 10 ms, DCS `29` |
| `interp_null_table_errors` | `0xfffffff6` |
| `interp_zero_length_errors` | `0xfffffff6` |

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_display_panel --vectors-output firmware/main-display-panel-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainDisplayPanel.java firmware/main-display-panel-vectors.json \
  firmware/main-display-panel-validation.json
python3 -m analysis_scripts.main_display_panel firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-display-panel-vectors.json \
  --validation firmware/main-display-panel-validation.json > analysis/main-display-panel.json
```

The vectors, native report and evidence regenerate byte for byte. The project
is opened read-only.

This is a driver **contract**, not a working display driver. Remaining work:

- Execute `drv_display_init` / `0x702c8c70`: the `bsd_1v8`/`bsd_3v3` rail
  enables, the `bsd_rst` reset sequence, ESD/`bsd_lcd` setup and the real init
  command tables (`0x709a8560`, `0x709a8570`, and the full panel-on sequence).
- Recover the framebuffer/refresh path (the window-set and memory-write DCS
  commands, the tear-effect/vsync handling) and the physical bus behind the
  device ops at `+0xc`/`+0x10`.
- Recover the backlight/brightness control end to end (DCS `0x51`/`0x53` seen
  here) and confirm panel timing, bring-up and the device's actual variant id
  on hardware.
