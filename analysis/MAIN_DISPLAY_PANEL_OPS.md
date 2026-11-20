# ICNA3311 panel operations: dimming, brightness, sawtooth, gamma, HBM and register access

All **15 native cases** pass in `main-runtime`. They execute the original
ICNA3311 panel operations through the already-validated DCS table player
`0x702c8314` ([MAIN_DISPLAY_PANEL.md](MAIN_DISPLAY_PANEL.md)). The DCS
write/read transfers and the logger are supplied. The evidence is in
[main-display-panel-ops.json](main-display-panel-ops.json).

## Unlock/lock wrapping

Each operation wraps its command in a vendor unlock and lock sequence:

| Pages | Unlock | Lock |
| --- | --- | --- |
| page 0 | `FE 80`, `F4 00`, `F5 00`, `FE 00` | `FE 80`, `F4 AC`, `F5 E1`, `FE 00` |
| vendor pages | `FE 20`, `F4 5A`, `F5 59` | `FE 20`, `F4 A5`, `F5 A5`, `FE 00` |

## Operations

| Operation | Address | Command (inside the wrapping) |
| --- | --- | --- |
| dimming off / on | `0x702c850c` / `0x702c851c` | `53 20` / `53 28` (write_control_display) |
| brightness | `0x702c854c(level)` | `51 <level>` (write_display_brightness) |
| sawtooth on / off | `0x702c85b4` / `0x702c85ec` | page `90`: `4E 1F` / `4E 00` |
| gamma | `0x702c8624(value)` | page `50`: `38 <value >> 8>`, `39 <value & 0xff>` |
| HBM on / off | `0x702c8e7a` / `0x702c8ed0` | the variant table when present, else `66 02` / `66 00` |
| register read / write | `0x702c8f22(info)` | unlock, `FE <page>`, then a DCS read of `reg` (the result goes to `info + 4`) or a write `reg value`, then lock |

For a register access, `info` is `{u16 page, u16 reg, u16 value, u8 op}`. An
unknown op returns 0 without any traffic. A null `info` returns 1.

## Reproduction

```sh
python3 -m analysis_scripts.main_display_panel_ops --vectors-output firmware/main-display-panel-ops-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-display-panel-ops-vectors.json \
  firmware/main-display-panel-ops-validation.json
python3 -m analysis_scripts.main_display_panel_ops firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-display-panel-ops-vectors.json \
  --validation firmware/main-display-panel-ops-validation.json > analysis/main-display-panel-ops.json
python3 -m unittest tests.test_main_display_panel_ops -q
```

The `bus` stub can now record a command buffer for reads. The other main
scopes regenerate byte for byte.

## Remaining

- The framebuffer → DSI refresh path, with TE IRQ `disp_ctrl_te_irq_callback`
  and the DSI semaphores.
- The interface enable/disable bodies `0x702c8208`/`0x702c8218`.
- The fitted panel variant's own tables.
