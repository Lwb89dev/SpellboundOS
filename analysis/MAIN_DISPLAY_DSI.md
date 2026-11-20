# ICNA3311 display: DSI command-write packet dispatch

`mhs_dc_write_cmd` (`0x701620f0`) sends a DCS command to the ICNA3311 panel over
the MIPI-DSI link. When the DSI engine is active (`0x80c1220c` and `0x80c12208`
set) it serializes three semaphores (`_dsi_cmd_semaphore`, then `_dsi_semaphore`
1 and 2, each with a 10000-tick timeout) around the transfer and runs the
controller programming `0x70161e66` over the `0x9a000000` register block. This
scope executes the **packet dispatch** with the engine idle (`0x80c1220c = 0`),
so the semaphores are skipped and the packetization logic runs with the
controller programming and the low-level writer supplied. Executed in
`main-runtime`; the evidence is in [main-display-dsi.json](main-display-dsi.json).
All **6 native cases pass**.

## Packetization

The configured command kind byte at `0x80c00c8c` selects the format:

- kind `2`: a **short packet** — `cmd[0] << 8`, MIPI data type `2`;
- otherwise the **MIPI data type is chosen by length**: `0x05` (length 1),
  `0x15` (length 2) or `0x39` (long write).

The low-level writer is then called as
`0x702a1eb0(config, data_type, byte0, &cmd[1], length-1)`.

## Return codes (observed natively)

| Case | Data type | Return |
| --- | --- | --- |
| short write, no param (len 1) | `0x05` | `0` |
| short write, 1 param (len 2) | `0x15` | `0` |
| long write (len > 2) | `0x39` | `0` |
| kind-2 short packet | `2` | `0` |
| writer failure | `0x15` | `-1` (logs `write cmd fail`) |
| NULL buffer / zero length | — | `-10` |

## Reproduction

```sh
python3 -m analysis_scripts.main_display_dsi --vectors-output firmware/main-display-dsi-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-display-dsi-vectors.json firmware/main-display-dsi-validation.json
python3 -m analysis_scripts.main_display_dsi firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-display-dsi-vectors.json \
  --validation firmware/main-display-dsi-validation.json > analysis/main-display-dsi.json
python3 -m unittest tests.test_main_display_dsi -q
```

## Remaining (display module)

- The **semaphore-serialized active path** (engine running) and the controller
  programming `0x70161e66` (the `0x9a000000` DSI register block, hardware MMIO).
- The **frame path**: `write_frame_work_out`, the framebuffer DMA to the DSI
  link and the TE (tearing-effect) interrupt. These are hardware-register/DMA
  orchestration and are documented here as the remaining display work.
- `mhs_dc_read_cmd` (`0x70161f2a`), the read counterpart with the same semaphore
  structure.
