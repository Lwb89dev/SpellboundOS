# ICNA3311 display bring-up and the real panel init tables

Both **2 native cases** pass (power/reset bring-up and the real init table) and
the nine embedded init tables are decoded from the firmware. This completes the
command contract started in [MAIN_DISPLAY_PANEL.md](MAIN_DISPLAY_PANEL.md). The
evidence is in [main-display-init.json](main-display-init.json).

## Power/reset bring-up (`0x702c8ae2`)

The executed bring-up performs, in order:

1. enable the 1.8 V rail;
2. delay 5 ms;
3. enable the 3.3 V rail;
4. configure the bus (with the descriptor's `+0x10` value);
5. drive the reset line (descriptor `+8`) low;
6. delay 12 ms;
7. drive the reset line high;
8. delay 12 ms.

The native case confirms this exact call sequence with the recovered rail
handles, reset pin and delays.

## Real init command tables

Each ICNA3311 variant descriptor holds its init table: the length at `+8` and a
pointer at `+0xc`. The DCS command-table player `0x702c8314` plays it. Executing
the player over the **real** firmware table for variant `0x1b0909` (416×416)
captures its 25 DCS writes, including:

| DCS | Meaning |
| --- | --- |
| `FE 20`, `F4 5A`, `F5 59`, … | ICNA3311 page select (`0xFE`) and vendor register writes |
| `35 00` | `set_tear_on` (TE line enabled) |
| `53 20` | `write_control_display` |
| `51 FF` | `write_display_brightness` (maximum) |
| `3A 55` | `set_pixel_format` = RGB565 (16 bpp) |
| `2A 00 12 01 B1` | `set_column_address` 0x0012–0x01B1 → 416 columns |
| `2B 00 00 01 9F` | `set_page_address` 0x0000–0x019F → 416 rows |

The capture is taken from the firmware's own data, so the init DCS stream is
verified rather than assumed.

## The nine ICNA3311 variants

The firmware carries nine variant descriptors; their decoded init tables give:

| Id | Table length | Entries | Geometry |
| --- | --- | ---: | --- |
| `0x250905` | `0x46` | 16 | 192×490 |
| `0x5a0905` | `0x46` | 16 | 192×490 |
| `0x250906` | `0x3c` | 14 | (no column/page set) |
| `0x1b0909` | `0x6a` | 25 | 416×416 |
| `0x4b090d` | `0x4a` | 17 | 390×450 |
| `0x5c0913` | `0xa7` | 40 | 390×450 |
| `0x5b0913` | `0xa7` | 40 | 390×450 |
| `0x250914` | `0xb7` | 44 | 390×450 |
| `0x2c0914` | `0xb7` | 44 | 390×450 |

The device runs exactly one of these; the Bip 6's actual variant is unknown
offline and must be read from the panel (`display_panel_read_id`).

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_display_init --vectors-output firmware/main-display-init-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainDisplayInit.java firmware/main-display-init-vectors.json \
  firmware/main-display-init-validation.json
python3 -m analysis_scripts.main_display_init firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-display-init-vectors.json \
  --validation firmware/main-display-init-validation.json > analysis/main-display-init.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining for a working display driver (needs the device):

- Sleep-out (`0x11`) / display-on (`0x29`) sequencing around the init table.
- The framebuffer/refresh path: the window-set and memory-write DCS commands,
  the tear-effect/vsync handshake and the physical bus behind the device ops.
- Backlight/brightness runtime control and confirmation of rail voltages, reset
  timing and the device's actual variant on hardware.
