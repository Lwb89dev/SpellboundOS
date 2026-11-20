# AG3335 GNSS: PAIR framing, acknowledgement table and command catalog

The GNSS receiver is an **Airoha AG3335M** (`dev_ag3335`, `uart1`, rails
`GPS_1V8`/`GPS_0V8`). The driver controls it with proprietary NMEA "PAIR"
sentences. The evidence is in [main-gnss-pair.json](main-gnss-pair.json).

## Framing

- The builder `0x704b5d8e(body)` formats `"P%s%s"` with `"AIR"` and the body,
  then `"$%s*%02X\r\n"` with the XOR checksum:
  **`$PAIR<code>[,<params>]*HH\r\n`**. For example, `$PAIR002*38`,
  `$PAIR104,1*22` and `$PAIR066,1,1,1,1,0,0*3A`.
- Frames that do not contain `600` are logged. The frame then goes to the
  UART writer `0x704bd530(frame, length, 1)`.
- The original checksum `0x704b5d74(buffer, length)` executes natively: all
  **8 cases** pass.
- The builder itself is decoded statically. Its libc `vfprintf` contains the
  word `0xf33b89ff` at `0x7094d4c2` (opcode `0x7f`), which neither Ghidra nor
  LLVM decodes.
- **Send with retry** `0x704b5e60` builds `"%s,%s"` (code and parameter), then
  waits up to 2000 ms for the acknowledgement event, with up to three
  attempts.
- The `PAIR001,<code>,<result>` parser `0x704b5c3c` matches replies against a
  **43-entry table** at `0x70bfe258`. Each entry holds a code, the result
  characters `0`/`1` and an event bit.

## Command catalog (49 call sites, operands verified)

| Group | Commands as sent |
| --- | --- |
| `set_gnss_band_mode` | `105` (query) → `003` → `104,1` or `104,0` → `002` |
| EPO aiding | `470,0`/`470,1`/`470,3`; `530,{0..4},7200`; `550,{0..3},30`; queries `533`, `472`, `553`, `513` |
| `gnss_pair_set_gnss_search_mode` | `066,<six flags>` |
| `gnss_set_glp_mode` | `680,0`/`680,1`, `730,0` |
| `gnss_defconfig_cmd` | `006`, `007`, `005`, `084,1`, `178,0`, `778,1` |
| init | `112,…`, `513`, `086,0`, `778,0` |
| other | `064,%d`, `058,…`, `113` (no acknowledgement entry) |

The meanings come only from the calling function names. Parameter semantics
of computed parameters are not decoded. The table in the evidence lists every
call site with its code and parameter.

## Reproduction

```sh
python3 -m analysis_scripts.main_gnss_pair --vectors-output firmware/main-gnss-pair-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-gnss-pair-vectors.json firmware/main-gnss-pair-validation.json
python3 -m analysis_scripts.main_gnss_pair firmware/bip6-4.6.0.3.zip --vectors firmware/main-gnss-pair-vectors.json \
  --validation firmware/main-gnss-pair-validation.json > analysis/main-gnss-pair.json
python3 -m unittest tests.test_main_gnss_pair -q
```

## Remaining

- The UART line settings and the receiver power and boot sequence
  (`brom_start_task`).
- The EPO/ELPO file formats and the NMEA/position path.
- Decoding the `0x7f`-opcode word in libc, which matters for any future native
  run through `vfprintf`.
