# Main UID export after actual probe and acquisition

All **16 native cases** pass in **141,306 instruction/service steps** (maximum
**23,961**, sixteenth valid UID copy). Actual main context interface
`0x702d5c26`, context/mutex helpers and chip ioctl `0x702d7414`, request 24, now
consume the state produced by [actual main UID acquisition](MAIN_NAND_UID.md)
inside the original probe/platform/FIFO/root chain.
[main-nand-uid-export.json](main-nand-uid-export.json) records **54 code/export
and 65 data hashes**, observations and limitations.

This is a direct context query. The generic NAND object ioctl accepts geometry
requests `0x1001`/`0x1002` and the no-op `0x1003`; it does not forward UID request
24. The native case with geometry/open/close and repeated UID export exercises
both interfaces in sequence, without inventing a generic UID command.

## Copy, retained state and locking

With an original descriptor's UID flag enabled, request 24 writes one length
byte followed by that many bytes from original main UID buffer `0x70f9bc50`.
The bounded supplied copy helper verifies all three arguments, original source,
129-byte output backing and length at most 128. It does not execute a firmware
copy body. Output and source guards are checked, and each operation records the
output bytes separately. No source mutation or new acquisition occurs on export.

| Prior acquisition/state | Actual export result |
| --- | --- |
| First or sixteenth valid complementary copy | Zero, length 16 and the accepted first half |
| UID setup mismatch or ECC rejection | Zero, authored retained length 17 and prior bytes |
| All 16 complementary checks fail | Zero, length zero; invalid cache payload is not copied |
| Original descriptor disables UID | `-201`, output remains untouched |
| Authored retained length zero or 128 after setup mismatch | Zero, copies the current declared length without freshness validation |

The 128-byte prior-length case is an authored bounded counterexample, not a
claim that a real device previously acquired an identity of that length.
Original Winbond, DOSILICON and ESMT descriptors are unchanged. The supported
Winbond family also executes its actual workaround before acquisition/export.

Normal context queries use the supplied RTOS mutex services through original
helpers. Authored IRQ/scheduler states select the original direct branches and
bypass locking. Acquisition failure reaches assertion owner `0x70a30f20`, line
36, before chip dispatch/copy. Release failure reaches owner `0x70a30f08`, line
42, **after output has been written**; no normal return ABI is claimed for either
stopped case. Assertions stop before their bodies/recovery execute.

A successful export therefore proves copying of software state, including
retained state after handled UID errors. It does not prove a fresh or physical
identity. The direct interface also does not require an open generic object
reference; the selected sequence exports twice after the generic close.

## Reproduction and continuation

Use the startup-aware main project and prior seeds described in
[MAIN_NAND_WORKAROUND.md](MAIN_NAND_WORKAROUND.md), then apply
`SeedMainNandUidExport.java`. This updates metadata only, including the copy
helper's three-argument signature. Firmware instructions remain unchanged.

```sh
python3 analysis_scripts/main_nand_uid_export.py \
  --vectors-output firmware/main-nand-uid-export-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandUidExport.java \
  -postScript ValidateMainNandUidExport.java \
  firmware/main-nand-uid-export-vectors.json firmware/main-nand-uid-export-validation.json

python3 analysis_scripts/main_nand_uid_export.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-uid-export \
  --vectors firmware/main-nand-uid-export-vectors.json \
  --validation firmware/main-nand-uid-export-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_uid_export` with
`DecompileWithLogger.java`, logger `0x702b38a2`. The recorded exports precede the
later BBT metadata seed; avoid replacing an earlier evidence corpus in place.
Firmware/exports remain local. Eighteen host checks cover export state, retained
bytes, context assertions and native evidence. All **434 previous main native
cases**, including these 16, reproduce byte for byte during the subsequent
[main BBT work](MAIN_NAND_BBT.md).

Further identity consumers, actual RTOS behavior/concurrency and physical UID
provenance remain open. BBT is supplied in this export scope; the subsequent BBT
scope executes its verifier/resume/CRC with supplied page/marker services.
