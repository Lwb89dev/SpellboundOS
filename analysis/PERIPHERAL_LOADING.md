# Bip 6 OTA: initial peripheral loader decompilation

Date: 2026-11-15. This is static analysis of the official 4.6.0.3 OTA, SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
The main firmware member has SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.
No watch execution or hardware access was performed.

## Method and address caveat

Earlier REA/Binwalk inventory identified candidate regions and strings. REA's
raw-binary Ghidra route previously did not accept RISC-V for this image, so this
pass uses Ghidra 12.1.2 headless directly, with `RISCV:LE:32:default`, `gcc`,
and raw image base `0x70160000`. The candidate base is supported by the stock
bootloader's apparent load address and by PC-relative references resolving to
relevant strings, but the device's actual runtime mapping has not been measured.
Addresses below are conditional on that mapping; file offsets identify bytes in
the decompressed `META/firmware_sign.bin` ZIP member.

An initial broad automated analysis was stopped because it generated a large
number of bad/unmapped references. Instead, function starts were manually
seeded from candidate RISC-V prologues and decompiled without whole-image
analysis using [DecompilePeripheralLoad.java](../analysis_scripts/DecompilePeripheralLoad.java).
Independent instruction disassembly corroborated the string references and
function prologues. Function boundaries, inferred parameter types and external
calls can still be wrong. Ghidra emitted `custom2()` for undecoded instructions;
the resulting pseudocode omits their effects and cannot establish full behavior.
Full logs and the analysis database are kept locally under ignored `firmware/`.

Reproduce from the project root with a locally installed Ghidra 12.1.2:

```sh
unzip -p firmware/bip6-4.6.0.3.zip META/firmware_sign.bin > firmware/firmware-main.bin
mkdir -p firmware/ghidra-targeted-repro
/path/to/ghidra/support/analyzeHeadless "$PWD/firmware/ghidra-targeted-repro" bip6-targeted \
  -import "$PWD/firmware/firmware-main.bin" -loader BinaryLoader \
  -loader-baseAddr 0x70160000 -processor RISCV:LE:32:default -cspec gcc \
  -noanalysis -scriptPath "$PWD/analysis_scripts" \
  -postScript DecompilePeripheralLoad.java -log "$PWD/firmware/ghidra-targeted-repro.log"
```

## Sensor-hub loading

- A candidate function at `0x707241fa` (file offset `0x5c41fa`) constructs a
  path using `/mnt/system/extfw`, `sensorhub@mhs003_sign.bin` and `%s/%s`, then
  queries and opens it. Its error strings include load, validation and open
  failures. The conditional `_sign` path calls candidate `0x702c50b0`,
  which in turn calls `0x702c2842`; a zero result leads to the validation
  error message.
- Candidate `0x702c2842` rejects lengths below 65 bytes, reads the final 64
  bytes, then processes the preceding bytes in blocks of up to `0x1000`, ending
  in a 32-byte output passed with the final 64 bytes to `0x702c2682`. The latter
  copies 64 bytes at firmware file offset `0x8cc2bc`; these match the candidate
  public key at bootloader file offset `0x37094` byte for byte, and passes them
  along with the 32-byte output and 64-byte trailer to another unresolved call.
  The separately verified SHA-256/ECDSA signatures are consistent with this
  flow, but the unresolved calls and static analysis do not by themselves prove
  the algorithm or runtime enforcement on the watch.
- The function requests a `0xa000`-byte buffer and loops over the image in
  chunks up to that size. On the first chunk it compares the first word with
  `0x5550434c`, little-endian ASCII `LCPU`. When it matches, it takes the next
  two words as candidate destination and entry arguments. Otherwise both fall
  back to `0x80f62000`. It passes these values and each chunk to the candidate
  routine at `0x70163860`. The decompilation does not prove complete copying,
  error handling, or execution because the called routine has undecoded
  instructions and the analysis lacks external function types.
- The actual OTA sensor-hub member begins with `LCPU`, followed by little-endian
  words `0x80f62000` and `0x80f62020`. At member offset `0x20` it contains
  another RISC-V-looking header with `HDRZ` and candidate entry `0x80f6224c`.
  These are static header values, not measured memory or a demonstrated boot
  procedure. The enclosing signed member's SHA-256 is
  `06f07541e8bb22b6118f081e791c3a4e40cbff2decd8ee478a7e82df826e9d0f`.
- Candidate `0x70163860` refers to address `0x90008084`, checks a computed
  upper bound against `0x81000000`, and has messages for sensor-hub load and
  bring-up. Its `custom2()` and other unmapped calls prevent identifying the
  transfer mechanism, registers, or actual hardware sequence.

## RTL8763 package

A candidate function at `0x703cd15a` (file offset `0x26d15a`) refers to
`/mnt/system/extfw/pamir/rtl8763_pack.bin`, queries a size and contains a
`0x200000` size bound. Its log messages describe loading patch RAM and failing
to open or read a patch package. It attempts an initial `0x48`-byte read. A
`custom2()` follows, so the decompiled result does not explain the transfer,
protocol, radio initialization or whether that package is actually used by a
particular device. More than one code reference to the path exists; only this
candidate function has been examined here.

## Open questions

1. Resolve the hash and signature callees and their failure handling, and
   independently establish which validation paths execute on the device.
2. Decode the custom instructions and resolve the called routines, actual copy
   mechanism, entry semantics and error paths before describing a usable HAL.
3. Analyze the RTL8763 package parser and transport; identify the real radio and
   bus independently before implementing any driver.
4. Establish an independently verified device backup and safe recovery/boot path
   before any hardware write. None was established by this analysis.
