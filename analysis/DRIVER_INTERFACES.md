# Bip 6: candidate driver interfaces and integrity routines

Static investigation on 2026-11-15. This report supplements
[PERIPHERAL_LOADING.md](PERIPHERAL_LOADING.md), including its firmware hashes,
Ghidra version, raw-image caveats, and interpretation of undecoded `custom2`
instructions. These are observations about bundled code, not proof that the
corresponding hardware exists or behaves this way on the connected watch.
No device I/O was performed.

## Image validation: digest and key

With the candidate main image base `0x70160000`, function `0x702c2842` calls
`0x7041c840` before processing the image payload. The initializer writes all
of the standard eight SHA-256 initial state words, beginning `0x6a09e667` and
ending `0x5be0cd19`. Candidate update `0x7041c89e` is called on chunks of the
payload, and finalizer `0x7041c8f8` produces 32 bytes. Padding and output layout
are consistent with SHA-256, but `custom2` instructions make portions of the
decompiled update/finalizer incomplete. Separately, the OTA's ECDSA signatures
were verified offline using Python `cryptography` (see
[ota-signatures.json](ota-signatures.json)).

The validation path calls `0x702c2682`, which copies 64 bytes from
`0x70a2c2bc`, the same public-key bytes found in the bootloader, and passes
those, the 32-byte digest, and the 64-byte trailer into `0x704ee55c`. The latter
contains large-integer/curve-like operations and many unresolved custom
instructions. This supports a signature-verification interpretation, but we
have not independently reconstructed that routine or observed it on the watch.

## Sensor hub: LSM6DSO candidate

The hub image is mapped experimentally at `0x80f62000`, based on its `LCPU`
header. The file is `META/extfw/sensorhub@mhs003_sign.bin`, SHA-256
`06f07541e8bb22b6118f081e791c3a4e40cbff2decd8ee478a7e82df826e9d0f`.
Under this mapping, independent PC-relative instruction scanning resolves
references to strings mentioning LSM6DSO reset and initialization. In the
following, addresses are candidate virtual addresses in this raw mapping.

- `0x80f726ee` references `dev_lsm6dso`, calls device/configuration routines,
  supplies a configuration field of `8000000` (units and exact meaning not
  established), and calls `0x80f71cb2`. Other strings in this path mention SPI
  and an interrupt initialization failure. These are clues to a candidate SPI
  implementation, not a verified bus assignment for the watch.
- `0x80f71cb2` calls reset candidate `0x80f7021c`, then an identification
  routine. The reset candidate calls `0x80f72bbe` to modify bit 0 of register
  `0x12`, and polls bit 0 through `0x80f72bfa` up to ten times. A helper called
  with `1` appears in the loop; its time units have not been verified. The
  identification path eventually asks an indirect read callback for one byte
  at register `0x0f`. Its returned value, error handling, and device identity
  comparison remain partly obscured by custom instructions.
- The context at `0x80fd876c` contains candidate callback pointers
  `0x80f6fb60` and `0x80f6fafa`, followed by a zero context word. The callback
  wrappers at `0x80f72914` and `0x80f7290e` call through the first and second
  pointers respectively. Under this static mapping, `0x80f6fafa` prepares a
  register byte with bit 7 set and calls `0x80f898ae` with a length of
  `requested_length + 1`; on a zero return it copies from the second received
  byte. `0x80f6fb60` prepares a register byte and data, and calls the same
  transfer helper. Custom instructions make buffer sizing and full error
  behavior uncertain. The actual pinout, chip select, register semantics and
  timing still require independent evidence.

These patterns are useful leads for a future independently implemented driver;
they are not sufficient to write one that is safe or functional on hardware.

## Main firmware: RTL8763 candidate transport

With the main image mapped at `0x70160000`, functions around `0x703c8cba` and
`0x703c8de2` reference log labels `rtl8763_sync_recv` and
`rtl8763_sync_send`. Their decompilation calls transport request routines,
waits for completion, and logs failed requests or timeouts. A candidate callback
at `0x703c8d78` accesses state shared with the receive routine. The send path
passes `3000` to a wait-like function, but its units and return conventions are
not established.

The request functions at `0x703ce4ea` and `0x703ce57c` reference labels
`bx_hal_trans_write_request` and `bx_hal_trans_read_request`, respectively;
they delegate to `0x702be72a` and `0x702be7b8`. Those appear to dispatch through
function pointers in a transport object. The concrete lower-level device,
serial framing, commands and pairing protocol are still unknown; these labels
alone do not establish that this is the watch's active Bluetooth path.

## Reproduction

[image-headers.json](image-headers.json) can be reproduced from the private
local OTA using `python3 analysis_scripts/inspect_image_headers.py
firmware/bip6-4.6.0.3.zip`. The parser reports only observed header fields;
it is not a general firmware parser or a validator of executable addresses.

[main-pcrefs.json](main-pcrefs.json) and [sensorhub-pcrefs.json](sensorhub-pcrefs.json)
were generated by [riscv_pc_references.py](../analysis_scripts/riscv_pc_references.py).
It checks adjacent `AUIPC`/`ADDI` pairs at every two-byte offset. Hits are
candidates, including possible data; it cannot establish function boundaries or
find every reference. The target offsets and assumed base are recorded in each
JSON. To regenerate, supply the corresponding extracted binary, `--base`, and
those target offsets. Confirm candidates with instruction disassembly and a
bounded decompilation before attributing behavior.

For example, from the project root with Ghidra 12.1.2 and the locally extracted
sensor image at `firmware/components/sensorhub@mhs003_sign.bin`:

```sh
mkdir -p firmware/ghidra-sensor-repro
/path/to/ghidra/support/analyzeHeadless "$PWD/firmware/ghidra-sensor-repro" bip6-sensor \
  -import "$PWD/firmware/components/sensorhub@mhs003_sign.bin" \
  -loader BinaryLoader -loader-baseAddr 0x80f62000 \
  -processor RISCV:LE:32:default -cspec gcc -noanalysis \
  -scriptPath "$PWD/analysis_scripts" -postScript DecompileFunctions.java \
  0x80f726ee 0x80f71cb2 0x80f7021c 0x80f72bbe 0x80f72bfa \
  0x80f72bb4 0x80f7290e 0x80f72914 0x80f6fb60 0x80f6fafa \
  -log "$PWD/firmware/ghidra-sensor-repro.log"
```

Use the same script with the main firmware and base `0x70160000` for the main
addresses in this report. The full local output is kept in ignored `firmware/`;
the repository does not redistribute vendor firmware or raw decompiler output.

## Remaining questions

- Decode the custom instructions and determine precise error/timeout behavior.
- Resolve the radio transport's function pointers and framing, then corroborate
  the actual bus and component on the watch without writing firmware.
- Identify the fitted motion sensor, bus, chip-select, interrupt, power and
  initialization sequence using independent hardware or diagnostic evidence.
- Establish a tested boot and recovery path before deploying a standalone OS.

## Later pass

The AndeStar profile resolves the LSM6DSO identification comparison as `0x6c`,
read through the previously identified register path. This strengthens the
bundled-driver interpretation; no sensor was queried on the watch. The expanded
corpus also links the radio to a serial abstraction and identifies the ZTW622
probe path; see [TOUCH_AND_SERIAL.md](TOUCH_AND_SERIAL.md). Earlier unresolved
custom-instruction comments describe the generic-profile pass and should be
read alongside [INSTRUCTION_PROFILE.md](INSTRUCTION_PROFILE.md).
