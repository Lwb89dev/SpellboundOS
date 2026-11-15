# Touch probe and radio serial initialization

These findings come from the local AndeStar main-image export, assuming base
`0x70160000`. Addresses identify code in that candidate mapping, not measured
hardware. Ghidra still infers some return types incorrectly; individual
signatures must be checked before relying on the pseudocode.

## ZTW622 touch path

Candidate `0x701eb88a` references the board registry entry `dev_ztw622`, obtains
a bus handle, configures board-provided GPIO fields and enters a probe path.
The probe has a fallback that reads a 16-bit value from candidate register
`0x120` and accepts `0xe622`. It also has a separate information-block path
using address `0x9d2` and length `0x16`. These checks show what the bundled
driver expects, not the identity measured from the watch.

The register helpers show a two-byte register-selection write followed by a
read. Candidate read wrapper `0x701eae7a` passes constant `0x20`, destination,
length and `10` to the bus routine and retries after a reset call. Its error
label is `_ztw622_i2c_read`; candidate `0x701eadce` passes a two-byte register
value to the write helper, and `0x701eae04` passes register plus value as four
bytes. Bus-address convention, transfer timing, GPIO wiring and power controls
have not been independently verified. No transaction was sent to the watch.

## Radio serial path

Candidate `0x703ce862` requests board registry entry `dev_bluebox`, copies
board-provided fields and calls initialization candidate `0x703ce314`. The
latter obtains a handle through `0x702be15e`, whose assertion strings identify
it as `serial_dev_get_handle`, and calls `0x702be1b8` (`serial_dev_init`) with
configuration words including `0x1c200`, zero and `0xc03`. The first value is
numerically 115200 and is a plausible baud-rate field; the exact structure and
units still need verification. GPIO configuration follows using board fields.

This narrows the earlier transport finding to an actual serial abstraction in
the bundled path. It does not yet identify a UART instance, pinout, line
settings, or the active radio revision on this device.

The local exported functions are under `firmware/decompiled/main/`, indexed in
`functions.tsv`. Reproduce the individual functions with `DecompileFunctions.java`
and the AndeStar profile; supply `0x701eb88a 0x701eadce 0x701eae04 0x701eae7a
0x703ce862 0x703ce314 0x702be15e 0x702be1b8` in a fresh main-image import.
