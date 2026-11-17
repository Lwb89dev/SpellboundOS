# NAND retry and UID through the original bus, QSPI and FIFO

All **67 native cases** pass in **1,565,265 instruction/service steps** (maximum
**679,078** for UID acquisition after a complete busy timeout). The original
retry setter, compatibility/retry/reset-check logic, connected page-read
recovery, UID acquisition and selected UID ioctl execute through the actual
platform, command builders, bus and QSPI/FIFO. A recovered private page read
also connects the actual DMA backend.

[nand-identity-stack.json](nand-identity-stack.json) contains the compared
observations and hashes for 52 code ranges/exports and 39 data ranges. The prior
90/28/47/31/27/64-case reports reproduce byte for byte: **287 regression cases**.
Thirty new host checks bring the suite to **1,305 passing tests**. No watch or
phone was accessed; no physical UID or ECC correction was obtained.

## Original candidates and supplied peripheral behavior

All eleven original candidate descriptors and their name/UID-sequence bytes are
guarded against the startup-aware image. Each selected descriptor is cloned to
emulator RAM, with the authored platform clock word 104 and plane flag zero.
Explicit UID flag/mode/copy-count/size variants are separately named fixtures.
The first fitted chip remains unidentified.

Only original candidate 3, `Winbond W25N04LWZEIG`, matches the retry compatibility
check. Both original family-name comparisons execute; their bounded `strncmp`
implementation is supplied. No alternate `W25N02LWZEIG` descriptor is invented
or claimed to be fitted.

Feature bytes now pass through original `0x0f` reads and `0x1f` writes, the bus
converter and real FIFO routines. The authored peripheral model records writes
to feature registers, supplies optional readback overrides, and can ignore
`0xe0` writes. Register `0xc0` has an independent authored status stream; its
reads are counted separately from `0xe0` reads. The reset model deliberately
retains authored register state, so this pass establishes software response to
that state, not physical reset semantics.

MMIO, reset clearing, timestamps, delays, version result 2, UID FIFO bytes,
cache/copy/zero/format/compare bodies and the BBT are supplied. Intermediate NAND
builders, feature/status helpers and the bus/HAL are not replaced.

## Setter verification and retry restoration

Actual setter `0x80c29d94(level)` reads feature register `0xe0`, preserves its
upper bits and writes/verifies when the low three bits differ. A matching level
performs only the initial read. A scripted second-attempt fixture confirms the
retry loop through actual FIFO writes and readbacks.

If all five readbacks disagree, the setter logs five mismatches but **returns
zero**. Ignoring writes in the authored peripheral leaves the old register value
unchanged. The connected retry can subsequently report success and finish with
the requested restoration still unconfirmed. The fixture starting at level 1
produces ten mismatches across initial level-zero selection and final restore,
yet returns zero with `0xe0` still 1.

Only argument 3 is rejected before accessing the bus. Authored values 4, 8, 256
and `0xffffffff` are accepted; the byte-sized OR operation can spill into upper
register bits or truncate the requested level. These are bounded API
counterexamples, not observed driver requests.

Actual retry `0x80c29e6e(page)` selects levels 0, 1 and 2, reloads the page and
executes the original busy loop after each selection. Selected success at each
level and exhaustion of all three levels execute. Normal success/exhaustion
then executes the original level-zero restoration. Exhaustion returns `-1`.

A natural HAL failure during restore stops at the original bus assertion even
after `retry_valid` was logged. It does not take the isolated pass's injected
nonzero helper-return path or produce a `restore_failed` log.

## Connected page read and reset check

The actual page reader remaps logical page 600 to 792, loads it, accepts authored
ECC-bad status `0x20`, and calls the actual supported-family retry with page 792.
Recovered cases log `workaround_ok`, fetch cache data and return zero. Recovery
at the last level reloads four times in total: initial load plus three retries.
Exhaustion still fetches cache data and then returns `-101`.

The private read case returns through actual DMA setup/wait and buffer copy.
DMA payload movement is not simulated: the copied `0xa5` sentinel is an expected
fixture outcome, not recovered NAND bytes. The direct cache stream is authored.

The actual reset check submits original `0x66` and `0x99` builders, with supplied
delays 1000 and 5000, then reads `0xe0`. A nonzero level reaches the real setter.
The check can therefore return zero after setter verification exhaustion too.

## UID FIFO acquisition and complement checks

All eleven original candidates execute the UID entry. Eight enable acquisition;
three skip it. Enabled candidates write and verify their original configuration
sequence, load the UID page, poll status, then use original opcode `0x03` cache
reads. The forced-direct flag keeps these 32-byte transfers on the actual
polling FIFO path despite their length.

Authored UID copies contain 16 bytes followed by their complements. The real
comparison loop accepts the first, second or sixteenth copy, publishes length
16, and formats/logs the selected bytes. Invalid copies advance the column by
32. Sixteen invalid copies leave the last invalid bytes in the UID buffer,
publish length zero, and log `-200`.

Configuration mismatch, ECC-bad status and an authored size 129 fail before
clearing prior UID length/data. An unsupported authored mode skips acquisition
and preserves them too. Other explicit variants, size 16 or zero copies,
reach a success log with length zero and no cache transfer; original candidates
all declare size 32 and sixteen copies.

The actual ioctl `0x18` copies the current length and bytes. It successfully
exports acquired data, but can also export the prior authored 16-byte sentinel
after configuration mismatch. Following invalid-copy exhaustion it returns
zero while exporting length zero. A UID-disabled descriptor returns `-201`.
The acquisition entry returns void, so its logs and global state matter to
callers; the ioctl does not establish successful fresh acquisition.

## Complete timeout and partial-failure state

Two cases each execute all 2,000 busy polls through original feature/bus/HAL
code. Timeout logs leave status output `0xff` and return zero. For the selected
descriptor, masked `0xff` does not equal ECC-bad `0x20`:

- Retry logs `retry_valid`, restores level zero and returns zero after timeout.
- UID acquisition continues into the authored cache stream and publishes a UID
  after timeout.

These are control-flow results, not physical recovery, valid identity or proof
that the actual NAND would supply those bytes while busy.

Initial feature, verification, load, cache and restoration failures stop at
checked original bus assertions. A cache-receive failure occurs **after** UID
length was cleared and the 32-byte UID area zeroed. Earlier failures retain
prior length and bytes. These state differences are checked alongside register
events, caller-buffer hashes and ABI canaries on normal returns.

## Guarding and remaining work

The BBT's 164-byte backing ends exactly at UID address `0x80df4370`. The extended
runner guards the combined BBT/128-byte UID range externally and checks the BBT
body immutable. A separate guard between these adjacent objects would overwrite
live input or reject legitimate UID writes. This is bounded observed backing,
not a complete static allocation-size claim.

Each fixture has a 1,500,000-step cap. Selected read/program/erase/copy/OOB and
retry/UID policies now connect to original bus/HAL code, with authored peripheral
effects. Higher storage integration, BBT provenance/repair, complete concurrency
and cache/IRQ behavior, physical chip/geometry/ECC/UID/persistence, device-specific
backup/restoration and standalone boot remain open.
