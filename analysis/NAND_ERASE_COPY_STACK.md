# NAND erase, page copy and OOB patch through the original stack

All **64 native cases** pass in **5,534,722 instruction/service steps**, with a
maximum of **1,353,573** for a copy timing out in both phases. The cases comprise
20 erase, 21 page-copy and 23 copy-with-OOB fixtures. Original outer policies,
BBT remappers, command builders, both busy loops, platform initialization, bus
transfer and QSPI/FIFO execute together. Complete compared observations and
code/data/export hashes are in [nand-maintenance-stack.json](nand-maintenance-stack.json).

The prior 90 QSPI, 28 DMA, 47 platform, 31 connected read and 27 connected program
reports reproduce **byte for byte** with the extended runner: 223 regression
cases. Twenty-seven new host tests bring the suite to **1,275 passing tests**.
No phone or watch was accessed. Status bytes, MMIO, timestamps, BBT/guard/plane
variants and leaf delay/sleep/cache services are authored. No physical NAND
cells, page cache or persistent data movement are simulated.

## Original command sequences

| Operation | Original root | Command sequence with immediate ready status |
| --- | --- | --- |
| Erase | `0x80c291e6(block, blocking)` | `06` write-enable → `d8` erase → `0f` status |
| Page copy | `0x80c28d7a(source, dest)` | `13` load → `0f` status → `06` enable → `10` execute → `0f` status |
| Copy with OOB | `0x80c28ec4(source, dest, data, count)` | `13` load → `0f` status → `06` enable → `34` patch → `10` execute → `0f` status |

The page/block remappers run before command submission. With authored bad blocks
`[1, 3, 7]`, erase block 12 maps to block 15 and opcode `d8` receives page address
`15 * 64 = 960`. Copy source 600 maps to 792; destination 700 maps to 892. Both
page mappings complete before the source-load command is sent. Inactive BBT
fixtures retain the original input addresses.

Complete selected platform initialization uses the original clock, pin, QSPI
and adjacent DMA descriptor helpers. Deferred fixtures instead enter the actual
initializer inside the first bus transaction, after remapping and validation.

## OOB command and plane selection

The original OOB patch builder at `0x80c2800a` hardcodes opcode **`0x34`**, whereas
the ordinary page-program cache builder uses `0x32`. It supplies two address
bytes, quad data and the forced-direct flag. The 64-byte OOB case therefore
executes direct FIFO writes, without selecting DMA or the private buffer.

Captured FIFO bytes equal the caller's authored bytes, including a 13-byte
word/tail case. Caller RAM is unchanged. These observations establish the
software command and payload path; they do not prove that a physical chip
preserves the loaded cache or programs the resulting page correctly.

The OOB column is 2048 for the selected original descriptor. With an explicitly
authored plane flag, bit `0x40` of the **mapped source page** adds `0x1000`:

- Source 536 maps to 728 and patches at column `0x1800` before programming
  destination 892.
- Source 600 maps to 792, whose bit is clear. Even if destination 536 maps to
  plane-bit-set page 728, the patch column remains `0x800`.

Count 65 exceeds the declared 64-byte spare area and is rejected before loading
the source. Count zero is accepted: the builder still submits opcode `0x34`
and the caller continues to program-execute, without FIFO payload writes.
Same-source/destination page copy is also accepted by this selected policy.

## Protection, mapping and ECC

The authored guard thresholds are eight blocks and 512 pages. Guard decisions
use mapped addresses. Logical erase block 4 maps to 6 and is rejected; logical
block 5 maps to 8 and is allowed. Copy source or destination 319 maps to 447 and
is rejected, while source 320 maps to 512 and is allowed. Guard rejection logs
the appropriate block/page guard and returns `-250` before any NAND command.
Explicitly disabled guard fixtures allow low addresses; no hardware write
protection is established.

Reserved source/destination mappings produce `-151` for erase and `-150` for
copy. Inactive-BBT inputs at block 1024 or page 65536 instead fail geometry
validation with `-1`. Missing chip returns `-2` without remapping. All these
failures log the outer result and submit no NAND command.

Copy rejects source status `0x20` with `-101` **before write-enable** and does
not invoke the read retry workaround. This differs from ordinary page read,
which can attempt retry and still fetch cache bytes. Program status bit `0x08`
returns `-102` after copy execution. Erase checks bit `0x04` and returns `-104`;
bit `0x08` alone does not fail erase.

## Full timeout behavior across both copy phases

Each status transaction executes the original feature builder, bus, HAL and
polling receiver. The delay service is supplied but its original caller and
argument are checked. Erase's blocking route executes 4,000 polls with delay
argument 5; its other route executes 20 polls with sleep argument 1. Copy uses
the original 2,000-poll helper independently for source load and destination
program completion.

Both helpers check the limit before accepting the final status, log timeout,
leave output `0xff`, and return the last successful helper status, zero.

| Authored status sequence | Reads | Outer result |
| --- | ---: | --- |
| Erase busy forever, blocking | 4,000 | `-104` |
| Erase ready only at the blocking limit | 4,000 | `-104` |
| Erase busy forever or ready only at sleep limit | 20 | `-104` |
| Copy source busy for 2,000 polls, then destination ready | 2,001 | **Zero**, despite source timeout |
| Copy source ready, destination busy to limit | 2,001 | `-102` |
| Copy busy to the limit in both phases | 4,000 | `-102`, two timeout logs |

The source-timeout case proceeds because `0xff & 0x30` is `0x30`, rather than
the selected bad-ECC value `0x20`. The caller issues write-enable and
program-execute anyway; a later ready destination status can produce a zero
return. This is an original software failure mode under authored inputs, not
evidence of valid source data, successful physical copy or a fitted-device bug.

## Failure stops and evidence boundary

Write-enable, erase-command, source-load, status-receive and OOB FIFO failures
stop at the original direct-bus assertions, with checked owner `0x80c37b7c` and
stage lines `0x11f`, `0x12a` or `0x132`. Outer copy/erase result logs and injected
helper-error returns are not reached after those assertions.

The runner pins 45 code ranges and eight data ranges and enforces a
1,500,000-step cap per case. It checks ABI canaries on normal returns and guards
the immutable BBT, descriptor and command-frame backing, caller RAM, original
adjacent DMA descriptors and registry. The selected maintenance paths use
polling transfer; DMA initialization executes as part of platform setup.

The selected read/program/erase/copy/OOB software paths now connect through the
bus and QSPI layers. Supported-family retry/UID through the HAL, higher storage
integration, BBT provenance/repair, real cache/IRQ/coherency and physical
ID/geometry/ECC/OOB/persistence remain open. Device-specific backup/restoration
and standalone boot are still unresolved.
