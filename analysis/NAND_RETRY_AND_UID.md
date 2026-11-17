# NAND read retry, UID acquisition and UID ioctl

All 86 native cases pass in 334,591 steps, with a maximum of 100,723 for UID
export after an all-busy timeout. Actual compatibility/level/retry/reset-check/
UID routines, selected command builders, busy loop and the UID ioctl branch
execute. Original descriptor facts are in [nand-identity.json](nand-identity.json);
complete observations and provenance are in
[nand-identity-native.json](nand-identity-native.json).

The first 79 cases cover retry/UID and the remaining seven connect UID acquisition
to export. The original 79 observations and step counts remain identical after
adding export. Forty-four new host tests bring the full suite to **1,091 passing
tests**.

Bus transfer `0x80c106f0` is supplied in this pass. Feature-register persistence,
readback/status bytes, UID copies, explicit helper-return faults and delays are
authored. Comparison, formatting and UID copy services are supplied. Actual QSPI
transfer/HAL and physical ECC correction or UID uniqueness are not established.
No watch or phone was accessed.

## Compatibility and retry-level setter

Actual compatibility helper `0x80c29d4c` compares the first 20 name bytes against
`Winbond W25N02LWZEIG` and `Winbond W25N04LWZEIG`. Only the latter appears in the
original eleven-chip table, at descriptor `0x80c3dde8`. An authored 02L name and
a name with a suffix beyond byte 20 also match. Missing descriptor and the other
original candidates return `-1`.

Actual setter `0x80c29d94(level)` rejects argument 3 before bus access. Otherwise
it reads feature register `e0`. Initial read error is returned. If the lower
three bits already equal the requested argument, it returns zero without writing.
For normal levels it preserves the upper bits and attempts to write/read back
the modified byte, up to five times.

The return value after exhausting those attempts is still the **successful
initial read status, zero**. Actual command-builder/bus execution with authored
unchanged readback confirms five mismatch logs and return zero while the
register remains unchanged. Separate explicit helper-entry injections confirm
the same outer result after five write failures or five readback failures.
Actual command builders normally return zero or assert on a failed bus callback;
those injected helper errors are not claimed as natural builder outcomes.

The selected setter checks only `level != 3`, rather than bounding the argument
to 0–2. Authored arguments 4, 8, 256 and `0xffffffff` execute. Its OR uses the
argument's low byte without masking it to three bits, so such inputs can change
upper bits or truncate. These are bounded software counterexamples, not observed
device requests or a supported public level range.

## Page retry and reset-time check

Actual workaround `0x80c29e6e(page)` first checks compatibility, then tries levels
0, 1 and 2. Each attempt calls the actual setter, page-to-cache builder and busy
loop. It declares the page valid when the returned status does not match the
selected descriptor's ECC-error mask/value. All-bad statuses exhaust three page
loads and return `-1`.

The workaround attempts to restore level zero after success or a loop error.
Restore failure is logged but does not replace an already successful page
result. An unconfirmed level change can therefore be followed by a page load,
and even an unconfirmed restore can coexist with return zero. This does not
establish that a physical ECC error was corrected.

The actual busy-loop timeout behavior from the
[page-policy pass](NAND_PAGE_POLICY.md) also reaches this workaround: 2,000
authored busy responses produce a timeout log and output `ff`. For the selected
descriptor, `ff & 0x30` is `0x30`, distinct from error value `0x20`. The workaround
then logs a valid page and returns zero. Actual hardware readiness and the
subsequent physical cache response remain unverified.

Actual reset check `0x80c29f5c` emits the actual reset-enable/reset command packets
`66` and `99`, requesting delays 1,000 and 5,000 through the original delay thunk.
It reads `e0` and accepts lower bits zero. Nonzero bits or an initial read error
fall back to the actual level-zero setter. The setter's unconfirmed-success
behavior therefore also affects this check. Bus failures at either reset builder
reach distinct assertions; execution stops before their bodies. The requested
delays do not establish measured timing or physical reset.

## Original UID descriptors

All eleven original descriptors specify UID mode 1, page zero, 32-byte copies
and a maximum of 16 copies. Eight enable acquisition. The disabled entries are
DOSILICON DS35M1GA, DS35M2GA and DS35M2GB. The four Winbond entries request
feature `b0 = 48`; the DOSILICON/ESMT descriptors request `b0 = 40`, including
entries whose UID flag disables the path. These are image facts, not fitted-chip
identification.

Actual UID routine `0x80c28422` checks the descriptor's UID flag and mode, bounds
the size to at most 128, writes/reads the requested feature sequence, loads the
descriptor page and runs the actual busy loop. The runner requires a non-null
descriptor for UID tests; it does not claim safe null-pointer handling. Explicit
descriptor-copy variants exercise other modes/sizes/counts and an extra feature
pair without changing original firmware bytes.

For the original 32-byte path, it clears the read buffer at `0x80df4370`, requests
a single-line cache read and compares the first 16 bytes with the complement of
the second 16. It checks every pair, including the final byte. A failed candidate
advances the column by 32. Authored successful first/second/sixteenth copies stop
at columns 0/32/480, publish length 16 at `0x80d81f24` and format 32 uppercase hex
characters. Sixteen invalid candidates log `-200` and leave length zero.

UID return status is not claimed: the routine has a void boundary. Normal
stack/saved-register preservation is checked. Observed outcomes are global
length/data, logs and control flow.

## UID error and publication state

The published length is cleared only **after** feature setup, page load, busy
poll and ECC-status acceptance. Feature write/read/mismatch diagnostics distinguish
`-5` / `-6` / `-7`, but the UID routine's outer diagnostic collapses them to `-5`.
Those early failures preserve the previous length. Page-load, busy-feature and
ECC errors similarly occur before clearing, logging `-52` / `-100` / `-101`.

Cache-helper error occurs after the clear: length remains zero and the read
buffer has been zeroed. The outer diagnostic is `-53`. Bus callback failures
inside the actual feature/cache builders instead reach assertions; explicit
helper-return injections separately exercise the outer UID branches.

Authored sizes 0, 64 and 128 pass the size bound but do not enter the 32-byte
complement-validation loop. They log the final UID message with length zero and
an empty formatted value. Size 129 logs `-1` before feature setup. Mode zero
skips acquisition without clearing prior length. Zero copies likewise reach the
final message with length zero.

An all-busy timeout can still be followed by successful supplied cache bytes and
publish length 16, for the same `ff`/ECC-mask reason as page retry. Complement
consistency checks alone do not establish physical UID provenance or uniqueness.

## Connected ioctl export

Seven cases call the actual chip ioctl `0x80c292ee(0x18, output, mode)` immediately
after actual UID acquisition. The selected branch tests the descriptor UID flag,
copies the global length as the first byte and requests exactly that many bytes
from the UID buffer. It does not rerun acquisition or inspect a preceding error.

- A valid authored UID produces return zero, length 16 and the exact 16 bytes.
- After an injected feature-read failure, an authored prior length 16 and prior
  buffer filled with `a5` are still copied, and ioctl returns zero. This proves
  stale-state exposure for the fixture, not a captured physical UID.
- After invalid copies, cache-helper failure or an authored non-32-byte size,
  ioctl returns zero with length zero.
- A descriptor with its UID flag disabled returns `-201` and leaves output
  unchanged.
- The all-busy fixture can export the supplied valid bytes despite its earlier
  timeout log.

The runner verifies the copied count, payload/length, destination guards and UID
source immutability. It bounds authored prior length to 128 for export cases;
larger corrupt lengths and caller buffer-capacity enforcement remain outside
coverage.

## Reproduction and limits

```sh
python3 analysis_scripts/nand_identity.py firmware/bip6-4.6.0.3.zip \
  --inventory-output analysis/nand-identity.json
python3 analysis_scripts/nand_identity.py \
  --vectors-output firmware/nand-identity-native-vectors.json
```

Apply `SeedNandIdentity.java` to the startup-aware `boot-runtime` project. Export
`nand_identity.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`,
to `firmware/decompiled/runtime-nand-identity`. The delay thunk is guarded and
executed but omitted from that export list because Ghidra resolves its function
to the supplied delay implementation. Then run:

```text
-postScript ValidateNandIdentity.java firmware/nand-identity-native-vectors.json firmware/nand-identity-native-validation.json
```

```sh
python3 analysis_scripts/nand_identity.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-identity \
  --vectors firmware/nand-identity-native-vectors.json \
  --validation firmware/nand-identity-native-validation.json > analysis/nand-identity-native.json
python3 -m unittest discover -s tests -p 'test_nand_identity.py' -q
```

Fifteen code and 37 data ranges are guarded, including original descriptors,
names, feature sequences, bus binding and format bytes. Each case is bounded to
500,000 steps. Unexpected PCs and bus/service arguments fail validation. The
runner checks exact command fields/payloads, complete traces, normal return ABI
or explicit assertion stops, UID/export hashes/guards and descriptor/name/
sequence immutability. Fourteen fresh export hashes are recorded.

Physical read retry/ECC recovery and UID provenance, lower QSPI/HAL behavior,
complete page-to-HAL integration, BBT creation/provenance, SFTL and persistence
remain open. Device-specific backup/restoration and standalone signed-chain boot
remain unresolved.

The subsequent [QSPI HAL pass](QSPI_HAL_AND_FIFO.md) executes the actual HAL and
connects selected NAND builders through actual bus transfer to an authored FIFO.
This earlier retry/UID pass still uses its supplied bus boundary. Physical timing,
DMA internals and complete page/private-buffer integration remain open.

The subsequent [connected retry/UID pass](NAND_RETRY_UID_STACK.md) executes
supported-family retry, page-read recovery, UID acquisition and selected ioctl
through original platform/bus/QSPI/FIFO, with selected private-read DMA.
Feature/UID/peripheral effects remain authored; physical correction and identity
provenance are unvalidated.
