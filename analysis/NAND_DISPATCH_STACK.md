# Original NAND partition, driver and RTOS-context dispatch

All **39 native cases** pass in **63,953 instruction/service steps** (maximum
7,925 for scheduler-delay erase timeout). Original partition read/ioctl,
operation-table callbacks, context selection and mutex wrappers execute through
the lower BBT/page/command/platform/QSPI stack. Normal 64-byte reads also execute
the actual DMA backend. Observations and 55 code/export plus ten data hashes are
in [nand-dispatch-stack.json](nand-dispatch-stack.json).

The prior 354 native cases reproduce byte for byte. Nineteen new host checks bring the suite to **1,324 passing tests**. No device
was accessed. Driver binding, partition/geometry/BBT backing, RTOS context and
mutex results, peripheral state and leaf services are authored. Concurrent
execution, physical NAND payload delivery and persistence are unverified.

## Original callback and context path

The driver property `0x80d81b28` points to original operations `0x80d811f4`.
Read entry +8 is `0x80c27c70`; ioctl entry +24 is `0x80c27b64`. The fixture binds
the driver global to that original property; registration and object lifetime
are outside this pass. Missing root/operations/callback fixtures use separate
RAM backing and return `-6` without entering a callback.

Actual helper `0x80c27a90` first calls supplied context query `0x80c170d4`.
A nonzero result skips the second query. Otherwise it calls supplied
`0x80c170e6(1)`. Either nonzero result makes the callback invoke the page/chip
routine with mode 1 and bypass mutex acquisition/release. No physical interrupt
or scheduler-state interpretation beyond these supplied results is established.

With both results zero, the original wrapper calls lock `0x80c27af2`, invokes
the lower operation with mode 0, and calls unlock `0x80c27b2c`. An absent mutex
skips the leaf RTOS calls while retaining mode 0. Authored mutex acquisition
checks the original wait-forever argument `0xffffffff`. Acquisition/release
failures stop at original assertion owner/line pairs; release failure occurs
after transfer. Ordinary lower read errors still reach unlock.

Mode 0 selects the private-buffer builder, so a 64-byte read reaches DMA.
Mode 1 forces direct FIFO reading. Smaller mode-zero reads still use polling.
Different direct/private buffer hashes are expected because the peripheral
model supplies FIFO bytes but does not simulate physical DMA movement.

## Partition arithmetic before BBT mapping

Actual `0x80c29532` validates a non-null handle/output and page alignment of the
partition base and effective extent. It adds `base / page_size` before dispatch.
With base `0x100000`, relative page 7 becomes 519. The actual BBT remapper then
maps it to 711 before opcode `0x13` is submitted.

The effective extent can be derived from geometry when zero, but the wrapper
does **not** check the requested page against that extent. An authored one-page
extent accepts relative page 9999 and dispatches page 10511; lower chip/BBT
validation still applies. The page addition also wraps: relative `0xffffffff`
plus base page 512 reaches the mapper as 511. These are software arithmetic
observations, not proof of permitted physical partition access.

## Original ioctl and mutation dispatch

Geometry queries execute the original callback/chip ioctl and return original
first-candidate values, including ECC positions `[4, 20, 36, 52]`. Partition
query 1 computes 5,632 pages locally for the authored extent and skips the
driver. Unknown chip query returns `-9` through the original error log.

Erase query 12 rebases blocks before actual BBT mapping. The context-selected
mode chooses either the 4,000-poll delay path or 20-poll scheduler-delay path.
A scheduler-delay timeout reaches original `-104` and then unlocks.

Copy-with-OOB query 15 rebases both source and destination **in the caller's
argument array before driver availability is checked**. The missing-driver case
therefore returns `-6` after changing those two words. The available-driver case
continues through original copy/OOB policy and opcode `0x34` FIFO transfer.

Partition format query 8 loops over actual driver erase calls but ignores their
returned errors. A two-block fixture has both erases rejected by the original
mapped-address guard, yet format returns zero. Lower assertions still stop
execution; only returned errors are ignored.

## Evidence boundary and next layer

The runner checks normal-return ABI and guards caller/argument/partition backing,
the BBT, command frame, DMA descriptors and registry. Context/mutex callbacks are
supplied services; the original selection and lock/unlock wrappers execute.
The selected functions prove no concurrent mutual exclusion or driver lifetime.

Next integration work connects EFTL page/OOB adapters and logical mapped reads to
this dispatch path. Physical chip/partition/BBT provenance, full concurrency,
cache/IRQ behavior, persistence, backup/restoration and standalone boot remain
open.

The subsequent [EFTL/QSPI pass](EFTL_QSPI_STACK.md) connects ready logical reads,
multi-page output, gaps and OOB extraction to this dispatch path.
