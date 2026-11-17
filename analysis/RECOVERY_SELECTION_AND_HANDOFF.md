# Recovery selection, synthetic counter writes and stopped handoff

This pass follows [RECOVERY_VALIDATOR_NATIVE.md](RECOVERY_VALIDATOR_NATIVE.md)
into raw header helpers, availability selection, image preparation/completion
and the launch/handoff control path. All 64 native cases pass: ten raw-header,
25 selection, 21 preparation/completion/sequence and eight handoff/launch cases.
They total 27,713 steps including intercepted calls; the maximum is 3,445.
All 522 Python tests pass, including 27 new checks. Complete traces, snapshots
and provenance are in [recovery-lifecycle.json](recovery-lifecycle.json).

Filesystem descriptors, reads/writes/base addresses, availability validation,
string/zero/log services and BSP cleanup are supplied. Native writes affect
only synthetic arrays in the runner, never a device or host partition. Earlier
validation code was tested separately; this pass supplies its Boolean results
at `0x80c0e9c2` and does not replay its SHA/crypto path on every selection.
Normal handoff cases stop at the image entry; one additional encoded-jump case
stops at startup + `0x22c`. No startup body or physical recovery operation runs.

## 1. Raw 72-byte header helpers

| Routine | Observed native contract |
| --- | --- |
| `0x80c0e438(name, output)` | Open, read 72 bytes at offset zero, return whether the count equals 72; close after either full or short read |
| `0x80c0e4d0(name, header)` | Open, recompute raw CRC over the first 68 bytes, store at + 68, attempt 72-byte write and close; no meaningful return status |

Open failure logs and returns without a descriptor. Short reads/writes log.
The raw getter does not check `RECO` or CRC, and the setter does not require
an existing valid header. Setter open failure leaves the caller's checksum
unchanged; after successful open, checksum is updated in caller memory even
when the supplied write is partial. These low-level contracts differ from
the earlier complete validator's magic/CRC/signature checks.

Ten cases check all three partition names and open/short-read/short-write
outcomes. Snapshots distinguish caller header, persisted synthetic bytes,
CRC validity and remaining open descriptors. All simulated writes are limited
to the first 72 bytes; image and remaining partition bytes are checked unchanged.

## 2. Availability and counter-based selection

Actual `0x80c0e9cc()` first validates selector 8 (`recovery_ota`). A supplied
valid result returns that candidate immediately, with no counter reads.
Otherwise it checks selectors 0 and 1 and uses their raw headers.

The selected fields are:

| Header offset | Role in this path |
| --- | --- |
| + 4 | Signed order field, named `generation` in fixtures; its wider meaning is not established |
| + 8 | Boot-up counter, corroborated by the diagnostic text |
| + 12 | Completion counter |

For each normal candidate, `delta = signed32(bootup - complete)` must be below
10. Native arithmetic wraps at 32 bits, and negative differences satisfy the
signed comparison in the synthetic cases. If only one candidate qualifies,
it wins. If both qualify:

- When both deltas are zero, the larger **signed** + 4 field wins; equal fields
  prefer `recovery0`.
- Otherwise the smaller delta wins; equal nonzero deltas prefer `recovery1`.

No candidate produces a null return and diagnostic `0x379`. The 25 cases cover
availability combinations, boundaries 9/10/11, negative deltas, differing tie
rules and signed order-field values including `0xffffffff` / `0x80000000`.

The selector ignores the raw getter's Boolean return after its availability
check. A supplied short read can still populate the compared fields. An open
failure leaves the corresponding local header with the fixture's prior stack
backing; the checked result then depends on those bytes. The runner fixes that
backing for a bounded demonstration. It does not establish live stack contents,
reachability or a general fallback rule after I/O failure. Availability is an
explicit fixture input and is not recomputed from mutated headers in this pass.

## 3. Preparation, completion and write outcomes

`0x80c0eaa6(ram_output, mapped_output)` returns zero immediately if both are null.
Otherwise it calls actual selection, opens the chosen partition and requires a
full 72-byte header read. A nonnull RAM output requests exactly the header's
image length from partition offset `0x1000`. A nonnull mapped output receives
the supplied descriptor base + `0x1000`, with native 32-bit wrap. It closes that
descriptor after successful reads and proceeds to header updates.

For normal recovery, a fresh zero-initialized temporary header is filled by
the raw getter; a successful getter increments boot-up at + 8 modulo 32 bits.
It then calls the setter regardless of that getter's result. For the OTA
candidate it skips the getter and writes the zero-initialized header directly.
The setter supplies a CRC even for this zero header, leaving `RECO` cleared.
Only the synthetic header is changed; copied image bytes remain intact.

Thus asking only for a mapped address still reaches counter/header writes.
The operation is not a read-only address query. These calls were executed only
against the runner's in-memory service implementation.

Fault fixtures distinguish several native outcomes:

| Supplied service result | Checked outcome |
| --- | --- |
| Short preparation header/image read | Return zero; the preparation descriptor remains open at return in this supplied service model |
| Counter reread open failure | The temporary header remains zero and is passed to the setter; preparation returns 1 |
| Counter reread short count | Increment is skipped; setter still runs and preparation returns 1 |
| Setter open failure or partial write | Diagnostic occurs, but preparation still returns 1 |

The tests record remaining descriptors rather than implicitly closing them.
They do not establish subsequent reset/global descriptor cleanup or observed
device faults. The partial-write fixture persists exactly the returned prefix;
actual flash write/atomicity behavior remains unexecuted.

Completion `0x80c0ebd4(all)` first attempts to write the zero header to OTA.
With `all != 0`, each supplied-valid normal recovery whose getter succeeds has
completion + 12 set equal to boot-up + 8 and is written back with fresh CRC.
The function returns 1 even when the supplied OTA write-open fails. Failed
normal reads skip that normal write while processing continues.

A connected prepare/select/finish/select sequence shows the counter effect:
normal preparation increments `recovery0`, making `recovery1` preferable on the
next selection; completion equalizes both deltas and the order-field rule
chooses `recovery0` again. Other cases cover counter wrap and mapped-address
wrap, null outputs, failed selection, RAM-only/address-only requests and OTA.

## 4. Actual launch and handoff boundary

Actual `0x80c0098c()` calls preparation with RAM destination `0x80d00000` and
no mapped output. Success logs and calls `0x80c0084a(0x80d00000)`. Failure emits
its two checked diagnostics and returns zero without handoff cleanup.

The handoff function executes:

1. Actual `0x80c0080a`: if console flag `0x80d81cec` is set, call the supplied
   console-close service and clear the flag.
2. Actual `0x80c16344`: clear bit 3 of emulated `mstatus`, then enter the supplied
   interrupt-controller cleanup at `0x80c1634c`.
3. Supplied device teardown at `0x80c133c0`, followed by supplied print with the
   destination address and first word.
4. Restore its stack/saved register and tail-jump to the supplied address itself.

The first word is printed, not loaded as an indirect vector target. Normal
fixtures stop when the PC reaches `0x80d00000`, before executing any payload.
The connected launch preserves the launch caller's 16-byte frame and return PC
`0x80c009d2`; direct handoff has the synthetic top-level caller's frame.
Saved-register/stack checks account for that distinction.

The original OTA recovery object begins with `JAL x0,+0x22c`, matching the
analysis ELF's entry `0x80d0022c`. One independently encoded instruction fixture
is compared byte-for-byte with that OTA entry, executed once, then stopped at
`0x80d0022c`. This checks the entry trampoline and unchanged link register;
the startup body does not execute. The original recovery member hash is recorded
alongside the bootloader hash. Actual raw-partition contents are still unknown.

The emulated CSR change, stopped PC and supplied BSP callbacks do not prove real
interrupt/cache/controller shutdown, memory protection, successful image startup
or a standalone OS boot route. No environment records or device partitions were
read or changed.

## Reproduction

Use startup-aware `boot-runtime` / `boot-runtime.elf` in
`firmware/ghidra-runtime` with the existing guarded AndeStar repairs. Apply
`SeedRecoveryLifecycle.java`, then export the ten `recovery_lifecycle.py:TARGETS`
with `DecompileWithLogger.java`, logger `0x80c1cd7a`, into ignored
`firmware/decompiled/runtime-recovery-lifecycle/`.

```sh
python3 analysis_scripts/recovery_lifecycle.py \
  --vectors-output firmware/recovery-lifecycle-native-vectors.json
```

Run with `-process boot-runtime.elf -noanalysis`:

```text
-postScript ValidateRecoveryLifecycle.java firmware/recovery-lifecycle-native-vectors.json firmware/recovery-lifecycle-native-validation.json
```

```sh
python3 analysis_scripts/recovery_lifecycle.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-recovery-lifecycle \
  --vectors firmware/recovery-lifecycle-native-vectors.json \
  --validation firmware/recovery-lifecycle-native-validation.json > analysis/recovery-lifecycle.json
python3 -m unittest discover -s tests -p 'test_recovery_lifecycle.py' -v
```

The runner guards code and CRC-table hashes, rejects unexpected PCs/services,
tracks descriptor ownership and caps each case at 100,000 steps. It compares
complete action traces, caller-header/RAM/partition hashes, persisted counters,
CRC state, mapping, console/CSR state and stopped-handoff fields with an
independent host contract. Output guards and unchanged partition bytes beyond
the header are checked. Vendor code/binaries/tools/databases stay ignored.
Physical non-destructive entry, backup/device-specific restoration, environment
lifecycle, actual VFS/raw-storage semantics and independent firmware boot remain
open; native case counts are not a completion percentage.

The subsequent [environment/reason/key-policy pass](BOOT_ENVIRONMENT_AND_KEY_POLICY.md)
adds 64 native cases and executes the boot-main prefix that constructs the exact
298-byte `upgrade` record. Backend storage remains supplied and execution stops
before later dispatch; neither record persistence nor physical entry is proven.
