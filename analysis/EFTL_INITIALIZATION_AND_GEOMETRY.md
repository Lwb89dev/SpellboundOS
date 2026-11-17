# Connected EFTL initialization, geometry and buffer lifetime

All 38 bounded native cases pass, totaling 10,603 steps (maximum 752 for scan
retry/rebuild). Actual initializer `0x80c02298`, geometry collector `0x80c02460`,
OOB scan/checksum, selected generic format loops and outer lazy initialization
`0x80c231d6` execute together. Complete traces and state are in
[eftl-initialize.json](eftl-initialize.json).

NAND lookup/ioctl outputs, heap, clocks and lower erase/OOB services are supplied.
Explicit format-error cases supply the format return instead of executing its
loop. No physical NAND, watch, phone, ECC or bus is accessed. The small authored
geometry does not establish real device capacity or fit the stock partition map.

## Geometry collection through supplied NAND ioctls

The collector looks up `eftl` when the context lacks a NAND handle. An existing
handle skips lookup. Actual code requests:

| Ioctl | Collected value |
| --- | --- |
| 1 | Page count |
| 2 | Page size |
| 3 | Pages per block |
| `12` hex | Spare size |
| `13` hex | Total spare ECC size |
| `14` hex | ECC unit size |
| `15` hex | Four position words, stored as u16 values |

It derives block count by integer division of page count by pages per block,
and base page by integer division of the supplied NAND descriptor's partition
offset by page size. Partial blocks/pages are truncated. Spare/ECC sizes and
positions are stored as u16 values. Tests also supply negative ioctl statuses
with populated outputs: the selected collector ignores those statuses and uses
the outputs.

Missing lookup result and zero required geometry/spare fields reach distinct
assertions. Those fixtures stop at the assertion entry before its body executes;
they claim no normal return or restored return ABI.

## Initializer guard, cleanup and allocations

An existing context marker `0xa5` returns zero immediately unless forced
initialization is requested. Forced initialization frees each nonzero old
flag/map/scratch pointer only when that marker was set, then clears the context
and collects geometry. Nonzero old pointers without the marker are not freed.

After geometry, byte +5 is set to 1 and a summary logged. Forced initialization
calls format; a supplied nonzero format return maps to `-1` before allocation.
Old marked buffers have already been freed at that point.

Actual allocation sizes are:

1. Block-count bytes for flags, filled with zero.
2. Twice block-count bytes for u16 mappings, filled with `ff`.
3. Page size plus the stored u16 spare size for scratch, filled with `ff`.

The selected call sites pass each allocation result directly to `memset`.
Failure at allocation 1, 2 or 3 reaches a null-destination fill. The runner stops
before writing address zero, recording the attempted length/fill and all live
buffers. Earlier successful allocations remain live. This establishes missing
local checks under supplied allocator failure, not a measured hardware crash.

An OOB scan error also returns with all three allocations live and marker clear.
Repeating that failed initializer loses the earlier pointer bindings without
freeing those buffers: six supplied allocations remain live after two attempts.
Successful repeated initialization instead uses the marker guard and allocates
nothing further.

## Connected scan retry and generic format

The actual [OOB scan/checksum](EFTL_OOB_MAPPING_RESUME.md) runs first with repair
argument zero. A positive result causes both flag/map buffers and all three
counters to reset, followed by the actual scan with argument one. A negative
scan result returns without the success summaries. Successful repair can still
leave every block reserved; zero return does not establish usable capacity.

Four forced cases execute actual generic format `0x80c0285a` against supplied
NAND ioctl results. With format kind zero, nonzero bad-block status skips erase,
including a negative status. With nonzero kind, every selected block is erased
without that check. Erase results are ignored by this loop, which returns zero
on completion. Subsequent OOB reads still use authored records; simulated erase
does not model physical changes to NAND or metadata.

This format policy differs from the scan's repair handling: the first scan can
attempt erase after a negative bad-block status. Exact call order for both
policies is recorded. The alternate format route and lower ioctl implementation
remain outside coverage.

## Outer lazy readiness and capacity publication

Actual lazy initialization now calls the full actual initializer, not a supplied
geometry stub. On the successful mixed fixture, it sets the global ready byte
and publishes block size 128 and capacity 384 from supplied four-page blocks,
32-byte pages, four blocks and one reserved block. The context marker and global
ready byte are distinct gates.

An inner scan error leaves global readiness clear, the descriptor's initial
capacity/block words unchanged and three heap buffers live. Existing global
readiness skips the entire initializer; a repeated successful lazy call does
the same. These descriptor values are fixture results, not actual watch geometry.

## Reproduction and verification

Use startup-aware `boot-runtime.elf`, apply `SeedEftlInitialize.java`, then export
`eftl_initialize.py:TARGETS` through `DecompileWithLogger.java`, logger
`0x80c1cd7a`, into ignored `firmware/decompiled/runtime-eftl-initialize`.
The seed guards initializer bytes and declares reviewed function signatures;
it modifies no image bytes.

```sh
python3 analysis_scripts/eftl_initialize.py \
  --vectors-output firmware/eftl-initialize-native-vectors.json
```

Run headless with:

```text
-postScript ValidateEftlInitialize.java firmware/eftl-initialize-native-vectors.json firmware/eftl-initialize-native-validation.json
```

```sh
python3 analysis_scripts/eftl_initialize.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-initialize \
  --vectors firmware/eftl-initialize-native-vectors.json \
  --validation firmware/eftl-initialize-native-validation.json > analysis/eftl-initialize.json
python3 -m unittest discover -s tests -p 'test_eftl_initialize.py' -q
```

The runner guards six executed code ranges, rejects unexpected PCs/service
arguments, caps each case at 100,000 steps and checks ABI for normal returns.
It compares full call/log order, context bytes/hash, geometry, flags/mappings/
scratch hashes, allocation ownership, pointers, counters and descriptor readiness/
capacity with the host contract. Context/heap guards and the synthetic NAND
descriptor are checked. Assertions and null writes have explicit stopped states.
Six fresh export hashes are recorded. Thirty-four new host checks pass; the
full Python suite reaches 853 passing tests.

Remaining work includes the actual NAND lookup/ioctl and OOB transport,
alternate format handling, physical geometry/ECC/bus behavior, mapping repair/
program/erase semantics, SFTL, persistence and device-specific backup/restoration.
Full boot through the signed chain remains unresolved.
