# Boot storage configuration and driver bindings

The original boot image publishes five storage backends and two byte-identical
16-row partition tables. Their startup-copy provenance, names, offsets, sizes,
initial descriptor words and callback bindings are recovered reproducibly in
[storage-map.json](storage-map.json). This is static image evidence; the native
dispatch tests in [ENV_STORAGE_SETUP_AND_NVMS.md](ENV_STORAGE_SETUP_AND_NVMS.md)
still use authored descriptors and callbacks.

## Publication and startup provenance

Board registration `0x80c01098` publishes `dev_flash` with the 16-byte
configuration at `0x80d805b0`, copied from image address `0x80c40268`:

| Field | Value |
| --- | --- |
| Device pointer array | `0x80d805c0`, five entries |
| Partition rows | `0x80c33a38`, 16 entries |

It also publishes `nand_partition` with an eight-byte configuration at
`0x80d81b48`, copied from `0x80c41800`. That pair references `0x80c33678`
and count 16. Both complete 960-byte partition tables are identical.
The startup-copied function word at `0x80d810fc` contains `0x80c24106`, linking
the flash device methods to registry setup.

These are ROM/startup configuration values, not a live RAM or flash dump.
The named tables alone do not prove which runtime initialization paths complete.

## Backend-relative partition map

Each row contains 24-byte partition and backend names, then offset, declared
span and an unclassified word. Names and numbers below come from the original
image. All offsets/sizes are hexadecimal bytes in the named backend's space.

| Partition | Backend | Offset | Declared span |
| --- | --- | --- | --- |
| raw | nand | `0` | `100000` |
| eftl | nand | `100000` | `b00000` |
| sftl | nand | `c00000` | `1e00000` |
| fs | nand | `2a00000` | `0` (derive from runtime capacity) |
| boot | nandraw | `0` | `100000` |
| nvms | eftl | `0` | `40000` |
| envbak | eftl | `40000` | `40000` |
| recovery | eftl | `80000` | `80000` |
| backup | eftl | `100000` | `800000` |
| ramdump | eftl | `900000` | `80000` |
| userdata | eftl | `980000` | `40000` |
| coredump | eftl | `9c0000` | `40000` |
| recovery0 | sftl | `0` | `60000` |
| recovery1 | sftl | `60000` | `60000` |
| env | sftl | `c0000` | `20000` |
| log | sftl | `e0000` | `1400000` |

The final word is 0 for rows backed by `nand`/`nandraw`, and 1 for rows backed
by `eftl`/`sftl`; its semantics are not established here. The tables contain no
`easyflash` row. If this table is the active registry without later additions,
the previously emulated setup therefore takes the `envbak`/`nvms`/`env` branch.
That is an inference from the recovered configuration, not an observed device
boot.

In particular, `env + 0x5000` means the `sftl` backend at offset `0xc5000`;
it must not be presented as a physical NAND address. Translation tables,
reserved blocks, bad-block handling, metadata and runtime geometry remain
necessary to resolve physical placement.

## Recovered callback bindings

The five startup descriptors are 76 bytes each. Read/program/erase/rewrite
callback slots are the same +44/+48/+52/+56 slots already executed in the
generic native dispatch pass. The recovered bindings are:

| Backend / descriptor | Initialize | Read | Program | Erase | Rewrite |
| --- | --- | --- | --- | --- | --- |
| nand / `80d81004` | `80c23418` | `80c236a2` | `80c235ea` | `80c23518` | `80c233e2` |
| nandraw / `80d81050` | `80c23762` | `80c23848` | `80c23940` | `80c23896` | `80c2398e` |
| eftl / `80d80fb8` | `80c231b2` | `80c23252` | `80c23336` | `80c232a0` | `80c23384` |
| disk / `80d80f20` | `80c22a10` | `80c22e22` | `80c22ffe` | `80c230fe` | `80c2300e` |
| sftl / `80d80f6c` | `80c229ec` | `80c22e12` | `80c22fea` | `80c230f0` | `80c22ffa` |

All five descriptors initially contain base word `0xffffffff`, capacity word
`0x7fffffff` and word +36 equal to 1. The initial block word is `0x20000` for
`nand`, `nandraw` and `eftl`, and `0x1000` for `disk` and `sftl`. These initial
words do not establish usable device capacity or final runtime geometry.

Static exports show `eftl` initializer `0x80c231b2` and `sftl` initializer
`0x80c229ec` logging that initialization will happen later, then returning zero.
The separate lazy EFTL routine `0x80c231d6` calls `0x80c02298` and, on success,
updates the EFTL descriptor's block/capacity fields before setting its ready
byte. Thus successful generic registration cannot by itself establish that
these backends are ready for I/O.

The JSON retains deinitialize, ioctl and two further unclassified callback
slots. Their presence in the vendor image is evidence of recovered bindings;
independent drivers, electrical timing and physical operation remain open.

## Registry setup, inspected statically

`0x80c24106` calls device initialization `0x80c23bd0`, then partition
initialization `0x80c24340`; after both return zero it publishes the outer
device table/count. Device initialization checks required read/program/erase
callbacks and calls optional initializers in array order. Its ready byte is
set only after all selected initializers succeed.

Partition initialization publishes row pointer/count, then `0x80c24140`
allocates an owner-pointer array if absent and resolves backend names through
`0x80c23cee` using a bounded 24-byte comparison. The selected code rejects a
partition start at or beyond the owner's capacity. A missing backend logs a
warning and continues without assigning that owner slot. Successful completion
sets the registry ready byte. These initialization branches have been inspected
statically; this pass adds no native initialization/fault cases.

## Reproduction and remaining work

On startup-aware `boot-runtime.elf`, run `SeedStorageMap.java`, then
`DecompileWithLogger.java` with logger `0x80c1cd7a`, output directory
`firmware/decompiled/runtime-storage-map` and `storage_map.py:EXPORTS`.
The seed guards registry bytes and fixes the board registration tail jump's
call/return metadata; image bytes are unchanged.

```sh
python3 analysis_scripts/storage_map.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-storage-map > analysis/storage-map.json
python3 -m unittest discover -s tests -p 'test_storage_map.py' -q
```

The parser verifies the boot member hash, startup-copy sources, bounded names,
table counts, required callbacks, owner bindings, duplicate tables and extent
arithmetic. Twenty new host checks cover parsing failures and the recovered
configuration; all 749 Python tests pass. Nine fresh export and code-range
hashes are recorded. Firmware and decompiled vendor material remain ignored.

Next: execute registry population and lazy backend initialization with bounded
services, follow real backend rewrite/read/program/erase behavior, and recover
FTL geometry/translation before deriving physical locations. Device-specific
backup/restoration and standalone boot through the signed chain remain open.

Subsequent passes execute [original registry population and lazy EFTL descriptor
updates](STORAGE_REGISTRY_AND_LAZY_EFTL.md) in 32 native cases and the
[EFTL translation/read routes](EFTL_TRANSLATION_AND_PAGE_READ.md) in 24 cases,
with lower initialization/geometry/NAND services supplied. They establish no
physical geometry or mapping provenance.
