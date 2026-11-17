# Native NAND probe, candidate table and driver-root setup

All 60 bounded native cases pass, totaling 30,716 steps (maximum 1,998 for failed
probe through outer registration). Original descriptor matching, ID/reset command
builders, the probe, mutex wrapper and driver-root initialization execute with
supplied bus/power/feature/BBT services. Candidate facts are in
[nand-chips.json](nand-chips.json); complete native observations and provenance
are in [nand-probe.json](nand-probe.json).

The received IDs are authored fixtures. These results identify the NAND chips
supported by this bootloader, not the chip fitted to the watch. No physical ID,
unique device data, NAND page, regulator or bus is accessed.

## Original candidate inventory

The table at `0x80c3dcd0` contains 11 pointers to 184-byte descriptors. The order
below is the actual probe order. Capacity is calculated from each descriptor's
page count and page size; it is neither a device measurement nor a datasheet
claim. Some separate initial capacity words are zero and are retained as such
in the JSON.

| Driver label | Required ID prefix, hex | Geometry capacity, MiB | Page bytes | Spare bytes | OOB record position |
| --- | --- | ---: | ---: | ---: | ---: |
| Winbond W25N01GWZEIB | `ef ba 21` | 128 | 2048 | 64 | 20 |
| Winbond W25N01KWZEIG | `ef be 21` | 128 | 2048 | 64 | 20 |
| Winbond W25N04KW | `ef ba 23` | 512 | 2048 | 128 | 20 |
| Winbond W25N04LWZEIG | `ef b2 23` | 512 | 4096 | 256 | 20 |
| DOSILICON DS35M1GA | `e5 21` | 128 | 2048 | 64 | 20 |
| DOSILICON DS35M1GB | `e5 a1` | 128 | 2048 | 64 | 16 |
| DOSILICON DS35M2GA | `e5 22` | 256 | 2048 | 64 | 20 |
| DOSILICON DS35M2GB | `e5 a2` | 256 | 2048 | 64 | 16 |
| DOSILICON DS35M4GB-IB | `e5 64` | 512 | 2048 | 64 | 16 |
| DOSILICON DS35M4GM-IB | `e5 a4` | 512 | 2048 | 64 | 16 |
| ESMT F50D4G41XB | `2c 35` | 512 | 4096 | 128 | 72 |

All declare 64 pages per block. The JSON also records complete match fields,
feature register/value pairs, ECC-layout fields, UID flag, names, descriptor
hashes and startup bus/driver operation bindings. These are extracted image
facts; supported part numbers alone do not establish a bill of materials.

## ID matching and probe attempts

Actual `0x80c28318` requires the first two candidate bytes. Subsequent zero match
fields are optional. Original fields four and five are zero for all candidates,
so the current table uses the two- or three-byte prefixes above.

A separate authored descriptor-copy counterexample verifies that optional
field +`0x30`, when nonzero, is compared with the **fourth received byte**; the
fifth received byte is not used by this matcher. This does not affect the 11
original entries because their +`0x30` fields are zero. Distinct first/second/
third/fourth/fifth-field mismatch statuses are recorded.

Actual probe `0x80c2874a` clears the selected descriptor, tries candidates in
table order and permits at most three rounds. Each attempt passes that candidate
to the supplied bus initializer and calls the actual read-ID builder
`0x80c2819e`. Its transfer packet requests command `0x9f` and five received bytes.
Every original ID selects its expected descriptor. An unmatched ID causes 33
attempts and returns `-4`; delayed fixtures succeed in the second or third round.

After selection, actual reset builder `0x80c281fc` emits the descriptor's reset
command (`ff` in these entries). The probe requests a delay of the descriptor
reset time divided by 1,000 plus one. These are requested delays passed to a
supplied callback, not measured timing or electrical verification.

## Power, feature verification and error state

The probe obtains `LSW0_1V8_NAND`, requests disable/delay/enable/delay when a
handle exists, and continues with a diagnostic if it does not. Selected regulator
return values are not checked. Successful supplied ID reads in these fixtures
do not imply that the hardware can operate without power.

Each candidate's original feature sequence is written and read back. Supplied
write error, read error and mismatched value map to `-5`, `-6` and `-7` respectively.
The selected descriptor remains published on those errors, while the final boot
guard counts remain unset. Workaround, conditional UID and BBT-service return
values are not checked in this selected probe path; their implementations and
physical effects remain outside coverage.

Bus initialization and ID/reset transfer failures reach distinct assertions.
The runner stops before the assertion bodies. Explicit helper-entry injections
separately exercise outer `-50`/`-51` error branches; those injected helper
returns are not presented as normal outcomes of the actual command builders.

On successful completion, the probe records the first-MiB boot guard in pages
and blocks. This yields 512/8 for the 2,048-byte-page candidates or 256/4 for
the 4,096-byte-page candidates. It does not establish physical protection.

## Mutex and outer registration

Actual operation initializer `0x80c27aac` runs the probe, then creates its mutex
only on success and when absent. An existing mutex skips creation but does not
skip probing. A failed mutex allocation reaches its assertion after the selected
descriptor and boot counts have already been set.

Actual `0x80c27524` obtains the supplied `dev_nand` property, stores the original
property pointer in the driver root, and invokes the original operation table's
initializer. Missing operation table/init callback and failed inner probe return
`-6`; the root update is not rolled back. Missing property reaches an assertion.

After successful probing/mutex setup it allocates 60 bytes, clears them, binds
the original method table at object +40 and calls the supplied object registry
with name `dev_nand` and type 23. Allocation failure returns `-6` while preserving
completed probe/mutex state. A supplied registration error propagates and leaves
the object allocation live. The object registry's linked-list/ownership behavior
is not executed in this pass.

## Original descriptors and OOB layout round trips

All 11 original ECC unit fields select the contiguous branch of the previously
verified [OOB routines](NAND_PARTITIONS_AND_OOB.md): four bytes at the second
position entry. Those offsets are 20, 16 or 72 as listed above.

For each candidate, the native probe first selects the descriptor using supplied
ID bytes. The harness then copies its layout fields into a bounded OOB context;
actual composer `0x80c026a6` and extractor `0x80c025d4` round-trip `01 00 45 46`.
The spare area is filled with `ff` outside the record, input/context remain
unchanged, and spare/output guards pass. This validates the original layout
values with the selected serializers, without programming or reading NAND.

## Reproduction and verification

Use startup-aware `boot-runtime.elf`, apply `SeedNandProbe.java`, then export
`nand_probe.py:TARGETS` through `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-nand-probe`. The seed guards probe
bytes and declares reviewed argument boundaries; image bytes remain unchanged.

```sh
python3 analysis_scripts/nand_probe.py firmware/bip6-4.6.0.3.zip \
  --table-output analysis/nand-chips.json
python3 analysis_scripts/nand_probe.py \
  --vectors-output firmware/nand-probe-native-vectors.json
```

Run headless with:

```text
-postScript ValidateNandProbe.java firmware/nand-probe-native-vectors.json firmware/nand-probe-native-validation.json
```

```sh
python3 analysis_scripts/nand_probe.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-probe \
  --vectors firmware/nand-probe-native-vectors.json \
  --validation firmware/nand-probe-native-validation.json > analysis/nand-probe.json
python3 -m unittest discover -s tests -p 'test_nand_probe.py' -q
```

The runner pins nine code and 40 data ranges, caps each case at 100,000 steps,
rejects unexpected PCs/service arguments and checks normal return ABI or explicit
assertion stops. It verifies ID/reset packets, complete power/bus/feature/BBT/
registration/log traces, selected/root/mutex/boot state, heap bytes and ownership,
descriptor/input immutability and OOB/heap guards. Nine fresh export hashes and
the original chip inventory hash are recorded. Thirty-six new host checks pass;
the full Python suite reaches 932 passing tests.

Remaining work includes the actual bus initializer/transfer and feature protocols,
UID/BBT internals, object registry, physical ID and timing/ECC corroboration,
mapping repair/write paths, SFTL and persistence. Device-specific restoration
and standalone boot through the signed chain remain unresolved.

The subsequent [QSPI platform and command pass](NAND_BUS_AND_COMMANDS.md)
executes the actual bus initializer/transfer, selected feature/cache/program/erase
builders, ROM policy and busy loops. Its 51 cases use supplied lower HAL/pin/DMA
services and emulator-only MMIO. It does not establish physical bus operation.
