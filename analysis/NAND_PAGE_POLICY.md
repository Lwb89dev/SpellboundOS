# NAND page read, program, copy and erase policy

All 77 native cases pass in 200,565 steps (maximum 96,107 for polling erase
timeout). Actual page read/write/copy/copy-with-OOB/erase routines execute with
both actual busy loops. Complete observations and provenance are in
[nand-page.json](nand-page.json). This extends the
[QSPI platform and command pass](NAND_BUS_AND_COMMANDS.md).

The original first chip descriptor supplies geometry and status masks. Its
pointer is redirected to an immutable emulator copy; plane tests explicitly
change only that copy's plane flag. Remapping, command builders, feature reads,
cache data, retry workaround and delays are supplied. The actual QSPI transfer
from the preceding pass is not executed in this pass. No device was accessed.

## Timeout consequences in actual callers

The previous pass established that the busy helpers can return zero after
logging a timeout while leaving the caller status byte `ff`. This pass executes
the actual caller together with the actual busy loop, with feature responses
supplied as busy forever:

| Actual operation | Status reads | Result after timeout |
| --- | ---: | --- |
| Page read `0x80c28a98` | 2,000 | Calls supplied cache read; returns zero if that call succeeds |
| Page program `0x80c28c06` | 2,000 | Returns `-102`, program-status failure |
| Erase `0x80c291e6`, polling | 4,000 | Returns `-104`, erase-status failure |
| Erase `0x80c291e6`, scheduler delay | 20 | Returns `-104`, erase-status failure |

The distinction follows the original descriptor: read checks whether
`status & 0x30` equals `0x20`. With `ff`, the masked value is `0x30`, so it skips
the ECC-error workaround and continues to cache transfer. Program tests bit
`0x08`; erase tests bit `0x04`; both are set in `ff` and produce errors.

The read case therefore demonstrates that this selected software path does not
propagate the busy timeout as an error when the later supplied cache operation
succeeds. It does not establish the bytes a busy physical chip would return,
whether the actual HAL would succeed, or an observed hardware failure. Reads
here return authored cache bytes. Nonzero supplied feature-helper status instead
causes the busy helper to return an error, which all selected callers map to
`-100`.

## Validation, remapping and first-MiB guard

The selected descriptor declares 65,536 pages, 1,024 blocks, 64 pages per block,
2,048 data bytes and 64 spare bytes. Missing chip returns `-2`. Read/write reject
a null buffer, zero length, mapped page at or above 65,536, or a column/count sum
greater than 2,112 with `-1`. The test at column 2,048 and length 64 succeeds;
the exclusive upper page/block bounds fail. These fixtures do not exhaust
malformed or overflowing argument combinations.

Page remap failure becomes `-150`; block remap failure becomes `-151`. A read
remap failure returns before the common result log. An authored +64 page remap
confirms that the mapped page is passed to load. Remapper implementation and BBT
content are not executed or validated here.

With the guard flag enabled, program and copy reject mapped pages below 512;
erase rejects mapped blocks below 8. Copy checks both source and destination.
They return `-250` before issuing a mutation command. Boundary values 512/8
succeed, as do lower values when the flag is disabled. This verifies a software
first-MiB policy for the selected geometry, not physical write protection.

## Read ECC and cache policy

Actual page read loads the mapped page, waits for ready, and checks the selected
ECC mask. On `status & 0x30 == 0x20` it calls supplied workaround
`0x80c29e6e(page)`. A zero workaround result clears the error and logs success.
An unsuccessful workaround still allows cache transfer but returns `-101`.
That ECC result overrides a subsequent cache-transfer error. A supplied zero
workaround result does not prove ECC correction or execute the retry algorithm.

Cache selection follows the caller's mode argument: zero calls the private-buffer
builder and nonzero calls the direct builder. Supplied command-helper failure
maps to `-52` for page-to-cache load, `-53` for direct cache read and `-54` for
private-buffer cache read. Successful fixtures deliver identical authored bytes.

The original first descriptor's plane flag is zero. Explicit flag-one copies
show that mapped page bit `0x40` inserts column bit `0x1000`. This does not claim
that the fitted chip uses that mode or establish a physical plane arrangement.

## Program, copy and erase ordering

Actual program issues write-enable, cache write, program-execute and busy poll,
in that order. Helper-entry error injections map to `-55` for write-enable,
`-56` for direct cache write, `-57` for private-buffer cache write and `-58` for
program-execute. Status bit `0x08` also maps to `-102`. The input buffer stays
unchanged in these fixtures.

Actual copy `0x80c28d7a` maps both pages, loads the source, polls, enables writing,
programs the destination and polls again. It requests no host cache-data transfer.
Unlike page read, its selected ECC-error path returns `-101` before write-enable
and does not call the retry workaround. Source-load and destination-program
errors retain `-52` / `-58`; a second status-read error becomes `-100`.

Actual copy-with-OOB `0x80c28ec4` adds cache-write helper `0x80c2800a` between
write-enable and program-execute. It bounds the supplied OOB count by the 64-byte
spare size and uses data-page size 2,048 as the cache column. With the authored
plane flag set, column bit `0x1000` comes from the **source** mapped page, even
when the destination's corresponding bit is different. Its cache-write error
maps to `-56`.

Actual erase maps the block, checks bounds/guard, enables writing, issues erase
and waits with timeout argument 20. Mode zero selects scheduler-delay polling;
nonzero selects the short-delay loop. Erase-command helper error maps to `-60`;
the erase failure bit maps to `-104`.

All command-helper return faults above are explicit entry injections. The
previous pass shows that selected actual command builders normally return zero
or reach a platform assertion on HAL failure. These injected outer branches are
not asserted to be naturally reachable through those builders.

## Reproduction

```sh
python3 analysis_scripts/nand_page.py \
  --vectors-output firmware/nand-page-native-vectors.json
```

In the startup-aware `boot-runtime` project, apply `SeedNandPage.java`, export
`nand_page.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`, into
`firmware/decompiled/runtime-nand-page`, then run:

```text
-postScript ValidateNandPage.java firmware/nand-page-native-vectors.json firmware/nand-page-native-validation.json
```

```sh
python3 analysis_scripts/nand_page.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-page \
  --vectors firmware/nand-page-native-vectors.json \
  --validation firmware/nand-page-native-validation.json > analysis/nand-page.json
python3 -m unittest discover -s tests -p 'test_nand_page.py' -q
```

Eight code and three original data guards pin executed routines, descriptor and
bus binding. Each case is bounded to 300,000 steps. The runner rejects unexpected
PCs and service arguments, checks normal return ABI, full callback/log ordering,
buffer hashes/guards and descriptor immutability. The report records eight fresh
export hashes. Thirty-one new host tests bring the full suite to 997 passing
tests.

Remaining work includes actual remapping/BBT, retry workaround, UID and lower
RAM HAL/ROM implementations; complete page-to-HAL integration and other chip
status policies; SFTL, mapping repair and physical partition provenance.
Electrical operation, real ECC correction, persistence, device-specific backup/
restoration and standalone boot through the signed chain remain unresolved.

The subsequent [BBT and mapping pass](NAND_BBT_AND_MAPPING.md) executes actual
BBT verification/resume/remapping and connects actual remappers to all five page
operations. The extended page runner additionally guards the two remapper code
ranges when reproducing this earlier pass; the original 77-case report remains
byte-for-byte unchanged. Physical BBT provenance and persistence remain open.
