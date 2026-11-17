# Environment initialization, readiness binding and backup-copy fallback

This pass connects the previously static initializer to actual callbacks,
collection/defaults restoration, readiness binding, four-block copying and the
diagnostic dump. All 34 native cases pass: 18 initializer-first, five binding,
seven copy and four dump cases, including a two-binding sequence. They total
1,232,662 bounded steps including supplied calls; the maximum is 400,568 for
dirty-sector collection inside initialization. All 696 Python tests pass,
including 30 new checks. Observations and provenance are in
[env-initialize.json](env-initialize.json).

The environment routines execute natively. Low-level storage, allocation,
memory/string functions and logging remain supplied. Copy/rewrite replaces
synthetic array bytes; erase fills arrays with `ff`; ordinary programming uses
AND. This does not establish device rewrite atomicity, actual backup provenance,
physical persistence or a watch/SoC boot path.

| Routine | Observed role |
| --- | --- |
| `0x80c0d58e` | Environment repair/scan/maintenance loop |
| `0x80c0d242` | Format an unrecognized sector and increment the invalid counter |
| `0x80c0cd56` | Request maintenance for a recognized dirty-state-3 sector |
| `0x80c0d0f4` | Repair marked/incomplete records during traversal |
| `0x80c0d67a` | Bind default table, invalidate cache addresses and gate readiness |
| `0x80c0bd10` | Copy four 4-KiB blocks from a reserve handle to the active handle |
| `0x80c0bc28` | Read/dump four blocks for diagnostics |

The last two roles replace the earlier provisional “setup/teardown” wording.
Actual creation and binding of device handles remain outside this pass.

## 1. Table binding and the ready flag

`0x80c0d67a(default_table, count)` requires a nonnull table; its null assertion
path is excluded. If byte `0x80d81d40` is already set, it returns zero immediately
without reads or updates. A supplied prior table/count/base and stale cache
bytes are preserved in that case.

Otherwise the actual wrapper invalidates the four sector-cache address tags
and the 16 key-cache record pointers. Other tag/age/end bytes retain their
supplied values. It sets base `0x80d81d4c` to zero, records the table/count at
`0x80d81d48` / `0x80d81d44`, logs `0x8fe` and calls the initializer. Only a zero
initializer return sets the ready byte to 1. Calling the initializer directly
does not set that outer flag.

The table is synthetic and has the previously checked 12-byte entries. This
verifies the binding contract, not the contents/provisioning of device defaults.

## 2. Invalid-header repair and saved copy status

Each outer initializer iteration sets duplicate-scan flag `0x80d81d3e` to 1,
then enumerates headers with actual callback `0x80c0d242`. An unrecognized header
logs, increments the counter and attempts formatting. The counter records the
attempt even when formatting fails.

With any invalid-header count, the first eligible attempt calls actual
`0x80c0bd10`. On success it restarts the outer walk once with the supplied reserve
image now copied into active storage. If that image still has invalid headers,
the later walk formats them and falls back to actual defaults restoration.
A flag prevents another copy through this initial invalid-header branch.

A missing source handle or allocation failure yields copy result 7; source-read
and rewrite failures yield 2 and 3. These results remain the initializer's saved
return status while defaults restoration can still populate the active array.
The defaults-restoration return itself is ignored by this caller.

The bound missing-backup fixture therefore has valid authored defaults but
returns 7 and keeps readiness zero. A second binding over those now-recognized
headers returns zero and sets readiness. Other tests retain copy-read/rewrite
errors 2/3 after successful defaults fallback, and retain 7 after an injected
defaults-format failure. An initial formatting error can also be repaired by a
successful copy and second walk. Storage/header/payload hashes distinguish all
these outcomes from simply observing a return value.

## 3. Record callbacks, collection and the three-pass route

After header handling, the initializer takes the environment lock path and walks
sectors with `0x80c0cd56`. A recognized dirty-state-3 sector sets the maintenance
flag and invokes actual maintenance/collection. Fixtures cover both collection
and the enough-empty-sectors case that clears the flag without erasing.

The actual record-repair callback behaves as follows:

- A CRC-valid state-3 record requests relocation under the active duplicate-scan
  flag. Successful relocation/duplicate handling logs `0x86e` and continues.
  Failure logs `0x872` and stops that traversal.
- A state-1 record attempts state 5 and stops traversal.
- The covered ordinary, deleted and CRC-bad state-2 records do not request a move.

Positive cases check actual copied bytes and source finalization. An existing
duplicate skips copying. A state-1 record before a marked record can stop the
walk while that later record remains untouched. A no-space marked-record failure
can coexist with initializer return zero when maintenance is not pending. These
are selected caller states; zero return is not a general storage-integrity proof.

When maintenance remains pending after the record walk, the initializer invokes
maintenance and retries the scan, up to three times in that inner cycle. After
three pending attempts it unlocks, calls the diagnostic dump, calls reserve-image
copying, then restarts the outer walk. The connected fixture verifies three
failed marked-record attempts, 256 dump rows, one successful four-block copy,
and termination over the resulting recognized image.

The outer restart loop is not given a general termination guarantee by these
tests. Permanent failures/repeating damaged reserve data on that route are not
simulated through an unbounded run. The return route clears the duplicate flag.

## 4. Copy and dump helper contracts

`0x80c0bd10` requires both reserve (`0x80d81d2c`) and active (`0x80d81d30`)
handles and one supplied 4,096-byte allocation. It reads offsets 0, `0x1000`,
`0x2000`, `0x3000` from the reserve handle using `0x80c24446`, then calls
`0x80c24652` for a full 4,096-byte rewrite to the active handle each time.
Missing handles/allocation return 7; a negative read returns 2, and negative
rewrite returns 3. Allocated storage is freed on success or either I/O failure.
Distinct authored active/reserve payloads prove a real array copy in the fixture.

The caller rejects only negative read results. A supplied 64-byte first read
still leads to a full-block rewrite. The rest of that fixture's freshly allocated
buffer contains `a5`, which reaches the active array. This documents caller
behavior under a short count; the real service's permitted returns remain open.

`0x80c0bc28` requires the active handle and the same allocation size, reads four
blocks and emits 64 diagnostic rows per block. A negative read frees and returns
2; missing handle/allocation return 7. Tests check row counts, calls, ownership
and failure cleanup; they do not compare the rendered diagnostic word values.

## Reproduction and scope

Use startup-aware `boot-runtime` / `boot-runtime.elf` with prior guarded AndeStar
repairs/environment metadata. Apply `SeedEnvInitialize.java` and export the seven
`env_initialize.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-env-init/`.

```sh
python3 analysis_scripts/env_initialize.py \
  --vectors-output firmware/env-initialize-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateEnvInitialize.java firmware/env-initialize-native-vectors.json firmware/env-initialize-native-validation.json
```

```sh
python3 analysis_scripts/env_initialize.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-env-init \
  --vectors firmware/env-initialize-native-vectors.json \
  --validation firmware/env-initialize-native-validation.json > analysis/env-initialize.json
python3 -m unittest discover -s tests -p 'test_env_initialize.py' -v
```

The runner guards 23 code ranges plus the CRC table, rejects unexpected PCs/
service arguments and caps each case at two million steps. It verifies returned
ABI, output guards, heap allocation/free pairing, complete I/O/diagnostic traces,
active/reserve/cache hashes, readiness/binding and repair flags against an
independent host model. The bounded name-copy service now reads only its requested
extent, matching non-terminated record names; the earlier 35 GC cases were rerun
unchanged after this harness correction.

Record search in one connected case requests 32 bytes at `0x3fe2`, crossing the
four-sector logical end by two bytes. This runner supplies explicit erased
adjacent read backing up to `0x4020` and allows no programming/erase beyond the
four sectors. Real address-window/partition behavior and failed boundary reads
remain unresolved. Seven fresh export hashes and the boot-member hash are
recorded; vendor material stays ignored.

The selected environment initialization path now executes, while physical handle
setup, actual reserve-image provenance/rewrite semantics, real default tables,
concurrency, permanence across reset and the subsequent boot/recovery/UI consumer
remain open. These results do not establish physical backup/restoration or an
independent watch boot through the signed chain.
