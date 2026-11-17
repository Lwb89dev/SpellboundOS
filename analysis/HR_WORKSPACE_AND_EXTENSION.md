# HR outer workspace ownership and borrowed configuration views

Following [ALGORITHM_MANAGER_AND_HR_ADAPTER.md](ALGORITHM_MANAGER_AND_HR_ADAPTER.md),
this pass executes 21 additional native cases: eight workspace lifecycle,
five processing-guard/unsupported-type and eight extension cases. They total
16,586 steps including intercepted calls, with a maximum of 3,076 per case.
All 452 Python tests pass, including 14 new checks. Full observations and
code/export hashes are in [hr-workspace.json](hr-workspace.json).

The real outer HR init/exit, unsupported-type processing paths and extension
pointer builder execute in Ghidra's emulator. Allocation/free/copy/zero services,
workspace setup `0x708a1432` and internal cleanup `0x708a16c4` are supplied.
Initialized mathematical processing, supported signal normalization, measurement
accuracy and hardware operation remain open.

## 1. Outer allocation and initialization

`0x7089adca` returns zero immediately when initialized byte `0x80c461be` is
nonzero. Otherwise it clears three words at `0x80c46194..0x80c4619c`, requests
the root workspace from `0x80d3c18a(pool=0, size=0x9dc4, alignment=4)` and stores
it at `0x80c46190`. Root allocation failure logs, returns 1 and does not call
setup. Subsequent exit while uninitialized performs no frees.

For successful supplied allocations, native code makes 78 requests totaling
89,556 bytes: a 40,388-byte root, 66 root children and eleven 200-byte scratch
arrays. It clears the root, writes rate field root + `0x15a = 25`, stores each
child pointer, clears the 56-byte scratch-pointer area and installs scratch
pointers at `0x80c46178/7c/80`, followed by `0x80c46158..74` in four-byte steps.
The child sizes and root-word indices are reconstructed in
`hr_workspace.py:CHILDREN`; the native allocation order and every stored pointer
are checked through full allocation/global hashes.

The setup call `0x708a1432(root)` is intercepted. Actual subsequent setter
`0x708a16c8(root, mode)` stores root + `0x76`: 14 when configuration byte
`0x80c46120` equals 4, otherwise 20. The outer initializer clears selected
history/status fields and sets initialized to 1 before returning zero.

This validates outer ownership and field setup under the stated boundary.
The intercepted setup normally initializes more root/child state; these
synthetic allocation contents are not claimed to reproduce a fully initialized
numerical workspace. Secondary allocation failures are not covered.

## 2. Exit, repeated calls and restart

`0x7089b360` returns zero immediately while uninitialized. Otherwise it clears
initialized and selected global words, sets byte `0x80c01c7c = 1`, and, when
the root exists, invokes supplied internal cleanup `0x708a16c4(root)`.
Native outer cleanup then releases the stored root children, the eleven scratch
arrays and the root through `0x80d3c1ea(pool=0, pointer)`. It clears released
pointer slots and finally the global root pointer. The special root-word-30
child has a conditional diagnostic/free branch.

The successful fixture checks exactly 78 frees, each for a distinct owned
allocation, with the root last. Full root hashes verify pointer clearing while
preserving unrelated rate/mode fields. Native free-call arguments are checked;
the supplied free service leaves emulator bytes readable for hash verification.
All allocations have 32-byte guards checked unchanged after every entry.

Repeated init while active and repeated exit while inactive make no additional
allocations/frees. The restart fixture allocates a second generation at different
addresses and frees all 156 allocations exactly once across the two cycles.
No internal-cleanup allocations/frees, allocator behavior, concurrency or live
sensor lifecycle are established.

## 3. Initialized unsupported-type processing

Actual processing entry `0x7089b82c` rejects an uninitialized backend with an
error and return 1. For initialized synthetic workspaces, unsupported descriptor
types 1, `0x8000`, `1 << 32` and `1 << 63` return zero after preparatory resets:
words at `0x80c46184/88/8c` and all eleven 200-byte scratch arrays become zero.
The supplied output area remains unchanged; no ready/result fields are written.

These cases execute the actual initialized early-return path, following outer
init and before outer exit. Root/other child contents remain unchanged, and
full global/allocation/output hashes distinguish this preparatory reset from
producing a measurement. Supported descriptor types and their resampling,
filtering/fusion/numerical processing do not execute.

## 4. Extension header and borrowed pointer views

The actual configuration extension `0x7089a252(base, length)` copies source
bytes 1/2/3 and the four-byte word at + 4 into metadata at `0x80c45f50`. Metadata
byte zero is preserved. It then stores 24 pointers, each `base + offset`, at
metadata + 8 through + `0x64`:

```text
000008 00000c 00268c 00270c 002710 002890
002a10 005a10 008a10 008b48 008c80 00ac30
00d330 00d468 00d5a0 00f550 011500 011638
011770 013720 0156d0 015850 0159d0 017dd0
```

It returns 1 only when both the length argument and copied header word equal
`0x1a1d0` (106,960 bytes). Header copying and pointer installation happen
before this result check. Mismatched sizes return zero after changing metadata;
an invalid second call replaces the views installed by a prior valid call.
No rollback or ownership transfer is inferred. The source bytes remain unchanged.

Each native fixture supplies a complete synthetic backing buffer even when its
declared sizes are invalid. The routine reads the header and builds pointer
values; it does not traverse the pointed-to regions in these cases. Lifetime,
data semantics, consumer validation and the consequences of a rejected
configuration on the watch remain open. These direct extension cases complement
the earlier control-to-supplied-extension tests; the full control/consumer
sequence is not replayed here.

## Reproduction

Use startup-aware `main-bbs` / `main-runtime.elf` and the established guarded
AndeStar/logger repairs. Export the six `hr_workspace.py:TARGETS` with
`DecompileWithLogger.java`, logger `0x702b38a2`, into ignored
`firmware/decompiled/runtime-hr-workspace/`.

```sh
python3 analysis_scripts/hr_workspace.py \
  --vectors-output firmware/hr-workspace-native-vectors.json
```

Run on the main project with `-process main-runtime.elf -noanalysis`:

```text
-postScript ValidateHrWorkspace.java firmware/hr-workspace-native-vectors.json firmware/hr-workspace-native-validation.json
```

```sh
python3 analysis_scripts/hr_workspace.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-hr-workspace \
  --vectors firmware/hr-workspace-native-vectors.json \
  --validation firmware/hr-workspace-native-validation.json > analysis/hr-workspace.json
python3 -m unittest discover -s tests -p 'test_hr_workspace.py' -v
```

The runner validates code hashes, rejects unexpected PCs/logs/frees and caps
each case at 100,000 steps. It checks stack and all twelve saved integer and
floating-point registers after every entry, plus full 192-byte main state,
104-byte extension metadata, allocation/output hashes and guard bytes. The host
contract independently checks the complete observations. Byte/export sizes are
provenance, not semantic coverage. Vendor material remains ignored; no device
access, settings or firmware changes were performed.
