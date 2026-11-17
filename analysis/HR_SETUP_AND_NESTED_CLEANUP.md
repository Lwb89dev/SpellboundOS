# HR setup, component allocations and nested cleanup

This pass replaces the broad setup/cleanup boundaries from
[HR_WORKSPACE_AND_EXTENSION.md](HR_WORKSPACE_AND_EXTENSION.md) with actual
execution of their selected descendants. All 37 additional native cases pass:
11 setup, six inner-initializer, 15 seeded-cleanup and five full owner cases.
They total 27,696 steps including intercepted calls; the maximum is 4,700.
All 471 Python tests pass, including 19 new checks. Complete observations and
provenance are in [hr-setup.json](hr-setup.json).

Allocator/free, memory zero/copy, logger and the initializer at `0x708a4818`
remain supplied. The other listed setup/component allocation/cleanup routines
execute their native instructions. This establishes memory/state contracts;
initialized signal-processing kernels, measurement accuracy and device behavior
are not validated.

## 1. Rate-scaled buffer clearing

Actual setup `0x708a1432(root)` reads the 16-bit software rate field at root +
`0x15a`, initially 25 in the outer initializer. It issues 27 buffer clear calls,
with integer truncation in the positions shown below. `r` denotes that field;
root indices are four-byte word indices containing the target pointers.

| Root word indices | Clear length in bytes |
| --- | --- |
| 0 | `4 * floor(512*r/25)` |
| 12..14 | `2*r` |
| 1..11 | `4 * floor(60*r/25)` |
| 30..33 | `8*r` |
| 34, 35, 41, 42 | `4 * floor(64*r/25)` |
| 37 | `4 * floor(256*r/25)` |
| 38 | `8 * floor(128*r/25)` |
| 40 | `4 * floor(128*r/25)` |
| 100 | `floor(30*r/25)` |

It sets bytes + `0x75 = 1`, + `0x76 = 20`, resets selected counters/flags, stores
halfword 1 at + `0x6624`, calls actual inner initializer `0x70897c46`, clears
ten bytes at + `0x3c` and clears byte + `0x77`.

Standalone fixtures cover rates 0, 1, 12, 24, 25, 26, 49, 50, 75 and 100 with
buffers explicitly resized/padded for those synthetic inputs. Full owner cases
use the actual outer initializer's fixed rate 25. Rate 26 distinguishes division
before multiplication: word 34 clears 264 bytes, not the result of moving
division after the final factor of four. Unused buffer tails and 32-byte guards
are checked. These software formulas do not prove physical sample frequency.

## 2. Inner initialization and allocation formulas

Actual `0x70897c46` copies four float constants to root + `0xac`, clears selected
existing buffers, sets flags and float defaults, propagates the rate into
substructures and calls their initializers. The coefficient values are
`0.96, 0.8, 1.5, 0.95`; other checked float bits include `-1.0`, `0x41f2d07f`
and `0.0005`. No physical meaning is assigned to these constants here.

| Executed native initializer | Observed allocation/reset contract |
| --- | --- |
| `0x708a16ce(root+0x3d04, r)` | Let `n=floor(18*r/25)+1`, `m=floor(9*r/25)+1`: three `4*n` buffers and one `4*n*m` matrix; all four cleared |
| `0x708a2cae(root+0xd0c)` | Reset substructure/ranges, store two `0xffff` sentinels; allocate two `256*floor(r/25)` and two `332*floor(r/25)` buffers |
| `0x70897046(root+0x3c64)` | Clear both existing pointed-to buffers with `4*floor(64*r/25)` |
| `0x7089781a(root+0x3c4c)` | Clear 24-byte header while preserving rate; allocate/clear two `floor(600*r/25)` buffers; store low byte of `3*r` |
| `0x7089fdbe(extra)` | Reset the new 8,188-byte workspace's selected counter/windows, preserving untouched bytes |

The call to `0x708a4818(root+0x218)` is intercepted and leaves its context
unchanged; supplied return 7 is ignored by the parent just like return zero.
That initializer's own constants, nested behavior and processing remain open.

After the component initializers, the parent allocates an additional `0x1ffc`
bytes and stores it at root + `0x9c14`. Success calls actual `0x7089fdbe`.
Failure logs and skips that workspace reset, but the void parent continues.
The full outer initializer subsequently returns zero and sets initialized even
in this supplied failure case. Its global-state snapshot matches the successful
case, while the root/heap snapshots capture the absent allocation. Subsequent
signal behavior under that partial initialization is not executed.

Zero-length component requests are exercised for small synthetic rates. The
allocator boundary supplies distinct nonnull backing for zero-size requests;
this does not establish what the device allocator returns. Other secondary
allocation failures remain open.

## 3. Actual nested cleanup

Actual root cleanup `0x70897e1c`, reached through thunk `0x708a16c4`, executes
three cleanup routines and conditionally frees the extra workspace:

| Routine | Slots relative to the root / clearing policy |
| --- | --- |
| `0x708a1782(root+0x3d04)` | Conditionally free `0x3da0/3da4/3da8/3dac`; leave these four stored pointer values unchanged |
| `0x708978ae(root+0x3c4c)` | Conditionally free and clear `0x3c58/3c5c` |
| `0x708a2d62(root+0xd0c)` | Unconditionally call free and clear `0xd4c`, `0xd54`, `0xd50`, `0xd58`, in that order |
| Parent | Conditionally free and clear `0x9c14` |

The 15 cleanup fixtures cover all-null, all-present, two alternating masks and
each of the eleven slots individually. The supplied free boundary accepts null
calls, records order and rejects duplicate/interior/unknown frees. Actual device
allocator behavior is not executed. Four first-group slots retain the released
addresses; repeated standalone cleanup with them populated is outside the tested
sequence. In the full owner sequence the enclosing root is later released,
and the inactive guard suppresses a second outer exit.

## 4. Integrated outer init/exit and restart

The native outer initializer and exit now run with the actual setup/inner/
component allocation/reset and nested cleanup paths above. With the one remaining
initializer boundary, successful cases make 89 requests totaling 101,108 bytes:
the prior 78 requests/89,556 bytes plus eleven nested requests/11,552 bytes.
Native cleanup releases all 89 exactly once, with the root last. This is a
deeper execution scope than the earlier 78-allocation result, which explicitly
supplied the whole setup/cleanup calls.

Cases check normal mode, mode 4 (post-setup limit byte becomes 14), repeated
init/exit, restart and extra-workspace allocation failure. Restart uses different
addresses for a second generation and balances all 178 requests. Failure of
only the 8,188-byte extra request leaves 88 successful allocations, all released
by the selected exit path. No live reachability, concurrency or initialized
measurement behavior is inferred from these caller sequences.

## Reproduction and evidence boundaries

Use startup-aware `main-bbs` / `main-runtime.elf` with the established guarded
AndeStar/logger repairs. Export the fourteen `hr_setup.py:TARGETS` with
`DecompileWithLogger.java`, logger `0x702b38a2`, into ignored
`firmware/decompiled/runtime-hr-setup/`.

```sh
python3 analysis_scripts/hr_setup.py --vectors-output firmware/hr-setup-native-vectors.json
```

Run on the main project with `-process main-runtime.elf -noanalysis`:

```text
-postScript ValidateHrSetup.java firmware/hr-setup-native-vectors.json firmware/hr-setup-native-validation.json
```

```sh
python3 analysis_scripts/hr_setup.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-hr-setup \
  --vectors firmware/hr-setup-native-vectors.json \
  --validation firmware/hr-setup-native-validation.json > analysis/hr-setup.json
python3 -m unittest discover -s tests -p 'test_hr_setup.py' -v
```

The runner checks code/constant hashes, rejects unexpected PCs/logs/frees and
caps each case at 100,000 steps. It checks stack, all twelve saved integer/FP
registers, full 192-byte global-state and all allocation hashes/guards after
each entry. Full zero/copy/allocation/free traces are compared with the host
contract. Synthetic fixture allocations are distinguished from requests made
by native code. Fresh pseudocode has tail-call/PIC artifacts around memory
helpers; reviewed instructions and native execution establish the selected
contracts, while export hashes serve as provenance, not semantic coverage.

Remaining work includes initializer `0x708a4818`, other allocation failures,
supported input normalization and mathematical kernels, engine activation,
motion/minute/reset/wear paths, transport/concurrency and physical validation.
Vendor material stays ignored. No device/settings access or firmware changes
were performed.
