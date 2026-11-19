# Actual main UID acquisition inside the original probe and FIFO path

All **14 native cases** pass in **130,133 instruction/service steps** (maximum
**24,357**, valid sixteenth UID copy). Original main UID body `0x702d6524`, page
load `0x702d5edc`, busy poll `0x702d6470`, cache read `0x702d5f42`, feature helpers
and [family workaround](MAIN_NAND_WORKAROUND.md) now join actual main probe/
platform/FIFO/root and later geometry consumers.
[main-nand-aux-uid.json](main-nand-aux-uid.json) records **54 code/export and
65 data hashes**, complete observations and limitations.

ID/UID/E0/status/FIFO responses, clocks, reset/completion and ROM string are
authored. Power/pin/BSP/RTOS/heap/PM and bounded zero/format/comparison services
remain supplied. **BBT still does not execute** in this scope. Complement-
consistent synthetic bytes do not establish a physical or unique device identity.

## Original UID contract and globals

The independent [main identity inventory](main-nand-identity.json) records all
eleven unchanged original descriptors. Their selected UID method is mode 1,
32-byte records and up to 16 copies; some original flags tell probe to skip UID.
Winbond descriptors configure B0 to `0x48`; selected DOSILICON/ESMT descriptors
use `0x40`. ECC masks differ across those families. Native cases cover first-chip
Winbond, supported-family Winbond, DOSILICON and ESMT, plus an original no-UID flag.

Actual UID setup writes/readbacks the original feature sequence, loads the
descriptor's page and polls original status using the bus wait callback
`0x7029681c` with requested delay 5. Cases cover ready on first/second status read
and ECC rejection. Busy exhaustion and its full 2000-poll workload remain outside
this selected scope; no invented feature/load helper error returns are injected.

After accepted status, original code clears published length byte `0x70f8e6f4`.
It clears the first 32 bytes of UID buffer `0x70f9bc50`, then reads each copy
through actual command/HAL/direct FIFO. These packets remain forced direct even
at length 32. A copy is accepted only when all 16 byte pairs in its two halves
XOR to `0xff`; then published length becomes 16 and bounded formatting produces
the uppercase byte text for logging. The 128-byte backing and guard checks
capture untouched tails as well as the active 32 bytes.

First, second and sixteenth-copy success execute. The latter performs 521 total
FIFO read bytes in this fixture, including ID/status/features. The auxiliary
harness raises its **total trace guard** to 1024; individual UID packets stay
32 bytes. This is not a physical FIFO-capacity claim, and the preceding full
probe scope keeps its original 512-byte total guard.

## Errors, retained state and void caller behavior

| Selected condition | Actual UID state / caller consequence |
| --- | --- |
| No complementary copy among 16 | Length zero, last invalid 32-byte payload retained; log `-200`; outer probe still succeeds |
| Successful feature readback mismatches requested UID setup | Prior length/backing retained; feature log `-7`, UID log `-5`; outer probe still succeeds |
| Authored status fails ECC mask | Prior length/backing retained; UID log `-101`; outer probe still succeeds |
| Original flag disables UID request | Body not entered; prior length/backing unchanged |
| UID feature-read readiness timeout | Actual transport assertion, line 305; prior length/backing retained, no normal UID completion |
| UID cache-read readiness timeout | Length already zero, first 32 bytes cleared; actual transport assertion, line 305 |
| UID cache-read completion timeout after FIFO delivery | Length still zero, received payload retained; actual transport assertion, line 305 |

Timeout assertions use owner `0x70a1bc8c`; assertion/recovery bodies do not run.
Formatting/zero helpers have explicit stack/buffer bounds. The authored prior
state is length 17 with `0xa5` backing, so retained bytes are fixture state rather
than a claim about any real previous identity.

UID is an actual **void** routine. Its handled errors can return normally after
logging; probe then executes ordinary feature setup, supplied BBT and actual
object registration/geometry. Ordinary feature setup restores its descriptor's
B0 value after UID configuration or a handled UID mismatch. Registration and
active geometry therefore do not establish valid UID acquisition. Direct main
UID ioctl export and downstream identity consumers are not executed here.
The subsequent [main UID export scope](MAIN_NAND_UID_EXPORT.md) executes the
context/chip request and its locking, including retained-state export.

## Reproduction, regression and continuation

```sh
python3 analysis_scripts/main_nand_aux.py --scope uid \
  --vectors-output firmware/main-nand-aux-uid-vectors.json
```

Use the seeded project/environment and `ValidateMainNandAux.java` command from
[MAIN_NAND_WORKAROUND.md](MAIN_NAND_WORKAROUND.md), substituting
`firmware/main-nand-aux-uid-vectors.json` and
`firmware/main-nand-aux-uid-validation.json`. Both auxiliary scopes share exports:

```sh
python3 analysis_scripts/main_nand_aux.py firmware/bip6-4.6.0.3.zip \
  --scope uid --decompiled firmware/decompiled/runtime-main-nand-aux \
  --vectors firmware/main-nand-aux-uid-vectors.json \
  --validation firmware/main-nand-aux-uid-validation.json
```

Inventory, vector sets and both evidence files reproduce. All **396 preceding
main native cases reproduce byte for byte** after narrow auxiliary/model/FIFO
extension hooks; previous fixed configurations and scope bounds remain unchanged.
The two scopes add **28 host checks** to the passing **1,830-test suite**.

The subsequent [main BBT scope](MAIN_NAND_BBT.md) executes verifier/resume/CRC
with supplied page/marker services. Next work includes BBT lower page integration,
remapping, further UID consumers and page/media callers. IRQ/cache/pin bodies, physical identity, electrical/
timing/coherency, persistence, safe backup/restoration and standalone boot remain
separate open requirements.
