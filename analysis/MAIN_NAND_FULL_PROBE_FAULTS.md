# Main probe FIFO retries, actual timeout assertions and retained root state

All **12 native retry/failure cases** pass in **85,212 instruction/service
steps** (maximum **29,185**, final candidate on the third round). They use the
[joined original main probe/platform/FIFO/root path](MAIN_NAND_FULL_PROBE.md).
[main-nand-full-probe-faults.json](main-nand-full-probe-faults.json) records
**43 code/export and 40 data hashes**, complete observations and limitations.

Peripheral values, FIFO ID/readback bytes, ROM string and ticks are authored.
Power/pin/GPIO/workaround/UID/BBT/BSP/RTOS/heap/library/PM services remain supplied.
No actual UID/BBT/media or physical failure is established by these fixtures.

## Retry and no-match paths with actual initialization

Second-round success executes 12 real platform initializations and ID requests.
Final-33rd success executes all three eleven-candidate rounds, then resets and
configures the selected original last descriptor and reaches registered-object
geometry consumers. Each attempt preserves original table/binding bytes while
reinitializing the same original DMA records and controller links.

All-`0xff` responses instead exhaust 33 attempts. Original probe returns `-4`,
then wrapper/root returns `-6` before allocation. Selection and guard counts
remain zero; actual DMA/controller initialization and registry slots 26/27 are
retained. Driver-object publication and hardware initialization are distinct
stages in this selected execution.

## Actual FIFO timeout propagation

Ticks advance by an authored 1001 units per supplied HAL tick call and frequency
is supplied as 1000. Selected readiness/completion register inputs stay zero
for one command index. Actual original wait loops produce timeout 3, followed
by original bus logging, supplied diagnostic and the actual assertion call.
These inputs exercise control/arithmetic, without physical unit calibration.

| Authored fault | First original stopped site / retained state |
| --- | --- |
| Bus disabled before ID | ID-builder assertion `0x70a30fa4`, line 383; actual platform/DMA links retained, zero HAL commands |
| First ID readiness never set | Transport assertion `0x70a1bc8c`, line 305; no FIFO bytes read, selection zero |
| Reset completion never set | Transport assertion `0x70a1bc8c`, line 294; selected descriptor retained, no feature writes |
| First feature-write completion never set | Transport assertion `0x70a1bc8c`, line 313; prior FIFO byte and feature-model state retained, guards zero |
| First feature-read readiness never set | Transport assertion `0x70a1bc8c`, line 305; prior write retained, no outer probe error return |

Assertion bodies/recovery do not run and stopped cases claim no return ABI.
For the feature-write completion timeout, the byte has reached the modeled FIFO;
this does not establish physical NAND acceptance or successful programming.

Successful receive with a deliberately mismatched byte follows a different
path: original probe returns `-7`, wrapper/root returns `-6`, selected descriptor
and feature write remain, guard counts and object allocation stay absent.
Missing regulator and selected negative pin-service returns still permit the
selected complete software path. Allocation failure after successful probe
retains selected chip, original DMA links and guard counts but no object/cache.

## Reproduction, regression and continuation

```sh
python3 analysis_scripts/main_nand_full_probe.py --scope faults \
  --vectors-output firmware/main-nand-full-probe-faults-vectors.json
```

Use the seeded project/environment and `ValidateMainNandFullProbe.java` command
from [MAIN_NAND_FULL_PROBE.md](MAIN_NAND_FULL_PROBE.md), substituting
`firmware/main-nand-full-probe-faults-vectors.json` and
`firmware/main-nand-full-probe-faults-validation.json`. Both scopes share exports:

```sh
python3 analysis_scripts/main_nand_full_probe.py firmware/bip6-4.6.0.3.zip \
  --scope faults --decompiled firmware/decompiled/runtime-main-nand-full-probe \
  --vectors firmware/main-nand-full-probe-faults-vectors.json \
  --validation firmware/main-nand-full-probe-faults-validation.json
```

Both evidence files/vector sets reproduce. All **369 preceding main native
cases reproduce byte for byte** after the narrow emulator/bound and model
initialization hooks. Parent fixed configuration, guards/log tags and default
10,000-step scope are unchanged. The two new scopes add **28 host checks** to
the passing **1,802-test suite**.

Next work is actual main workaround/UID/BBT and page/media callers through this
chain, plus main IRQ/cache/pin bodies and broader storage lifetimes. Physical
identity, electrical/timing/coherency, safe backup/restoration, signed-chain
enforcement and standalone boot remain separate open requirements.
