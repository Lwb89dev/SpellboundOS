# Claude handoff — 2026-11-19

The user requested this checkpoint because their weekly Codex credits are nearly
exhausted. This is a completed-work handoff, not a paused native validation or an
unfinished analysis patch. Repository documentation stays **English**; user-facing
conversation is Italian. The user has repeatedly requested committing/pushing
completed work to `origin/main` and continuing in substantial blocks.

## Start here

- Repository: `/home/antona89/Documents/vscode/SpellboundFit`.
- Remote: `https://github.com/Lwb89dev/SpellboundOS.git`, branch `main`.
- Latest analysis commit: **`3685f79`**. This handoff is committed after it.
- Latest complete host suite: **2,112 tests passed in 235.951 seconds**.
- Latest native scopes: **43 cache-range + 22 critical-section cases**, all pass.
- Latest regression: **186 preceding backend/IRQ/cache/NAND cases reproduce byte
  for byte**. This is the selected regression set, not all project native cases.
- No pending analysis edits or running validation jobs at checkpoint creation.
  Recheck `git status` before starting; the handoff documentation is the only
  additional change being prepared in this session.

Read [GOAL.md](GOAL.md), [analysis/RE_STATUS.md](analysis/RE_STATUS.md), then
[MAIN_CACHE_CSR_RANGES.md](analysis/MAIN_CACHE_CSR_RANGES.md) and
[MAIN_RTOS_CRITICAL_SECTIONS.md](analysis/MAIN_RTOS_CRITICAL_SECTIONS.md).
[PROGRESS.md](PROGRESS.md) is the full chronological record; its latest dated
entries and `Next work` section are more efficient starting points than reading
its entire history. Older reports retain historical scope limitations; follow
subsequent-report links before treating an old open item as still untouched.

## What the project is, and how much remains

The goal is an independently authored standalone Bip 6 OS plus the SpellboundFit
Android companion, including notifications/actions, Roadstr navigation and
technically supported calling behavior. Current RE evidence is not a working
watch OS or a set of finished, hardware-tested reusable drivers. `kernel/` is a
QEMU virt UART prototype, not a Bip 6 image.

The qualitative planning estimate reviewed on **2026-11-19 remains 50–60% of the
RE needed for the project**, with roughly **40–50% remaining** and substantial
uncertainty. Test/export counts are not a coverage denominator. This is not an
OS implementation percentage or a credible calendar estimate. Recent work
substantially deepens selected storage/cache contracts, but the major remaining
areas still include:

1. Device-specific backup/restoration and a viable boot route through the signed
   chain. This is an unresolved feasibility gate; no working unlock is known.
2. Necessary hardware/board/firmware integration, real DMA/cache/IRQ/timing and
   sensor validation, plus remaining algorithm/application consumers.
3. Fresh pairing/key provisioning/counter lifecycle, complete Bluetooth behavior
   and the required phone/watch application contracts.
4. Independent OS/driver/Android implementation and real device integration after
   those contracts and feasibility requirements are established.

Preserve [GOAL.md](GOAL.md)'s backup/recovery prerequisites before any watch write.
The OTA is not a verified complete physical flash/ROM backup. No custom firmware
has been installed by this work. This checkpoint does not assume a phone/watch
is currently connected; recheck device state before any future runtime work.

## Recent completed blocks

| Commit | Completed evidence |
| --- | --- |
| `0a5810b` | Main mode-zero read through original initialized RX DMA (16 cases), and mapped/guarded erase with original sleep polling (14) |
| `debffcb` | Main mode-zero program through original initialized TX DMA, staging, execute/status and fault state (26) |
| `a6f727d` | Main IRQ dispatch (26), actual high-half cache guards through backend/IRQ (72) and full NAND read/program (16/26) |
| `3685f79` | Positive-address cache CSR loops (43) and actual context/critical/diagnostic bodies (22), with 32 new host checks |

The first NAND scopes follow full original probe/platform/DMA initialization,
UID, BBT marker/read/CRC/repair and root publication. Earlier completed work also
includes actual full 2000/4000-poll NAND busy boundaries, connected boot storage/
EFTL paths, selected optical/health IPC paths and one live Gadgetbridge session.
See the status matrix for their exact evidence and remaining limitations.

Important contracts to preserve:

- Mode zero still waits in the selected NAND/QSPI paths. A stored no-op callback
  does not prove asynchronous IRQ scheduling; those bus paths do not invoke it.
- Hardware DMA movement is not modeled. RX success can copy retained authored
  private-buffer bytes; TX observes staging and software completion without
  fabricating FIFO DMA writes or NAND persistence.
- Alternate DMA completion can return zero while retaining RX tracking and
  skipping cache finish. Primary completion clears tracking. IRQ primary and
  alternate handling have distinct cleanup/callback behavior too.
- Main DMA's unknown-base fallback uses registry slots 28–34 over explicit
  guarded backing. This does not prove a fifth physical DMA bank or production
  allocation extent.
- Original cache range guards skip signed-nonpositive addresses, including the
  original NAND private buffer. Positive-address loops use supplied CSR feedback;
  there is no software address stride or timeout. Marked command-bound stops
  are harness stops, not firmware errors/normal returns.
- The three original cache `fence` sites are recorded, supplied no-ops because
  Ghidra lacks their userop. No physical ordering effect is claimed.
- Original critical entry clears MIE, then conditionally increments thread
  depth. Exit enables MIE only on a depth transition to zero. The pair is not a
  saved-MIE restore. Scheduler-off, existing-depth and wrap cases differ.
- Nonzero context bypasses critical entry/exit and writes zero to the save output;
  normal-context save leaves the output untouched, and selected restore ignores
  its argument. Context/scheduler labels are working interpretations of tested
  fields; legal production states and concurrency remain open.

## Immediate next work

Keep the boot/backup/restoration feasibility gate prominent when choosing work;
read [BOOT_RECOVERY_AND_METADATA.md](analysis/BOOT_RECOVERY_AND_METADATA.md) and
[RECOVERY_SELECTION_AND_HANDOFF.md](analysis/RECOVERY_SELECTION_AND_HANDOFF.md).
Record which missing evidence can be obtained offline and which needs permitted
physical observation before estimating implementation time.

A concrete continuation from the current native thread is to recover writers
and callers of the context/scheduler/current-thread fields, and connect actual
main interrupt entry/registration to the now-covered DMA handler. Start with
`InspectNativeReferences.java` at the addresses below, then confirm raw
instructions/control flow because existing reference metadata can be incomplete.

| Entry / field | Address |
| --- | --- |
| Cache all / prepare / finish / invalidate | `0x7029fe74`, `0x7029fea0`, `0x7029ff04`, `0x7029ff68` |
| Save / restore wrappers | `0x80d379ee`, `0x80d37a1a` |
| Context query / queried word | `0x80d41190`, `0x80c121a4` |
| Critical enter / exit | `0x80d3a062`, `0x80d3a0ae` |
| Scheduler gate / current-thread pointer | `0x80c07e5c`, `0x80c07fa8` |
| Current-thread depth | pointer + `0x50` |
| Diagnostic body / enable / table | `0x80d33720`, `0x80c44244`, `0x80dff708` |
| Main DMA IRQ / registry | `0x702a041c`, `0x80c11738` |
| Original TX / RX / private buffer | `0x80c10df4`, `0x80c10db0`, `0x80d93960` |

Establish the context word's actual producer/entry/exit lifecycle before calling
it a proven ISR-state contract. Then follow real callback consumers, production
positive-address cache/DMA callers, board/pin/power services and broader PM/
storage consumers. Bluetooth pairing and remaining health/application contracts
are independent substantive work areas; do not infer their completion from
additional low-level storage test counts.

## Local tools and artifacts

`firmware/` is ignored and must stay out of Git. It contains the vendor package,
startup-aware ELFs/projects, native vectors/reports, exports and tool evidence.
Preserve it on this machine. A fresh GitHub clone will not contain these inputs.

- OTA: `firmware/bip6-4.6.0.3.zip`, SHA-256
  `ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
- Main image SHA-256:
  `a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.
- Ghidra: `firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless`.
- Projects: `firmware/ghidra-runtime`, project `main-runtime`, program
  `main-runtime.elf`; boot/sensor runtime projects also exist there.
- Language: startup-aware RV32 AndeStar mappings with guarded BBS and two DSP
  repairs. See [NATIVE_REPAIR.md](analysis/NATIVE_REPAIR.md),
  [ZRPC_BRANCHES_AND_MEMORY.md](analysis/ZRPC_BRANCHES_AND_MEMORY.md) and
  [TIMER_ARITHMETIC.md](analysis/TIMER_ARITHMETIC.md) before rebuilding tooling.
- Latest exports: `firmware/decompiled/runtime-main-cache-control/`.
- Latest vectors/reports: `firmware/main-cache-{range,critical}-{vectors,validation}.json`.
- Latest native/regression log: `firmware/main-cache-control-stdout.log`.

Use one headless process at a time per Ghidra project. Reuse reviewed startup,
ABI/logger/volatile metadata rather than importing a raw image with generic
mapping. New metadata can change decompiled names: export new scopes into new
directories and preserve prior golden exports/reports. Vendor-derived C/binaries
stay local; commit authored scripts, tests, reports/hashes and documentation.

## Verification and reproduction

Fast latest-scope check (32 tests):

```sh
python3 -m unittest tests.test_main_cache_control -q
```

Latest full Python suite on this machine (approximately four minutes):

```sh
PYTHONPATH=/home/antona89/.cache/uv/archive-v0/pRlDmMUlc-kov_qh:/home/antona89/.cache/uv/archive-v0/moSdF0ezShhZQMKQ \
  python3 -m unittest discover -s tests -p 'test_*.py' -q
```

Those local cache paths provide `cryptography` and `cffi`; they are not portable
dependency locations. Use an appropriate Python environment if they disappear.
`make test` is the separate QEMU prototype check and was not part of the recorded
2,112-test result. Documentation-only handoff changes do not require rerunning
the full native/host suite.

The tracked reproducible procedure is in
[MAIN_CACHE_CSR_RANGES.md](analysis/MAIN_CACHE_CSR_RANGES.md). It generates both
vector sets, seeds `SeedMainCacheControl.java`, runs
`ValidateMainCacheControl.java`, and rebuilds evidence with
`analysis_scripts/main_cache_control.py`. Preserve the 5,000-step bound, at most
16 commands, and marked nonreturning stalls. Compare regenerated JSON bytes to
`analysis/main-cache-range.json` and `analysis/main-cache-critical.json`.

The latest selected regression set is:

| Native runner | Local vector/report stem | Cases |
| --- | --- | ---: |
| `ValidateMainDmaBackend.java` | `main-dma-backend` | 46 |
| `ValidateMainDmaIrq.java` | `main-dma-irq` | 26 |
| `ValidateMainDmaIrq.java` | `main-dma-cache-guards` | 72 |
| `ValidateMainNandReadCacheGuards.java` | `main-nand-cache-read` | 16 |
| `ValidateMainNandProgramCacheGuards.java` | `main-nand-cache-program` | 26 |

Vectors/golden reports are `firmware/<stem>-vectors.json` and
`firmware/<stem>-validation.json`. Write reruns to separate temporary paths and
compare bytes. The local convenience wrapper `/tmp/main_cache_native.py` exists
at handoff and runs both new scopes plus these regressions, but `/tmp` is
transient; the tracked procedures and recorded log are the durable reference.

## Suggested message to resume Claude

> Read HANDOFF_CLAUDE.md, GOAL.md and analysis/RE_STATUS.md. The latest analysis
> baseline is 3685f79, with 2,112 passing host tests and no unfinished analysis
> edits. Continue in substantial verified blocks, starting with the next-work
> priorities in the handoff. Preserve evidence boundaries and original golden
> reports, keep documentation in English, and commit/push completed work to
> origin/main. Keep backup/restoration and standalone-boot feasibility prominent.
