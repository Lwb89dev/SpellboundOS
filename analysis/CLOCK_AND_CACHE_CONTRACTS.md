# Clock readers, cache commands and shared-address policy

Follow-up: [timer arithmetic](TIMER_ARITHMETIC.md) resolves the missing DSP
instructions, executes the complete helper on bounded vectors and establishes
`floor(raw/1000)`. The helper limitations below describe this earlier snapshot;
physical frequency and cache/coherency remain unresolved.

Three consecutive blocks recover selected wide clock interfaces, cache-control
operations and their transfer callers, then encode bounded host models.
The inputs remain OTA 4.6.0.3; all work is offline. Neither cache commands nor
clock changes were executed on the watch.

## Wide readers and volatile CSR metadata

[SeedClockCache.java](../analysis_scripts/SeedClockCache.java) guards the exact
38-byte native counter-reader body before changing analysis metadata. It
marks the existing CSR memory block volatile, adds a guarded volatile clock
window at `0x9a000000`, and assigns the compiler's default convention and
reviewed register-pair return widths. This preserves separate hardware/CSR
reads and writes, rather than treating them as ordinary variables.

Main `0x80d4548c` reads counter high, low, then high again at
`0xe6000004`/`0xe6000000`, retrying if high changes. It returns the combined
64-bit value. `0x80d4549c` applies the same consistency pattern to `mcycleh`
and `mcycle`. The host snapshot model bounds retries at 128; native code has
no such bound in the reviewed reader.

`0x80d45464` performs the memory-counter snapshot and passes the pair with
argument 1000 to helper `0x70945b3c`, returning its register pair. Its previous
void export hid this relationship. The helper's proposed wide signature makes
the caller visible, but its body still reaches undecoded instructions, including
bytes at `0x70945bd4`. No complete helper emulation or physical counter scale
is claimed. The earlier IPC wait limit of 1000 therefore remains in reader
units, without a measured duration.

Fresh inspection confirms that ordinary `divu` is supported by Ghidra; the
remaining helper failure must not be dismissed as a missing generic M extension.
LLVM also needs `--mattr=+m` to display those standard multiply/divide operations
for this ELF. Some other encodings in the helper remain unassigned.

## Nominal CPU frequency selection

The newly typed `0x80d413a8` selects its control word from `0x90008000` for
role 1 and `0x9a000000` for role 0. Source mode is the low two bits:

| Mode | Selected nominal source |
| --- | --- |
| 0 or 1 | compiled constant 48,000,000 |
| 2 | helper `0x80d412f0`, register `0x9100021c` |
| 3 | helper `0x80d412a8`, register `0x91000214` |

Both PLL helpers use the following register-derived arithmetic:

```text
feedback = ((word >> 16) & 31) + 32
divider = (word >> 21) & 7
if bit 27 is clear:
    factor = (word >> 24) & 15
    remap factor 1 -> 2, 2 -> 3
    divider *= factor
nominal_source = feedback * 48,000,000 / divider
```

The host rejects a zero divider instead of modeling the native arithmetic
edge case. Role 1 then divides the selected source by `2*(field[7:4]+1)`
unless bit 8 bypasses division. Role 0 divides by `field[7:4]+2` unless bit
24 bypasses it. These are compiled formulas using supplied register words;
24/48 MHz synthetic outputs are not measured watch clock rates.

Delay routine `0x80d453d4` uses the cycle counter, with a target calculated
as `(nominal_rate / 1,000,000) * argument`. The reviewed multiply is RV32,
so the host preserves its 32-bit product wrap and integer truncation. This
cycle-based delay and the memory-counter/1000 reader are distinct clock paths.
Recovering one formula does not establish the other's physical frequency.

## Cache-control commands and range guards

The pinned [Zephyr v4.2.0 Andes driver](https://github.com/zephyrproject-rtos/zephyr/blob/v4.2.0/drivers/cache/cache_andes.c)
supplies independent names for the matching command numbers and enable bits.
This supports the operation labels below without identifying the fitted CPU
or proving watch coherency. The reviewed source snapshot is retained only in
ignored `firmware/tool-evidence/` and its hash is recorded in the JSON.

| Native routine | Command to CSR `0x7cc` | Matching operation |
| --- | ---: | --- |
| `0x7029fea0` | 1 | data-cache writeback by address |
| `0x7029ff04` | 2 | data-cache writeback/invalidate by address |
| `0x7029ff68` | 0 | data-cache invalidate by address |
| `0x7029fe74` | 6 | data-cache writeback/invalidate all |

Startup `0x701637ec` separately sets bits 1 and 0 in CSR `0x7ca`, consistent
with the reference driver's data/instruction cache enable bits, then executes
`fence.i`. Volatile CSR semantics preserve both writes. This is a software
initialization path, not evidence of the actual runtime enable state.

The three range routines first execute a **signed** `start <= 0` guard,
confirmed by raw `blez` at `0x7029fea0`. Consequently the recovered shared
pool addresses `0x80f00000`, `0x80f05000`, `0x80f0a000` are skipped. This
explains a software policy; it does not prove that those addresses are
physically uncached, aliased or coherent.

For a positive address, the routine saves interrupt state. If CSR `0x7ca`
bit 1 is clear, it executes a plain `fence`. Otherwise it writes
`start & ~31` to CSR `0x7cb`, issues the command at least once, and repeats
while CSR `0x7cb` readback is below the wrapped 32-bit end address. It restores
interrupt state afterward. Even size zero enters that command loop. The host
models alignment, signed guard, end wrap and minimum command count; it does
not invent a software increment or simulate hardware command progress.

The later [main DMA/IRQ and connected NAND cache-guard scopes](MAIN_DMA_CACHE_GUARDS.md)
execute the original signed entry guards for high-half/zero addresses, matching
this contract. Positive-address CSR progress and physical coherency remain open.

## Transfer callers and scope

Call sites were located as candidate RISC-V calls, then selected wrappers
were regenerated. `0x702a01c0` and `0x702a02a0` call the writeback routine
for buffer arguments according to a raw context mode at `+4`:

| Mode | Pre-transfer writeback arguments | Saved completion range |
| --- | --- | --- |
| 0 | both buffer arguments | second buffer and size |
| 1 | second buffer | second buffer and size |
| 2 | first buffer | cleared |

Completion wrapper `0x702a0264` calls writeback/invalidate for the saved range,
then clears it. These DMA-shaped paths connect cache primitives to transfer
lifetimes; direction labels and the exact peripheral-engine register map are
not fully established. Pointer-based register side effects in those wrappers
must not be treated as fully validated I/O ordering from pseudocode alone.

The recovered paths are still insufficient to assert a working shared-memory
driver. In particular, no selected range-cache call operates on the high-bit
shared addresses, and the earlier rpmsg ordering hooks contain only `fence.i`.
Physical memory attributes and inter-core visibility require corroboration.

## Reproduction and validation

On the existing corrected main project, run `SeedClockCache.java` before
`DecompileWithAbi.java`. The 16 clock/cache targets are enumerated in
`clock_cache.py:TARGETS`; the four selected callers are `CALLERS`.
Retained exports are `runtime-clock-cache` and
`runtime-clock-cache-followup`. Logs include
`firmware/ghidra-clock-cache-final-stdout.log`,
`firmware/ghidra-clock-cache-followup-stdout.log` and the targeted instruction
inspection log `firmware/ghidra-timer-instructions-stdout.log`.

```sh
python3 analysis_scripts/clock_cache.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled \
  --andes-source firmware/tool-evidence/zephyr-v4.2.0-cache_andes.c \
  > analysis/clock-cache.json
python3 -m unittest discover -s tests -p 'test_clock_cache.py' -v
```

[clock-cache.json](clock-cache.json) guards source/image hashes, fingerprints
20 selected exports and reviewed instruction ranges, checks both startup
enable writes and wide reader return, and explicitly records the still-broken
arithmetic helper. Nine new host tests cover snapshot rollover/bounds, source
selection, divisor/bypass behavior, cycle-target overflow, shared-address
rejection, disabled-cache fencing, alignment and zero-size/wrapped-end cases.
All 243 Python tests pass with signature/cipher dependencies. The JSON
reproduces byte-for-byte; no native arithmetic helper or hardware cache was
executed by those tests.
