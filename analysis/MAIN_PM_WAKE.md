# Power-management wake gate, dynamic IRQ re-registration and wake body

All **13 native cases** pass in **457 instruction steps**. This scope executes
the main-image power-management wake path that is ordinary code:

- the configuration gate `0x80d341d8`, which reads custom CSR `0xfc1`;
- the conditional re-registration routine `0x80d4217c`, which re-points PLIC
  sources `0xe`/`0xc`/`0xb` at RAM handlers through the original PLIC register
  and enable bodies covered by
  [MAIN_TRAP_IRQ_DISPATCH.md](MAIN_TRAP_IRQ_DISPATCH.md);
- the three identical RAM handlers `0x80d42004`/`0x80d42018`/`0x80d4202c`;
- the wake body `0x80d41fb8`, which pokes the `0x90008000` clock/PM block and
  the `0x91000004` register, waits a bounded delay and then restores them.

The evidence is in [main-pm-wake.json](main-pm-wake.json). It reuses and
re-pins the trap/PLIC ranges, so no earlier golden export or report changes.

The deep-sleep save/restore twins are **documented statically only**. No
hardware power event, clock change or wake interrupt is delivered.

## Deep-sleep context save and restore (static)

`0x80d34470` is the sleep entry. It clears Andes CSR `0x7c6`, parks the
interrupted `sp` in `mscratch`, switches to a dedicated stack at `0x80d1b048`
and saves the full context into it:

- `x1`–`x31` (the saved `sp` comes from `mscratch`);
- `mstatus`, `mie`, Andes `0x7d0`, `mtvec`, `mepc`, `0x7c7` and `fcsr`;
- all 32 FP registers as 64-bit values.

It then advances the stack by `0x400`, sets `ra` to the resume twin
`0x80d343a0`, clears `mie.MTIE` (bit 7), executes `fence` and `wfi`, and
`ret`s into the resume twin. `0x80d343a0` reverses the save: it restores the
FP and integer registers and the CSRs, sets `mstatus` bits `0x6000`, writes
`0x7c6 = 0x21` and returns. The `0x7c6 = 0x21` and `0x7c7` handling matches the
hardware stack-protection interpretation in
[MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md).

`fence`, `wfi` and the dedicated sleep stack are not executed here. The real
sleep current and wake latency are hardware properties and remain unproved.

## Configuration gate

`0x80d341d8` reads CSR `0xfc1` and returns 1 only when the three-bit field at
bits 6–8 is zero (`(csr >> 6) & 7 == 0`); bits outside that field are ignored.
The native cases confirm the field: bit 6 or bit 8 set yields 0, and a value
with only higher bits set still yields 1. CSR `0xfc1` is a custom Andes
configuration register; the meaning of the field is not established, but it
acts as an enable for the dynamic re-registration below.

## Dynamic re-registration

`0x80d4217c` calls the gate. When it returns 1, it re-registers three PLIC
sources through the original API, each as register then enable:

| Source | RAM handler | Argument |
| --- | --- | --- |
| `0xe` | `0x80d42004` | 0 |
| `0xc` | `0x80d42018` | 0 |
| `0xb` | `0x80d4202c` | 0 |

Each registration writes the handler and argument into the external table,
marks the entry enabled, sets its PLIC priority to 1 and sets the PLIC enable
bit. Source `0xe` is also the one `vPortSetupTimerInterrupt` registers with the
timer-tick acknowledgement handler; this routine replaces that binding whenever
it runs. Because registration overwrites the table entry, the effective handler
for `0xe`/`0xc`/`0xb` depends on call order, which this scope does not
establish. When the gate returns 0, the routine writes nothing.

The native evidence confirms the six far-call sites to the register
(`0x80d35c6c`) and enable (`0x80d35bcc`) bodies with an independent raw decoder.

## RAM handlers and the wake body

The three RAM handlers are identical. Each reads `0x90008020`, and if bit 12 is
set it tail-jumps to the wake body `0x80d41fb8`; otherwise it returns. The
`0x90008020` status and the `0x90008000` block are also touched by the
deep-sleep path, which is what ties this to power management.

The wake body:

1. reads `0x90008000`, writes it with bits 4–8 cleared and bits 4–6 set
   (`(value & ~0x1f0) | 0x70`);
2. sets bit 4 (`0x10`) in `0x90008014`;
3. sets bit 16 (`0x10000`) in `0x91000004`;
4. spins a 10-iteration empty delay loop;
5. clears bit 4 in `0x90008014`;
6. clears bit 16 in `0x91000004`;
7. restores `0x90008000` to its original value.

The body preserves every other bit of each register and leaves `0x90008000`
unchanged on return. The `0x91000004` register and the `0x90008000` block are
interpreted as clock/power-management control from this access pattern, not
from a datasheet.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| Gate | 5 | Field zero → 1; bit 6, bit 8 and the full field → 0; high bits outside the field ignored |
| Re-registration | 2 | Three sources bound to RAM handlers with priority 1 and enable bits when gated; nothing written when not gated |
| Wake body | 3 | Set/restore of all three registers; other bits preserved; `0x90008000` restored; delay bounded |
| Handler | 3 | Wake runs only when status bit 12 is set; clear or other bits return with no writes |

Every executed PC is inside a hash-guarded original range. The runner records
every store, every CSR access, every supplied MMIO read and the gate's return
value. The independent Python model reproduces all of them.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_pm_wake --vectors-output firmware/main-pm-wake-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainPmWake.java firmware/main-pm-wake-vectors.json firmware/main-pm-wake-validation.json
python3 -m analysis_scripts.main_pm_wake firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-pm-wake-vectors.json --validation firmware/main-pm-wake-validation.json \
  > analysis/main-pm-wake.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining work:

- Execute the deep-sleep save/`wfi`/resume twins on hardware (or a model that
  can represent `wfi`), and establish the real sleep states and wake latency.
- Recover the meaning of CSR `0xfc1`'s field, the `0x90008000`/`0x90008020`
  block and the `0x91000004` register from board evidence.
- Follow which device sources are registered against `0xe`/`0xc`/`0xb` at
  runtime and in what order, and the handlers for the zero-argument sources
  (`0xb` image handler `0x70295c30`, `0xc` `0x702970e0`, `0x10`, `0x4f`,
  `0x50`, `0x51`) and the shared handler `0x70293d50`.
