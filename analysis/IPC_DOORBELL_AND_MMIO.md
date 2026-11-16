# IPC interrupt, volatile register sequences and notification control

Follow-up: [clock and cache contracts](CLOCK_AND_CACHE_CONTRACTS.md) restores
wide reader signatures and volatile CSR semantics, recovers CPU clock formulas
and range-cache operations, and shows that their signed guard skips shared
pool addresses. The later [timer arithmetic pass](TIMER_ARITHMETIC.md) resolves
the helper to unsigned division and establishes the reader's `floor(raw/1000)`
conversion. Physical frequency and coherency remain open; the helper limitations
below describe this earlier snapshot.

Three further blocks connect the recovered rpmsg queues to their native
notification/interrupt route, preserve previously omitted register writes,
and model selected synchronization decisions on the host. The analysis covers
the same main and sensor OTA 4.6.0.3 images as
[RPMSG_NATIVE_AND_FRAGMENTS.md](RPMSG_NATIVE_AND_FRAGMENTS.md).
No device registers were accessed.

## Queue notification and interrupt route

Queue notification callback `0x707bfb32` loads the queue ID at context `+0x50`
and enters sender `0x707bf7e0`. The transmitted token is queue ID plus one.
Initialization `0x707bfa04` registers handler `0x707bf926` for untagged external
IRQ `0x10` through `0x80d35c6c`. The external interrupt enable/disable helpers
operate on bank `0xe4002000 + 4*(irq >> 5)` with mask `1 << (irq & 31)`.
For IRQ 16, that is `0xe4002000`, mask `0x10000`.

These numbers describe software interrupt/controller addresses. They are not
PCB pin assignments or proof that an interrupt was delivered on the watch.
Tagged internal interrupt IDs take a different path, excluded from the host
external-IRQ helper.

| Runtime role predicate | Send register | Sender polls | Receive/echo-ACK register |
| --- | --- | --- | --- |
| 0 | `0x90008070` | `0x90008074` | `0x9000807c` |
| 1 | `0x90008078` | `0x9000807c` | `0x90008074` |

The predicate is the previously recovered CSR `0xfc1` mask test. Its 14
instruction bytes match on main (`0x80d341d8`) and sensor (`0x80fd2dec`).
The active role and live register values remain unobserved.

The ISR subtracts one from the received token and calls `0x707bf72c`.
That dispatcher bounds the index to 0–31, looks up a queue context in the
32-entry table at `0x70fe69c4`, then invokes callback offset `+0x30` through
`0x707c07a4` if context/callback exist. For the RX queue this reaches the
rpmsg endpoint-dispatch route recovered previously. Normal processing writes
the received token back to the same receive register after dispatch. This is
an observed echo acknowledgement, not a complete register bus specification.

For role 0, token `0xff` takes an exception path and is echoed **before** that
path is invoked. It is not a queue number. Zero and values above 32 would hit
the native dispatcher guard; the bounded host decoder rejects them. Only six
queue IDs are used by the recovered three-pool setup, although the registry
has room for 32.

The sensor counterparts `0x80fa6ad6` (notify), `0x80fa6c7a` (ISR) and
`0x80fa6a26` (dispatch) corroborate the same register pairs, token mapping and
exception sentinel. Sensor callback storage is at `0x80f56468`.

## Why volatile I/O metadata matters

The first main export omitted transient writes and produced an apparent
write to `0x90008070` on a role-1 path. Raw instructions showed a different
sequence. Ghidra had ordinary memory semantics for the unmapped MMIO globals,
allowing intermediate stores and register reads to be simplified.

[MarkIpcMmio.java](../analysis_scripts/MarkIpcMmio.java) now creates guarded,
uninitialized, readable/writable, non-executable **volatile** analysis blocks:

| Base | Analysis bytes |
| --- | --- |
| `0x90008000` | `0x1000` |
| `0x91000000` | `0x1000` |
| `0xe4000000` | `0x4000` |
| `0xe6000000` | `0x1000` |

The script guards the exact reviewed main or sensor notify routine. Existing
blocks must match the declared extent. These windows preserve decompiler
side effects; they do not establish physical register coverage, memory aliases
or a complete hardware map. Neither firmware bytes nor hardware are changed.

With volatile metadata, both processors retain the role-1 wake sequence:

1. Publish the token to `0x90008078`.
2. Read/OR/write `0x91000004` with bit 0, then separately with bit 16.
3. When status `0x90008020` has bit 12 set, save `0x90008000` and write
   `(saved & 0xfffffe0f) | 0x70`.
4. Set bit 4 of `0x90008014`, set bit 16 of `0x91000004`, run the small
   ten-iteration delay loop, then clear those bits in the reviewed order.
5. Restore the saved `0x90008000`, then poll the receive-side condition.

Each read/modify/write is a separate operation; the model does not collapse
them into atomic writes. On role 0 the token is written after polling, even
when polling times out. Role 1 publishes before waiting. Thus a timeout return
cannot be interpreted as evidence that no notification register was written.

The wait uses a limit of 1000 in the native reader's units. Raw instructions
at `0x80d45464` sample counter high/low/high at `0xe6000004`/`0xe6000000`,
retry on a changed high word, then call a helper with divisor argument 1000.
The helper's wide return signature remains underspecified, so no physical time
unit or measured timeout duration is assigned. The host timeout predicate
models the observed unsigned 64-bit difference only, excluding MMIO/scheduler
timing and the native poll-before-time-check ordering.

## Synchronization, queue suppression and limits

`0x707bf9be` increments a critical-section reference count and disables IRQ
16 only on entry from zero. `0x707bf982` decrements it and enables the IRQ
only when returning to zero. The native paths clear global MIE around the
counter manipulation and set it on exit; they do not visibly restore a saved
MIE value. Caller interrupt-state assumptions need further analysis. The host
counter helper covers balanced nesting with explicit overflow/underflow bounds,
not concurrent callers or global interrupt state.

Queue kick `0x707c0726` can skip notification. Without its event-index feature
branch, used-ring flag bit 0 suppresses a kick. With that branch enabled, the
reviewed predicate is:

```text
notify = num_added > ((available_index - 1 - event_index) & 0xffff)
```

The host model retains the 16-bit arithmetic, including index wrap. The native
successful/suppressed path clears `num_added`; kick failure returns earlier.
No retry scheduler, fairness or interrupt-race behavior is inferred.

The ordering hooks at `0x707bf66c`, `0x707bf672`, `0x707bf678` are independently
checked as bytes `0f1000008280`: `fence.i` followed by return. The reviewed
address-conversion body remains an empty return. No complete data-cache
clean/invalidate or coherency mechanism has been recovered from these selected
hooks. Shared-memory hardware behavior remains an open driver prerequisite.

## Exports and reproduction

The corrected BBS Ghidra installation is now retained in ignored
`firmware/tools/ghidra_12.1.2_PUBLIC/`, with its verified official archive.
This avoids depending on a temporary installation across sessions. The
existing original-export evidence files were preserved.

The main pass first exported 24 targets without volatile I/O to
`runtime-rpmsg-doorbell`, then 26 with `MarkIpcMmio.java` to
`runtime-rpmsg-mmio`. It uses `DecompileWithAbi.java` and the existing fresh
main project. The sensor pass imports its startup-aware ELF into fresh
`firmware/ghidra-bbs/sensor-bbs`, runs `MarkIpcMmio.java sensor`, then
`DecompileWithLogger.java output-directory 0x80f86d34 targets...` for ten
targets. The selected sensor entries have ordinary stack prologues; this
exporter supplies logger return metadata, not main-image save/restore fixups.
The large inlined sensor exception path is outside the reviewed contract.

```sh
python3 analysis_scripts/ipc_doorbell.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled \
  --language firmware/tools/ghidra_12.1.2_PUBLIC/Ghidra/Processors/RISCV/data/languages \
  > analysis/ipc-doorbell.json
python3 -m unittest discover -s tests -p 'test_ipc_doorbell.py' -v
```

Targets are enumerated in `ipc_doorbell.py:TARGETS/SENSOR_TARGETS`. Private
logs are `firmware/ghidra-{rpmsg-doorbell,rpmsg-mmio,sensor-doorbell}-stdout.log`.
The [JSON](ipc-doorbell.json) fingerprints 38 selected files: two baseline
exports, 26 volatile main exports and ten sensor exports. It checks that both
volatile wake routines retain two mode-register writes, that the exception
echo is present, that role bytes match and that all three ordering hooks match.

Nine new tests cover both role routes, exception ordering, index/IRQ-bank
bounds, nesting, notification suppression and rollover, and timeout boundaries.
All 234 Python tests pass with signature/cipher dependencies. JSON regeneration
is byte-identical. Host models and successful decompilation do not establish
live interrupts, power transitions or standalone driver operation.
