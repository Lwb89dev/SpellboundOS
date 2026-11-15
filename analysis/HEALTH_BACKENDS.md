# Sensor availability policy and health data paths

Follow-up: [NATIVE_REPAIR.md](NATIVE_REPAIR.md) records the corrected targeted
pass, including the recovered glucose-record write path and HR array loop.
The references below to truncated broad exports describe their original state.

This continues [SENSOR_CLASSES.md](SENSOR_CLASSES.md) using the original main
image, local exports and targeted LLVM instruction inspection. It distinguishes
API policy, cached values and service calls from physical sensor detection.

## All six availability callbacks

Define `service` as the boolean from `0x70444220`, `authority` as the signed
value from `0x704445f2`, and `type` as the byte from `0x704445bc`.
The first helper looks up the current application and tests type 7; its log
names this a service check. The authority helper returns a context field at
offset `0x10`, with `-1` on a missing context. The type helper returns `0xff`
when lookup fails. These are inferred application-context semantics, not a
fully recovered permission specification.

Let `A = !service || authority > 0` and `T = type != 3 && type != 4`.
The bounded availability paths are:

| Class | Callback | Observed condition |
| --- | --- | --- |
| `compass` | `0x7045771e` | `A && T` |
| `gps` | `0x70458498` | `A && T && capability(18)` |
| `gyro` | `0x70459bc6` | `A && T && capability(2)` |
| `acc` | `0x704562de` | `A && T && capability(1)` |
| `sound` | `0x7045d856` | `A` |
| `glucose` | `0x70456ba2` | Always true (`LI a0,1; RET`) |

`T` comes from `0x7045cb38`, whose unsigned-byte comparison rejects only 3
and 4. A missing application's `0xff` type therefore passes this particular
test; the surrounding runtime and other gates still matter.

The motion/GPS capability wrappers (`0x702db9ee`, `0x702db9f8`, `0x702dba02`)
tail-call `0x704c6cc4` with constants 1, 2 and 18. Its export identifies a
thunk to `0x701e3562`: depending on another state check, that function either
returns true or queries `0x70722c98`. The query accepts IDs 1–35 and tests a
byte in a writable capability table around `0x70fd6079`. This is another
software state gate, not a mandatory bus identity transaction.

Combined with the common `checkAvailable` registry lookup, these results show
why API availability must not be treated as a hardware inventory. In
particular, the glucose callback is unconditionally positive even though the
class exposes record-management methods. Its data-source/persistence path
still needs instruction-level recovery after the false logger boundaries.

## Heart-rate getters

The class-specific getter `0x7045a85a` selects by magic value:

| Property | Selector | Observed path |
| --- | --- | --- |
| `last` | `0x0d01` | `0x703d4752` -> `0x7022bf16` -> last-value service |
| `current` | `0x0d02` | Cached byte at `*(0x70fbc57c) + 0x0c` |
| `today` | `0x0d03` | Array-building path via `0x7045a7b2` / `0x703d47c6`; logger-truncated |
| `rest` | `0x0d04` | `0x703d46c2` -> `0x7022beb2` |

The last-value service context is acquired through `0x7022ccd6`; its export
shows lazy allocation and the state pointer `0x70f8e2ac`. The downstream
`0x7022d83e` mentions continuous and historical values, time conversion and
selection. It is truncated at logs and affected by the save/restore ABI
described in [COMPILER_ABI.md](COMPILER_ABI.md). Treat its inferred types and
argument relationships as unresolved until the caller's register flow is
checked. It does not expose a direct PPG register read at the JS getter layer.

The `getMaxRecord` wrapper `0x7045a1a4` obtains data from `0x703d488e` and
builds a JS object with time, zone and HR fields. The AFib wrapper at
`0x70459d66` has no export in the current corpus. These names alone do not
establish AFib functionality on the target.

## SpO2 cache and events

Getter `0x7045ddbc` uses state pointer `0x70fbc7bc`:

| Property | Selector | Cached/service source |
| --- | --- | --- |
| `current` | `0x1701` | Unsigned byte at state `+4` |
| `time` | `0x1702` | Word at state `+0` |
| `retcode` | `0x1703` | Word at state `+8` |
| `hourAvgOfDay` | `0x1704` | `0x703d5a86`; array path logger-truncated |

Registration calls `0x703d5950(2, 0x7045df78)`. The ABI-corrected instruction
path saves those incoming arguments, acquires the SpO2 context and passes the
arguments to `0x70248048`. The original C export instead incorrectly derives
them from the register-save helper's alleged return value.

Event callback `0x7045df78` reads an event code at input `+4` and a payload
pointer at input `+0x10`. For code 1 it accepts a changed byte value in the
unsigned range 70–100, copies its accompanying word and byte into the cache,
sets cached status 1 and emits a sensor event through `0x7045c990`. Code 2 can
copy the same payload, sets status 2 and can invoke the stop path. Other
handled codes clear the cached value/time and store the event code as status.
Those are software status numbers; their full semantic names remain unknown.

Start candidate `0x7045e036` calls `0x703d59a4` and sets state byte `+0x0c`.
Stop candidate `0x7045df5c` calls `0x703d59d8` and clears it. Last-record wrapper
`0x7045e05e` calls `0x703d5a0a`, whose raw instructions preserve its output
pointer correctly despite a broken broad signature. No complete IPC or
sensor-hub-to-main measurement pipeline has yet been recovered.

## Evidence and reproduction

The main-image member hash is
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.
Function addresses above locate the corresponding private C exports. For
missing or suspect functions, prepare the zero-based ELF as documented in
[SENSOR_CLASSES.md](SENSOR_CLASSES.md) and inspect these file-offset ranges:

| Path | Start | Exclusive end |
| --- | --- | --- |
| Compass callback | `0x2f771e` | `0x2f7758` |
| Gyro callback | `0x2f9bc6` | `0x2f9c0a` |
| Accelerometer callback | `0x2f62de` | `0x2f6322` |
| Glucose callback | `0x2f6ba2` | `0x2f6ba6` |
| Sound callback | `0x2fd856` | `0x2fd882` |
| Capability wrappers | `0x17b9ee` | `0x17ba0c` |
| Last-HR wrapper | `0x274752` | `0x274772` |
| SpO2 last-record wrapper | `0x275a0a` | `0x275a32` |

Use `llvm-objdump -D --start-address=... --stop-address=... --mattr=+c
firmware/main-disassembly.elf`. Add `0x70160000` to displayed offsets.
The six callback assignments are reproducible through `sensor_classes.py`;
the policy interpretation is a manual analysis, not a generated theorem or a
runtime/device test. The underlying optical driver is now separately mapped
in [PPG_AND_SENSOR_MEMORY.md](PPG_AND_SENSOR_MEMORY.md).
