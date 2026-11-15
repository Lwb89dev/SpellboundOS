# Native sensor classes and their registration

Static investigation on 2026-11-15 of Bip 6 OTA 4.6.0.3, main-member SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.
The inspector [`sensor_classes.py`](../analysis_scripts/sensor_classes.py)
combines original OTA descriptor bytes with explicit constant assignments and
calls in the existing local Ghidra exports. Neither input is executed. Its
output is [sensor-classes.json](sensor-classes.json).

## What is registered

The `hmSensor` constructor `0x7045c8dc` calls dispatcher `0x7045cb54`, which
contains 28 direct registration-function calls. Each calls the common registrar
`0x7045c792` with a writable state structure and a read-only class descriptor.
The recovered classes have 159 class-specific property entries in total:

| ID | Native class name | Property entries |
| ---: | --- | ---: |
| 18 | `activity` | 1 |
| 10 | `battery` | 4 |
| 11 | `step` | 2 |
| 12 | `calorie` | 2 |
| 15 | `distance` | 1 |
| 26 | `time` | 19 |
| 13 | `heart` | 7 |
| 14 | `pai` | 10 |
| 22 | `stress` | 8 |
| 19 | `fatburn` | 2 |
| 16 | `stand` | 2 |
| 23 | `spo2` | 6 |
| 27 | `vibrate` | 8 |
| 28 | `wear` | 1 |
| 29 | `worldClock` | 4 |
| 17 | `weather` | 7 |
| 30 | `music` | 8 |
| 31 | `sleep` | 9 |
| 32 | `sport` | 20 |
| 34 | `baro` | 2 |
| 35 | `fatigue` | 1 |
| 36 | `compass` | 6 |
| 37 | `gps` | 10 |
| 38 | `gyro` | 4 |
| 39 | `acc` | 4 |
| 40 | `jsScreen` | 5 |
| 42 | `sound` | 2 |
| 44 | `glucose` | 4 |

These are candidate runtime registrations, not measured hardware capabilities.
The dispatcher includes calls without explicit arguments in some decompiled
lines, although the callee signatures expect a context; inferred prototypes
are one limitation of the bulk exports. Allocation failures can prevent a
registration, and there is no device-side confirmation of successful startup.

## Descriptor and shared prototype

The registrar's uses of its third argument support this 40-byte descriptor:

| Byte offset | Observed use |
| ---: | --- |
| `0x00` | Pointer to the class-name string |
| `0x04` | Cleanup/finalizer candidate, copied into the state structure |
| `0x14` | Class-specific QuickJS property table pointer |
| `0x18` | Exact property-table entry count |
| `0x1c` | Additional list/record storage pointer |
| `0x20` | Number of records inserted into a state-linked list |
| `0x24` | Callback passed to the candidate QuickJS C constructor helper |

Fields `0x08` through `0x10` remain unclassified. The JSON retains the name,
constructor, cleanup callback, exact property tables and nested constants, plus
the writable-state and registration-function addresses. IDs come from explicit
assignments to state offset `+8` in the corresponding C export; class names and
properties come from the binary descriptor rather than guessed string labels.

The common registrar installs each class-specific table, followed by seven
shared entries from `0x70be5000`: `start`, `stop`, `period`,
`addEventListener`, `removeEventListener`, `checkAvailable`, and `toString`.
It links the resulting class into the registry rooted at `0x70fbc698`.
The factory `createSensor` (`0x7045bf06`) searches that registry by ID and
maintains per-app instance records. Its broad pseudocode is truncated by the
same false non-returning logger seen in earlier reports; it is not a complete
factory implementation.

## Enumeration is broader than registration

The initializer `0x7045bc20` calls `0x7045cc08`, which exports `id`, `event`
and `freq_mode` from table `0x70be50c0`. The `id` child table contains 36
symbols for 35 distinct numbers: `FAT_BURRING` and `FAT_BURNING` alias ID 19.
Seven IDs have no registration in the examined dispatcher:

| ID | Public symbol |
| ---: | --- |
| 20 | `SUN` |
| 21 | `WIND` |
| 24 | `BODY_TEMP` |
| 25 | `PRESS` |
| 33 | `BPRESSURE` |
| 41 | `BODY_COMPOSITION` |
| 43 | `BUZZER` |

This is an absence in the inspected dispatch path, not proof that those IDs
cannot be registered elsewhere. Conversely, the existence of a class does not
prove physical sensing: `glucose` exposes `addRecord`, `getRecords`,
`getLastRecord` and `event`. Its add-record wrapper (`0x70456dce`) reads a value
argument and contains an `mmol/L` log string. That supports a glucose-data
interface, not an on-watch glucose sensor. The broad export truncates at log
calls, so the persistence and data source remain unresolved.

`heart` exposes `last`, `current`, `today`, `rest`, event constants and record
queries; `spo2` exposes `current`, `time`, `retcode`, `hourAvgOfDay` and record
queries. Their magic getter selectors include respectively `0x0d01`–`0x0d04`
and `0x1701`–`0x1704`. These are useful next entry points to health backends;
they do not identify the PPG analog front end.

## Reproduction and validation

```sh
python3 analysis_scripts/sensor_classes.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/main > analysis/sensor-classes.json
python3 -m unittest discover -s tests -p 'test_sensor_classes.py' -v
```

The JSON includes SHA-256 hashes of every consumed C source text. Original
exports stay under ignored `firmware/`. Eight synthetic-fixture tests cover
registration/descriptor joins, nested getter and constant tables, aliases,
missing or duplicate IDs, malformed pointers/counts and cycles. The full suite
passes 78 tests with the existing signature dependencies available. The JSON
regenerates byte-for-byte from the local archive and exports.

The parser deliberately accepts the observed Ghidra syntax and fails on
unresolved registration calls. It does not reconstruct missing exports or
repair inferred prototypes/control flow. BLE's initializer directly installs
its previously mapped 50-entry export table; deeper BLE callback behavior
remains a separate target.

## Targeted availability disassembly

Although `checkAvailable` at `0x7045c43c` has no C file in this corpus, its
instructions through `0x7045c4c0` decode using ordinary RV32 instructions.
They check the argument count, convert an ID, reject an unsigned ID above 44,
call the app-context helper, and search the registry at `0x70fbc698` for a
matching state `+8` ID. A missing entry returns false. A matching entry loads
a callback from state `+0x40`: a null pointer takes the true-return path;
otherwise an indirect call determines the boolean result. The returned
`a1 = 1` tag is consistent with a QuickJS boolean.

Thus availability is registry membership plus an optional callback, rather
than a mandatory hardware probe. The class registration exports explicitly
assign such callbacks for six classes: `compass` (`0x7045771e`), `gps`
(`0x70458498`), `gyro` (`0x70459bc6`), `acc` (`0x704562de`), `sound`
(`0x7045d856`), and `glucose` (`0x70456ba2`). The JSON records these assignments;
no assignment found is recorded as unknown, not as a proven null pointer.
Callback behavior and initial writable-state contents need separate analysis.

To reproduce this bounded instruction inspection with LLVM, use the extracted
main image (file offset zero mapped to `0x70160000`):

```sh
llvm-objcopy -I binary -O elf32-littleriscv -B riscv32 \
  firmware/firmware-main.bin firmware/main-disassembly.elf
llvm-objdump -D --start-address=0x2fc43c --stop-address=0x2fc4c2 \
  --mattr=+c firmware/main-disassembly.elf
```

The ELF has zero-based section addresses; add `0x70160000` to the displayed
offsets. The original image hash must match the member hash above. This is
manual static interpretation, not an emulation or device observation.
