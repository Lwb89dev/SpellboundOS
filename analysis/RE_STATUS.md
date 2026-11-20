# Reverse-engineering status and completion criteria

The investigation covers OTA 4.6.0.3 and one live Gadgetbridge/Bip 6 protocol
session. It is not a complete physical flash/ROM dump or native execution trace.
Completion has no measured percentage: disassembly/export and test counts do not
measure behavioral coverage. At the user's request, the rough qualitative planning
estimate, reviewed for the Claude handoff on 2026-11-19, remains **50–60% of the
reverse engineering needed for the project**, with roughly **40–50% remaining**
and substantial uncertainty. It is a subjective assessment of scope,
not a coverage metric or a basis for estimating remaining time. Hardware
validation, complete pairing and restoration/standalone boot remain major gates.

The 2026-11-19 checkpoint recorded analysis baseline `3685f79` with 2,112 passing
host tests; later entries in [PROGRESS.md](../PROGRESS.md) extend it. This
percentage describes RE scope, not OS implementation progress.

Completion still depends on four broad work areas:

- Finish the required algorithm/application contracts, including supported sensor
  inputs, activation, error handling and remaining consumers.
- Close pairing/authentication, transport lifetimes and the required Bluetooth
  application behavior with runtime evidence.
- Verify necessary drivers, electrical/timing assumptions and peripheral firmware
  behavior on the actual hardware.
- Establish safe backup, device-specific restoration and a viable standalone
  boot path through the signed chain. This is still a major feasibility gate.

These areas are not four fixed-size tasks or a time estimate. The current state
remains targeted contract reconstruction/verification; final device integration
requires evidence beyond OTA analysis and emulator case counts.

| Area | Current evidence | Still needed to close the area |
| --- | --- | --- |
| Package integrity / signatures | Hashes/signatures plus variable-length metadata and raw-recovery validator path; manifest fully verified and the `res_info` mismatch explained (it embeds the manifest's own digest); `fw_info` sizes/CRC-32 match | Observe device enforcement, update-script interpreter and rollback policy |
| Main/sensor startup | Copy/zero tables reconstructed; startup-aware analysis ELFs; main kernel identified as FreeRTOS; 57 native trap-entry/frame/C-handler/core-and-PLIC-dispatch/PLIC-API/timer/exception/syscall/first-task cases with 23 recovered interrupt registrations (18 far calls, 5 direct RAM calls), including four DMA controllers on one handler; 61 native FreeRTOS tick/switch/timer-setup/run-time/stack-init/static-creation/critical-section cases, also joined to the original trap entry and scheduler start; 13 native power-management wake-gate/re-registration/handler/clock-poke cases, with the deep-sleep save/restore twins recorded statically; 18 native GPIO pad-mux/dispatcher/shared-handler cases, including the shared handler's tail call into the per-pin dispatcher; 13 native GPIO pull/drive-writer and interrupt-enable/commit cases over the same callback table; 12 native GPIO interrupt-registration cases completing the register/enable/dispatch chain | Validate full boot context, aliases, memory protection, retained/device data |
| Native corpus | Guarded BBS and two Andes DSP semantics, ABI/logger fixes, targeted main/sensor exports; volatile MMIO/CSR metadata; wide division helper checked in 52,294 host executions | Audit remaining affected exports and unsupported DSP forms; runtime/type validation |
| App bytecode | 44 members structurally parsed; QuickJS engine fingerprinted; official C reader agrees on nine header fields for all 1,072 functions | Runtime semantics, operand-level validation and independently implemented host |
| JS/native boundary | Modules, export tables, classes and initializer ownership mapped | Argument/error contracts, object lifetimes and behavior behind each implementation |
| Optical sensing | MAX8617X driver, board/SPI/chip-select records; clock/flag/divider and polling/error contracts; bus/completion/reference paths; initial DMA slots null; native register/polling checks; 45 FIFO/recovery/cache/sample cases; 557 flush/packet/mode-1 cases; 178 reference/listener/cache-queue and mode-2/3 cases; 29 filter/buffer/flush-to-IPC-send cases; eight register-table inventories | Exact fitted part, electrical mode/timing, live bus/IRQ operation, dynamic DMA bindings/ownership guarantees, remaining consumer modes and concurrency, complete allocator/receiver/event/transport operation, calibration and measurement chain |
| Health data | Heart/SpO2 caches/services; sensor/zrpc framing and queues; interrupt/wake route; clock formulas; counter/1000 conversion; distinct main/sensor periodic intervals and suspension conversions; 90 native timer/AON/dispatch cases; phase-aware IPC timeout; selected cache commands/transfer callers and shared-address guard; filtering/cache event through opcode-0x15 send callback; 66 main/sensor decoder, receive/reconstruction/listener-ownership and bounded malformed-record cases; 40 main cache registration, retained engine event, fanout and actual HR-consumer/output-policy cases with supplied algorithm results; 48 actual algorithm registration/lifetime/HR-adapter/configuration cases; 21 HR outer workspace/free/restart, unsupported-type reset and extension-view cases; 37 actual setup/component allocation/nested-cleanup and 89-request owner cases | Remaining application consumers/registration and real engine activation/mask transitions; algorithm-0x100d initializer 0x708a4818 and other secondary allocation failures, supported signal normalization/math and extension consumers, HR motion/minute/reset/wear branches; event/transport/IRQ/vring lifetimes and operation, complete malformed-input/producer constraints, physical timer/cache/coherency, counter continuity across power states, complete sleep state machine, exact-multiple device case, remaining payloads and measurement validation |
| Motion / other peripherals | CW6305 charger register contract (38 native cases: I2C 0x0b, charge enable, 10–470 mA current code, power off, safety timer, IRQ/status, 11-register init table with retries); Candidate identities and selected probe paths; 12 native LSM6DSO cases executing init/probe, CTRL3_C reset, WHO_AM_I and the SPI read/write callbacks with captured bit-7 read framing; 11 native attach cases over the real board record (sens_spi1_dev0 at 8 MHz, IRQ pin 43, ODR trim, sensor registration) and the decoded hub board-record table; 95-case native sweep of all 26 register accessors; 26 native enable/disable cases recovering the applied configuration (±8 g, 2000 dps, HP/ULP/normal power, 26–833 Hz ODR/batch, continuous FIFO); 28 native FIFO-drain cases (0xf8 bulk tagged read, 160-word cache, packet header/timestamp, decoder, 8-entry orientation remap and wrist flip) | Complete configuration, interrupts, power/timing and physical verification |
| Bluetooth | Static builder/auth/curve models; all 62 announced modules matched; 103 initial transfers/69 AES checks; synthetic notification fields matched on the link and app-logo exchange observed; native reply/action serializers; selected notification listener/queue/store route followed to `NotificationNotifyScreen` request | Full GATT/handle coverage, fresh pairing/key derivation, counter persistence, remaining payloads/JS linkage, actual notification rendering/replies/actions, special storage/rich formats, Roadstr handoff and call/audio behavior |
| GNSS / touch | Container sections, candidate code and identity clues; 29 native ZTW622 cases executing the I2C register layer (0x20, 16-bit registers, reset-and-retry) and the report handler (point status 0x0080, rotation/flip, large-object, wake gesture 0x0126, clear-interrupt 0x0003); 23 native attach/probe, rail, reset, mode and version cases (vddd then vdda power-up, GPIO reset timing, 0x09d2 info block, chip id 0xe622) | Full mappings, loader/command protocols, runtime integration |
| Boot/debug/recovery | Startup-aware boot/recovery inputs; reset/handoff split and key/UI paths; 62 validation and 64 selection/counter/handoff native cases; one matched entry reaches startup +0x22c; environment wrappers, reason/key policy and upgrade record; KV40/cache/scan/reservation/tail-space contracts; 35 GC/default, 34 environment-init/reserve-copy, 52 handle/NVMS/bootstrap, 32 registry/lazy-EFTL, 24 translation/read, 27 OOB scan, 38 initializer/heap, 58 NAND dispatch/OOB and 60 original candidate-probe/root/layout cases; 51 QSPI platform/command/ROM-policy/busy-loop cases with supplied HAL and emulated MMIO; 77 page/program/copy/OOB/erase cases with actual busy loops and supplied remap/command/feature services; 58 BBT/CRC/resume/remap and 21 connected actual-remapping/page cases with supplied storage/command services; 86 retry/UID/command/busy/ioctl cases over a supplied bus; 90 actual QSPI HAL/FIFO/DMA-wrapper/clock and connected NAND-command cases with authored MMIO/timer/DMA services; 60 actual DMA init/setup/wait/cancel/count/IRQ cases over authored MMIO/cache/timer/callback services; 28 connected actual QSPI/backend/private-buffer NAND cases with authored peripheral/cache/copy/timer inputs; 47 actual pin/platform-init/original-DMA-link/reinitialization cases over authored peripherals; 31 connected actual page-read/BBT/status-FIFO/platform/QSPI/DMA cases including full busy timeouts; 27 connected actual page-program/guard/cache/program/status/FIFO/DMA cases including wrapping-column and full-timeout behavior; 64 connected actual erase/copy/OOB/mapping/guard/platform/bus/FIFO cases including complete two-phase copy/erase timeouts; 67 connected supported-family retry/setter/reset/page-recovery/UID/ioctl/platform/bus/FIFO cases with selected DMA recovery; 39 connected partition/callback/context/mutex/ioctl/erase/OOB/read cases through actual lower stack; 32 ready EFTL mapped/page/OOB/cross-page/gap cases through actual NAND/QSPI/DMA; 24 registered nvms/envbak/recovery bounds/read cases through original EFTL callback and lower NAND/QSPI stack; 36 upper program/logical-erase/rewrite/full-page/OOB/free-block/flag cases through original NAND/QSPI/TX DMA; 16 enabled readback/checksum/publication cases with conditional wrong-logical-record acceptance; 22 bad-mark/erase-reselect/zero-prefix-relocation/allocator-failure cases through original NAND/QSPI; 20 one/two-page prefix-migration/heap-lifetime/recursive-repair cases with authored full-page cache inputs; 20 combined prefix-repair/enabled-readback/repeated-relocation cases tracing OOB scratch reuse and retained publication after failed checks; 22 original map-scan/three-page-marker/OOB/erase cases through NAND/BBT/QSPI with authored FIFO records; 23 connected lookup/geometry/initializer/format/scan/retry/lazy-readiness cases over an authored eight-block NAND partition, including ready publication with zero capacity and retained readiness after forced eager scan failure; 26 connected eleven-candidate platform/ID/reset/feature probe cases through original QSPI FIFO with authored IDs and supplied auxiliary UID/workaround/BBT; 21 actual BBT verification/CRC/tail scan/backup repair/subsequent-read cases through NAND/QSPI; 12 first-chip probe cases joined to actual BBT recovery and unsupported-family workaround, including ignored real no-table return; 11 first-chip probe/UID/BBT/ioctl cases with real UID acquisition and retained-state export after early errors; 10 candidate-3 probe/reset/E0-level/UID cases with supplied BBT, including successful probe after five unconfirmed level writes; 19 original object-registry lookup/duplicate/list/name/type/lock cases; 14 complete selected NAND root/property/callback/probe/UID/BBT/object-registration cases, including retained unlinked allocation after duplicate rejection and findable device with inactive BBT; 17 original object-open/reference/register-open/ioctl cases; 15 connected registered-NAND open/geometry/context/chip/BBT consumer cases, with original object suspend/resume methods returning zero without transfers; 26 main-image open/close/write/ioctl/active cases with authored callbacks and 15 connected original main NAND-method cases with supplied lower geometry queries, including count zero after failed close and unchanged positive count when close callback is missing; 13 actual main context/chip/BBT-active geometry cases over authored original-descriptor/magic/RTOS state; 12 actual main root/wrapper/registry/cache/PM publication cases with supplied probe/BSP/heap/PM services, including late PM assertion after publication; 24 actual main eleven-candidate probe/matcher/ID/reset cases with supplied bus/regulator/feature/UID/workaround/BBT services; 10 connected actual main probe/root/registry/PM/geometry cases, including last-stage publication retained at PM assertion and registered device with inactive BBT; 35 actual main platform/bus/feature-packet cases with supplied HAL/revision/DMA/pin services, including disabled-before-reinit rejection and direct/bounce faults; 25 connected actual main probe/platform/bus/feature/root/geometry cases over all eleven unchanged descriptors, with distinct transport/helper assertions and actual readback mismatch propagation; 89 actual main QSPI HAL/FIFO/count/readiness/completion/DMA-wrapper/clock/revision cases over authored MMIO/timer/ROM/DMA services; 24 connected main bus/feature-to-HAL/FIFO cases, including actual timeout assertions and success with unchanged authored bounce bytes after ignored setup failure; 46 actual main DMA init/setup/cancel/count/wait cases, including unrecognized-base fallback-slot publication over explicit guarded backing; 28 connected actual main QSPI/DMA-backend and NAND bounce-packet cases with authored MMIO/timers and supplied cache/copy services, including alternate-success tracking retention and separate wait budgets; eight actual main platform/clock/QSPI/DMA-initialization cases using original adjacent record addresses and startup-zero facts; 14 connected main platform/backend/bounce-transfer cases including repeated initialization and disabled-before-reinit ordering, with pin/GPIO/cache/copy services and peripheral inputs supplied; 15 joined original main probe/root/platform/clock/FIFO/revision/DMA-init/object-consumer cases over all eleven unchanged descriptors, with auxiliary UID/BBT and BSP/power services supplied; 12 full main retry/failure cases including last-33rd match, no-match, actual HAL timeout assertions and retained FIFO feature state; eight actual main family/reset/E0-level workaround cases inside probe, including ignored unsupported return and success after five unconfirmed writes; 14 actual main UID setup/load/busy/cache/complement cases inside the platform/FIFO/root chain, including retained prior state, no valid copy, post-FIFO timeout state and registration despite handled UID errors, with BBT still supplied; 16 actual main context/chip UID-export cases, including retained state after acquisition errors and copied output before release assertion; 18 actual main BBT verifier/resume/CRC cases inside first-chip probe/UID/root/geometry/export with supplied page/marker services, including active RAM table after repair errors and ignored no-table return; 20 actual main block/page remapping cases over recovered BBT state, including retained output, malformed lists and unsigned wrap; 23 actual main mapped-page/load/status/direct-x4-cache/FIFO cases, including ECC error after delivery, exact/wrapping column bounds, timeout-retained bytes and per-operation snapshots, with recovery page callbacks still supplied; 14 actual main recovery record-read/remap/load/status/direct-cache/FIFO cases before CRC, including ECC-delivered reread data and skipped repair; 13 original main three-page marker/tail-selection cases through actual reader/FIFO, including final reserved pair and transient ECC producing backup without primary, with repair erase/write still supplied; 11 actual main repair-erase/remap/enable/command/status/QSPI cases, including active RAM table after returned erase failure; 13 connected actual main repair-program/direct-cache/execute/status/TX-FIFO cases, including exact 140-byte backup payload, returned failure versus stopped transport and no primary readback; five full main read-busy cases with 2000 actual status/FIFO polls, last-poll ready/ECC discard and CRC acceptance after busy exhaustion; six full main repair-busy cases with 4000 erase/2000 program polls, penultimate/last-ready distinctions and active RAM recovery after caller errors, using counted exact trace hashes; 16 actual main mode-zero mapped-page/private-buffer-DMA cases over original initialized RX records, including direct/DMA length and ROM thresholds, alternate completion tracking retention, retained-byte copying without modeled DMA movement and assertions after root publication; 14 actual main mode-zero erase/guard/sleep-poll cases, including ignored twentieth ready status and successful nineteenth ready status, with supplied sleep services; 26 actual main mode-zero program/guard/cache/TX-DMA/execute/status cases over original initialized TX records, including retained staging before failed transfers, no fabricated DMA FIFO writes, actual direct payloads and unsigned column wrap; 26 original main IRQ ordinary-call cases with primary/alternate callback ordering, linked/nonlinked cleanup and fallback-bank dispatch over guarded backing; 72 backend/IRQ cases executing actual signed cache entry guards, plus 16 full recovered NAND read and 26 program cases with those guards, identical preceding observations and two extra executed instructions per cache call; 43 original positive-address cache command/control/feedback cases with authored CSR readbacks, backward/zero-length/wrapped-end behavior and marked nonreturning command bounds; 22 original main critical/context/diagnostic cases over authored thread/RTOS state, including depth wrap, output-cookie/argument behavior and MIE transitions that differ from saved-bit restoration; original five-backend/16-partition and independently extracted main/boot 11-chip tables; ROM default `boots=0` | Physical non-destructive entry, complete page/ECC/board integration, physical pin mapping and live DMA/IRQ/cache coherency, remaining board/regulator services, broader storage callers/partitions, broader registry/startup, initial BBT creation and broader chip/BBT geometry integration, repeated failing initialization with distinct heap generations and persistent map reconstruction, larger prefix migration, further readback/recursive-repair branches and complete repair atomicity, remaining retry/UID consumers and complete concurrency/coherency, BBT provenance/creation and repair atomicity, physical retry/UID and remaining consumers, physical chip/geometry/OOB metadata corroboration, broader main close callers and object removal/reclamation/concurrency, lower NAND page/ECC/DMA behavior, alternate format, SFTL and mapping repair/write paths, physical partition map and rewrite/mutex behavior, reserve-image provenance and factory data, malformed/stale-cache/concurrency/boundary-read paths and real persistence, subsequent boot/recovery/UI dispatch, physical reason/gesture behavior, startup/device enforcement, device-specific restoration and standalone boot |
| Standalone OS / companion | Independent QEMU UART prototype; project goal recorded | Hardware boot/drivers, secure transport, Android implementation and device tests |

The remaining native work now has a concrete prerequisite: use the corrected
startup mappings and account for compiler save/restore effects before trusting
new decompilation. See [MAIN_MEMORY.md](MAIN_MEMORY.md) and
[COMPILER_ABI.md](COMPILER_ABI.md). The original temporary Ghidra installation
was absent; Ghidra 12.1.2 has now been reacquired from its official release with
checksum verification. A fresh startup-aware project and a 12-function
ABI/logger-corrected pass are recorded in [NATIVE_REPAIR.md](NATIVE_REPAIR.md).
Broad corpus regeneration remains open.

Continue offline with the optical initialization/FIFO and health IPC paths,
then Bluetooth pairing/transport and boot/recovery. An actual end-to-end
completion claim additionally requires runtime and hardware evidence. Static
OTA analysis alone cannot establish physical pinout, recovery reliability,
measurement accuracy or successful standalone boot.

Latest detailed findings:

- [Sensor availability and health backends](HEALTH_BACKENDS.md)
- [Optical driver and sensor RAM](PPG_AND_SENSOR_MEMORY.md)
- [Main RAM code and analysis ELFs](MAIN_MEMORY.md)
- [Compiler ABI and corpus limitations](COMPILER_ABI.md)
- [Targeted corrected native exports](NATIVE_REPAIR.md)
- [Optical FIFO and initial sensor IPC payloads](PPG_FIFO_AND_IPC.md)
- [Sensor zrpc packet headers, CRC and rpmsg boundary](ZRPC_PACKETS.md)
- [AndeStar branch defect, fragment termination and shared-memory pools](ZRPC_BRANCHES_AND_MEMORY.md)
- [Corrected native IPC exports, rpmsg queues and host fragments](RPMSG_NATIVE_AND_FRAGMENTS.md)
- [IPC interrupt, volatile MMIO and notification control](IPC_DOORBELL_AND_MMIO.md)
- [Wide clock readers, CPU frequency formulas and cache range contracts](CLOCK_AND_CACHE_CONTRACTS.md)
- [Andes DSP repair, native division execution and timer scaling](TIMER_ARITHMETIC.md)
- [Main/sensor periodic timers, counter consistency and suspension](RTOS_TIMER_AND_SUSPEND.md)
- [Optical SPI binding, controller configuration and timeout/delay contracts](OPTICAL_SPI_AND_TIMING.md)
- [SPI bus ownership, initial DMA slots, completion and references](SPI_OWNERSHIP_AND_COMPLETION.md)
- [Native optical register transactions with synthetic peripheral inputs](SPI_REGISTER_NATIVE_EXECUTION.md)
- [Native FIFO faults, recovery notification and cache/sample primitives](PPG_FIFO_LIFECYCLE.md)
- [Coordinated sensor flush, native packet pointers and mode-1 optical consumer](SENSOR_FLUSH_AND_PACKETS.md)
- [Packet lifetime, listener delivery, cache queue and optical modes 2/3](SENSOR_DELIVERY_AND_MODES.md)
- [Cache filtering, packed-buffer flush, event ownership and opcode-21 IPC send](CACHE_FILTER_FLUSH_AND_IPC.md)
- [Main/sensor cache receiving, listener ownership and malformed-record boundaries](CACHE_RECEIVER_AND_OWNERSHIP.md)
- [Main cache registration, retained engine events and native HR result policy](ENGINE_CACHE_AND_HR_POLICY.md)
- [Actual HR algorithm registration, reference ownership, dispatch and configuration](ALGORITHM_MANAGER_AND_HR_ADAPTER.md)
- [HR outer workspace allocation/free/restart and borrowed extension views](HR_WORKSPACE_AND_EXTENSION.md)
- [Actual HR setup, component allocation/reset and nested cleanup](HR_SETUP_AND_NESTED_CLEANUP.md)
- [Boot/recovery control flow and signed metadata](BOOT_RECOVERY_AND_METADATA.md)
- [Bootloader main-firmware load, signature gate and handoff](MAIN_BOOT_GATE.md)
- [Bootloader recovery-entry gate and boot manager decision](MAIN_RECOVERY_GATE.md)
- [ICNA3311 display panel: DCS read-id, probe and command-table player](MAIN_DISPLAY_PANEL.md)
- [ICNA3311 display bring-up and real panel init tables](MAIN_DISPLAY_INIT.md)
- [Sensor-hub LSM6DSO probe, reset and SPI register framing](SENSORHUB_IMU_PROBE.md)
- [Sensor-hub LSM6DSO attach and the hub board records](SENSORHUB_IMU_INIT.md)
- [Sensor-hub LSM6DSO register accessors: native sweep](SENSORHUB_IMU_REGS.md)
- [Sensor-hub LSM6DSO enable/disable: the applied configuration](SENSORHUB_IMU_MODE.md)
- [Sensor-hub LSM6DSO FIFO read, packet and orientation remap](SENSORHUB_IMU_FIFO.md)
- [ZTW622 touch: I2C register layer and touch report handler](MAIN_TOUCH_REPORT.md)
- [Main-image board records: the hardware map](MAIN_BOARD_RECORDS.md)
- [ZTW622 touch control: attach/probe, rails, reset, modes and version](MAIN_TOUCH_CONTROL.md)
- [CW6305 charger: register layer and controls](MAIN_CHARGER_CW6305.md)
- [Native recovery CRC, metadata policy, signed coverage and partition validation](RECOVERY_VALIDATOR_NATIVE.md)
- [Storage registry, environment handle setup, NVMS mirrors and stopped bootstrap](ENV_STORAGE_SETUP_AND_NVMS.md)
- [Original boot partition tables, backend geometry words and actual driver bindings](STORAGE_MAP_AND_DRIVER_BINDINGS.md)
- [Native original registry population, owner failure paths and lazy EFTL geometry](STORAGE_REGISTRY_AND_LAZY_EFTL.md)
- [Native EFTL logical translation and generic/alternate page-read routes](EFTL_TRANSLATION_AND_PAGE_READ.md)
- [Native EFTL OOB checksum, mapping reconstruction, flags and retry signal](EFTL_OOB_MAPPING_RESUME.md)
- [Connected EFTL initializer, supplied geometry collection, heap lifetime and format/retry](EFTL_INITIALIZATION_AND_GEOMETRY.md)
- [Native NAND partition lookup, driver ioctls/read dispatch and EFTL OOB serialization](NAND_PARTITIONS_AND_OOB.md)
- [Original NAND chip candidates, native probe/ID/reset, mutex and driver-root setup](NAND_PROBE_AND_CHIP_TABLE.md)
- [NAND QSPI platform, command conversion, ROM policy and busy deadlines](NAND_BUS_AND_COMMANDS.md)
- [NAND page/program/copy/erase policy and connected busy-timeout consequences](NAND_PAGE_POLICY.md)
- [NAND BBT verification/resume, malformed tables and connected page remapping](NAND_BBT_AND_MAPPING.md)
- [NAND retry levels, UID acquisition, error state and connected ioctl export](NAND_RETRY_AND_UID.md)
- [QSPI HAL, FIFO/DMA-wrapper/timeout policy and connected NAND commands](QSPI_HAL_AND_FIFO.md)
- [DMA initialization/setup/wait/cancel, registry and IRQ dispatch](DMA_BACKEND_AND_IRQ.md)
- [Connected QSPI/DMA backend, independent wait budgets and NAND private buffer](QSPI_DMA_INTEGRATION.md)
- [Original NAND platform initialization, pin fields and adjacent DMA links](NAND_PLATFORM_AND_PINS.md)
- [Connected NAND page read, BBT, status FIFO and DMA](NAND_READ_STACK.md)
- [Connected NAND page program, mapped guard, FIFO and DMA](NAND_PROGRAM_STACK.md)
- [Connected NAND erase, page copy, OOB patch and two-phase timeouts](NAND_ERASE_COPY_STACK.md)
- [Connected NAND supported-family retry, read recovery, UID FIFO and ioctl](NAND_RETRY_UID_STACK.md)
- [Connected NAND partition, original driver callbacks and RTOS-context wrappers](NAND_DISPATCH_STACK.md)
- [Ready EFTL mapped/page/OOB reads through original NAND/QSPI](EFTL_QSPI_STACK.md)
- [Registered storage read/bounds through ready EFTL and NAND/QSPI](STORAGE_EFTL_STACK.md)
- [Upper storage program/logical erase/rewrite through EFTL and full-page NAND/QSPI](EFTL_MUTATION_STACK.md)
- [Enabled EFTL write readback, checksum and mapping publication](EFTL_READBACK_STACK.md)
- [Original bad marking, erase reselection and zero-prefix EFTL relocation](EFTL_REPAIR_STACK.md)
- [EFTL prefix migration, temporary-buffer lifetime and recursive relocation](EFTL_PREFIX_STACK.md)
- [Combined prefix repair, enabled readback and repeated relocation](EFTL_REPAIR_READBACK.md)
- [EFTL map reconstruction through original NAND marker and OOB reads](EFTL_SCAN_STACK.md)
- [Connected EFTL initialization, geometry and readiness through NAND/QSPI](EFTL_BOOTSTRAP_STACK.md)
- [Original NAND candidate probe, platform and ID/reset/feature QSPI FIFO](NAND_PROBE_STACK.md)
- [BBT recovery, backup repair and subsequent mapped reads through NAND/QSPI](NAND_BBT_STACK.md)
- [Original first-chip probe joined to actual BBT recovery and selected workaround](NAND_PROBE_BBT_STACK.md)
- [Actual UID inside first-chip probe/BBT and subsequent ioctl export](NAND_PROBE_UID_BBT.md)
- [Supported-family reset, E0-level and UID inside original candidate probe](NAND_PROBE_AUX.md)
- [Original object registry lookup, insertion, name/type boundaries and lock policy](NAND_OBJECT_REGISTRY.md)
- [NAND driver root through actual probe/UID/BBT and object registration](NAND_DRIVER_ROOT_STACK.md)
- [Original object opening, reference counts and ioctl policy](NAND_OBJECT_OPEN.md)
- [Consumers of the registered NAND object and original geometry queries](NAND_OBJECT_CONSUMER.md)
- [Main-image object close, reference and write/ioctl contracts](MAIN_OBJECT_LIFECYCLE.md)
- [Original main NAND methods behind generic object consumers](MAIN_NAND_OBJECT.md)
- [Main NAND geometry through actual context, chip and BBT-active code](MAIN_NAND_QUERY_STACK.md)
- [Main root/registry/cache/PM publication joined to geometry consumers](MAIN_NAND_ROOT_STACK.md)
- [Original main eleven-candidate probe, ID/reset packets and feature policy](MAIN_NAND_PROBE.md)
- [Actual main probe joined to root publication and NAND geometry consumers](MAIN_NAND_PROBE_ROOT.md)
- [Original main bus/platform, disabled/reinit flags and feature packets](MAIN_NAND_BUS.md)
- [Actual main probe/bus/feature path joined to root consumers](MAIN_NAND_BUS_PROBE.md)
- [Original main QSPI HAL, FIFO, DMA wrappers, timer and revision policy](MAIN_QSPI_HAL.md)
- [Main NAND bus and feature builders through actual main HAL/FIFO](MAIN_QSPI_BUS.md)
- [Original main DMA init/setup/cancel/count/wait and registry fallback](MAIN_DMA_BACKEND.md)
- [Main QSPI wrappers and NAND bounce packets through actual DMA backend](MAIN_QSPI_DMA.md)
- [Original main platform initialization and adjacent DMA links](MAIN_NAND_PLATFORM.md)
- [Main NAND platform and reinitialized bounce transfers](MAIN_NAND_PLATFORM_TRANSFER.md)
- [Main candidate probe/root through original platform and QSPI FIFO](MAIN_NAND_FULL_PROBE.md)
- [Main FIFO probe retry rounds, timeout assertions and retained root state](MAIN_NAND_FULL_PROBE_FAULTS.md)
- [Original main family/reset/level workaround inside probe](MAIN_NAND_WORKAROUND.md)
- [Actual main UID acquisition and retained state through FIFO/root](MAIN_NAND_UID.md)
- [Main context/chip UID export, retained bytes and mutex failures](MAIN_NAND_UID_EXPORT.md)
- [Actual main BBT verification/resume/CRC with supplied page services](MAIN_NAND_BBT.md)
- [Main block/page remapping over actual recovered BBT state](MAIN_NAND_BBT_MAPPING.md)
- [Actual main mapped page read through load/status/cache/direct FIFO](MAIN_NAND_PAGE_READ.md)
- [Main recovery record reads through actual NAND/QSPI before CRC](MAIN_NAND_BBT_RECORD_READ.md)
- [Original main tail-marker scan through page/FIFO and transient-error selection](MAIN_NAND_BBT_MARKER_READ.md)
- [Actual main BBT repair erase through enable/command/status/QSPI](MAIN_NAND_BBT_ERASE.md)
- [Original main BBT repair program and exact 140-byte TX FIFO payload](MAIN_NAND_BBT_PROGRAM.md)
- [Complete main read-busy polling, late-ready/ECC discard and BBT acceptance](MAIN_NAND_BUSY_READ.md)
- [Complete main erase/program busy limits and retained active recovery state](MAIN_NAND_BUSY_REPAIR.md)
- [Main mode-zero page reads through original initialized private-buffer DMA](MAIN_NAND_ASYNC_READ.md)
- [Main mode-zero erase guards and complete sleep-poll limit](MAIN_NAND_SLEEP_ERASE.md)
- [Main mode-zero program, original TX DMA staging and post-publication faults](MAIN_NAND_MODE_ZERO_PROGRAM.md)
- [Original main DMA IRQ dispatch, callback ordering and registry fallback](MAIN_DMA_IRQ.md)
- [Actual original cache guards through main DMA/IRQ and recovered NAND RX/TX](MAIN_DMA_CACHE_GUARDS.md)
- [Original positive-address cache CSR loops, wrapped ends and marked bounded stalls](MAIN_CACHE_CSR_RANGES.md)
- [Actual main critical-section depth/MIE, context wrappers and diagnostic state](MAIN_RTOS_CRITICAL_SECTIONS.md)
- [Main trap entry, interrupt dispatch, PLIC API and FreeRTOS port](MAIN_TRAP_IRQ_DISPATCH.md)
- [FreeRTOS tick, context selection, port timer and task creation](MAIN_FREERTOS_KERNEL.md)
- [Power-management wake gate, dynamic IRQ re-registration and wake body](MAIN_PM_WAKE.md)
- [GPIO pad multiplexer, shared IRQ handler and per-pin callback dispatch](MAIN_GPIO_DISPATCH.md)
- [GPIO pull/drive pad writer and interrupt enable/commit](MAIN_GPIO_CONFIG.md)
- [GPIO interrupt registration: callback-row insert/update and trigger mode](MAIN_GPIO_REGISTER.md)
- [xTaskResumeAll: scheduler unlock, pending-ready and tick catch-up](MAIN_SCHED_RESUME.md)
- [vTaskDelay: suspend, delayed-list insertion, resume and yield](MAIN_TASK_DELAY.md)
- [vTaskDelete and prvDeleteTCB task deletion](MAIN_TASK_DELETION.md)
- [eTaskGetState, uxTaskPriorityGet and vTaskPrioritySet](MAIN_TASK_QUERY.md)
- [Recovery selection/counter writes, preparation/completion and stopped handoff](RECOVERY_SELECTION_AND_HANDOFF.md)
- [Boot environment wrappers, reason cache, key policy and stopped upgrade-record caller](BOOT_ENVIRONMENT_AND_KEY_POLICY.md)
- [Native KV40 records, staged writes, cached lookup/deletion and storage adapters](ENV_RECORDS_AND_STORAGE.md)
- [Empty-cache lookup, EF40 sector traversal and reservation/maintenance retry policy](ENV_SCAN_AND_RESERVATION.md)
- [Actual detailed sector space, tail scan, end-cache reuse and reservation](ENV_SPACE_AND_TAIL_SCAN.md)
- [Actual record relocation, sector collection/format and defaults restoration](ENV_GC_AND_DEFAULTS.md)
- [Connected environment initialization, readiness binding and reserve-copy/dump fallback](ENV_INITIALIZATION_AND_BACKUP.md)
- [Native GATT registrations and transport bindings](GATT_REGISTRATION.md)
- [Native channel framing and authentication crypto delegate](NATIVE_CHANNEL.md)
- [Authentication module, request layouts and ECDH key material](AUTH_SESSION.md)
- [GAPP compiled UI: complete decode of Application.bin](GAPP_UI.md)
- [Sports-peripheral client and the four custom BLE UUIDs](SPORT_PERIPHERAL.md)
- [Package manifest and the `res_info` mismatch](PACKAGE_MANIFEST.md)
- [Official QuickJS C reader cross-check](QJS_CROSSCHECK.md)
- [First live Gadgetbridge session and native cipher validation](LIVE_GADGETBRIDGE.md)
- [All announced application services and selected payload contracts](APPLICATION_SERVICES.md)
- [Notification reverse messages, controlled test and Roadstr source](NOTIFICATION_ACTIONS_AND_ROADSTR.md)
- [Native notification listeners, storage and screen-request route](NOTIFICATION_PIPELINE.md)

No custom firmware write or installation is justified by the current results. The
project's existing backup/boot/recovery prerequisites in [GOAL.md](../GOAL.md)
remain unresolved.
