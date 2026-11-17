# Reverse-engineering status and completion criteria

The investigation covers OTA 4.6.0.3 and one live Gadgetbridge/Bip 6 protocol
session. It is not a complete physical flash/ROM dump or native execution trace.
There is no defensible percentage for completion.
Disassembly and export counts do not measure behavioral understanding.

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
| Main/sensor startup | Copy/zero tables reconstructed; startup-aware analysis ELFs | Validate full boot context, aliases, memory protection, retained/device data |
| Native corpus | Guarded BBS and two Andes DSP semantics, ABI/logger fixes, targeted main/sensor exports; volatile MMIO/CSR metadata; wide division helper checked in 52,294 host executions | Audit remaining affected exports and unsupported DSP forms; runtime/type validation |
| App bytecode | 44 members structurally parsed; QuickJS engine fingerprinted; official C reader agrees on nine header fields for all 1,072 functions | Runtime semantics, operand-level validation and independently implemented host |
| JS/native boundary | Modules, export tables, classes and initializer ownership mapped | Argument/error contracts, object lifetimes and behavior behind each implementation |
| Optical sensing | MAX8617X driver, board/SPI/chip-select records; clock/flag/divider and polling/error contracts; bus/completion/reference paths; initial DMA slots null; native register/polling checks; 45 FIFO/recovery/cache/sample cases; 557 flush/packet/mode-1 cases; 178 reference/listener/cache-queue and mode-2/3 cases; 29 filter/buffer/flush-to-IPC-send cases; eight register-table inventories | Exact fitted part, electrical mode/timing, live bus/IRQ operation, dynamic DMA bindings/ownership guarantees, remaining consumer modes and concurrency, complete allocator/receiver/event/transport operation, calibration and measurement chain |
| Health data | Heart/SpO2 caches/services; sensor/zrpc framing and queues; interrupt/wake route; clock formulas; counter/1000 conversion; distinct main/sensor periodic intervals and suspension conversions; 90 native timer/AON/dispatch cases; phase-aware IPC timeout; selected cache commands/transfer callers and shared-address guard; filtering/cache event through opcode-0x15 send callback; 66 main/sensor decoder, receive/reconstruction/listener-ownership and bounded malformed-record cases; 40 main cache registration, retained engine event, fanout and actual HR-consumer/output-policy cases with supplied algorithm results; 48 actual algorithm registration/lifetime/HR-adapter/configuration cases; 21 HR outer workspace/free/restart, unsupported-type reset and extension-view cases; 37 actual setup/component allocation/nested-cleanup and 89-request owner cases | Remaining application consumers/registration and real engine activation/mask transitions; algorithm-0x100d initializer 0x708a4818 and other secondary allocation failures, supported signal normalization/math and extension consumers, HR motion/minute/reset/wear branches; event/transport/IRQ/vring lifetimes and operation, complete malformed-input/producer constraints, physical timer/cache/coherency, counter continuity across power states, complete sleep state machine, exact-multiple device case, remaining payloads and measurement validation |
| Motion / other peripherals | Candidate identities and selected probe paths | Complete configuration, interrupts, power/timing and physical verification |
| Bluetooth | Static builder/auth/curve models; all 62 announced modules matched; 103 initial transfers/69 AES checks; synthetic notification fields matched on the link and app-logo exchange observed; native reply/action serializers; selected notification listener/queue/store route followed to `NotificationNotifyScreen` request | Full GATT/handle coverage, fresh pairing/key derivation, counter persistence, remaining payloads/JS linkage, actual notification rendering/replies/actions, special storage/rich formats, Roadstr handoff and call/audio behavior |
| GNSS / touch | Container sections, candidate code and identity clues | Full mappings, loader/command protocols, runtime integration |
| Boot/debug/recovery | Startup-aware boot/recovery inputs; reset/handoff split and key/UI paths; 62 validation and 64 selection/counter/handoff native cases; one matched entry reaches startup +0x22c; environment wrappers, reason/key policy and upgrade record; KV40/cache/scan/reservation/tail-space contracts; 35 GC/default, 34 environment-init/reserve-copy, 52 handle/NVMS/bootstrap, 32 registry/lazy-EFTL, 24 translation/read, 27 OOB scan, 38 initializer/heap, 58 NAND dispatch/OOB and 60 original candidate-probe/root/layout cases; 51 QSPI platform/command/ROM-policy/busy-loop cases with supplied HAL and emulated MMIO; 77 page/program/copy/OOB/erase cases with actual busy loops and supplied remap/command/feature services; 58 BBT/CRC/resume/remap and 21 connected actual-remapping/page cases with supplied storage/command services; 86 retry/UID/command/busy/ioctl cases over a supplied bus; 90 actual QSPI HAL/FIFO/DMA-wrapper/clock and connected NAND-command cases with authored MMIO/timer/DMA services; 60 actual DMA init/setup/wait/cancel/count/IRQ cases over authored MMIO/cache/timer/callback services; 28 connected actual QSPI/backend/private-buffer NAND cases with authored peripheral/cache/copy/timer inputs; 47 actual pin/platform-init/original-DMA-link/reinitialization cases over authored peripherals; 31 connected actual page-read/BBT/status-FIFO/platform/QSPI/DMA cases including full busy timeouts; 27 connected actual page-program/guard/cache/program/status/FIFO/DMA cases including wrapping-column and full-timeout behavior; 64 connected actual erase/copy/OOB/mapping/guard/platform/bus/FIFO cases including complete two-phase copy/erase timeouts; original five-backend/16-partition and 11-chip tables; ROM default `boots=0` | Physical non-destructive entry, complete page/ECC/board integration, physical pin mapping and live DMA/IRQ/cache coherency, remaining board/regulator services, supported-family retry/UID through the HAL and higher storage integration, BBT provenance/creation and repair atomicity, physical retry/UID and remaining consumers, physical chip/geometry/OOB metadata corroboration, object registry internals, lower NAND page/ECC/DMA behavior, alternate format, SFTL and mapping repair/write paths, physical partition map and rewrite/mutex behavior, reserve-image provenance and factory data, malformed/stale-cache/concurrency/boundary-read paths and real persistence, subsequent boot/recovery/UI dispatch, physical reason/gesture behavior, startup/device enforcement, device-specific restoration and standalone boot |
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
