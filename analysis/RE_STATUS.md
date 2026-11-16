# Reverse-engineering status and completion criteria

The investigation covers OTA 4.6.0.3 and one live Gadgetbridge/Bip 6 protocol
session. It is not a complete physical flash/ROM dump or native execution trace.
There is no defensible percentage for completion.
Disassembly and export counts do not measure behavioral understanding.

| Area | Current evidence | Still needed to close the area |
| --- | --- | --- |
| Package integrity / signatures | Hashes/signatures plus variable-length metadata and raw-recovery validator path; manifest fully verified and the `res_info` mismatch explained (it embeds the manifest's own digest); `fw_info` sizes/CRC-32 match | Observe device enforcement, update-script interpreter and rollback policy |
| Main/sensor startup | Copy/zero tables reconstructed; startup-aware analysis ELFs | Validate full boot context, aliases, memory protection, retained/device data |
| Native corpus | Guarded BBS repair, ABI/logger fixes and targeted main/sensor exports; volatile IPC windows preserve previously omitted I/O side effects | Audit remaining BBS/volatile-affected exports; broaden type and runtime validation |
| App bytecode | 44 members structurally parsed; QuickJS engine fingerprinted; official C reader agrees on nine header fields for all 1,072 functions | Runtime semantics, operand-level validation and independently implemented host |
| JS/native boundary | Modules, export tables, classes and initializer ownership mapped | Argument/error contracts, object lifetimes and behavior behind each implementation |
| Optical sensing | MAX8617X driver, initial board data, IRQ/FIFO route, host FIFO model, eight register-table inventories | Exact fitted part, full mode/timing behavior, calibration and measurement chain |
| Health data | Heart/SpO2 caches/services; sensor payloads; zrpc headers/CRC/priority; pools/queues/endpoints; main/sensor interrupt/token/wake route; bounded fragment and notification-control models | Live IRQ/wake/vring operation, cache/coherency, exact-multiple device case, remaining payloads, algorithms and measurement validation |
| Motion / other peripherals | Candidate identities and selected probe paths | Complete configuration, interrupts, power/timing and physical verification |
| Bluetooth | Static builder/auth/curve models; all 62 announced modules matched; 103 initial transfers/69 AES checks; synthetic notification fields matched on the link and app-logo exchange observed; native reply/action serializers; selected notification listener/queue/store route followed to `NotificationNotifyScreen` request | Full GATT/handle coverage, fresh pairing/key derivation, counter persistence, remaining payloads/JS linkage, actual notification rendering/replies/actions, special storage/rich formats, Roadstr handoff and call/audio behavior |
| GNSS / touch | Container sections, candidate code and identity clues | Full mappings, loader/command protocols, runtime integration |
| Boot/debug/recovery | Startup-aware boot/recovery inputs; reset/handoff split and key/UI/validation paths | Proven non-destructive debug/boot path, full backup and device-specific restoration |
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
- [Boot/recovery control flow and signed metadata](BOOT_RECOVERY_AND_METADATA.md)
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
