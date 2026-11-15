# Reverse-engineering status and completion criteria

The investigation is of OTA 4.6.0.3, not a complete physical flash/ROM dump or
an observed execution trace. There is no defensible percentage for completion.
Disassembly and export counts do not measure behavioral understanding.

| Area | Current evidence | Still needed to close the area |
| --- | --- | --- |
| Package integrity / signatures | Hashes/signatures plus variable-length metadata and raw-recovery validator path | Explain manifest/size mismatches; observe device enforcement and rollback policy |
| Main/sensor startup | Copy/zero tables reconstructed; startup-aware analysis ELFs | Validate full boot context, aliases, memory protection, retained/device data |
| Native corpus | Broad exports plus targeted instruction checks | Repair save/restore ABI, logger call effects and relocated-code mappings; validate selected functions |
| App bytecode | 44 members structurally parsed; QuickJS engine fingerprinted | Independent reader cross-check; runtime semantics and independently implemented host |
| JS/native boundary | Modules, export tables, classes and initializer ownership mapped | Argument/error contracts, object lifetimes and behavior behind each implementation |
| Optical sensing | MAX8617X driver, initial board data, IRQ/FIFO route, host FIFO model, eight register-table inventories | Exact fitted part, full mode/timing behavior, calibration and measurement chain |
| Health data | Heart/SpO2 caches and services; sensor process/control IPC payloads modeled | Outer zrpc transport, remaining packet families, record formats, algorithms and validation |
| Motion / other peripherals | Candidate identities and selected probe paths | Complete configuration, interrupts, power/timing and physical verification |
| Bluetooth | Radio image records, transport candidates, GATT inventory, JS framing | Active GATT contract, pairing/authentication, radio command framing and audio behavior |
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
- [Boot/recovery control flow and signed metadata](BOOT_RECOVERY_AND_METADATA.md)

No device write or installation is justified by the current results. The
project's existing backup/boot/recovery prerequisites in [GOAL.md](../GOAL.md)
remain unresolved.
