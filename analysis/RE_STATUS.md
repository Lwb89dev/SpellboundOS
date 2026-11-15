# Reverse-engineering status and completion criteria

The investigation is of OTA 4.6.0.3, not a complete physical flash/ROM dump or
an observed execution trace. There is no defensible percentage for completion.
Disassembly and export counts do not measure behavioral understanding.

| Area | Current evidence | Still needed to close the area |
| --- | --- | --- |
| Package integrity / signatures | Hashes/signatures plus variable-length metadata and raw-recovery validator path; manifest fully verified and the `res_info` mismatch explained (it embeds the manifest's own digest); `fw_info` sizes/CRC-32 match | Observe device enforcement, update-script interpreter and rollback policy |
| Main/sensor startup | Copy/zero tables reconstructed; startup-aware analysis ELFs | Validate full boot context, aliases, memory protection, retained/device data |
| Native corpus | Broad exports plus targeted instruction checks | Repair save/restore ABI, logger call effects and relocated-code mappings; validate selected functions |
| App bytecode | 44 members structurally parsed; QuickJS engine fingerprinted | Independent reader cross-check; runtime semantics and independently implemented host |
| JS/native boundary | Modules, export tables, classes and initializer ownership mapped | Argument/error contracts, object lifetimes and behavior behind each implementation |
| Optical sensing | MAX8617X driver, initial board data, IRQ/FIFO route, host FIFO model, eight register-table inventories | Exact fitted part, full mode/timing behavior, calibration and measurement chain |
| Health data | Heart/SpO2 caches and services; sensor process/control IPC payloads modeled | Outer zrpc transport, remaining packet families, record formats, algorithms and validation |
| Motion / other peripherals | Candidate identities and selected probe paths | Complete configuration, interrupts, power/timing and physical verification |
| Bluetooth | Eight service/31 characteristic specs; 0016/0017 and RFCOMM 0022 bindings; native framing, plaintext host model, crypto delegate, CRC and counter policy; auth module `0x82` request layouts, sect163r2 public parameters, session-key/cloud-binding slicing and key store | Active handles/state, full task lifecycle and cipher interoperability, pairing/key provisioning and counter persistence, JS payload linkage, notification/audio behavior |
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
- [Native GATT registrations and transport bindings](GATT_REGISTRATION.md)
- [Native channel framing and authentication crypto delegate](NATIVE_CHANNEL.md)
- [Authentication module, request layouts and ECDH key material](AUTH_SESSION.md)
- [GAPP compiled UI: complete decode of Application.bin](GAPP_UI.md)
- [Sports-peripheral client and the four custom BLE UUIDs](SPORT_PERIPHERAL.md)
- [Package manifest and the `res_info` mismatch](PACKAGE_MANIFEST.md)

No device write or installation is justified by the current results. The
project's existing backup/boot/recovery prerequisites in [GOAL.md](../GOAL.md)
remain unresolved.
