# Bootloader recovery-entry gate and the boot manager decision

All **8 native cases** pass in **1,758 instruction steps**. This scope executes
the original recovery-entry detector `0x80c00312` end to end in the
`boot-runtime` project, supplying the boot-reason reader, the power check, the
key poll and the delay as stubs. The evidence is in
[main-recovery-gate.json](main-recovery-gate.json).

It answers the recoverability question raised in
[MAIN_BOOT_GATE.md](MAIN_BOOT_GATE.md): a failed main-firmware verification does
**not** fall through to recovery on its own.

## The boot manager decides; main boot is the unconditional last step

The boot manager `0x80c00454` (read statically; the detector below is executed)
runs this order:

1. Read the boot reason and the `upgrade` environment record (magic
   `0xb007cca6`, 298 bytes). If the detector `0x80c00312` returns 1, it writes an
   `upgrade` record and hands off.
2. If the `upgrade` record is present with state `2`, it enters recovery
   (`0x80c0098c`) and hands off (`0x80c0082c`).
3. **Unconditionally, as the final step, it calls the main-firmware boot
   `0x80c00918`** (see [MAIN_BOOT_GATE.md](MAIN_BOOT_GATE.md)), then returns.

Because the main boot is the last thing the manager does, and the main boot
*returns* on a signature failure (it does not jump into unverified bytes), a
failed main verification leads back out of the manager, not into recovery.
Recovery is reached only **earlier**, when either:

- the detector `0x80c00312` returns 1 (a physical gesture), or
- an `upgrade` record already requests it (a software request written during a
  normal OTA, before the reboot).

There is no observed automatic "main failed, therefore boot recovery" edge.

## The recovery-entry detector `0x80c00312`

The executed detector returns 1 (enter recovery) only when **all** hold:

1. The boot reason is neither 3 nor 6. Those reasons return 0 immediately,
   before any power or key access.
2. External power is present. The power check must succeed and report a nonzero
   flag; otherwise it logs `boot no power supply !` and returns 0, without
   polling any key.
3. Two keys (poll indices 0 and 1) are held together through two windows:
   - it first waits for key 0 to be released;
   - then it waits up to 20 polls (`0x32` ms each) for **both** keys to read
     pressed; a timeout returns 0;
   - then it logs `boot press detected !` and requires both keys to stay held
     for a further 20-poll confirmation window. Releasing key 0 or key 1 during
     this window returns 0; holding both to the end logs `backup check key
     pass !` and returns 1.

The two logical inputs and the power condition describe a candidate recovery
gesture. Physical button mapping, timing and boot reason on the A2435 remain
unverified.

## Cases

| Case | Result |
| --- | --- |
| `reason_ota_skips` (reason 6) | no recovery; no power/key access |
| `reason_reset_skips` (reason 3) | no recovery; no power/key access |
| `no_external_power` | no recovery; keys never polled |
| `power_check_error` | no recovery; keys never polled |
| `keys_never_pressed_times_out` | no recovery after the bounded wait |
| `recovery_gesture_succeeds` | **enters recovery** |
| `key_released_during_confirm_aborts` | no recovery |
| `second_key_late_then_held` | **enters recovery** once both settle and hold |

The native runner records every supplied call and the detector's return value;
the independent Python model reproduces them. Each key poll writes a scripted
per-index button state, and the power check writes its flag, into the quiet
stack window via a `store` stub kind, so no real key matrix, power rail or timer
is read.

## Consequence for physical recovery

The analyzed boot manager has two observed recovery branches:

1. A positive result from the key and power detector. The caller can write an
   `upgrade` record before completing the transition.
2. A pre-existing `upgrade` record in state 2, used by the OTA flow.

BLE through the companion is the observed live interface. The existence of a
wired service path remains open. The [physical feasibility record](RECOVERY_INPUTS.md)
tracks the backup, recovery and signed-boot requirements.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_recovery_gate --vectors-output firmware/main-recovery-gate-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime boot-runtime \
  -process boot-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainRecoveryGate.java firmware/main-recovery-gate-vectors.json \
  firmware/main-recovery-gate-validation.json
python3 -m analysis_scripts.main_recovery_gate firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-recovery-gate-vectors.json \
  --validation firmware/main-recovery-gate-validation.json > analysis/main-recovery-gate.json
```

The vectors, native report and evidence regenerate byte for byte. The boot
project is opened read-only.

Remaining work:

- Execute the boot manager `0x80c00454` end to end to confirm the recovery/
  main-boot ordering under each boot reason and `upgrade` state.
- Map the two poll indices to physical buttons and confirm the power threshold
  and debounce timing on the device.
- Verify whether a supported recovery route restores a stock signed image and
  preserves device-specific state.
