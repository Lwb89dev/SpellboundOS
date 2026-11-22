# Defeating the bootloader signature by fault injection: what it would take

This records, for the project's own A2435 hardware, the established methodology
for bypassing a secure-boot signature check by fault injection (FI), and an
honest assessment of what it requires on *this* device. It documents a research
path on hardware the project owns; it is not a worked exploit, because no mask-ROM
vulnerability is known and the target's boot flow, rails and pinout are
undocumented. Read it alongside the chain analysis in
[ROOT_OF_TRUST_AND_BOOTLOADER_KEY.md](ROOT_OF_TRUST_AND_BOOTLOADER_KEY.md).

## Why FI is the only lever left

Every software layer is cryptographically closed and already mapped: the
downstream anchor is an embedded bootloader key (not fused), so controlling the
bootloader controls the chain, and the one unknown is whether the on-die mask ROM
enforces a signature on the bootloader. FI targets exactly that enforcement. The
aim is to make the mask ROM's verify-and-branch behave as if verification passed
— to corrupt the `sig_ok` value or skip the conditional jump after the ECDSA
check — so an unsigned, project-signed bootloader at the boot partition is
accepted. After that single fault, the embedded-key property does the rest and
SpellboundOS can be signed by us. This is the classic secure-boot FI target: a
glitch can make a device incorrectly take the "boot OK" path by corrupting the
check result or skipping the check
([NCC Group, MediaTek BootROM glitch](https://www.nccgroup.com/research/there-s-a-hole-in-your-soc-glitching-the-mediatek-bootrom/)).

## The two injection methods

| Method | Mechanism | Pros | Cons on this target |
| --- | --- | --- | --- |
| **Voltage FI (crowbar)** | short the SoC core rail to ground through a MOSFET for a few ns–µs at the right instant | cheap, deterministic pulse, well-documented with ChipWhisperer | affects the whole die; needs direct access to the core VDD rail (soldering to a tiny, shielded watch PCB) |
| **EM FI (EMFI)** | a localized EM pulse from a coil over the die injects faults without a rail connection | no soldering to the rail; localized; one 2022 study saw ~45× higher success than voltage FI | needs XY positioning over the die, a pulse injector (ChipSHOUTER/PicoEMP), and spatial mapping; still needs a timing trigger |

Both require the same two things: **temporal alignment** (fault at the exact
moment of the check) and an **automated parameter search** (offset, width,
voltage/intensity), because the optimal timing depends on the device's power
network and cannot be computed analytically — it is found by sweeping
([Synacktiv, How to voltage fault injection](https://www.synacktiv.com/en/publications/how-to-voltage-fault-injection);
[Lu, Injecting Software Vulnerabilities with Voltage Glitching](https://arxiv.org/pdf/1903.08102)).

## The prerequisite chain specific to the A2435

FI is the last step, not the first. On this watch every prerequisite below is
harder than on the SoCs where public bypasses exist (MediaTek, ESP32, AMD),
because those were documented parts with known boot flows, known rail/pin
locations and many cheap identical units. Here the AP is **captive ZEPP silicon
with no datasheet**, the device has **no wired port**, and there is effectively
**one unit** ([HARDWARE_PROFILE.md](HARDWARE_PROFILE.md),
[RECOVERY_INPUTS.md](RECOVERY_INPUTS.md)).

1. **A recoverable NAND backup first.** The boot partition is raw NAND on a
   soldered chip with no wired access. Before touching anything, do a chip-off or
   in-system read of the full NAND (including spare/OOB, bad-block markers, FTL
   metadata), read it twice and compare, and keep it. Without this, every later
   step is a one-way brick. [Backup requirements](RECOVERY_INPUTS.md).
2. **A way to put a custom bootloader on the boot medium.** A successful glitch
   only helps if a project-signed bootloader is already at the boot partition.
   With no wired flashing path, this means writing the NAND off-board (chip-off
   programmer) or finding an in-system program route — itself a rework project on
   a dense, multilayer, shielded board, likely with a PoP/stacked memory.
3. **Physical access to the attack points.** Open the watch, remove the EMI
   shield, and locate: the SoC **core VDD rail** (for voltage FI) or a clear die
   surface (for EMFI), a **reset/power-enable** line to control each boot attempt,
   and a **trigger source**. These are undocumented and must be found by probing.
4. **A boot-timed trigger.** The fault must land at the signature check. The
   standard trick is to sniff the boot-medium bus (NCC used an FPGA passively
   listening to eMMC traffic to trigger the glitch); here that means tapping the
   **NAND/QSPI** lines as a reference, then measuring the delay from power-on to
   the check — which needs observability (power/EM side-channel traces) on a
   sealed target. [NCC Group](https://www.nccgroup.com/research/there-s-a-hole-in-your-soc-glitching-the-mediatek-bootrom/);
   ESP32 work likewise first measures the interval from power-on to secure boot.
5. **Automated reset→glitch→observe loop.** Power-cycle, trigger, inject, detect
   success (e.g. UART boot log, or our bootloader's own signal), sweep offset and
   width over thousands of attempts.

## Equipment

- **Injector:** ChipWhisperer-Husky + crowbar/`CW521` for voltage FI, or
  ChipSHOUTER / open-source PicoEMP for EMFI (optionally on a 3D-printer XY gantry
  for die mapping).
- **Trigger/observability:** FPGA or fast logic analyzer to tap NAND/QSPI; an
  oscilloscope for power/EM traces.
- **Rework:** stereo microscope, hot-air and fine-tip soldering, 0.05 mm wire,
  bench PSU; a **NAND chip-off programmer** and adapter for the fitted package.
- **Control:** a scripted harness (ChipWhisperer's Python API) for the sweep.

## Honest feasibility verdict

- **Capability, not a recipe.** Nothing here is a working bypass. It is the
  apparatus to *search* for one on an undocumented mask ROM. The vulnerability
  (a glitchable check) may or may not exist; some secure boots harden the check
  (double-check, random delays, glitch detectors).
- **Low odds, high cost, destructive risk.** Documented campaigns report single
  to low-double-digit success *per thousands of automated attempts over days*,
  on known targets — 15–20% for MediaTek after days of brute force, ~0.55% for a
  DIY-EMFI Android secure-boot bypass. On captive silicon with one unit, no
  datasheet and no wired recovery, the practical odds are worse and the cost of a
  mistake is a dead watch.
- **Not noob-friendly, by a wide margin.** This is expert hardware-security work:
  microsoldering to a sub-millimetre shielded PCB, NAND chip-off, side-channel
  timing and multi-day glitch campaigns. It is the opposite of the constraint set
  for this project.

**Conclusion.** FI is the only avenue that could admit a custom bootloader on
this hardware, and it is a genuine research path on a device one owns — but it is
expert-level, expensive, likely to destroy the only unit, and of low and
unproven probability against undocumented captive silicon. For the project's
stated goals it is out of scope; value is better pursued within the signed system
(companion app, Zepp OS mini-apps) as recorded in [GOAL.md](../GOAL.md).

## References

- [NCC Group — Glitching the MediaTek BootROM](https://www.nccgroup.com/research/there-s-a-hole-in-your-soc-glitching-the-mediatek-bootrom/)
- [Synacktiv — How to voltage fault injection](https://www.synacktiv.com/en/publications/how-to-voltage-fault-injection)
- [Lu — Injecting Software Vulnerabilities with Voltage Glitching](https://arxiv.org/pdf/1903.08102)
- [Physical Fault Injection and Side-Channel Attacks on Mobile Devices (survey)](https://arxiv.org/pdf/2105.04454)
- [SoK: A Beginner-Friendly Introduction to Fault Injection Attacks](https://arxiv.org/pdf/2509.18341)
