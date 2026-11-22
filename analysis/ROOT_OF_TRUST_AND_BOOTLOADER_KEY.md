# Root of trust: where the signed boot chain is anchored

The signed boot chain analyzed in [MAIN_BOOT_GATE.md](MAIN_BOOT_GATE.md) and
[MAIN_RECOVERY_GATE.md](MAIN_RECOVERY_GATE.md) is anchored by **a single
secp256k1 public key carried as a plain constant inside the bootloader image**.
The main firmware, recovery, factory and sensor-hub images each verify against
that embedded key; it is **not** read from an eFuse or OTP word. The reproducible
evidence is [root-of-trust-key.json](root-of-trust-key.json), produced by
`analysis_scripts/bootloader_root_key.py`.

The consequence reframes the standalone-boot problem. The obstacle is not five
independent signatures to defeat. It is one layer: whoever controls the
bootloader controls the key, and therefore every downstream check. The question
"can SpellboundOS boot?" reduces to "can the bootloader be replaced?", which
reduces to a **single fact that is not in the OTA**: whether the on-die mask ROM
enforces a signature on the bootloader at power-on. [Project goal](../GOAL.md).

```sh
python3 -m analysis_scripts.bootloader_root_key firmware/bip6-4.6.0.3.zip
python3 -m unittest tests.test_bootloader_root_key -v
```

The signature suite needs `cryptography` installed. No device is accessed; the
tool reads the archive, extracts the key constant and checks a mathematical
relationship and a static byte scan.

## The trust anchor

The main-image loader's verifier `0x80c0e2b6` hashes the image body with SHA-256
and passes the digest and the trailing 64-byte signature to `0x80c0e144`. That
function copies a fixed 64-byte constant from the bootloader body (file offset
`0x37094` in `META/bootloader_sign.bin`) and calls the ECDSA verify against it.
The same embedded key, with curve secp256k1, verifies the bootloader, main
firmware, recovery, factory-test and sensor-hub signatures offline; see the
independent [OTA signature report](ota-signatures.json) from
`verify_ota_signatures.py`, which uses the identical offset and key.

| Property | Value |
| --- | --- |
| Location | constant in `META/bootloader_sign.bin` body, offset `0x37094` |
| Curve | secp256k1 (64-byte `x \|\| y`, 64-byte `r \|\| s` signatures, SHA-256) |
| On curve | yes (`y^2 == x^3 + 7 mod p`) |
| Read from eFuse/OTP | no |
| Anchors | bootloader, main firmware, recovery, factory, sensor hub |

```
x = 4c5ee3be1fc08452f8b7064cbec0bd13b65a9fced76acf9d87c7fba91add3dd5
y = 85356d12dbb8278e4b3c8b61c40b87c62ab613c1f0f69f8c21b90bde5856687e
```

Because the anchor is a constant inside a mutable image rather than a fused
value, a bootloader the device accepts can carry any key its author chooses. A
replacement bootloader would re-root the whole chain, after which an
independently signed SpellboundOS main image would pass the main-boot gate
unchanged. The downstream signatures are therefore **not** the barrier; the
barrier is entirely at the bootloader-acceptance layer below.

## The single open question: the mask ROM

What loads and verifies `META/bootloader_sign.bin` at power-on is the SoC's
on-die mask ROM (stage 0). It is not contained in the OTA, so archive analysis
cannot settle whether it enforces a signature on the bootloader, nor against
which key. Two outcomes bound the project:

- **Mask ROM does not verify the bootloader** (secure-boot fuse not blown): a
  structurally valid custom bootloader written to the boot partition would run,
  and the embedded-key property above makes the rest of the chain ours.
- **Mask ROM verifies the bootloader against an eFuse-fused key**: a true
  hardware root of trust. Only a mask-ROM vulnerability or fault injection could
  admit an unsigned bootloader.

The OTA shows the hardware has the machinery for the second case without proving
it is enabled. The bootloader body references an eFuse power domain, a unique die
identity and a "good die check", and unlocks a write-protected boot partition
before programming it. These are reported as present/absent in the JSON evidence
block; presence of the surface is not proof of enforcement.

| Evidence token | Meaning |
| --- | --- |
| `EFUSE_PWR` | bootloader powers an eFuse block (hardware has eFuse) |
| `@aUID` | a unique die identity is read |
| `good die check failed` | a die-level validity check exists |
| `nand boot part unlock` | the boot partition is hardware write-protected |

## Boot media placement

The bootloader occupies the `boot` partition on the `nandraw` backend at offset
`0x0`, size `0x100000` (1 MiB), and executes from RAM at `0x80c00000`
([STORAGE_MAP_AND_DRIVER_BINDINGS.md](STORAGE_MAP_AND_DRIVER_BINDINGS.md)). A
bootloader replacement is a write to that raw region; the device has **no wired
USB or debug port**, so any such write — like any recovery — must go through the
over-the-air path, with no wired fallback if the chain breaks
([RECOVERY_INPUTS.md](RECOVERY_INPUTS.md)).

## Silicon

The candidate identifiers are platform `mhs003`, application-processor candidate
`AX861`, core Andes RISC-V (AndeStar v5), an in-house multi-core Huami/Zepp SoC
([HARDWARE_PROFILE.md](HARDWARE_PROFILE.md)). The A2435 FCC internal photos
(exhibit 8066732) visually confirm the application SoC is branded `ZEPP` captive
silicon, not an off-the-shelf part. A public review on 2026-11-22 found no
teardown, chip identification, mask-ROM dump or published boot-mode for the
Bip 6 / A2435 / `mhs003` / `AX861`. The older Amazfit unlock and unbrick
procedures (Pace, Stratos) target a different U-Boot/fastboot ARM platform and do
not apply. Determining the mask ROM's policy therefore needs the physical device
or an identification of the exact silicon, not further OTA analysis.

## What this does and does not establish

- Establishes: the downstream signature anchor is an in-bootloader constant, on
  secp256k1, verifying every signed member; it is not fused. The custom-boot
  problem reduces to bootloader acceptance by the mask ROM.
- Does not establish: whether the mask ROM enforces a bootloader signature,
  whether the secure-boot eFuse is blown on production A2435 units, the mask
  ROM's contents, or any device-side state. No device, eFuse or mask ROM was
  read.
