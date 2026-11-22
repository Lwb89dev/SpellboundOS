#!/usr/bin/env python3
"""Locate the signed boot chain's trust anchor and report where it lives.

The bootloader carries a 64-byte secp256k1 public key as a plain constant in its
own image body. The main firmware, recovery, factory and sensor-hub images are
each verified against *that* embedded key (see analysis/MAIN_BOOT_GATE.md for the
executed verifier `0x80c0e2b6` -> `0x80c0e144`). This tool proves the property
that matters for a custom boot path: the anchor is inside the mutable bootloader
image, not read from a fused eFuse/OTP word, so whoever controls the bootloader
controls every downstream signature check. What verifies the bootloader itself at
power-on is the on-die mask ROM, which is not present in the OTA and is therefore
the single open question this analysis isolates.

This checks a static fact and a mathematical relationship. It does not read the
device, the mask ROM, or any eFuse state. Requires the Python cryptography
package.
"""
import argparse
import hashlib
import json
import sys
import zipfile

from cryptography.hazmat.primitives.asymmetric import ec

from analysis_scripts.verify_ota_signatures import (
    BOOT, MEMBERS, KEY_OFFSET, verify)

# secp256k1 field prime, for the on-curve check y^2 == x^3 + 7 (mod p).
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Printable evidence tokens for the on-chip secure-boot surface. Presence in the
# bootloader body is reported; it documents that the hardware exposes an eFuse
# block, a unique die identity and a write-protected boot partition. Presence of
# the surface is not proof that bootloader verification is enforced.
EVIDENCE_TOKENS = {
    'efuse_power_domain': b'EFUSE_PWR',
    'unique_die_id': b'@aUID',
    'good_die_check': b'good die check failed',
    'boot_partition_write_protect': b'nand boot part unlock',
    'downstream_verify_failure_log': b'sign verify not pass',
    'firmware_secure_verify_log': b'firmware secure verify failed',
}

# Recovered boot media placement for the bootloader image (see
# analysis/STORAGE_MAP_AND_DRIVER_BINDINGS.md). Static configuration recovered
# from the image, not an observed device read.
BOOT_PARTITION = {'backend': 'nandraw', 'offset': '0x0', 'size': '0x100000'}

# Candidate silicon identifiers compiled into the main image (see
# analysis/HARDWARE_PROFILE.md). Not a measurement of fitted silicon.
SILICON = {'platform': 'mhs003', 'ap_candidate': 'AX861',
           'core': 'Andes RISC-V (AndeStar v5)'}


def extract_key(boot_bytes, offset=KEY_OFFSET):
    """Return the 64-byte (x || y) key constant embedded in the bootloader."""
    key = boot_bytes[offset:offset + 64]
    if len(key) != 64:
        raise ValueError('bootloader is too short for the candidate public key')
    return bytes(key)


def on_secp256k1_curve(key_bytes):
    """True when (x, y) from the 64-byte key satisfies the secp256k1 equation."""
    if len(key_bytes) != 64:
        raise ValueError('key must be 64 bytes (x || y)')
    x = int.from_bytes(key_bytes[:32], 'big')
    y = int.from_bytes(key_bytes[32:], 'big')
    if not (0 < x < SECP256K1_P and 0 < y < SECP256K1_P):
        return False
    return (y * y - (x * x * x + 7)) % SECP256K1_P == 0


def public_key_from_bytes(key_bytes):
    """Build a secp256k1 public key, raising if the point is invalid."""
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(key_bytes[:32], 'big'),
        int.from_bytes(key_bytes[32:], 'big'),
        ec.SECP256K1()).public_key()


def analyze(archive_path):
    with open(archive_path, 'rb') as source:
        archive_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    with zipfile.ZipFile(archive_path) as archive:
        boot = archive.read(BOOT)
        key = extract_key(boot)
        on_curve = on_secp256k1_curve(key)
        public_key = public_key_from_bytes(key)
        anchored = []
        for member in MEMBERS:
            data = archive.read(member)
            anchored.append({'member': member,
                             'verified_with_embedded_key': verify(data, public_key)})
        evidence = {name: (token in boot) for name, token in EVIDENCE_TOKENS.items()}
    every_member = all(entry['verified_with_embedded_key'] for entry in anchored)
    return {
        'archive_sha256': archive_hash,
        'trust_anchor': {
            'location': 'constant inside META/bootloader_sign.bin body',
            'key_offset_in_bootloader': hex(KEY_OFFSET),
            'curve': 'secp256k1',
            'public_key_x_hex': key[:32].hex(),
            'public_key_y_hex': key[32:].hex(),
            'public_key_xy_hex': key.hex(),
            'on_secp256k1_curve': on_curve,
            'read_from_efuse_or_otp': False,
            'anchors_every_downstream_image': every_member,
        },
        'downstream_images': anchored,
        'on_chip_secure_boot_evidence': evidence,
        'boot_partition': BOOT_PARTITION,
        'silicon': SILICON,
        'no_wired_debug_port': True,
        'open_question': (
            'What verifies META/bootloader_sign.bin at power-on is the on-die '
            'mask ROM (stage 0), which is not contained in this OTA. Whether it '
            'enforces a signature on the bootloader, and against an eFuse-fused '
            'key, determines whether a custom bootloader can be written. That bit '
            'is not answerable from the archive alone.'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        result = analyze(args.archive)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(f'Cannot analyze archive: {error}', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    anchor = result['trust_anchor']
    return 0 if anchor['on_secp256k1_curve'] and anchor['anchors_every_downstream_image'] else 1


if __name__ == '__main__':
    sys.exit(main())
