#!/usr/bin/env python3
"""Verify the five observed OTA signatures using the key embedded in the bootloader.

This checks a mathematical relationship, not the authenticity of the archive or
what the device actually enforces. Requires the Python cryptography package.
"""
import argparse
import hashlib
import json
import sys
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

BOOT = 'META/bootloader_sign.bin'
MEMBERS = (BOOT, 'META/firmware_sign.bin', 'META/extfw/recovery_sign.bin',
           'META/extfw/fct_test_sign.bin', 'META/extfw/sensorhub@mhs003_sign.bin')
KEY_OFFSET = 0x37094


def verify(data, public_key):
    if len(data) < 65:
        raise ValueError('image is too short to contain a payload and signature')
    digest = hashlib.sha256(data[:-64]).digest()
    r = int.from_bytes(data[-64:-32], 'big')
    s = int.from_bytes(data[-32:], 'big')
    try:
        public_key.verify(utils.encode_dss_signature(r, s), digest,
                          ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def analyze(archive_path):
    with open(archive_path, 'rb') as source:
        archive_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    with zipfile.ZipFile(archive_path) as archive:
        boot = archive.read(BOOT)
        key = boot[KEY_OFFSET:KEY_OFFSET + 64]
        if len(key) != 64:
            raise ValueError('bootloader is too short for the candidate public key')
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(key[:32], 'big'), int.from_bytes(key[32:], 'big'),
            ec.SECP256K1()).public_key()
        results = []
        for member in MEMBERS:
            data = archive.read(member)
            valid = verify(data, public_key)
            changed = bytearray(data)
            changed[(len(changed) - 64) // 2] ^= 1
            results.append({'member': member, 'size': len(data),
                            'sha256': hashlib.sha256(data).hexdigest(),
                            'signature_valid': valid,
                            'modified_payload_rejected': not verify(changed, public_key)})
    with open(archive_path, 'rb') as source:
        archive_data = source.read()
    modified_archive = bytearray(archive_data)
    modified_archive[len(modified_archive) // 2] ^= 1
    archive_signature = {'trailer_marker_hex': archive_data[-112:-104].hex(),
                         'signature_valid': verify(archive_data, public_key),
                         'modified_payload_rejected': not verify(modified_archive, public_key)}
    return {'archive_sha256': archive_hash, 'archive_signature': archive_signature, 'curve': 'secp256k1',
            'key_offset_in_bootloader': hex(KEY_OFFSET),
            'public_key_xy_hex': key.hex(), 'members': results}


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
    return 0 if result['archive_signature']['signature_valid'] and result['archive_signature']['modified_payload_rejected'] and all(x['signature_valid'] and x['modified_payload_rejected']
                    for x in result['members']) else 1


if __name__ == '__main__':
    sys.exit(main())
