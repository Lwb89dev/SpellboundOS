#!/usr/bin/env python3
"""Inspect variable-length metadata immediately before observed OTA signatures.

This is a structural inspector, not signature verification or device validation.
Metadata fields are reported without treating all variants as one fixed header.
"""
import argparse
import hashlib
import json
import struct
import zipfile

MAGICS = (b'HMBZSIGN', b'HMRVYSIG', b'HMZPSIGN')
MEMBERS = ('META/bootloader_sign.bin', 'META/firmware_sign.bin',
           'META/extfw/recovery_sign.bin', 'META/extfw/fct_test_sign.bin',
           'META/extfw/sensorhub@mhs003_sign.bin')


def inspect(data):
    candidates = []
    end = len(data) - 64
    for magic in MAGICS:
        start = max(0, end - 4096)
        while (start := data.find(magic, start, max(0, end))) >= 0:
            if start + 10 <= end:
                length = struct.unpack_from('<H', data, start + 8)[0]
                if length in (48, 64) and start + length == end:
                    candidates.append((start, length, magic))
            start += 1
    if len(candidates) != 1:
        raise ValueError(f'expected one self-sized signature metadata block, found {len(candidates)}')
    offset, length, magic = candidates[0]
    metadata = data[offset:end]
    body_end, product, variant = struct.unpack_from('<IHH', metadata, 10)
    version = metadata[18:34].split(b'\0', 1)[0].decode('ascii')
    secondary = struct.unpack_from('<I', metadata, 34)[0]
    result = {'magic': magic.decode(), 'metadata_offset': offset, 'metadata_bytes': length,
              'signature_offset': end, 'signature_bytes': 64,
              'body_size_field': body_end, 'body_size_matches_offset': body_end == offset,
              'product_field': product, 'variant_field': variant, 'version': version,
              'secondary_size_field': secondary, 'size_field_difference': body_end - secondary,
              'metadata_sha256': hashlib.sha256(metadata).hexdigest(),
              'tail_field_hex': metadata[38:].hex()}
    if length == 64:
        result['build_text_candidate'] = metadata[38:].split(b'\0', 1)[0].decode('ascii')
    return result


def analyze(path):
    with open(path, 'rb') as source:
        archive_data = source.read()
    result = {'archive_sha256': hashlib.sha256(archive_data).hexdigest(),
              'archive': inspect(archive_data), 'members': []}
    with zipfile.ZipFile(path) as archive:
        uncompressed = sum(info.file_size for info in archive.infolist())
        result['archive_zip_uncompressed_bytes'] = uncompressed
        result['archive_secondary_size_minus_zip_total'] = result['archive']['secondary_size_field'] - uncompressed
        for member in MEMBERS:
            data = archive.read(member)
            result['members'].append({'member': member, 'size': len(data),
                                      'sha256': hashlib.sha256(data).hexdigest(),
                                      'metadata': inspect(data)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        result = analyze(args.archive)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect signature metadata: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
