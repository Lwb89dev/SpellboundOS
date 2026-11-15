#!/usr/bin/env python3
"""Verify the OTA package manifest and its self-referencing metadata chain.

The archive carries a JSON manifest ``filehash`` (member path → SHA-256), a
``META/res_info`` stamp, ``META/fw_info`` (sizes and CRC-32 of the three boot
images) and ``packageDiscription.json`` (vendor spelling). This tool checks
every manifest entry against the archive and explains the one entry that does
not match: ``res_info`` is completed only after the manifest is written,
because it ends with the SHA-256 of ``filehash`` itself, so the manifest can
only record the digest of its earlier, shorter form.

The checks are pure hashing of archive members. Nothing is installed or run.
"""
import argparse
import hashlib
import json
import zipfile
import zlib

MANIFEST = 'filehash'
RES_INFO = 'META/res_info'
BUILD_INFO = 'META/build_info'
FW_INFO = 'META/fw_info'
DESCRIPTION = 'packageDiscription.json'
UPDATE_SCRIPT = 'update-script'
FW_MEMBERS = {'firmware': 'META/firmware_sign.bin',
              'bootloader': 'META/bootloader_sign.bin',
              'recovery': 'META/extfw/recovery_sign.bin'}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_manifest(archive):
    manifest = json.loads(archive.read(MANIFEST))
    names = set(archive.namelist())
    files = {n for n in names if not n.endswith('/')}
    mismatched = sorted(n for n, digest in manifest.items()
                        if n in names and sha256(archive.read(n)) != digest)
    return {
        'entries': len(manifest),
        'verified': len(manifest) - len(mismatched)
                    - sum(n not in names for n in manifest),
        'mismatched': mismatched,
        'missing_from_archive': sorted(n for n in manifest if n not in names),
        'unlisted_archive_files': sorted(files - set(manifest)),
    }, manifest


def explain_res_info(archive, manifest):
    """Decompose res_info and test each line against the other metadata."""
    res_info = archive.read(RES_INFO)
    lines = res_info.split(b'\n')
    if len(lines) != 3:
        raise ValueError('res_info does not have three lines')
    stamp, version, appended = lines
    description = json.loads(archive.read(DESCRIPTION))
    firmware = next(e for e in json.loads(archive.read(FW_INFO))['fw_info']
                    if e['name'] == 'firmware')
    manifest_digest = sha256(archive.read(MANIFEST))
    return {
        'stamp': stamp.decode(),
        'stamp_equals_build_info': stamp == archive.read(BUILD_INFO),
        'listed_digest_equals_sha256_of_stamp': manifest.get(RES_INFO) == sha256(stamp),
        'version': version.decode(),
        'version_matches_fw_info': version.decode() == firmware['version'],
        'version_matches_description': version.decode() == description.get('firmwareVer'),
        'appended_hash': appended.decode(),
        'appended_hash_is_sha256_of_manifest': appended.decode() == manifest_digest,
        'description_resource_hash_matches': description.get('resourceHash') == manifest_digest,
    }


def check_fw_info(archive):
    out = []
    for entry in json.loads(archive.read(FW_INFO))['fw_info']:
        member = FW_MEMBERS.get(entry['name'])
        data = archive.read(member) if member else b''
        out.append({'name': entry['name'], 'version': entry['version'],
                    'member': member, 'size_matches': len(data) == entry['size'],
                    'crc32_matches': zlib.crc32(data) == int(entry['crc'], 16)})
    return out


def inspect(archive):
    summary, manifest = check_manifest(archive)
    description = json.loads(archive.read(DESCRIPTION))
    return {
        'manifest': summary,
        'manifest_sha256': sha256(archive.read(MANIFEST)),
        'res_info': explain_res_info(archive, manifest),
        'fw_info': check_fw_info(archive),
        'description': {k: description[k] for k in sorted(description)
                        if k != 'resourceHash'},
        'update_script': archive.read(UPDATE_SCRIPT).decode().splitlines(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        report = inspect(archive)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
