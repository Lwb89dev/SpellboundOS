import hashlib
import io
import json
import unittest
import zipfile
import zlib
from analysis_scripts.package_manifest import inspect


def build(tamper=None):
    """A synthetic package built the way the vendor archive is."""
    firmware, boot, recovery = b'fw' * 10, b'bl' * 7, b'rc' * 5
    stamp = b'2026-01-01 00:00:00,root,abc'
    members = {'META/firmware_sign.bin': firmware, 'META/bootloader_sign.bin': boot,
               'META/extfw/recovery_sign.bin': recovery, 'META/build_info': stamp,
               'META/res_info': stamp,
               'META/fw_info': json.dumps({'fw_info': [
                   {'name': 'firmware', 'version': '1.2', 'size': len(firmware),
                    'crc': hex(zlib.crc32(firmware))},
                   {'name': 'bootloader', 'version': '9', 'size': len(boot),
                    'crc': hex(zlib.crc32(boot))},
                   {'name': 'recovery', 'version': '8', 'size': len(recovery),
                    'crc': hex(zlib.crc32(recovery))}]}).encode()}
    # 1) manifest over the files while res_info is still the bare stamp,
    manifest = json.dumps({n: hashlib.sha256(d).hexdigest() for n, d in members.items()}).encode()
    digest = hashlib.sha256(manifest).hexdigest()
    # 2) then res_info gains the version and the manifest's own digest.
    members['META/res_info'] = stamp + b'\n1.2\n' + digest.encode()
    if tamper == 'filehash':
        # Rewrite the manifest after res_info captured its digest (valid JSON).
        manifest = manifest[:-1] + b', "extra": "0"}'
        tamper = None
    members['filehash'] = manifest
    members['packageDiscription.json'] = json.dumps(
        {'platform': 'p1', 'resourceHash': digest, 'firmwareVer': '1.2'}).encode()
    members['update-script'] = b'mkfs("SYSTEM");\n'
    if tamper:
        members[tamper] = members[tamper] + b'x'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


class ManifestTest(unittest.TestCase):
    def test_res_info_is_the_only_expected_mismatch(self):
        report = inspect(build())
        self.assertEqual(report['manifest']['mismatched'], ['META/res_info'])
        self.assertEqual(report['manifest']['unlisted_archive_files'],
                         ['filehash', 'packageDiscription.json', 'update-script'])
        self.assertTrue(all(v for k, v in report['res_info'].items()
                            if k.endswith(('matches', 'manifest', 'build_info', 'stamp'))))
        self.assertTrue(all(e['size_matches'] and e['crc32_matches'] for e in report['fw_info']))

    def test_tampering_is_detected(self):
        report = inspect(build(tamper='META/firmware_sign.bin'))
        self.assertIn('META/firmware_sign.bin', report['manifest']['mismatched'])
        firmware = next(e for e in report['fw_info'] if e['name'] == 'firmware')
        self.assertFalse(firmware['crc32_matches'])

    def test_res_info_chain_breaks_if_manifest_changes(self):
        report = inspect(build(tamper='filehash'))
        self.assertFalse(report['res_info']['appended_hash_is_sha256_of_manifest'])
        self.assertFalse(report['res_info']['description_resource_hash_matches'])


if __name__ == '__main__':
    unittest.main()
