import hashlib
from pathlib import Path
import tempfile
import unittest

from analysis_scripts.backup_audit import audit


class BackupAuditTest(unittest.TestCase):
    def test_stock_copy_and_device_export_remain_distinct(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            entries = []
            for name, kind, data in [('firmware.zip', 'stock_ota', b'ota'),
                                     ('private-export', 'device_export', b'export')]:
                (directory / name).write_bytes(data)
                entries.append(dict(file=name, kind=kind, size=len(data),
                                    sha256=hashlib.sha256(data).hexdigest()))
            record = {'schema': 1, 'artifacts': entries}
            self.assertEqual(audit(directory, record), {
                'integrity_verified': True,
                'verified_artifacts': {'stock_ota': 1, 'device_export': 1},
                'device_restore_verified': False,
            })
            (directory / 'private-export').write_bytes(b'tamper')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                audit(directory, record)

    def test_rejects_aliases_short_reads_and_missing_artifacts(self):
        data = b'fixture'
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / 'flash.bin').write_bytes(data)
            (directory / 'alias.bin').symlink_to('flash.bin')
            entry = dict(file='flash.bin', kind='device_readback', size=len(data),
                         sha256=hashlib.sha256(data).hexdigest())
            for entries, reason in [
                ([entry, entry], 'duplicate'),
                ([dict(entry, file='../flash.bin')], 'invalid'),
                ([dict(entry, file='alias.bin')], 'non-regular'),
                ([dict(entry, file='missing.bin')], 'missing'),
                ([dict(entry, size=len(data) + 1)], 'length mismatch'),
            ]:
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    audit(directory, {'schema': 1, 'artifacts': entries})
