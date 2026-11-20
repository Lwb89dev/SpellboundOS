import json
from pathlib import Path
import unittest

from analysis_scripts import main_ota_install as ota


class MainOtaInstallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_ota_install_'): c for c in ota.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-ota-install.json').read_bytes())

    def test_native_crc32_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (8, 8))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_ota_install_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_crc32_check_vector_and_chaining(self):
        # The canonical CRC32 of "123456789" after the firmware's final inversion.
        ascii_a0 = self.cases['ascii']['expected']['rows'][0]['a0']
        self.assertEqual(ascii_a0 ^ 0xffffffff, 0xCBF43926)
        # Feeding chunk-1's running CRC into chunk-2 equals hashing the 32 bytes in one pass.
        self.assertEqual(self.cases['chunk_chain']['expected']['rows'][0]['a0'],
                         self.cases['firmware_header']['expected']['rows'][0]['a0'])
        self.assertEqual(self.cases['empty']['expected']['rows'][0]['a0'], 0xFFFFFFFF)

    def test_crc32_update_reference(self):
        self.assertEqual(ota.crc32_update(0xFFFFFFFF, b'123456789') ^ 0xFFFFFFFF, 0xCBF43926)
        self.assertEqual(ota.crc32_update(0xFFFFFFFF, b'') , 0xFFFFFFFF)

    def test_integrity_contract(self):
        integ = self.evidence['integrity']
        self.assertEqual(integ['function'], '0x70161360(crc, buffer, length)')
        self.assertEqual(integ['check_vector'], {'input': '123456789', 'crc32': '0xcbf43926'})
        self.assertIn('0xedb88320', integ['algorithm'])

    def test_validation_flow_is_readback(self):
        flow = self.evidence['validation_flow']
        self.assertEqual(flow['function'], '0x7021b990 (downloader_request_validate)')
        joined = ' '.join(flow['steps']).lower()
        self.assertIn('received crc32', joined)
        self.assertIn('read the file back', joined)

    def test_records_and_keys(self):
        rec = self.evidence['download_record']
        keys = {r['file_type']: r['property_key'] for r in rec['keys']}
        self.assertEqual(keys[0], 'ota.record.v1.firmware')
        self.assertEqual(keys[8], 'ota.record.v1.data')
        self.assertEqual(set(keys), {0, 8, 48, 49, 50, 51, 160, 252, 254})
        self.assertIn('received_CRC32', rec['layout'])
        self.assertEqual(self.evidence['upgrade_package_record']['property_key'], 'ota.record.v1.upgrade.package')
        self.assertEqual(self.evidence['upgrade_package_record']['size_bytes'], 40)

    def test_module_catalog_and_limits(self):
        catalog = {r['file_type']: r['install_path'] for r in self.evidence['module_catalog']}
        self.assertEqual(len(self.evidence['module_catalog']), 13)
        self.assertEqual(catalog[0], '/mnt/data/ota/firmware.bin')
        self.assertEqual(catalog[8], '/mnt/data/ota/data.bin')
        self.assertEqual(catalog[19], '/mnt/data/resources/offlineasr_data.zip')
        self.assertEqual(self.evidence['size_limits'], {'firmware': 0x20000000, 'data': 0x200000})
        self.assertEqual(len(self.evidence['delegate_callbacks']), 6)


if __name__ == '__main__':
    unittest.main()
