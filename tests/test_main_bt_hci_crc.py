import json
from pathlib import Path
import unittest

from analysis_scripts import main_bt_hci_crc as bt


class MainBtHciCrcTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_bt_hci_crc_'): c for c in bt.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-bt-hci-crc.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (7, 7))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_bt_hci_crc_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_modbus_check_vector_and_chaining(self):
        self.assertEqual(self.cases['ascii']['expected']['rows'][0]['a0'], 0x4B37)
        self.assertEqual(self.cases['empty']['expected']['rows'][0]['a0'], 0xFFFF)
        # Feeding chunk-1's running CRC into chunk-2 equals hashing the 16 bytes in one pass.
        self.assertEqual(self.cases['chunk_chain']['expected']['rows'][0]['a0'],
                         bt.crc16_update(0xFFFF, bytes(range(16))))

    def test_reference(self):
        self.assertEqual(bt.crc16_update(0xFFFF, b'123456789'), 0x4B37)
        self.assertEqual(bt.crc16_update(0xFFFF, b''), 0xFFFF)

    def test_contract(self):
        c = self.evidence['crc16']
        self.assertEqual(c['function'], '0x703ceb56(crc, buffer, length)')
        self.assertIn('0xA001', c['algorithm'])
        self.assertEqual(c['check_vector'], {'input': '123456789', 'crc16': '0x4b37'})


if __name__ == '__main__':
    unittest.main()
