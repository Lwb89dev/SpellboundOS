import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_board_records as board


class FakeMemory:
    def __init__(self, base, data):
        self.base, self.data = base, data

    def read(self, address, size):
        off = address - self.base
        if off < 0 or off + size > len(self.data):
            raise ValueError('unmapped')
        return self.data[off:off + size]


class MainBoardRecordsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(Path('analysis/main-board-records.json').read_bytes())
        cls.records = {r['name']: r for r in cls.evidence['records']}

    def test_registration_sequence(self):
        self.assertEqual(tuple(self.records), board.EXPECTED_NAMES)
        self.assertEqual(self.evidence['record_count'], 22)

    def test_peripheral_buses_and_rails(self):
        z = self.records['dev_ztw622']['decoded']
        self.assertEqual((z['bus'], z['reset_pin'], z['interrupt_pin'], z['vdda_rail'], z['vddd_rail']),
                         ('i2c3', 15, 21, 'LDO2_TP', 'TP_1V8'))
        self.assertEqual(self.records['dev_stk31e60']['decoded'], dict(bus='i2c3', rail='TP_1V8'))
        self.assertEqual(self.records['dev_cw6305']['decoded']['bus'], 'sens_i2c1')
        self.assertEqual(self.records['dev_ag3335']['decoded']['rails'], ['GPS_1V8', 'GPS_0V8'])
        self.assertEqual(self.records['dev_bluebox']['decoded']['bus'], 'uart2')
        self.assertEqual(self.records['dev_psram0']['decoded']['word2_hz'], 198000000)
        self.assertEqual(self.records['dev_icna3311']['decoded']['rails'], ['LCD_1V8', 'LCD_3V3'])
        self.assertEqual(self.records['system_info']['decoded']['product'], 'Amazfit Bip 6')

    def test_scanner_on_synthetic_code(self):
        base = 0x1000
        # auipc a1,0 ; addi a1,a1,0x100 ; c.li a2,8 ; auipc a0,0 ; addi a0,a0,0x200 ;
        # auipc ra,0 ; jalr ra,ra,X  where X reaches REGISTER from base+0x14
        target = board.REGISTER
        code = struct.pack('<IIHII', 0x00000597, 0x10058593, 0x4621, 0x00000517, 0x20050513)
        site = base + len(code)
        delta = target - site
        hi = (delta + 0x800) & 0xfffff000
        lo = delta - hi
        code += struct.pack('<II', 0x00000097 | hi, 0x000080e7 | ((lo & 0xfff) << 20))
        mem = FakeMemory(base, code + b'\0' * 0x400)
        rows = board.scan(mem, base, base + len(code))
        self.assertEqual(rows, [(base + 0xa + 0x200, base + 0x100, 8, site + 4)])

    def test_unresolved_operand_rejected(self):
        with self.assertRaises(ValueError):
            board._row({}, 0)


if __name__ == '__main__':
    unittest.main()
