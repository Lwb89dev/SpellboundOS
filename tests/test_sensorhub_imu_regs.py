import json
from pathlib import Path
import unittest

from analysis_scripts import sensorhub_imu_probe as probe
from analysis_scripts import sensorhub_imu_regs as regs


def spi(tx):
    return f'spi:{probe.SPI_HANDLE}:{len(tx) // 2}:{probe.SPI_TIMEOUT}:{tx}'


class SensorhubImuRegsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = regs.native_vectors()
        cls.cases = {c['name'].removeprefix('sensorhub_imu_regs_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-regs.json').read_bytes())

    def expected(self, name):
        return self.cases[name]['expected']

    def spis(self, name):
        return [a for a in self.expected(name)['actions'] if a.startswith('spi:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (95, 95))
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_regs_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= regs.BOUND)

    def test_every_accessor_is_listed(self):
        table = {r['address']: r for r in self.evidence['accessors']}
        self.assertEqual(len(table), len(regs.SETTERS) + len(regs.GETTERS) + len(regs.RAW) + 2)
        self.assertEqual(table['0x80f7291a']['fields'], [dict(register='0x10', field_mask='0x0c')])
        self.assertEqual(table['0x80f72cf8']['fields'], [dict(register='0x18', field_mask='0x02'),
                                                         dict(register='0x62', field_mask='0x18')])

    def test_full_scale_setter_is_masked_read_modify_write(self):
        self.assertEqual(self.spis('xl_full_scale_set_set_from_zero'), [spi('9000'), spi('100c')])
        self.assertEqual(self.spis('xl_full_scale_set_clear_from_ones'), [spi('9000'), spi('10f3')])
        self.assertEqual(self.spis('gy_full_scale_set_value_one'), [spi('9100'), spi('11a3')])

    def test_unmasked_shift_setters_drop_overflow(self):
        # ODR field: (val << 4) | (old & 0x0f); 0xff << 4 keeps 0xf0 in the byte.
        self.assertEqual(self.spis('xl_data_rate_set_set_from_zero')[-1], spi('10f0'))
        # boot_set/gy_power_mode_set: val << 7; val 0xff -> 0x80 within the byte.
        self.assertEqual(self.spis('boot_set_set_from_zero')[-1], spi('1280'))

    def test_two_register_setters(self):
        self.assertEqual(self.spis('xl_power_mode_set_set_from_zero'),
                         [spi('9400'), spi('1480'), spi('9500'), spi('1510')])
        self.assertEqual(self.spis('i3c_disable_set_set_from_zero'),
                         [spi('9800'), spi('1802'), spi('e200'), spi('6218')])
        self.assertEqual(self.expected('xl_power_mode_set_second_read_error')['rows'][0]['a0'], 1)
        self.assertEqual(len(self.spis('i3c_disable_set_first_write_error')), 2)

    def test_setter_errors(self):
        self.assertEqual(self.spis('xl_full_scale_set_read_error'), [spi('9000')])
        self.assertEqual(self.expected('xl_full_scale_set_read_error')['rows'][0]['a0'], 1)
        self.assertEqual(self.expected('xl_full_scale_set_write_error')['rows'][0]['a0'], 1)

    def test_getters_extract_fields(self):
        def out(name):
            return self.expected(name)['rows'][0]['snapshot'][str(regs.OUT)][:2]
        self.assertEqual(out('mem_bank_get_42'), '01')
        self.assertEqual(out('mem_bank_get_80'), '02')
        self.assertEqual(out('mem_bank_get_ff'), '00')
        self.assertEqual(out('boot_get_80'), '01')
        self.assertEqual(out('gy_flag_data_ready_get_42'), '01')
        self.assertEqual(out('fifo_ovr_flag_get_42'), '01')

    def test_raw_reads_and_fifo_level(self):
        self.assertEqual(self.spis('acceleration_raw_get_data'), [spi('a8' + '00' * 6)])
        self.assertEqual(self.spis('angular_rate_raw_get_data'), [spi('a2' + '00' * 6)])
        snap = self.expected('acceleration_raw_get_data')['rows'][0]['snapshot'][str(regs.OUT)]
        self.assertEqual(snap, '1112131415160000')
        level = self.expected('fifo_data_level_get_10_c1')['rows'][0]['snapshot'][str(regs.OUT)]
        self.assertEqual(level[:4], '1001')     # 0x10 + (0xc1 & 3) << 8 = 0x110
        zero = self.expected('odr_cal_reg_get_error_stores_zero')['rows'][0]
        self.assertEqual((zero['a0'], zero['snapshot'][str(regs.OUT)][:2]), (1, '00'))

    def test_model_rejects_unmodeled_paths(self):
        case = dict(self.cases['boot_get_00'])
        with self.assertRaises(ValueError):
            regs.contract(dict(case, spi=[probe.fail(2)]))
        with self.assertRaises(ValueError):
            regs.contract(dict(case, scope='other'))


if __name__ == '__main__':
    unittest.main()
