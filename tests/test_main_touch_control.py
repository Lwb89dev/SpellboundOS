import json
from pathlib import Path
import unittest

from analysis_scripts import main_touch_control as ctl
from analysis_scripts import main_touch_report as rpt


class MainTouchControlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = ctl.native_vectors()
        cls.cases = {c['name'].removeprefix('main_touch_control_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-touch-control.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def result(self, name):
        return self.cases[name]['expected']['rows'][0]['a0']

    def calls(self, name, *targets):
        return [a for a in self.actions(name) if a.split(':')[0] == 'call' and int(a.split(':')[1]) in targets]

    def writes(self, name):
        return [a.rsplit(':', 1)[1] for a in self.actions(name) if a.startswith(f'bus:{rpt.BUS_WRITE}:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (23, 23))
        for row in report['cases']:
            name = row['name'].removeprefix('main_touch_control_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= ctl.BOUND)

    def test_attach_power_up_order(self):
        seq = self.calls('attach_probe_info_block', ctl.REG_ENABLE, ctl.REG_DISABLE, ctl.REG_DISCHARGED,
                         ctl.REG_GET, ctl.DELAY, ctl.GPIO_WRITE)
        vdda, vddd = (int.from_bytes(ctl.BSD_RECORD[o:o + 4], 'little') for o in (0xc, 0x10))
        self.assertEqual(seq[:12], [
            f'call:{ctl.GPIO_WRITE}:15:0',
            f'call:{ctl.REG_GET}:{vdda}', f'call:{ctl.REG_DISABLE}:{ctl.REG_HANDLE}',
            f'call:{ctl.REG_GET}:{vdda}', f'call:{ctl.REG_DISCHARGED}:{ctl.REG_HANDLE}:5',
            f'call:{ctl.DELAY}:100',
            f'call:{ctl.REG_GET}:{vddd}', f'call:{ctl.REG_ENABLE}:{ctl.REG_HANDLE}',
            f'call:{ctl.REG_GET}:{vdda}', f'call:{ctl.REG_ENABLE}:{ctl.REG_HANDLE}',
            f'call:{ctl.DELAY}:1', f'call:{ctl.DELAY}:1',
        ])
        self.assertEqual(self.result('attach_probe_info_block'), ctl.DEVICE)

    def test_probe_bus_sequence(self):
        self.assertEqual(self.writes('attach_probe_info_block'), ['f801', '00c00100', 'd209', 'f80f'])
        self.assertEqual(self.writes('attach_info_block_wrong_id_then_register'), ['f801', '00c00100', 'd209',
                                                                                    'f80f', '2001'])
        self.assertEqual(self.result('attach_info_block_wrong_id_then_register'), ctl.DEVICE)
        self.assertEqual(self.result('attach_soft_reset_fails_reads_register'), ctl.DEVICE)

    def test_attach_failures_return_zero_and_release(self):
        for name in ('attach_wrong_chip_id_powers_down', 'attach_i2c_handle_missing', 'attach_i2c_config_fails',
                     'attach_vdda_not_discharged', 'attach_hardware_reset_fails'):
            self.assertEqual(self.result(name), 0)
            self.assertIn(f'call:{ctl.MUTEX_DELETE}:{rpt.MUTEX}', self.actions(name))
        self.assertNotIn(f'call:{ctl.I2C_RELEASE}:{rpt.I2C_HANDLE}', self.actions('attach_i2c_handle_missing'))
        self.assertIn(f'call:{ctl.I2C_RELEASE}:{rpt.I2C_HANDLE}', self.actions('attach_wrong_chip_id_powers_down'))
        self.assertEqual(len(self.calls('attach_wrong_chip_id_powers_down', ctl.GPIO_DEINIT)), 2)

    def test_hardware_reset_timing(self):
        seq = self.calls('reset_hardware', ctl.DELAY, ctl.GPIO_WRITE, ctl.BUS_SUSPEND, ctl.BUS_RESUME)
        self.assertEqual(seq, [
            f'call:{ctl.DELAY}:1', f'call:{ctl.GPIO_WRITE}:15:1', f'call:{ctl.DELAY}:10',
            f'call:{ctl.BUS_SUSPEND}:{rpt.I2C_HANDLE}', f'call:{ctl.GPIO_WRITE}:15:0', f'call:{ctl.DELAY}:100',
            f'call:{ctl.GPIO_WRITE}:15:1', f'call:{ctl.BUS_RESUME}:{rpt.I2C_HANDLE}', f'call:{ctl.DELAY}:200'])
        self.assertEqual(self.writes('reset_command_0ff8'), ['f80f'])
        self.assertEqual(self.writes('reset_command_0000'), ['0000'])
        self.assertEqual(self.result('reset_invalid_type'), ctl.word(-10))

    def test_modes(self):
        self.assertEqual(self.writes('mode_0b')[:6], ['22011f00', '35010900', '00012500', '7f006400', '0000',
                                                     '10000b00'])
        self.assertEqual(self.writes('mode_0e')[:2], ['10000e00', '0000'])
        self.assertEqual(self.writes('mode_01')[:5], ['22010d00', '35010000', '00013c00', '10000100', '0000'])
        self.assertEqual(self.writes('mode_01')[5:], ['0300'] * 5)

    def test_power_and_version(self):
        self.assertEqual(self.result('power_invalid_rail'), ctl.word(-10))
        self.assertEqual(self.result('power_without_record'), ctl.word(-4))
        self.assertEqual(self.result('power_regulator_missing'), 5)
        acts = self.actions('version')
        self.assertIn(f'w:{ctl.CTX + 0x18}:2:{0x1a0}', acts)
        self.assertIn(f'w:{ctl.CTX + 0xa}:2:3', acts)
        self.assertEqual(self.writes('version')[1:], ['1200', '2101', '1300', 'c000', 'c100', '6000', '6100',
                                                     '1f01'])
        self.assertEqual(self.result('version_reset_fails'), ctl.word(-1))
        self.assertEqual(self.result('version_glove_read_fails'), 6)


if __name__ == '__main__':
    unittest.main()
