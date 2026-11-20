import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import sensorhub_imu_init as init
from analysis_scripts import sensorhub_imu_probe as probe


class SensorhubImuInitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = init.native_vectors()
        cls.cases = {c['name'].removeprefix('sensorhub_imu_init_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-init.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def result(self, name):
        return self.cases[name]['expected']['rows'][0]['a0']

    def calls(self, name):
        return [a for a in self.actions(name) if a.startswith('call:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (11, 11))
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_init_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= init.BOUND)

    def test_board_records_from_original_registration_table(self):
        records = self.evidence['board_records']
        lsm = records['dev_lsm6dso']
        self.assertEqual((lsm['bus'], lsm['irq_pin'], lsm['irq_mode']), ('sens_spi1_dev0', 43, 4))
        self.assertTrue(records['dev_bmi2xx']['same_as_lsm6dso'])
        self.assertEqual(records['dev_ak09918']['bus'], 'sens_i2c2')
        self.assertEqual(records['dev_mmc5603']['bus'], 'sens_i2c2')
        self.assertEqual(records['dev_max8617x']['bus'], 'sens_spi0_dev0')
        self.assertEqual(records['dev_max8617x']['rails'], ['PPG_1V8', 'PPG_VLED'])
        self.assertEqual(records['system_info']['board'], 'Pamir')

    def test_full_attach_sequence(self):
        acts = self.actions('full_success')
        self.assertEqual(acts[1:6], [
            f'call:{init.BOARD_FIND}:{init.NAME_DEV}',
            f'call:{init.SPI_FIND}:{init.BUS_NAME}:{init.HANDLE_PTR}',
            f'call:{init.SPI_CONFIG}:{probe.SPI_HANDLE}',
            'cap:' + struct.pack('<5I', 8000000, 0x807, 0, 0, 0).hex(),
            f'w:{init.DEV_PTR}:4:{init.BSD}',
        ])
        self.assertIn('spi:%d:2:5000:e300' % probe.SPI_HANDLE, acts)   # INTERNAL_FREQ_FINE read
        self.assertEqual(self.calls('full_success')[-5:], [
            f'call:{init.GPIO_INIT}:43',
            f'call:{init.GPIO_INSTALL_IRQ}:43:4:{init.IRQ_HANDLER}:{init.DEV_PTR}',
            f'call:{init.GPIO_DISABLE_IRQ}:43',
            f'call:{init.SENSOR_REGISTER}:{init.ACC_DESC}',
            f'call:{init.SENSOR_REGISTER}:{init.GYR_DESC}',
        ])
        self.assertEqual(self.result('full_success'), 0)

    def test_odr_trim_is_stored_as_binary32(self):
        for name, fine in (('full_success', 0), ('odr_trim_negative', -20), ('odr_trim_positive', 37),
                           ('odr_read_error_uses_zero', 0)):
            bits = struct.unpack('<I', struct.pack('<f', 6667 * (1 + 0.0015 * fine) / 256))[0]
            self.assertIn(f'w:{init.ODR_PTR}:{init.EMULATED_FSW_BYTES}:{bits}', self.actions(name))
        self.assertAlmostEqual(self.evidence['odr_trim']['samples']['0'], 26.04296875)

    def test_error_results(self):
        self.assertEqual(self.result('board_record_missing'), 4)
        self.assertEqual(self.result('spi_handle_not_found'), 4)
        self.assertNotIn(f'call:{init.SPI_CONFIG}:{probe.SPI_HANDLE}', self.actions('spi_handle_not_found'))
        self.assertEqual(self.result('probe_fails'), 1)
        self.assertEqual(self.result('cache_alloc_fails'), 10)
        for name in ('gpio_init_fails_still_registers', 'irq_install_fails_still_registers',
                     'irq_disable_fails_still_registers'):
            self.assertEqual(self.result(name), 0)
            self.assertEqual(self.calls(name)[-2:], [f'call:{init.SENSOR_REGISTER}:{init.ACC_DESC}',
                                                     f'call:{init.SENSOR_REGISTER}:{init.GYR_DESC}'])

    def test_cache_publication(self):
        acts = self.actions('full_success')
        self.assertIn(f'w:{init.CACHE_PTR}:4:{init.CACHE_ADDRESS}', acts)
        self.assertIn(f'w:{init.CACHE_TAIL_PTR}:4:{init.CACHE_ADDRESS + 0x460}', acts)

    def test_auipc_addi_decoder(self):
        class Mem:
            def __init__(self, data):
                self.data = data

            def read(self, address, size):
                return self.data[:size]
        # auipc a0,0x72 ; addi a0,a0,-0xbe at 0x80f6258e
        raw = struct.pack('<II', 0x00072517, 0xf4250513)
        self.assertEqual(init.pc_pair(Mem(raw), 0x80f6258e), 0x80fd44d0)
        with self.assertRaises(ValueError):
            init.pc_pair(Mem(struct.pack('<II', 0x00072517, 0xf4258593)), 0)

    def test_contract_rejects_other_scopes(self):
        case = dict(self.cases['full_success'])
        with self.assertRaises(ValueError):
            init.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            init.contract(dict(case, spi=case['spi'] + [probe.write_ok()]))


if __name__ == '__main__':
    unittest.main()
