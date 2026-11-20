import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import sensorhub_imu_fifo as fifo
from analysis_scripts import sensorhub_imu_probe as probe


class SensorhubImuFifoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fifo.native_vectors()
        cls.cases = {c['name'].removeprefix('sensorhub_imu_fifo_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-fifo.json').read_bytes())

    def row(self, name):
        return self.cases[name]['expected']['rows'][0]

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def packet(self, name):
        return bytes.fromhex(self.row(name)['snapshot'][str(fifo.PACKET)])

    def samples(self, name, n):
        p = self.packet(name)
        return [struct.unpack_from('<hhh', p, 0x40 + 6 * i) for i in range(n)]

    def events(self, name):
        return [struct.unpack('<HHI', bytes.fromhex(a[4:])) for a in self.actions(name) if a.startswith('cap:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (28, 28))
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_fifo_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= fifo.BOUND)

    def test_bulk_read_and_packet_header(self):
        acts = self.actions('three_accel_words')
        bulk = [a for a in acts if a.startswith('spi:') and a.split(':')[2] == '22']
        self.assertEqual(len(bulk), 1)
        self.assertTrue(bulk[0].endswith(':f8' + '00' * 15))
        p = self.packet('three_accel_words')
        hdr = 0x18
        self.assertEqual(struct.unpack_from('<HH', p, 0), (1, 18))
        self.assertEqual(struct.unpack_from('<Q', p, hdr)[0], 2)
        self.assertEqual(struct.unpack_from('<Q', p, hdr + 8)[0], fifo.TS)
        self.assertEqual(struct.unpack_from('<IHH', p, hdr + 0x10), (4096, 3, 25))
        self.assertEqual(self.samples('three_accel_words', 3), [(100, -200, 4096), (101, -202, 4095), (102, -204, 4094)])
        self.assertIn(f'w:{fifo.BUFFERED}:2:3', acts)
        self.assertEqual(self.row('three_accel_words')['a0'], 0)

    def test_orientation_table_applied(self):
        x, y, z = 1000, -2000, 4096
        for o, (m0, m1, m2, m3, m4) in enumerate(fifo.ORIENTATION):
            got = self.samples(f'orientation_{o}', 1)[0]
            self.assertEqual(got, (m0 * x + m1 * y, m2 * x + m3 * y, m4 * z))
        self.assertEqual(self.samples('wrist_flip_negates_xy', 1)[0], (-1000, 2000, 4096))
        self.assertEqual(self.samples('orientation_out_of_range_logged', 1)[0], (100, -200, 4096))

    def test_offsets_and_tags(self):
        self.assertEqual(self.samples('calibration_offsets_added', 1)[0], (110, -220, 4096 + 0x30))
        self.assertEqual(self.events('mixed_tags_gyro_skipped_count_mismatch'), [(0x102, 0, 0)])
        self.assertEqual(self.samples('gyro_flag_even_pairs', 2), [(4, 5, 6), (10, 11, 12)])
        self.assertIn(f'w:{fifo.OUT}:2:1', self.actions('gyro_flag_even_pairs'))

    def test_timestamp_backdating_and_rate(self):
        p = self.packet('timestamp_backdated_by_remaining')
        # 40 in FIFO, 150 buffered -> 10 taken, 30 left; 1000 // 104 = 9 ms per word.
        self.assertEqual(struct.unpack_from('<Q', p, 0x18 + 8)[0], fifo.TS - 9 * 30)
        self.assertEqual(struct.unpack_from('<H', p, 0x18 + 0x16)[0], 100)
        self.assertEqual(struct.unpack_from('<H', self.packet('rate_833_rounded'), 0x18 + 0x16)[0], 825)

    def test_error_paths(self):
        self.assertEqual(self.row('inactive_returns_3')['a0'], 3)
        self.assertEqual(self.row('large_read_heap_failure')['a0'], 10)
        self.assertEqual(self.row('spi_failure')['a0'], 4)
        self.assertEqual(self.row('packet_alloc_failure')['a0'], 0)
        self.assertEqual(self.row('cache_full_overflow_event')['a0'], 6)
        self.assertEqual(self.events('cache_full_overflow_event'), [(0x102, 0, 0)])
        self.assertIn(f'call:{fifo.RESTORE}', self.actions('cache_full_third_overflow_restores'))
        self.assertEqual(self.row('fifo_overrun_event')['a0'], 6)
        dump = [a for a in self.actions('fifo_overrun_with_dump') if a.startswith('spi:')]
        self.assertEqual(len(dump), 3 + 0x80 + 2)

    def test_heap_buffer_above_60_words(self):
        acts = self.actions('large_read_uses_heap_buffer')
        self.assertIn(f'call:{fifo.MALLOC}:4:{fifo.TAG_STR}:{61 * 7 + 1}:4', acts)
        self.assertIn(f'call:{fifo.FREE}:4:{fifo.TAG_STR}:{fifo.BIG}', acts)

    def test_algorithm_event_and_release(self):
        self.assertEqual(self.events('algorithm_flag_posts_event'), [(0x10e, 0, 0)])
        self.assertIn(f'call:{fifo.FREE}:4:{fifo.PKT_TAG_STR}:{fifo.PACKET}', self.actions('queue_refused_packet_freed'))
        self.assertNotIn(f'call:{fifo.FREE}:4:{fifo.PKT_TAG_STR}:{fifo.PACKET}', self.actions('three_accel_words'))

    def test_remap_sample_helper(self):
        self.assertEqual(fifo.remap_sample(1, 2, 3, (0, -1, 1, 0, 1), 0), (0xfffe, 1, 3))
        self.assertEqual(fifo.remap_sample(1, 2, 3, (1, 0, 0, 1, 1), 1), (0xffff, 0xfffe, 3))

    def test_evidence_orientation_matches_constants(self):
        self.assertEqual(self.evidence['orientation']['entries'], [list(t) for t in fifo.ORIENTATION])
        self.assertEqual(probe.SPI_TIMEOUT, 5000)


if __name__ == '__main__':
    unittest.main()
