import struct
import unittest

from analysis_scripts.notification_pipeline import EvictionRecord, inspect_listeners, select_app_eviction
from analysis_scripts.sensorhub_memory import StartupMemory


class NotificationPipelineTest(unittest.TestCase):
    def memory(self):
        image = bytearray(256)
        struct.pack_into('<2I', image, 0, 0x1020, 0x1040)
        struct.pack_into('<6I', image, 0x20, 0x1080, 0x10c0, 0, 0, 0, 0x10c2)
        struct.pack_into('<6I', image, 0x40, 0x1090, 0x10c4, 0, 0, 0, 0)
        image[0x80:0x88] = b'message\0'
        image[0x90:0x95] = b'call\0'
        return image

    def inspect(self, image, **kwargs):
        memory = StartupMemory(image, 0x1000, 0, 0, 0, 0)
        return inspect_listeners(memory, 0x1000, **kwargs)

    def test_android_records_are_distinct_and_preserve_missing_callbacks(self):
        records = self.inspect(self.memory())
        self.assertEqual([record['name'] for record in records], ['message', 'call'])
        self.assertEqual(records[0]['callbacks']['legacy_message'], 0x10c0)
        self.assertEqual(records[0]['callbacks']['rich_message'], 0x10c2)
        self.assertEqual(records[1]['callbacks']['reply_result'], 0)

    def test_invalid_record_and_callback_pointers_fail(self):
        for offset, pointer in ((0, 0), (0, 0x1021), (0, 0x10fc),
                                (0x24, 0x10c1), (0x24, 0x1100), (0x20, 0x1100)):
            with self.subTest(offset=offset, pointer=pointer):
                image = self.memory()
                struct.pack_into('<I', image, offset, pointer)
                with self.assertRaises(ValueError):
                    self.inspect(image)
        for count in (0, 17):
            with self.assertRaises(ValueError):
                self.inspect(self.memory(), count=count)

    def test_threshold_is_existing_twenty_and_matches_app_not_total(self):
        same = [EvictionRecord(b'app', i) for i in range(19)]
        self.assertIsNone(select_app_eviction(same, b'app'))
        self.assertIsNone(select_app_eviction(same + [EvictionRecord(b'other', 0)], b'app'))
        self.assertEqual(select_app_eviction(same + [EvictionRecord(b'app', 25)], b'app'), 0)

    def test_zero_priority_word_wins_before_age(self):
        records = [EvictionRecord(b'app', 0, 1) for _ in range(20)]
        records[7] = EvictionRecord(b'app', 99, 0)
        self.assertEqual(select_app_eviction(records, b'app'), 7)
        records[11] = EvictionRecord(b'app', 100, 0)
        self.assertEqual(select_app_eviction(records, b'app'), 7)

    def test_nonzero_priority_is_boolean_and_timestamp_ties_choose_later(self):
        records = [EvictionRecord(b'app', 9, i + 1) for i in range(20)]
        self.assertEqual(select_app_eviction(records, b'app'), 19)
        records[5] = EvictionRecord(b'app', 1, 0xffffffff)
        self.assertEqual(select_app_eviction(records, b'app'), 5)

    def test_scan_stops_at_twentieth_match_and_keeps_absolute_index(self):
        records = [EvictionRecord(b'other', 0)] + [EvictionRecord(b'app', 100) for _ in range(20)]
        records += [EvictionRecord(b'app', 1)]
        self.assertEqual(select_app_eviction(records, b'app'), 20)
        self.assertIsNone(select_app_eviction(records, None))

    def test_model_rejects_non_native_words_and_embedded_terminators(self):
        for app, timestamp, priority in ((b'a\0b', 0, 0), ('app', 0, 0),
                                         (b'app', -1, 0), (b'app', 0, 2**32),
                                         (b'app', True, 0)):
            with self.subTest(app=app, timestamp=timestamp, priority=priority), self.assertRaises(ValueError):
                EvictionRecord(app, timestamp, priority)


if __name__ == '__main__':
    unittest.main()
