import struct
import unittest

from analysis_scripts.js_cfunction_tables import Image
from analysis_scripts.sensor_classes import (
    called_functions, descriptor, enum_coverage, expand_table, registration,
)

BASE = 0x1000


def fixture():
    data = bytearray(0x800)
    for offset, text in ((0x20, b'heart'), (0x30, b'current'), (0x40, b'event'), (0x50, b'CHANGE')):
        data[offset:offset + len(text) + 1] = text + b'\0'
    struct.pack_into('<10I', data, 0x100,
                     0x1020, 0x1600, 0, 0, 0, 0x1200, 2, 0x1700, 1, 0x1620)
    struct.pack_into('<IBBhII', data, 0x200, 0x1030, 1, 2, 3330, 0x1640, 0)
    struct.pack_into('<IBBhII', data, 0x210, 0x1040, 0, 8, 0, 0x1300, 1)
    struct.pack_into('<IBBhII', data, 0x300, 0x1050, 0, 4, 0, 3330, 0)
    source = '''void FUN_ram_70450000(void) {
      _DAT_ram_70fbc108 = 0xd;
      FUN_ram_7045c792(param_1,0x70fbc100,&PTR_DAT_ram_00001020_ram_00001100);
    }'''
    return data, source


class SensorClassTest(unittest.TestCase):
    def setUp(self):
        self.data, self.source = fixture()
        self.image = Image(self.data, BASE)

    def test_registration_combines_code_id_and_binary_properties(self):
        result = registration(self.image, self.source)
        self.assertEqual(result['name'], 'heart')
        self.assertEqual(result['sensor_id'], 13)
        self.assertEqual(result['constructor'], 0x1620)
        current, event = result['properties']
        self.assertEqual((current['magic'], current['getter']), (3330, 0x1640))
        self.assertEqual(event['entries'][0]['value'], 3330)

    def test_missing_and_ambiguous_registration_or_id_rejected(self):
        for source in ('', self.source + self.source,
                       self.source.replace('_DAT_ram_70fbc108', '_DAT_ram_70fbc10c')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                registration(self.image, source)

    def test_bad_constructor_or_table_rejected(self):
        for offset, value in ((0x124, 0xffffffff), (0x118, 2048), (0x114, 0x9999)):
            data, _ = fixture()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                descriptor(Image(data, BASE), 0x1100)
        with self.assertRaises(ValueError):
            descriptor(self.image, 0x17f0)

    def test_cyclic_and_zero_length_table_rejected(self):
        struct.pack_into('<IBBhII', self.data, 0x300, 0x1040, 0, 8, 0, 0x1200, 2)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            descriptor(self.image, 0x1100)
        with self.assertRaises(ValueError):
            expand_table(self.image, 0x1200, 0)

    def test_aliases_count_as_one_registered_id(self):
        classes = [{'sensor_id': 19}]
        missing = enum_coverage(classes, [
            {'kind': 'int32', 'name': 'FAT_BURRING', 'value': 19},
            {'kind': 'int32', 'name': 'FAT_BURNING', 'value': 19},
            {'kind': 'int32', 'name': 'BODY_TEMP', 'value': 24},
        ])
        self.assertEqual(classes[0]['enum_names'], ['FAT_BURRING', 'FAT_BURNING'])
        self.assertEqual(missing, [{'sensor_id': 24, 'enum_names': ['BODY_TEMP']}])

    def test_duplicate_unknown_or_noninteger_ids_rejected(self):
        entries = [{'kind': 'int32', 'name': 'HEART', 'value': 13}]
        for classes in ([{'sensor_id': 13}, {'sensor_id': 13}], [{'sensor_id': 99}]):
            with self.assertRaises(ValueError):
                enum_coverage(classes, entries)
        with self.assertRaises(ValueError):
            enum_coverage([], [{'kind': 'object', 'name': 'x'}])

    def test_function_definition_is_excluded_from_call_list(self):
        self.assertEqual(called_functions(self.source), [0x7045c792])

    def test_optional_availability_callback_preserves_unknown_state(self):
        self.assertIsNone(registration(self.image, self.source)['availability_callback_assignment'])
        source = self.source.replace('0xd;', '0xd; _DAT_ram_70fbc140 = &LAB_ram_70451234;')
        self.assertEqual(registration(self.image, source)['availability_callback_assignment'], 0x70451234)


if __name__ == '__main__':
    unittest.main()
