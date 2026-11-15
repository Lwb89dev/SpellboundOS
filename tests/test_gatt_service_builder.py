import struct
import unittest

from analysis_scripts.gatt_service_builder import recover


def fixture():
    data = bytearray(0x200)
    data[0x20:0x25] = b'FEE0\0'
    data[0x30:0x37] = b'2A4D11\0'
    struct.pack_into('<II', data, 0x100, 0x1020, 0x1030)
    source = '''void candidate_7035e766(void) {
      undefined4 uStack_40; undefined4 uStack_3c; undefined4 *puStack_38;
      undefined4 uStack_30; undefined4 uStack_2c; undefined4 uStack_28;
      uStack_40 = uRam00001100; uStack_3c = 1; puStack_38 = &uStack_30;
      (*(code *)0x70947ce8)(&uStack_30,0,12);
      uStack_30 = uRam00001104; uStack_2c = 0xa041a;
      uStack_28 = 0x01010008;
      iVar1 = candidate_703b2236(&uStack_40);
      if (iVar1 == 0) {
        uStack_2c = CONCAT22(uStack_2c._2_2_,0x12);
        uStack_28._0_2_ = 244;
        candidate_703b2236(&uStack_40);
      }
    }'''
    return data, source


class GattBuilderTest(unittest.TestCase):
    def test_reconstructs_stack_layout_and_qualified_uuid(self):
        data, source = fixture()
        first, second = recover(data, source, 0x1000)
        self.assertEqual(first['uuid'], 'fee0')
        char = first['characteristics'][0]
        self.assertEqual((char['uuid'], char['internal_identifier']), ('2a4d', '2a4d11'))
        self.assertEqual(char['conditional_descriptor_uuids'], ['2902', '2908'])
        self.assertEqual(char['extra_bytes'], [1, 1])
        char = second['characteristics'][0]
        self.assertEqual((char['properties_raw'], char['permissions_raw']), (0x12, 10))
        self.assertEqual(char['max_length_field'], 244)

    def test_missing_memset_does_not_invent_initial_bytes(self):
        data, source = fixture()
        source = source.replace('uStack_28 = 0x01010008;', '')
        source = source.replace('(*(code *)0x70947ce8)(&uStack_30,0,12);', '')
        with self.assertRaisesRegex(ValueError, 'uninitialized'):
            recover(data, source, 0x1000)

    def test_bad_uuid_and_registry_pointers_rejected(self):
        data, source = fixture()
        for value in (0xffffffff, 0x1080):
            changed = bytearray(data)
            struct.pack_into('<I', changed, 0x104, value)
            with self.subTest(pointer=value), self.assertRaises(ValueError):
                recover(changed, source, 0x1000)

    def test_unknown_expressions_and_control_flow_rejected(self):
        data, source = fixture()
        for changed in (source.replace('uStack_3c = 1', 'uStack_3c = unknown()'),
                        source.replace('iVar1 == 0', 'iVar1 != 0'), source + '\nwhile (1) {}'):
            with self.assertRaises(ValueError):
                recover(data, changed, 0x1000)

    def test_invalid_counts_and_absent_registration_rejected(self):
        data, source = fixture()
        for changed in (source.replace('uStack_3c = 1', 'uStack_3c = 0'), ''):
            with self.assertRaises(ValueError):
                recover(data, changed, 0x1000)


if __name__ == '__main__':
    unittest.main()
