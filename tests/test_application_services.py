import unittest
from analysis_scripts.application_services import captured_announcement, parse_announcement, recover_descriptor
from analysis_scripts.native_channel import encode_data


SOURCE = '''void registration(void) {
  undefined4 uStack_5c;
  undefined4 uStack_58;
  code *pcStack_1c;
  (*(code *)0x70947ce8)(&uStack_5c,0,0x4c);
  uStack_5c = 0x1011e;
  uStack_58 = 0x703893fc;
  pcStack_1c = candidate_7038946a;
  iVar1 = func_0x7036c636(&uStack_5c);
}'''


class ApplicationServicesTest(unittest.TestCase):
    def test_golden_announcement(self):
        self.assertEqual(parse_announcement(bytes.fromhex('04 02 00 1e 00 01 0b 00 00')),
                         [{'module_id': 30, 'announced_encrypted': True},
                          {'module_id': 11, 'announced_encrypted': False}])

    def test_invalid_counts_flags_duplicates_and_trailing(self):
        for hex_data in ('', '04', '03 00 00', '04 01 00', '04 00 00 ff',
                         '04 01 00 01 00 02', '04 02 00 01 00 00 01 00 01'):
            with self.subTest(hex_data=hex_data), self.assertRaises(ValueError):
                parse_announcement(bytes.fromhex(hex_data))

    def test_crosschecks_native_payload_and_labels(self):
        data = bytes.fromhex('04 01 00 1e 00 01')
        wire = encode_data(3, 1, 2, 0, data, total_size=len(data), module_id=0)
        capture = ('onCharacteristicChanged: 00000017-0000-3512-2118-0009af100700 <@ ' + wire.hex() + '\n'
                   'Plaintext data 0x0000: ' + data.hex() + '\n'
                   'Zepp OS Service: endpoint=001e encrypted=true name=ZeppOsNotificationService\n')
        self.assertEqual(captured_announcement(capture)[0]['gadgetbridge_label'], 'ZeppOsNotificationService')
        for changed in (capture.replace('encrypted=true', 'encrypted=false'),
                        capture.replace('endpoint=001e', 'endpoint=000b'),
                        capture.replace('ZeppOsNotificationService', 'PRIVATE_NAME'),
                        capture.replace('Plaintext data 0x0000:', 'other data:')):
            with self.assertRaises(ValueError):
                captured_announcement(changed)

    def test_recovers_policy_bytes_and_callback_offsets(self):
        descriptor = recover_descriptor(SOURCE)
        self.assertEqual((descriptor['module_id'], descriptor['require_authorization_raw'],
                          descriptor['require_encryption_raw']), (30, 1, 1))
        self.assertEqual(descriptor['receive_callbacks'], {'0x40': 0x7038946a})
        self.assertEqual(descriptor['unknown_byte_offsets'], [])

    def test_partial_and_array_assignments(self):
        source = SOURCE.replace('undefined4 uStack_5c;', 'undefined2 uStack_5c[2];')
        source = source.replace('uStack_5c = 0x1011e;', 'uStack_5c[0] = 0x11e; uStack_5c[1] = 1;')
        descriptor = recover_descriptor(source)
        self.assertEqual((descriptor['module_id'], descriptor['require_authorization_raw'],
                          descriptor['require_encryption_raw']), (30, 1, 1))
        partial = recover_descriptor(SOURCE.replace('uStack_5c = 0x1011e;', 'uStack_5c._0_1_ = 30;'))
        self.assertEqual(partial['require_encryption_raw'], 0)
        concat = SOURCE.replace('undefined4 uStack_5c;', 'uint uStack_5c[2];')
        concat = concat.replace('uStack_5c = 0x1011e;', 'uStack_5c[0] = CONCAT22(uStack_5c[0]._2_2_,0x13c);')
        self.assertEqual(recover_descriptor(concat)['module_id'], 0x3c)

    def test_guarded_raw_u16_prefix_does_not_invent_pointer_width(self):
        source = SOURCE.replace('undefined4 uStack_5c;', 'undefined *apuStack_5c[2];')
        source = source.replace('(&uStack_5c', '(apuStack_5c')
        source = source.replace('uStack_5c = 0x1011e;', 'apuStack_5c[0] = &scause;')
        override = {'expression': '&scause', 'value': 0x142, 'store_width': 2}
        descriptor = recover_descriptor(source, prefix_override=override)
        self.assertEqual((descriptor['module_id'], descriptor['require_authorization_raw'],
                          descriptor['require_encryption_raw']), (0x42, 1, 0))
        self.assertEqual(descriptor['receive_callbacks'], {'0x40': 0x7038946a})

    def test_dynamic_registrar_keeps_same_descriptor_layout(self):
        descriptor = recover_descriptor(SOURCE.replace('7036c636(', '7036c834('))
        self.assertEqual(descriptor['registrar'], 0x7036c834)
        self.assertEqual(descriptor['module_id'], 30)

    def test_dynamic_values_are_unknown_not_zero(self):
        descriptor = recover_descriptor(SOURCE.replace('uStack_5c = 0x1011e;',
                                                     'uStack_5c = param_1; uStack_5c._0_1_ = 30;'))
        self.assertEqual(descriptor['module_id'], 30)
        self.assertIsNone(descriptor['require_encryption_raw'])
        self.assertEqual(descriptor['unknown_byte_offsets'], [1, 2, 3])

    def test_unsupported_mutations_and_missing_zeroing_fail(self):
        for source in (SOURCE.replace('0,0x4c', '0,0x48'),
                       SOURCE.replace('uStack_5c = 0x1011e;', 'if (param_1) uStack_5c = 0x1011e;'),
                       SOURCE.replace('uStack_5c = 0x1011e;', 'mutate(&uStack_5c);'),
                       SOURCE.replace('uStack_5c = 0x1011e;', '*(int *)&uStack_5c = 0x1011e;')):
            with self.assertRaises(ValueError):
                recover_descriptor(source)


if __name__ == '__main__':
    unittest.main()
