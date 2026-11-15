import json
import struct
import unittest

from analysis_scripts.application_payloads import encode_notification
from analysis_scripts.native_channel import encode_data, make_envelope, mix_key
from analysis_scripts.notification_protocol import (
    decode_action, decode_capabilities, decode_image_request, decode_logo_response,
    decode_reply, decode_reply_result, diagnostic_capture, encode_action, encode_reply,
    named_notification,
)
from analysis_scripts.verify_gadgetbridge_channel import aes_ecb, verify


class NotificationProtocolTest(unittest.TestCase):
    def test_named_fields_and_category_three_phone_number(self):
        wire = encode_notification(42, 3, 2, (b'app', b'Title', b'Body', b'App', b'+123'), True,
                                   optional_byte=0x81, optional_bool=True, optional_string=b'extra')
        notification = named_notification(wire)
        self.assertEqual((notification['identifier'], notification['category_id'], notification['event_id']), (42, 3, 2))
        self.assertEqual((notification['app_id'], notification['title'], notification['message'],
                          notification['app_name'], notification['phone_number']),
                         (b'app', b'Title', b'Body', b'App', b'+123'))
        self.assertTrue(notification['reply_available'])
        self.assertEqual(notification['event_flags'], 0x81)

    def test_action_golden_and_optional_id_direction(self):
        self.assertEqual(encode_action(1), b'\x05\x01')
        self.assertEqual(encode_action(2), b'\x05\x02')
        self.assertEqual(encode_action(3, 0x12345678), bytes.fromhex('05 03 78 56 34 12'))
        self.assertEqual(decode_action(encode_action(3, 0x12345678))['identifier'], 0x12345678)
        self.assertIsNone(decode_action(b'\x05\x09')['identifier'])
        self.assertEqual(decode_action(b'\x05\x02tail')['ignored_trailing'], b'tail')
        with self.assertRaises(ValueError):
            encode_action(2, 42)
        with self.assertRaises(ValueError):
            encode_action(3)

    def test_action_truncation_and_wrong_opcode(self):
        wire = encode_action(3, 42)
        for size in range(len(wire)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_action(wire[:size])
        with self.assertRaises(ValueError):
            decode_action(b'\x04\x01')

    def test_text_reply_and_reply_result(self):
        self.assertEqual(encode_reply(0x12345678, b'OK'), bytes.fromhex('04 78 56 34 12 4f 4b 00'))
        reply = decode_reply(encode_reply(42, 'caffè'.encode()) + b'tail')
        self.assertEqual((reply['identifier'], reply['text'], reply['ignored_trailing']), (42, 'caffè'.encode(), b'tail'))
        self.assertEqual(decode_reply(encode_reply(42, b''))['text'], b'')
        self.assertEqual(decode_reply_result(bytes.fromhex('06 78 56 34 12 07'))['result_raw'], 7)
        for wire in (b'\x04\x01', b'\x04\x01\x00\x00\x00unterminated'):
            with self.assertRaises(ValueError):
                decode_reply(wire)
        with self.assertRaises(ValueError):
            encode_reply(42, b'a\0b')
        with self.assertRaises(ValueError):
            encode_reply(42, b'a' * 32768)

    def test_logo_and_message_image_requests_have_different_height_guard(self):
        request = b'\x10app\0' + struct.pack('<BHH', 5, 128, 128)
        self.assertEqual((decode_image_request(request)['format_raw'], decode_image_request(request)['width']), (5, 128))
        message = b'\x19app\0' + struct.pack('<IBHH', 42, 5, 128, 0)
        self.assertEqual(decode_image_request(message)['height'], 0)
        for data in (b'\x10\0' + struct.pack('<BHH', 5, 128, 128),
                     b'\x10app\0' + struct.pack('<BHH', 11, 128, 128),
                     b'\x10app\0' + struct.pack('<BHH', 5, 0, 128),
                     b'\x10app\0' + struct.pack('<BHH', 5, 128, 0), request[:-1]):
            with self.assertRaises(ValueError):
                decode_image_request(data)
        self.assertEqual(decode_logo_response(b'\x11app\0\x01')['status_raw'], 1)

    def test_capabilities_versions_and_feature_blob(self):
        for version, middle in ((2, b''), (3, b'\x01'), (4, b'\x01\x00'), (5, b'\x01\x00')):
            wire = struct.pack('<BBH', 2, version, 100) + middle + b'\x01\x00\x00\x00'
            self.assertEqual(decode_capabilities(wire)['maximum'], 100)
        wire = bytes.fromhex('02 05 64 00 01 01 03 00') + b'abc' + b'\x01\x00\x00\x00'
        self.assertEqual(decode_capabilities(wire)['feature_bytes'], b'abc')
        for changed in (wire[:-1], wire[:9], b'\x03\x05\x64\x00'):
            with self.assertRaises(ValueError):
                decode_capabilities(changed)

    def test_transfer_observer_sees_only_verified_payload_and_report_stays_private(self):
        key = bytes(range(16))
        body = b'private synthetic text'
        envelope = make_envelope(body, 5, padding=bytes(-(len(body) + 8) % 16))
        cipher = aes_ecb(mix_key(key, 2), envelope, encrypt=True)
        raw = encode_data(11, 1, 2, 0, cipher, total_size=len(body), module_id=30)
        prefix = 'Shared Session Key: ' + key.hex() + '\n'
        line = 'WriteAction 00000016-0000-3512-2118-0009af100700 >@ ' + raw.hex() + '\n'
        observations = []
        report = verify(prefix + line, on_transfer=lambda **value: observations.append(value))
        self.assertEqual(observations[0]['payload'], body)
        self.assertNotIn(body.decode(), json.dumps(report))
        corrupted = bytearray(raw)
        corrupted[-1] ^= 1
        observations.clear()
        bad_line = line.replace(raw.hex(), corrupted.hex())
        with self.assertRaises(ValueError):
            verify(prefix + bad_line, on_transfer=lambda **value: observations.append(value))
        self.assertEqual(observations, [])

    def test_diagnostic_summary_requires_controlled_title_and_excludes_content(self):
        key = bytes(range(16))
        payload = encode_notification(42, 250, 0, (b'nodomain.freeyourgadget.gadgetbridge',
            b'Spellbound_RE_test', b'Notification body', b'Gadgetbridge'), False)
        envelope = make_envelope(payload, 1, padding=bytes(-(len(payload) + 8) % 16))
        ciphertext = aes_ecb(mix_key(key, 3), envelope, encrypt=True)
        raw = encode_data(11, 1, 3, 0, ciphertext, total_size=len(payload), module_id=30)
        text = 'WriteAction 00000016-0000-3512-2118-0009af100700 >@ ' + raw.hex()
        key_capture = 'Shared Session Key: ' + key.hex()
        summary = diagnostic_capture(text, key_capture)
        self.assertTrue(summary['observations'][0]['expected_fields_match'])
        self.assertNotIn('Notification body', json.dumps(summary))
        self.assertNotIn(key.hex(), json.dumps(summary))
        with self.assertRaises(ValueError):
            diagnostic_capture('', key_capture)
        with self.assertRaises(ValueError):
            diagnostic_capture(text, key_capture + '\nShared Session Key: ' + bytes(16).hex())


if __name__ == '__main__':
    unittest.main()
