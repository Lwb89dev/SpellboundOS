import hashlib
import unittest

from analysis_scripts.auth_session import (
    cloud_binding_digest, decode_request, derive_material, encode_request, load_key, save_key,
)
from analysis_scripts.native_channel import decode, encode_data


class AuthSessionTest(unittest.TestCase):
    def test_golden_authorize_request_and_api_truncation(self):
        point = bytes(range(48))
        wire = encode_request(4, api_level=0x102, mode=1, values=(point,))
        self.assertEqual(wire, b'\x04\x02\x01\x01' + point)
        request = decode_request(wire)
        self.assertEqual((request.opcode, request.api_level_wire, request.api_level, request.mode), (4, 0x102, 2, 1))
        self.assertEqual(request.values, (point,))

    def test_auth_payload_has_native_module_82(self):
        auth = encode_request(5, values=(bytes(range(16)), bytes(range(16, 32))))
        self.assertEqual(auth, b'\x05' + bytes(range(32)))
        wire = encode_data(7, 1, 2, 0, auth, total_size=33, module_id=0x82)
        self.assertEqual(wire[:11], bytes.fromhex('03 07 01 02 00 21 00 00 00 82 00'))
        packet = decode(wire)
        self.assertEqual((packet.module_id, decode_request(packet.payload).opcode), (0x82, 5))

    def test_request_lengths_and_ignored_trailing(self):
        examples = {0: b'\x00', 1: b'\x01\x02\x00' + bytes(16),
                    2: b'\x02\x02\x00' + bytes(48), 3: b'\x03' + bytes(64),
                    4: b'\x04\x02\x00\x02' + bytes(48), 5: b'\x05' + bytes(32),
                    6: b'\x06', 7: b'\x07' + bytes(32), 8: b'\x08',
                    9: b'\x09', 10: b'\x0a', 11: b'\x0b'}
        for opcode, wire in examples.items():
            self.assertEqual(decode_request(wire).opcode, opcode)
            self.assertEqual(decode_request(wire + b'tail').ignored_trailing, b'tail')
            with self.subTest(opcode=opcode), self.assertRaises(ValueError):
                decode_request(wire[:-1])

    def test_invalid_encoding_and_unsupported_opcode(self):
        for wire in (b'', b'\x0c', b'\xff', b'\x04\x02\x00'):
            with self.assertRaises(ValueError):
                decode_request(wire)
        for arguments in ({'opcode': 1, 'api_level': 2, 'values': (bytes(15),)},
                          {'opcode': 0, 'api_level': 2}, {'opcode': 6, 'mode': 1},
                          {'opcode': 4, 'api_level': 2, 'mode': 1}, {'opcode': 12}):
            with self.assertRaises(ValueError):
                encode_request(**arguments)

    def test_session_material_byte_order_and_unused_y(self):
        material = derive_material(bytes(range(16)), bytes(range(48)))
        self.assertEqual(material, (b'\x08' * 8 + b'\x18' * 8, 0x03020100, 0x07060504))
        self.assertEqual(derive_material(bytes(range(16)), bytes(range(24)) + bytes(24)), material)
        for key, point in ((bytes(15), bytes(48)), (bytes(16), bytes(24))):
            with self.assertRaises(ValueError):
                derive_material(key, point)

    def test_store_round_trip_and_inactive_flag(self):
        store = save_key(bytes(144), 42, bytes(range(16)))
        self.assertEqual(store[:18], b'\x01\x2a' + bytes(range(16)))
        self.assertEqual(load_key(store, 42), bytes(range(16)))
        self.assertIsNone(load_key(bytes(144), 0))
        self.assertIsNone(load_key(store, 41))
        self.assertEqual(load_key(b'\x02' + store[1:], 42), bytes(range(16)))

    def test_save_selects_first_free_and_invalidates_later_duplicate(self):
        store = bytearray(144)
        store[36:54] = b'\x01\x2a' + b'old key bytes!!!'
        self.assertEqual(len(store), 144)
        updated = save_key(store, 42, bytes(range(16)))
        self.assertEqual(updated[:18], b'\x01\x2a' + bytes(range(16)))
        self.assertEqual(updated[36:54], b'\x00\xff' + b'old key bytes!!!')
        self.assertEqual(load_key(updated, 42), bytes(range(16)))

    def test_full_store_update_and_capacity_failure(self):
        store = b''.join(bytes((1, app)) + bytes((app,)) * 16 for app in range(8))
        with self.assertRaisesRegex(ValueError, 'full'):
            save_key(store, 9, bytes(16))
        updated = save_key(store, 3, b'x' * 16)
        self.assertEqual(load_key(updated, 3), b'x' * 16)
        self.assertEqual(updated[:54], store[:54])
        self.assertEqual(updated[72:], store[72:])

    def test_store_size_and_identifiers_are_bounded(self):
        for store in (b'', bytes(143), bytes(145)):
            with self.assertRaises(ValueError):
                load_key(store, 1)
        for app in (-1, 256):
            with self.assertRaises(ValueError):
                save_key(bytes(144), app, bytes(16))
        with self.assertRaises(ValueError):
            save_key(bytes(144), 1, bytes(15))

    def test_cloud_digest_uses_raw_address_and_complete_point(self):
        address, point = bytes(range(6)), bytes(range(6, 54))
        self.assertEqual(cloud_binding_digest(address, point), hashlib.sha256(bytes(range(54))).digest())
        self.assertNotEqual(cloud_binding_digest(address[::-1], point), cloud_binding_digest(address, point))
        with self.assertRaises(ValueError):
            cloud_binding_digest(address, point[:-1])


if __name__ == '__main__':
    unittest.main()
