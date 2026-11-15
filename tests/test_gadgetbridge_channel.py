import json
import unittest

from analysis_scripts.native_channel import encode_data, make_envelope, mix_key
from analysis_scripts.verify_gadgetbridge_channel import aes_ecb, verify

KEY = bytes(range(16))
PREFIX = 'Shared Session Key: ' + KEY.hex() + '\n'


def wire_line(raw, incoming=False):
    uuid = '00000017' if incoming else '00000016'
    uuid += '-0000-3512-2118-0009af100700'
    return ('onCharacteristicChanged: ' + uuid + ' <@ ' if incoming else
            'WriteAction ' + uuid + ' >@ ') + raw.hex() + '\n'


def encrypted(session, counter, incoming=False):
    payload = b'synthetic private body'
    padding = b'\xa5' * (-(len(payload) + 8) % 16)
    envelope = make_envelope(payload, counter, padding=padding)
    cipher = aes_ecb(mix_key(KEY, session), envelope, encrypt=True)
    packet = encode_data(11, 1, session, 0, cipher, total_size=len(payload), module_id=7)
    return wire_line(packet, incoming)


class CapturedChannelTest(unittest.TestCase):
    def test_aes_known_answer(self):
        plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
        ciphertext = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        self.assertEqual(aes_ecb(KEY, ciphertext), plaintext)
        self.assertEqual(aes_ecb(KEY, plaintext, encrypt=True), ciphertext)

    def test_both_directions_crc_and_counter_wrap(self):
        report = verify(PREFIX + encrypted(1, 0xffffffff) + encrypted(2, 0)
                        + encrypted(3, 5, True) + encrypted(4, 6, True))
        self.assertEqual(report['encrypted_transfers_verified'], 4)
        self.assertEqual(report['subsequent_counter_checks_passed'], 2)
        self.assertEqual(report['exact_counter_successors'], 2)
        self.assertFalse(report['independent_initial_counter_check'])
        serialized = json.dumps(report)
        self.assertNotIn(KEY.hex(), serialized)
        self.assertNotIn('synthetic private body', serialized)

    def test_rejects_crc_damage_counter_regression_and_wrong_route(self):
        good = encrypted(1, 4)
        damaged = good.rstrip()[:-2] + ('00' if not good.rstrip().endswith('00') else 'ff') + '\n'
        for capture in (PREFIX + damaged, PREFIX + good + encrypted(2, 3),
                        PREFIX + good.replace('00000016-', '00000017-')):
            with self.subTest(capture=capture), self.assertRaises(ValueError):
                verify(capture)

    def test_auth_challenge_and_success_response(self):
        challenge = bytes(range(16, 32))
        request = b'\x04\x02\x00\x02' + bytes(48)
        response = b'\x10\x04\x01' + challenge + bytes(48)
        proof = b'\x05' + bytes(16) + aes_ecb(KEY, challenge, encrypt=True)
        log = PREFIX
        for session, data, incoming in ((1, request, False), (2, response, True),
                                         (3, proof, False), (4, b'\x10\x05\x01', True)):
            log += wire_line(encode_data(3, 1, session, 0, data, total_size=len(data), module_id=0x82), incoming)
        report = verify(log)
        self.assertTrue(report['auth_session_key_proof_matches'])
        self.assertTrue(report['auth_success_response_observed'])
        self.assertEqual((report['auth_api_level_wire'], report['auth_mode']), (2, 2))

    def test_incomplete_and_ambiguous_sessions_fail(self):
        with self.assertRaises(ValueError):
            verify(PREFIX + wire_line(encode_data(1, 1, 1, 0, b'a', total_size=2, module_id=7)))
        for log in ('', PREFIX, PREFIX + 'Shared Session Key: ' + bytes(16).hex() + '\n' + encrypted(1, 1)):
            with self.assertRaises(ValueError):
                verify(log)


if __name__ == '__main__':
    unittest.main()
