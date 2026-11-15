import struct
import unittest

from analysis_scripts.sensor_ipc import (
    decode_payload, encode_control, encode_process, local_irq_message, worker_process_message)


class SensorIpcTest(unittest.TestCase):
    def test_process_golden_bytes_and_little_endian_reason(self):
        self.assertEqual(encode_process(6, 0), bytes.fromhex('10060000'))
        self.assertEqual(encode_process(37, 0x1234), bytes.fromhex('10253412'))
        self.assertEqual(decode_payload(bytes.fromhex('10253412')),
                         {'opcode': 16, 'sensor_id': 37, 'reason': 0x1234})

    def test_control_payload_sizes_and_order(self):
        for opcode in (4, 6, 7):
            for length in range(7):
                payload = bytes(range(length))
                encoded = encode_control(opcode, 6, 0x1234, payload)
                self.assertEqual(encoded[:6], struct.pack('<BBHH', opcode, 6, 0x1234, length))
                self.assertEqual(decode_payload(encoded)['payload'], payload)

    def test_local_and_worker_irq_layouts(self):
        self.assertEqual(local_irq_message(6), bytes.fromhex('0106000000000000'))
        self.assertEqual(worker_process_message(6), bytes.fromhex('0500000006000000'))
        self.assertEqual(local_irq_message(6, 0x1234)[4:6], b'\x34\x12')
        self.assertEqual(worker_process_message(6, 0x1234)[4:], bytes.fromhex('06003412'))

    def test_invalid_ids_reasons_opcodes_and_payloads(self):
        for sensor, reason in ((256, 0), (-1, 0), (0, 65536), (0, -1)):
            with self.subTest(sensor=sensor, reason=reason), self.assertRaises(ValueError):
                encode_process(sensor, reason)
        for args in ((5, 6, 1), (4, 6, 65536), (4, 6, 1, bytes(65536)), (4, 6, 1, 'text')):
            with self.subTest(opcode=args[0]), self.assertRaises(ValueError):
                encode_control(*args)

    def test_exact_lengths_and_unknown_opcodes(self):
        for data in (b'', b'\xff', b'\x10\x06\x00', b'\x10\x06\x00\x00\x00',
                     b'\x04\x06', bytes.fromhex('040601000100'), bytes.fromhex('040601000000ff')):
            with self.subTest(data=data.hex()), self.assertRaises(ValueError):
                decode_payload(data)


if __name__ == '__main__':
    unittest.main()
