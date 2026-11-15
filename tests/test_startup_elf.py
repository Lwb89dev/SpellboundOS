import struct
import unittest

from analysis_scripts.export_startup_elf import build_elf
from analysis_scripts.sensorhub_memory import StartupMemory


class StartupElfTest(unittest.TestCase):
    def test_load_segments_reproduce_copy_and_zero_regions(self):
        data = bytearray(0x100)
        struct.pack_into('<3I2I', data, 0, 0x1080, 0x2000, 5, 0x3000, 16)
        data[0x80:0x88] = b'abcdefgh'
        memory = StartupMemory(data, 0x1000, 0, 1, 12, 1)
        output = build_elf(memory, 0x1040)
        self.assertEqual(output[:7], b'\x7fELF\x01\x01\x01')
        fields = struct.unpack_from('<16sHHIIIIIHHHHHH', output)
        self.assertEqual(fields[2], 243)
        self.assertEqual(fields[4], 0x1040)
        self.assertEqual(fields[10], 3)
        for index, (address, filesz, memsz, contents) in enumerate((
                (0x1000, 0x100, 0x100, bytes(data)), (0x2000, 8, 8, b'abcdefgh'),
                (0x3000, 0, 16, b''))):
            program = struct.unpack_from('<8I', output, fields[5] + index * 32)
            self.assertEqual((program[2], program[4], program[5]), (address, filesz, memsz))
            self.assertEqual(output[program[1]:program[1] + filesz], contents)
        strings_header = struct.unpack_from('<10I', output, fields[6] + fields[13] * 40)
        strings = output[strings_header[4]:strings_header[4] + strings_header[5]]
        self.assertIn(b'.copy0\0', strings)
        self.assertIn(b'.zero1\0', strings)

    def test_entry_must_be_in_initialized_memory(self):
        memory = StartupMemory(bytes(64), 0x1000, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            build_elf(memory, 0x2000)


if __name__ == '__main__':
    unittest.main()
