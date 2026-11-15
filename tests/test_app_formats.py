import struct
import unittest
from analysis_scripts.app_formats import inspect_atoms, inspect_gapp, inspect_initial_function, uleb128


class AppFormatTest(unittest.TestCase):
    def test_atom_table_with_narrow_and_wide_strings(self):
        data = b'\x01\x02\x06abc\x03\xa9\x03\x0e\x00'
        info, atoms = inspect_atoms(data)
        self.assertEqual(atoms, ['abc', '\u03a9'])
        self.assertEqual(info['following_object_tag'], 14)
        self.assertEqual(info['atom_table_end'], 9)

    def test_atom_truncation_and_overflow(self):
        for data in (b'\x01\x01\x04a', b'\x01\x01\x02a', b'\x01\xff\xff\xff\xff\x7f'):
            with self.assertRaises(ValueError): inspect_atoms(data)
        with self.assertRaises(ValueError): uleb128(b'\x80', 0)

    def test_initial_function_bounds(self):
        # tag, flags, mode, name ref; eight ULEB counts; one opaque opcode byte.
        data = bytes([14, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0x28])
        result = inspect_initial_function(data, 0)
        self.assertEqual(result['bytecode_offset'], 13)
        self.assertEqual(result['bytecode_length'], 1)
        self.assertEqual(result['prefix_end_before_constant_pool'], len(data))
        for bad in (data[:-1], data[:4]):
            with self.assertRaises(ValueError): inspect_initial_function(bad, 0)
        bad = bytearray(data)
        bad[12] = 1  # local_count=1 with zero args and vars is inconsistent.
        with self.assertRaises(ValueError): inspect_initial_function(bad, 0)

    def test_list_type_is_outside_declared_size(self):
        data = b'RIFF' + struct.pack('<I', 0) + b'GAPP'
        data += b'LIST' + struct.pack('<I', 4) + b'LAYR' + b'1234'
        data += b'DAMR' + struct.pack('<I', 2) + b'xy'
        result = inspect_gapp(data)
        self.assertEqual(result['sections'][0]['physical_end'], 28)
        self.assertTrue(result['top_level_walk_reaches_eof'])
        with self.assertRaises(ValueError): inspect_gapp(data[:-1])


if __name__ == '__main__': unittest.main()
