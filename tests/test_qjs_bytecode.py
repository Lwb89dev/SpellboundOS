import struct
import unittest
from analysis_scripts.qjs_bytecode import (
    BytecodeError, Reader, analyze, disassemble, verified_opcodes)


def leb(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def string(text):
    raw = text.encode('latin1')
    return leb(len(raw) << 1) + raw


# Synthetic descriptor table (not QuickJS numbering).
OPS = [dict(name=n, temporary=False, size=s, format=f) for n, s, f in (
    ('invalid', 1, 'none'), ('push_i32', 5, 'i32'), ('get_loc', 3, 'loc'),
    ('goto8', 2, 'label8'), ('get_var', 5, 'atom'), ('push_const', 5, 'const'),
    ('return', 1, 'none'))]
BUILTINS = [None, 'null', '<ret>']  # first file atom index is 3


def program(goto_delta=11, const_index=0, bytecode=None):
    code = bytecode or (bytes([1]) + struct.pack('<i', 7)        # pc 0
                        + bytes([2]) + struct.pack('<H', 0)      # pc 5
                        + bytes([3, goto_delta & 0xff])          # pc 8
                        + bytes([4]) + struct.pack('<I', 3)      # pc 10
                        + bytes([5]) + struct.pack('<I', const_index)  # pc 15
                        + bytes([6]))                             # pc 20
    fn = (bytes([14]) + struct.pack('<H', 0) + bytes([0]) + leb(2 << 1)
          + leb(0) + leb(1) + leb(0) + leb(2) + leb(0) + leb(1)
          + leb(len(code)) + leb(1)
          + leb(3 << 1) + leb(0) + leb(0) + bytes([0])           # vardef "x"
          + code
          + bytes([7]) + string('hi'))                            # cpool[0]
    return bytes([1]) + leb(1) + string('x') + fn


class ReaderTest(unittest.TestCase):
    def test_reads_and_disassembles(self):
        reader, root, listings, histogram = analyze(program(), BUILTINS, OPS)
        self.assertEqual(reader.pos, len(program()))
        self.assertEqual(reader.atom_text(root['name']), '<ret>')
        listing = listings[0][1]
        self.assertEqual([(i['pc'], i['op']) for i in listing],
                         [(0, 'push_i32'), (5, 'get_loc'), (8, 'goto8'),
                          (10, 'get_var'), (15, 'push_const'), (20, 'return')])
        self.assertEqual(listing[0]['operands'], ['7'])
        self.assertEqual(listing[1]['operands'], ['0:x'])
        self.assertEqual(listing[2]['operands'], ['@20'])
        self.assertEqual(listing[3]['operands'], ['x'])
        self.assertEqual(listing[4]['operands'], ['cpool[0]:string'])
        self.assertEqual(histogram['return'], 1)

    def test_rejects_branch_into_instruction(self):
        with self.assertRaises(BytecodeError):
            analyze(program(goto_delta=10), BUILTINS, OPS)

    def test_rejects_constant_out_of_range(self):
        with self.assertRaises(BytecodeError):
            analyze(program(const_index=1), BUILTINS, OPS)

    def test_rejects_invalid_and_truncated_code(self):
        with self.assertRaises(BytecodeError):
            analyze(program(bytecode=bytes([0])), BUILTINS, OPS)
        with self.assertRaises(BytecodeError):
            analyze(program(bytecode=bytes([1, 0])), BUILTINS, OPS)
        with self.assertRaises(BytecodeError):
            analyze(program()[:-3], BUILTINS, OPS)

    def test_version_and_zigzag_sleb(self):
        with self.assertRaises(BytecodeError):
            Reader(b'\x02\x00', BUILTINS).read_file()
        value = Reader(bytes([1, 0, 5, 5]), BUILTINS).read_file()
        self.assertEqual(value, {'type': 'int32', 'value': -3})

    def test_header_table_must_be_in_firmware(self):
        header = 'FMT(none)\nDEF(invalid, 1, 0, 0, none)\n'
        with self.assertRaises(BytecodeError):
            verified_opcodes(b'\x00' * 16, '#define FMT\n#define DEF\n' + header)


if __name__ == '__main__':
    unittest.main()
