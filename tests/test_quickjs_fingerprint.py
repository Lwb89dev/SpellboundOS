import unittest
from analysis_scripts.quickjs_fingerprint import (
    active_lines, upstream_atoms, upstream_opcodes, opcode_table_bytes,
    firmware_atoms)

# Synthetic headers shaped like quickjs-atom.h / quickjs-opcode.h.
ATOM_H = '''
DEF(null, "null") /* must be first */
DEF(false, "false")
#ifdef CONFIG_BIGNUM
DEF(bigint, "bigint")
#endif
#ifdef CONFIG_ATOMICS
DEF(ok, "ok")
#endif
DEF(empty_string, "")
DEF(last, "last")
'''

OPCODE_H = '''
#ifdef FMT
FMT(none)
FMT(i32)
#undef FMT
#endif
#ifdef DEF
#ifndef def
#define def(id, size, n_pop, n_push, f) DEF(id, size, n_pop, n_push, f)
#endif
DEF(invalid, 1, 0, 0, none)
DEF(push_i32, 5, 0, 1, i32)
DEF(nop, 1, 0, 0, none)
def(enter_scope, 3, 0, 0, none)
#if SHORT_OPCODES
DEF(push_0, 1, 0, 1, none)
#endif
#ifdef CONFIG_BIGNUM
DEF(push_bigint, 5, 0, 1, i32)
#endif
#undef DEF
#endif
'''


class PreprocessorTest(unittest.TestCase):
    def test_conditionals(self):
        lines = list(active_lines('#ifdef A\nx\n#else\ny\n#endif\n#if B\nz\n#endif',
                                  {'A': '1', 'B': '0'}))
        self.assertEqual(lines, ['x'])

    def test_atoms_follow_default_build(self):
        self.assertEqual(upstream_atoms(ATOM_H),
                         ['null', 'false', 'ok', '', 'last'])

    def test_opcode_table_keeps_temporary_entries_in_header_order(self):
        formats, entries = upstream_opcodes(OPCODE_H)
        self.assertEqual(formats, ['none', 'i32'])
        self.assertEqual([e['name'] for e in entries],
                         ['invalid', 'push_i32', 'nop', 'enter_scope', 'push_0'])
        self.assertTrue(entries[3]['temporary'])
        self.assertEqual(opcode_table_bytes(formats, entries)[:8],
                         bytes([1, 0, 0, 0, 5, 0, 1, 1]))


class FirmwareAtomTest(unittest.TestCase):
    def test_blob_keeps_single_empty_atom_and_stops_at_padding(self):
        data = (b'xx' + b'null\0false\0true\0if\0else\0return\0'
                b'await\0\0length\0last\0\0\0\0junk')
        offset, atoms = firmware_atoms(data)
        self.assertEqual(offset, 2)
        self.assertEqual(atoms, ['null', 'false', 'true', 'if', 'else',
                                 'return', 'await', '', 'length', 'last'])

    def test_missing_blob(self):
        with self.assertRaises(ValueError):
            firmware_atoms(b'no atoms here')


if __name__ == '__main__':
    unittest.main()
