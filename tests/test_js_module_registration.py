"""Synthetic instruction/data fixtures; no vendor firmware is needed."""
import struct
import unittest

from analysis_scripts.js_cfunction_tables import Image, bootstrap_modules
from analysis_scripts.js_module_registration import (
    boundaries, constructor, jal_target, long_call_target, registrations,
    relative_pointer, setup_arguments,
)

BASE = 0x1000
NEW_MODULE, ADD_EXPORTS = 0x1800, 0x1840


def auipc_addi(address, target, register):
    delta = target - address
    upper = (delta + 0x800) >> 12
    lower = delta - (upper << 12)
    return struct.pack('<II', ((upper << 12) | register << 7 | 0x17) & 0xffffffff,
                       (lower & 0xfff) << 20 | register << 15 | register << 7 | 0x13)


def long_call(address, target):
    result = bytearray(auipc_addi(address, target, 1))
    instruction = struct.unpack_from('<I', result, 4)[0]
    struct.pack_into('<I', result, 4, (instruction & ~0x7f) | 0x67)
    return result


def jal(address, target, rd=1):
    delta = (target - address) & 0x1fffff
    return (delta >> 20) << 31 | ((delta >> 1) & 1023) << 21 | (
        (delta >> 11) & 1) << 20 | ((delta >> 12) & 255) << 12 | rd << 7 | 0x6f


def fixture():
    data = bytearray(b'\x01\x00' * 0x800)  # C.NOP padding
    for offset, text in ((0x50, b'timer'), (0x60, b'hmUI'),
                         (0x80, b'open'), (0x90, b'close')):
        data[offset:offset + len(text) + 1] = text + b'\0'
    source = (b"import * as timer from 'timer';\nglobalThis.timer = timer;\n"
              b"import * as hmUI from 'hmUI';\nglobalThis.hmUI = hmUI;\n")
    data[0x900:0x900 + len(source)] = source
    for index in range(2):
        block, create, table = 0x100 + 14 * index, 0x300 + 0x100 * index, 0x700 + 32 * index
        data[block:block + 8] = auipc_addi(BASE + block, BASE + 0x50 + 16 * index, 11)
        struct.pack_into('<HI', data, block + 8, 0x8522, jal(BASE + block + 10, BASE + create))
        data[create:create + 8] = auipc_addi(BASE + create, BASE + 0x600 + 16 * index, 12)
        struct.pack_into('<IH', data, create + 8, 0x00112023, 0x8522)  # SW ra,0(sp); C.MV
        data[create + 14:create + 22] = long_call(BASE + create + 14, NEW_MODULE)
        struct.pack_into('<HH', data, create + 22, 0xc101, 0x4689)  # C.BEQZ; C.LI a3,2
        data[create + 26:create + 34] = auipc_addi(BASE + create + 26, BASE + table, 12)
        struct.pack_into('<HH', data, create + 34, 0x85aa, 0x8522)  # C.MV a1,a0; a0,s0
        data[create + 38:create + 46] = long_call(BASE + create + 38, ADD_EXPORTS)
        for j, name in enumerate((0x80, 0x90)):
            struct.pack_into('<IBBhII', data, table + j * 16,
                             BASE + name, 3, 0, 0, 1, BASE + 0x650 + j * 2)
    return data


class RegistrationTest(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.image = Image(self.data, BASE)
        self.modules = bootstrap_modules(self.data)

    def recover(self):
        return registrations(self.image, self.modules, 0x1100, 0x1140)

    def test_chain_and_constructor_arguments(self):
        modules = self.recover()
        self.assertEqual([m['module'] for m in modules], ['timer', 'hmUI'])
        self.assertEqual([m['create_function'] for m in modules], [0x1300, 0x1400])
        for index, module in enumerate(modules):
            result = constructor(self.image, module['create_function'], NEW_MODULE, ADD_EXPORTS, 0x80)
            self.assertEqual(result['init_function'], 0x1600 + 16 * index)
            self.assertEqual(result['table_address'], 0x1700 + 32 * index)
            self.assertEqual(result['count'], 2)
            self.assertEqual([e['name'] for e in result['entries']], ['open', 'close'])

    def test_incomplete_or_duplicate_bootstrap_rejected(self):
        for modules in ([], self.modules + self.modules, self.modules + [{'module': 'hmFS', 'global': 'hmFS'}]):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                registrations(self.image, modules, 0x1100, 0x1140)

    def test_wrong_context_move_or_call_register_rejected(self):
        for offset, fmt, value in ((0x108, '<H', 0x8526),
                                   (0x10a, '<I', jal(0x110a, 0x1300, rd=0))):
            with self.subTest(offset=offset):
                data = fixture()
                struct.pack_into(fmt, data, offset, value)
                with self.assertRaises(ValueError):
                    registrations(Image(data, BASE), self.modules, 0x1100, 0x1140)

    def test_duplicate_complete_chain_rejected(self):
        for offset, name, create in ((0x120, 0x1050, 0x1300), (0x12e, 0x1060, 0x1400)):
            self.data[offset:offset + 8] = auipc_addi(BASE + offset, name, 11)
            struct.pack_into('<HI', self.data, offset + 8, 0x8522, jal(BASE + offset + 10, create))
        with self.assertRaisesRegex(ValueError, 'found 2'):
            self.recover()

    def test_unknown_load_does_not_preserve_stale_argument(self):
        struct.pack_into('<I', self.data, 0x308, 0x00012603)  # LW a2,0(sp)
        with self.assertRaisesRegex(ValueError, 'cannot reconstruct'):
            constructor(self.image, 0x1300, NEW_MODULE, ADD_EXPORTS, 0x80)

    def test_branch_in_setup_is_rejected(self):
        struct.pack_into('<H', self.data, 0x322, 0xc101)  # replace a move after table setup
        with self.assertRaisesRegex(ValueError, 'cannot reconstruct'):
            constructor(self.image, 0x1300, NEW_MODULE, ADD_EXPORTS, 0x80)

    def test_missing_helper_and_malformed_table_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            constructor(self.image, 0x1300, NEW_MODULE, ADD_EXPORTS + 2, 0x80)
        struct.pack_into('<I', self.data, 0x700, 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'invalid table'):
            constructor(self.image, 0x1300, NEW_MODULE, ADD_EXPORTS, 0x80)


class InstructionTest(unittest.TestCase):
    def test_signed_relative_addresses_and_jal(self):
        for target in (0x1010, 0x1f00):
            data = bytearray(0x1000)
            data[0x800:0x808] = auipc_addi(0x1800, target, 11)
            self.assertEqual(relative_pointer(Image(data, BASE), 0x1800, 11), target)
            self.assertEqual(jal_target(jal(0x1800, target), 0x1800), target)
            data[0x800:0x808] = long_call(0x1800, target)
            self.assertEqual(long_call_target(Image(data, BASE), 0x1800), target)

    def test_truncated_or_unsupported_instructions(self):
        image = Image(b'\x13\x00\x00\x00', BASE)  # one ADDI, 4 bytes
        with self.assertRaisesRegex(ValueError, 'inside an instruction'):
            boundaries(image, BASE, BASE + 2)
        self.assertEqual(boundaries(image, BASE, BASE + 2, allow_partial_end=True), [])
        with self.assertRaisesRegex(ValueError, 'unsupported instruction length'):
            boundaries(Image(b'\x1f\x00', BASE), BASE, BASE + 2)
        with self.assertRaisesRegex(ValueError, 'outside image'):
            relative_pointer(image, BASE, 11)

    def test_signed_compressed_and_full_width_counts(self):
        for instruction in (struct.pack('<H', 0x56fd), struct.pack('<I', 0xfff00693)):
            image = Image(instruction, BASE)  # C.LI a3,-1 / ADDI a3,zero,-1
            _, values = setup_arguments(image, [BASE], BASE + len(instruction), (13,))
            self.assertEqual(values[13], 0xffffffff)


if __name__ == '__main__':
    unittest.main()
