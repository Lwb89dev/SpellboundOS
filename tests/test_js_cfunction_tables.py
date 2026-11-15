import pathlib
import struct
import tempfile
import unittest
from analysis_scripts.js_cfunction_tables import (
    Image, bootstrap_modules, corpus_calls, inventory, label, summarize)

BASE = 0x1000


def build():
    """Synthetic image: a string pool, a 3-entry table and a nested 2-entry table."""
    data = bytearray(0x400)
    names = {}
    cursor = 0x10
    for text in ('open', 'size', 'mode', 'A', 'B', 'x y'):
        data[cursor:cursor + len(text)] = text.encode()
        names[text] = BASE + cursor
        cursor += len(text) + 1

    def put(offset, name, flags, kind, first, second, magic=0):
        struct.pack_into('<IBBhII', data, offset, names[name], flags, kind, magic,
                         first, second)

    put(0x100, 'A', 0, 4, 7, 0)                       # nested: int32 constants
    put(0x110, 'B', 0, 4, 0xffffffff, 0)
    put(0x200, 'open', 3, 0, 2, BASE + 0x80)          # function, arity 2
    put(0x210, 'size', 1, 1, BASE + 0x84, 0)          # getter only
    put(0x220, 'mode', 0, 8, BASE + 0x100, 2)         # nested table, 2 entries
    return bytes(data), names


class EntryTest(unittest.TestCase):
    def setUp(self):
        self.data, self.names = build()
        self.image = Image(self.data, BASE)

    def test_decodes_kinds(self):
        self.assertEqual(self.image.entry(0x200),
                         {'name': 'open', 'kind': 'function', 'arity': 2,
                          'address': BASE + 0x80})
        self.assertEqual(self.image.entry(0x210)['getter'], BASE + 0x84)
        self.assertIsNone(self.image.entry(0x210)['setter'])
        self.assertEqual(self.image.entry(0x110)['value'], -1)
        self.assertEqual(self.image.entry(0x220)['count'], 2)

    def test_rejects_malformed(self):
        self.assertIsNone(self.image.entry(0x300))  # null name pointer
        bad = bytearray(self.data)
        struct.pack_into('<I', bad, 0x200, self.names['x y'])  # not an identifier
        self.assertIsNone(Image(bytes(bad), BASE).entry(0x200))
        bad = bytearray(self.data)
        struct.pack_into('<I', bad, 0x20c, 0x90000000)         # function outside image
        self.assertIsNone(Image(bytes(bad), BASE).entry(0x200))

    def test_runs(self):
        self.assertEqual([(a, len(e)) for a, e in self.image.runs()],
                         [(BASE + 0x100, 2), (BASE + 0x200, 3)])
        self.assertIsNone(self.image.table(BASE - 0x40, 1))


class InventoryTest(unittest.TestCase):
    def test_call_site_counts_bound_tables(self):
        data, _ = build()
        with tempfile.TemporaryDirectory() as folder:
            source = pathlib.Path(folder) / 'ram_00001090.c'
            source.write_text(
                'void f(void){\n  FUN_ram_00001234(p,m,&PTR_s_open_ram_00001010_ram_00001200,2);\n'
                '  FUN_ram_00005678(a,&PTR_DAT_ram_00001300,0xfffffffe);\n}\n')
            calls = corpus_calls(folder)
        self.assertEqual(list(calls), [0x1200])  # the huge count is ignored
        self.assertEqual(calls[0x1200]['callees'], {'FUN_ram_00001234'})
        runs, tables = inventory(data, calls, {'hmFS': {'open', 'size', 'stat'}}, BASE)
        by_address = {t['address']: t for t in tables}
        self.assertEqual(by_address[0x1200]['count_source'], 'call-site')
        self.assertEqual(by_address[0x1200]['count'], 2)
        self.assertEqual(by_address[0x1200]['label']['module'], 'hmFS')
        # The third run entry is kept as a remainder; its child table is exact.
        self.assertEqual(by_address[0x1220]['count_source'], 'run')
        self.assertEqual(by_address[0x1100]['count_source'], 'parent-entry')
        summary = summarize(runs, tables, [], {'hmFS': {'open', 'size', 'stat'}})
        self.assertEqual(summary['known_methods_not_found'], {'hmFS': ['stat']})


class HelpersTest(unittest.TestCase):
    def test_bootstrap(self):
        source = (b"junk\0import * as timer from 'timer';\nglobalThis.timer = timer;\n"
                  b"import * as hmUI from 'hmUI';\nglobalThis.hmUI = hmUI;\n\0")
        self.assertEqual([m['global'] for m in bootstrap_modules(source)],
                         ['timer', 'hmUI'])

    def test_label_needs_a_clear_winner(self):
        entries = [{'name': 'open'}, {'name': 'close'}]
        self.assertIsNone(label(entries, {'a': {'open', 'close'}, 'b': {'open', 'close'}}))
        self.assertEqual(label(entries, {'a': {'open', 'close'}, 'b': {'open'}})['module'], 'a')


if __name__ == '__main__':
    unittest.main()
