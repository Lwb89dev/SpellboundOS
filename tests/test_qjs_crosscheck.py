import unittest
from analysis_scripts.qjs_crosscheck import compare, digest, parse_c_output


NAME = 'META/js_apps/test/app.bin'
RECORD = (1, 2, 1, 4, 0, 1, 12, 0, 1)


def line(index=0, values=RECORD):
    return 'FN\t/tmp/' + NAME.replace('/', '__') + '\t' + str(index) + '\t' + '\t'.join(map(str, values))


class CrosscheckTest(unittest.TestCase):
    def test_parses_and_compares_multiple_functions(self):
        records = parse_c_output('noise\n' + line() + '\n' + line(1))
        self.assertEqual(records, {NAME: [RECORD, RECORD]})
        summary, members = compare({NAME: [RECORD, RECORD]}, records)
        self.assertTrue(summary['agree'])
        self.assertEqual(summary['functions_compared'], 2)
        self.assertEqual(members[0]['status'], 'match')

    def test_missing_extra_count_and_field_mismatches_fail(self):
        python = {NAME: [RECORD]}
        for c in ({}, {NAME: []}, {NAME: [(0,) + RECORD[1:]]},
                  {**python, 'unexpected': [RECORD]}):
            with self.subTest(c=c):
                self.assertFalse(compare(python, c)[0]['agree'])
        with self.assertRaises(ValueError):
            compare({}, {})

    def test_malformed_duplicate_and_skipped_records_fail(self):
        for text in (line().rsplit('\t', 1)[0], line(1), line() + '\n' + line(),
                     line(values=(-1,) + RECORD[1:]), line(values=RECORD[:-1] + (2,)),
                     line().replace('META__js_apps__', 'elsewhere__')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_c_output(text)

    def test_fingerprint_depends_on_fields_and_not_dict_order(self):
        self.assertEqual(digest({'b': [RECORD], 'a': []}), digest({'a': [], 'b': [RECORD]}))
        self.assertNotEqual(digest({NAME: [RECORD]}), digest({NAME: [RECORD, RECORD]}))


if __name__ == '__main__':
    unittest.main()
