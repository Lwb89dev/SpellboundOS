import unittest
from analysis_scripts.ble_identifiers import classify, inspect


class ClassifyTest(unittest.TestCase):
    def test_huami_short_id_and_dfu(self):
        cat, _, short = classify('00000016-0000-3512-2118-0009af100700')
        self.assertEqual((cat, short), ('huami', '00000016'))
        cat, label, short = classify('00001531-0000-3512-2118-0009af100700')
        self.assertEqual(cat, 'huami')
        self.assertIn('firmware-update', label)

    def test_standard_and_apple_services(self):
        self.assertEqual(classify('00001101-0000-1000-8000-00805f9b34fb')[0],
                         'bt-sig')
        self.assertEqual(classify('7905f431-b5ce-4e99-a40f-4b1e122d00d0')[0],
                         'ancs')
        self.assertEqual(classify('89d3502b-0f36-433a-8ef4-c502ad55f8dc')[0],
                         'ams')

    def test_unknown_is_custom(self):
        self.assertEqual(classify('cc353442-be58-4ea2-876e-11d8d6976366')[0],
                         'custom')


class InspectTest(unittest.TestCase):
    def test_dedup_sort_and_counts(self):
        blob = (b'junk7905F431-B5CE-4E99-A40F-4B1E122D00D0more'
                b'00000001-0000-3512-2118-0009af100700x'
                b'00000001-0000-3512-2118-0009AF100700x'  # duplicate, mixed case
                b'cc353442-be58-4ea2-876e-11d8d6976366end')
        result = inspect(blob)
        self.assertEqual(result['uuid_count'], 3)  # duplicate collapsed
        self.assertEqual([e['uuid'] for e in result['uuids']],
                         sorted(e['uuid'] for e in result['uuids']))
        self.assertEqual(result['category_counts'],
                         {'ancs': 1, 'huami': 1, 'custom': 1})


if __name__ == '__main__':
    unittest.main()
