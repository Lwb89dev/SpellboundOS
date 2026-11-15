import unittest
from analysis_scripts.hardware_profile import (
    driver_parts, health_counts, soc_identifiers, inspect)


class HardwareProfileTest(unittest.TestCase):
    def test_driver_parts_requires_digits(self):
        text = 'dev_ztw622 dev_gpio dev_ag3335 dev_bt dev_icna3311'
        # dev_gpio and dev_bt have no >=2 digit run and are excluded.
        self.assertEqual(driver_parts(text), ['ag3335', 'icna3311', 'ztw622'])

    def test_known_parts_get_vendor_and_corroboration(self):
        result = inspect('dev_ztw622 dev_newpart99')
        by_part = {d['part']: d for d in result['drivers']}
        self.assertEqual(by_part['ztw622']['vendor'], 'Zinitix')
        self.assertIn('corroboration', by_part['ztw622'])
        self.assertNotIn('vendor', by_part['newpart99'])
        self.assertEqual(result['identified_driver_count'], 1)

    def test_health_counts_wholeword_and_sparse(self):
        counts = health_counts('spo2 spo2 hrv sleeping heartrate')
        self.assertEqual(counts['spo2'], 2)
        self.assertEqual(counts['hrv'], 1)
        # "sleeping"/"heartrate" are not whole-word matches of sleep/heart rate.
        self.assertNotIn('sleep', counts)

    def test_soc_identifiers(self):
        self.assertEqual(soc_identifiers('boot AX861 core mhs003 x'),
                         ['AX861', 'mhs003'])


if __name__ == '__main__':
    unittest.main()
