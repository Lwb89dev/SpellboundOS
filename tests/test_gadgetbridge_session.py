import json
import unittest
from analysis_scripts.gadgetbridge_session import summarize


UUID = '00000016-0000-3512-2118-0009af100700'
BUILDER = {'services': [{'uuid': 'fee0', 'characteristics': [
    {'uuid': UUID, 'internal_identifier': UUID, 'properties_raw': 0x16},
    {'uuid': '2a2b', 'internal_identifier': '2a2b', 'properties_raw': 0x1a}]}]}
LOG = ('ZeppOsBtleSupport: characteristic: (Propr: Chunked Write): ' + UUID + ' (read,writeNoResponse,notify)\n'
       'BluetoothGatt: onConfigureMTU(AA:BB:CC:DD:EE:FF, 247, 0)\n'
       'ZeppOsServicesService: Number of services: 62\n')


class GadgetbridgeSessionTest(unittest.TestCase):
    def test_compares_live_subset_with_static_properties(self):
        report = summarize(LOG, '<hierarchy><node text="Connesso"/></hierarchy>',
                           'versionName=2026.11.1\nversionCode=257 targetSdk=35', BUILDER)
        self.assertEqual(report['logged_characteristic_count'], 1)
        self.assertTrue(report['all_logged_characteristics_match_static_properties'])
        self.assertEqual(report['successful_mtu_events'], [247])
        self.assertEqual(report['announced_application_service_counts'], [62])
        self.assertEqual(report['ui_connection_states'], ['connected'])
        self.assertEqual(len(report['unlogged_static_characteristics']), 1)

    def test_omits_all_unselected_sensitive_content(self):
        private = 'PERSONAL_NOTIFICATION_BODY persistent_key=VERY_SECRET AA:BB:CC:DD:EE:FF'
        report = summarize(LOG + private, '<hierarchy><node text="' + private + '"/></hierarchy>', private, BUILDER)
        encoded = json.dumps(report)
        for sensitive in ('PERSONAL_NOTIFICATION_BODY', 'VERY_SECRET', 'AA:BB:CC:DD:EE:FF'):
            self.assertNotIn(sensitive, encoded)

    def test_bad_properties_empty_capture_and_failed_mtu(self):
        with self.assertRaises(ValueError):
            summarize(LOG.replace('read,', 'unknown,'), '<hierarchy/>', '', BUILDER)
        report = summarize('BluetoothGatt: onConfigureMTU(<MAC>, 247, 1)', '<hierarchy/>', '', BUILDER)
        self.assertFalse(report['all_logged_characteristics_match_static_properties'])
        self.assertEqual(report['successful_mtu_events'], [])
        changed = summarize(LOG.replace('read,', ''), '<hierarchy/>', '', BUILDER)
        self.assertFalse(changed['all_logged_characteristics_match_static_properties'])


if __name__ == '__main__':
    unittest.main()
