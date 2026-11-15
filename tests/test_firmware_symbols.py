import unittest
from analysis_scripts.firmware_symbols import inventory


class InventoryTest(unittest.TestCase):
    def test_families_group_and_dedup(self):
        blob = (b'tag:zrpc_link_send end\0assert zrpc.ch ok\0'
                b'AUD_IPC_CMD_PLAY_START\0AUD_IPC_CMD_PLAY_START dup\0'
                b'bx_core_gatt_init\0bx_core_gap_cleanup\0'
                b'app_handle_set_sensor_cmd\0noise')
        result = inventory(blob)
        fam = result['families']
        self.assertEqual(fam['zrpc_rpmsg']['count'], 2)  # zrpc_link_send, zrpc.ch
        self.assertEqual(fam['audio_dsp_ipc']['count'], 1)  # duplicate collapsed
        self.assertEqual(set(fam['bt_host']['symbols']),
                         {'bx_core_gatt_init', 'bx_core_gap_cleanup'})
        self.assertEqual(fam['app_cmd_handlers']['symbols'],
                         ['app_handle_set_sensor_cmd'])

    def test_companion_presence(self):
        blob = b'_weather_add_city\0app_contacts_list_data\0nothing_music_here'
        comp = inventory(blob)['companion_modules']
        self.assertTrue(comp['weather']['present'])
        self.assertTrue(comp['contacts']['present'])
        self.assertFalse(comp['find_device']['present'])

    def test_symbols_sorted(self):
        blob = b'bx_core_zeta\0bx_core_alpha\0'
        syms = inventory(blob)['families']['bt_host']['symbols']
        self.assertEqual(syms, sorted(syms))


if __name__ == '__main__':
    unittest.main()
