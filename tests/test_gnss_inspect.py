import struct
import unittest
from analysis_scripts.gnss_inspect import inspect_gnss
from analysis_scripts.gnss_find_bases import find

class GnssContainerTest(unittest.TestCase):
    def image(self):
        data = bytearray(0x100+15)
        data[0x20:0x24] = b'\x55\xaa\xaa\x55'
        struct.pack_into('<5I', data, 0x24, 1, 2, 3, 4, 5)
        return data

    def test_candidate_regions_account_for_whole_payload(self):
        regions = inspect_gnss(self.image())
        self.assertEqual([x['file_offset'] for x in regions], [256,257,259,262,266])
        self.assertEqual(regions[-1]['file_offset']+regions[-1]['length'],271)

    def test_rejects_truncated_or_inconsistent_container(self):
        data = self.image()
        with self.assertRaises(ValueError): inspect_gnss(data[:100])
        with self.assertRaises(ValueError): inspect_gnss(data[:-1])
        data[0x20] = 0
        with self.assertRaises(ValueError): inspect_gnss(data)


class GnssBaseHeuristicTest(unittest.TestCase):
    def test_literal_pointer_to_string_proposes_known_aligned_base(self):
        data = bytearray(64)
        data[16:26] = b'gnss_test\0'
        struct.pack_into('<I', data, 0, 0x08000010)
        matches = find(data,0x08000000,0x09000000)
        self.assertEqual(matches[0]['candidate_base'],0x08000000)
        self.assertEqual(matches[0]['match_count'],1)
        self.assertEqual(find(data,0x04000000,0x05000000),[])

if __name__ == '__main__': unittest.main()
