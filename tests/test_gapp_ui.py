import struct
import unittest
from analysis_scripts.gapp_ui import (
    inspect, parse_args, parse_tree, read_name, walk_sections)


def node(tag, body):
    tag = tag.encode() if isinstance(tag, str) else tag
    tag = tag.ljust(4, b'\0')[:4]
    return tag + struct.pack('<I', len(body)) + body


def pstr(text):
    raw = text.encode() + b'\0'
    return struct.pack('<H', len(raw)) + raw


def args(pairs):
    body = struct.pack('<H', len(pairs))
    for key, value in pairs:
        for item in (key, value):
            raw = item.encode() + b'\0'
            body += struct.pack('<H', len(raw)) + raw
    return node('ARGS', body)


class HelpersTest(unittest.TestCase):
    def test_read_name_skips_header_words(self):
        body = struct.pack('<HHH', 32, 390, 450) + pstr('AddLayer')
        self.assertEqual(read_name(body), 'AddLayer')
        self.assertIsNone(read_name(struct.pack('<HHH', 1, 2, 3)))

    def test_parse_args_pairs_and_bounds(self):
        body = node('ARGS', b'')  # extract inner body
        count, pairs = parse_args(args([('color', '0x999999'),
                                        ('alpha', '${control:alpha}')])[8:])
        self.assertEqual(count, 2)
        self.assertEqual(pairs, [('color', '0x999999'),
                                 ('alpha', '${control:alpha}')])
        # A count larger than the data stops cleanly instead of overrunning.
        self.assertEqual(parse_args(struct.pack('<H', 99))[1], [])


class TreeTest(unittest.TestCase):
    def test_containment_and_header_rejection(self):
        # REXT body carries a header, a name and a child ARGS node.
        inner_args = args([('color', 'red')])
        rext = node('REXT', struct.pack('<HH', 0, 5) + pstr('text') + inner_args)
        act = node('ACT\0', struct.pack('<H', 0) + pstr('gra.ccallback')
                   + pstr('gre.press') + args([('function', 'onTap')]))
        layer_body = struct.pack('<HHH', 32, 390, 450) + pstr('L') + rext + act
        layer = node('LAYR', layer_body)
        forest = parse_tree(layer, 0, len(layer))
        self.assertEqual([n.tag for n in forest], ['LAYR'])
        kinds = [c.tag for c in forest[0].children]
        self.assertEqual(kinds, ['REXT', 'ACT'])
        self.assertEqual([c.tag for c in forest[0].children[0].children], ['ARGS'])

    def test_false_tag_inside_string_is_rejected(self):
        # 'ARGS' appears inside a string value but with a size that overruns.
        poisoned = args([('name', 'ARGS\xff\xff\xff\xffxx')])
        layer = node('LAYR', struct.pack('<HHH', 0, 0, 0) + pstr('L') + poisoned)
        forest = parse_tree(layer, 0, len(layer))
        # Only the real ARGS node is a child; the embedded bytes are not.
        self.assertEqual([c.tag for c in forest[0].children], ['ARGS'])


class ContainerTest(unittest.TestCase):
    def build(self):
        scene = node('SCEN', struct.pack('<HH', 0, 0) + pstr('HomeScreen'))
        # LIST size excludes the 4-byte 'LAYR' form type, which sits outside it.
        list_chunk = b'LIST' + struct.pack('<I', len(scene)) + b'LAYR' + scene
        riff_body = b'GAPP' + list_chunk
        return b'RIFF' + struct.pack('<I', len(riff_body)) + riff_body

    def test_sections_and_scene_name(self):
        data = self.build()
        names = [s[0] for s in walk_sections(data)]
        self.assertEqual(names, ['LAYR'])
        report = inspect(data)
        self.assertEqual(report['scene_names'], ['HomeScreen'])
        self.assertEqual(report['node_tag_counts'].get('SCEN'), 1)

    def test_rejects_non_gapp(self):
        with self.assertRaises(ValueError):
            walk_sections(b'RIFFxxxxWAVE')


if __name__ == '__main__':
    unittest.main()
