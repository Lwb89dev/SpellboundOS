import struct
import unittest
from analysis_scripts.gapp_ui import (
    LEND, content_end, decode_app_header, inspect, parse_args, parse_damr,
    parse_inst, parse_rate, parse_step, parse_tree, read_name, walk_sections)


def node(tag, body):
    """A node as the container stores it: body padded to even length with zero."""
    tag = tag.encode() if isinstance(tag, str) else tag
    if len(body) % 2:
        body += b'\0'
    return tag.ljust(4, b'\0')[:4] + struct.pack('<I', len(body)) + body


def pstr(text):
    raw = text.encode() + b'\0'
    return struct.pack('<H', len(raw)) + raw


def args(pairs):
    body = struct.pack('<H', len(pairs))
    for key, value in pairs:
        body += pstr(key) + pstr(value)
    return node('ARGS', body)


class HelpersTest(unittest.TestCase):
    def test_read_name_skips_header_words(self):
        body = struct.pack('<HHH', 32, 390, 450) + pstr('AddLayer')
        self.assertEqual(read_name(body), 'AddLayer')
        self.assertIsNone(read_name(struct.pack('<HHH', 1, 2, 3)))

    def test_parse_args_pairs_utf8_and_bounds(self):
        count, pairs = parse_args(args([('color', '0x999999'),
                                        ('text', '今日'),
                                        ('alpha', '${control:alpha}')])[8:])
        self.assertEqual(count, 3)
        self.assertEqual(pairs[0], ('color', '0x999999'))
        self.assertEqual(pairs[1][1], '今日')
        self.assertEqual(parse_args(struct.pack('<H', 99))[1], [])


class TreeTest(unittest.TestCase):
    def test_last_child_before_parent_padding_is_kept(self):
        # Header of odd length (9 bytes) followed by one ARGS: the REXT body is
        # padded, so the ARGS ends one zero byte before the REXT does.
        rext = node('REXT', struct.pack('<HH', 0, 5) + pstr('text')
                    + args([('color', 'red')]))
        layer = node('LAYR', struct.pack('<HHH', 32, 390, 450) + pstr('L') + rext)
        forest = parse_tree(layer, 0, len(layer))
        self.assertEqual([c.tag for c in forest[0].children], ['REXT'])
        self.assertEqual([c.tag for c in forest[0].children[0].children], ['ARGS'])

    def test_false_tags_inside_strings_are_rejected(self):
        # Odd size, overrunning size and a malformed ARGS body inside strings.
        poisoned = args([('name', 'ARGS\x01\x00\x00\x00x'), ('n2', 'CNTL\xff\xff\xff\xff')])
        layer = node('LAYR', struct.pack('<HHH', 0, 0, 0) + pstr('L') + poisoned)
        forest = parse_tree(layer, 0, len(layer))
        self.assertEqual([c.tag for c in forest[0].children], ['ARGS'])
        self.assertEqual(forest[0].children[0].children, [])

    def test_lend_marker_closes_the_section(self):
        nodes = node('SCEN', pstr('A')) + node('SCEN', pstr('B'))
        section = nodes + LEND
        self.assertEqual(content_end(section, 0, len(section)), len(nodes))
        self.assertEqual(len(parse_tree(section, 0, len(section))), 2)


class RecordTest(unittest.TestCase):
    def test_rate_curves(self):
        rate = node('RATE', struct.pack('<4f', 0.84, 0.0, 0.16, 1.0) + pstr('ease'))
        curves, terminated = parse_rate(rate + LEND, 0, len(rate) + len(LEND))
        self.assertTrue(terminated)
        self.assertEqual(curves[0]['name'], 'ease')
        self.assertEqual(curves[0]['bezier'], [0.84, 0.0, 0.16, 1.0])

    def test_data_model_rows_and_padding(self):
        rows = (struct.pack('<H', 1) + pstr('k1') + pstr('v') + struct.pack('<H', 0)
                + struct.pack('<H', 4) + pstr('k2') + pstr('255') + pstr('scroll_change'))
        damr = struct.pack('<I', 2) + rows + b'\0'
        count, parsed, padding = parse_damr(damr, 0, len(damr))
        self.assertEqual(count, 2)
        self.assertEqual(parsed, [(1, 'k1', 'v', ''), (4, 'k2', '255', 'scroll_change')])
        self.assertEqual(padding, 1)
        with self.assertRaises(ValueError):
            parse_damr(damr[:-3], 0, len(damr) - 3)

    def test_step_and_inst(self):
        step = struct.pack('<HH', 1, 0) + b''.join(
            pstr(t) for t in ('${app:L.x}', '0', '255', '500', 'linear', '400'))
        parsed = parse_step(step)
        self.assertEqual((parsed['target'], parsed['easing'], parsed['offset_ms']),
                         ('${app:L.x}', 'linear', '400'))
        inst = bytearray(19)
        inst[0], inst[1], inst[3] = 0xff, 1, 2
        struct.pack_into('<H', inst, 13, 60)
        parsed = parse_inst(bytes(inst) + pstr('todoLayer'))
        self.assertEqual((parsed['lead_byte'], parsed['flags'], parsed['index'],
                          parsed['candidate_y'], parsed['layer']),
                         (0xff, 1, 2, 60, 'todoLayer'))

    def test_app_header(self):
        body = struct.pack('<HHIHHIII', 0, 1, 0x07888820, 390, 450, 461, 1049, 35)
        header = decode_app_header(body + pstr('Application') + pstr('3.0'))
        self.assertEqual((header['width'], header['height'], header['count_fields'],
                          header['name'], header['version']),
                         (390, 450, [461, 1049, 35], 'Application', '3.0'))


class ContainerTest(unittest.TestCase):
    def build(self):
        scene = node('SCEN', struct.pack('<HH', 0, 0) + pstr('HomeScreen'))
        payload = scene + LEND
        # LIST size excludes the 4-byte 'SCEN' form type, which sits outside it.
        list_chunk = b'LIST' + struct.pack('<I', len(payload)) + b'SCEN' + payload
        riff_body = b'GAPP' + list_chunk
        return b'RIFF' + struct.pack('<I', len(riff_body)) + riff_body

    def test_sections_and_scene_name(self):
        data = self.build()
        self.assertEqual([s[0] for s in walk_sections(data)], ['SCEN'])
        report = inspect(data)
        self.assertEqual(report['scene_names'], ['HomeScreen'])
        self.assertEqual(report['node_tag_counts'].get('SCEN'), 1)

    def test_rejects_non_gapp(self):
        with self.assertRaises(ValueError):
            walk_sections(b'RIFFxxxxWAVE')


if __name__ == '__main__':
    unittest.main()
