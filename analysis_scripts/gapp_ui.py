#!/usr/bin/env python3
"""Decode the GAPP compiled UI tree inside Application.bin.

``META/resources/Application.bin`` is a RIFF/GAPP container. Its LIST sections
(LAYR, SCEN, ANIM) hold a tree of tagged nodes that describe the watchfaces and
mini-program screens: layers, groups, controls, drawable primitives, event
handlers and their property arguments. This reader walks that tree and reports
its structure and vocabulary. It does not render anything or execute callbacks.

Node format: a 4-byte tag, a little-endian ``uint32`` body size, then the body.
A body begins with primitive header words and length-prefixed names, then holds
child nodes. ``ARGS`` bodies are a ``uint16`` count followed by that many
key/value string pairs, each a ``uint16`` length and bytes. The grammar is
recovered from the bytes, not from vendor documentation.
"""
import argparse
import collections
import hashlib
import json
import struct
import zipfile

MEMBER = 'META/resources/Application.bin'
CONTAINER_TAGS = {b'LAYR', b'GRUP', b'CNTL', b'REXT', b'SCRL', b'ACT\x00', b'ARGS',
                  b'TAB\x00', b'SCEN', b'INST', b'ANIM', b'STEP'}
# Section LISTs whose bodies hold the node tree.
TREE_SECTIONS = ('APP', 'LAYR', 'SCEN', 'ANIM')


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def read_name(body):
    """First NUL-terminated length-prefixed ASCII string in a node header."""
    offset = 0
    while offset + 2 <= len(body):
        length = u16(body, offset)
        end = offset + 2 + length
        if 2 <= length <= 64 and end <= len(body) and body[end - 1] == 0 \
                and all(32 <= c < 127 for c in body[offset + 2:end - 1]):
            return body[offset + 2:end - 1].decode('ascii')
        offset += 2
    return None


def parse_args(body):
    """(count, [(key, value), ...]) for an ARGS body, bounded and validated.

    Keys are ASCII. Values are UTF-8 text (translations include non-Latin
    scripts); undecodable values are reported as None.
    """
    if len(body) < 2:
        return 0, []
    count, offset, pairs = u16(body, 0), 2, []
    for _ in range(count):
        parts = []
        for _ in range(2):
            if offset + 2 > len(body):
                return count, pairs
            length = u16(body, offset)
            offset += 2
            if length > len(body) - offset:
                return count, pairs
            parts.append(body[offset:offset + length].rstrip(b'\0'))
            offset += length
        key, value = parts
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            value = None
        pairs.append((key.decode('latin1'), value))
    return count, pairs


class Node:
    __slots__ = ('tag', 'start', 'end', 'body', 'children')

    def __init__(self, tag, start, end, body):
        self.tag = tag
        self.start = start
        self.end = end
        self.body = body
        self.children = []


def args_consumed(body):
    """Bytes consumed by an ARGS body's declared pairs, or None if it overruns."""
    if len(body) < 2:
        return None
    count, offset = u16(body, 0), 2
    for _ in range(2 * count):
        if offset + 2 > len(body):
            return None
        length = u16(body, offset)
        offset += 2
        if length > len(body) - offset:
            return None
        offset += length
    return offset


def _well_formed_args(body):
    """ARGS pairs fill the body exactly, or leave one zero alignment byte."""
    used = args_consumed(body)
    return used is not None and (used == len(body) or
                                 (used + 1 == len(body) and body[used] == 0))


def _candidate_nodes(data, lo, hi):
    """Tag positions with an even size inside [lo, hi); ARGS must parse exactly.

    Node sizes are always even: bodies are padded with one zero byte to 2-byte
    alignment, and the padding is counted in the declared size.
    """
    found = {}
    for tag in CONTAINER_TAGS:
        start = lo
        while True:
            at = data.find(tag, start, hi)
            if at < 0:
                break
            size = u32(data, at + 4)
            end = at + 8 + size
            if end <= hi and size % 2 == 0 and (
                    tag != b'ARGS' or _well_formed_args(data[at + 8:end])):
                found[at] = (tag.rstrip(b'\0').decode('ascii'), end)
            start = at + 1
    return found


LEND = b'LEND\0\0\0\0'


def content_end(data, lo, hi):
    """End of a section's nodes: LIST bodies close with an 8-byte LEND marker."""
    if hi - lo >= len(LEND) and data[hi - len(LEND):hi] == LEND:
        return hi - len(LEND)
    return hi


def parse_tree(data, lo, hi):
    """Parse the node forest in [lo, hi) by flat scan and size containment.

    A candidate is a known tag whose end lands on another candidate's start or
    on the region end, which rejects tag bytes that fall inside string data.
    The surviving nodes nest strictly by their [start, end) ranges.
    """
    hi = content_end(data, lo, hi)
    candidates = _candidate_nodes(data, lo, hi)
    # A node is accepted when it ends on a boundary, or one zero padding byte
    # before one: a last child ends where its parent's padding begins. Node ends
    # are boundaries too, so iterate to a fixed point.
    def lands(end, marks):
        return end in marks or (end + 1 in marks and end < hi and data[end] == 0)
    boundaries = set(candidates) | {hi}
    valid = {}
    while True:
        accepted = {at: info for at, info in candidates.items()
                    if lands(info[1], boundaries)}
        if accepted.keys() == valid.keys():
            break
        valid = accepted
        boundaries = set(candidates) | {hi} | {end for _, end in valid.values()}
    nodes = {at: Node(tag, at, end, data[at + 8:end])
             for at, (tag, end) in valid.items()}
    forest, stack = [], []
    for at in sorted(nodes):
        node = nodes[at]
        while stack and at >= stack[-1].end:
            stack.pop()
        if stack:
            stack[-1].children.append(node)
        else:
            forest.append(node)
        stack.append(node)
    return forest


def walk_sections(data):
    """Top-level RIFF/GAPP walk → list of (name, body_start, body_end)."""
    if data[:4] != b'RIFF' or data[8:12] != b'GAPP':
        raise ValueError('not a RIFF/GAPP container')
    sections, offset = [], 12
    while offset + 8 <= len(data):
        tag = data[offset:offset + 4]
        size = u32(data, offset + 4)
        if tag == b'LIST':
            # The 4-byte LIST form type sits outside the declared size in this
            # container, so the body is the full `size` bytes after it.
            name = data[offset + 8:offset + 12].decode('latin1')
            sections.append((name, offset + 12, offset + 12 + size))
            offset = offset + 12 + size
        else:
            sections.append((tag.rstrip(b'\0').decode('latin1'),
                             offset + 8, offset + 8 + size))
            offset = offset + 8 + size
    return sections


def iter_nodes(forest):
    stack = list(forest)
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.children)


def lp_strings(body, offset, count):
    """Read `count` u16-length-prefixed strings; return (texts, next_offset)."""
    out = []
    for _ in range(count):
        if offset + 2 > len(body):
            raise ValueError('truncated string length')
        length = u16(body, offset)
        if length > len(body) - offset - 2:
            raise ValueError('string overruns its node')
        raw = body[offset + 2:offset + 2 + length].rstrip(b'\0')
        out.append(raw.decode('utf-8', 'replace'))
        offset += 2 + length
    return out, offset


def decode_app_header(body):
    """Fixed APP header fields, the application name and its version string."""
    if len(body) < 24:
        raise ValueError('APP header too short')
    fields = struct.unpack_from('<HHIHHIII', body, 0)
    (name, version), _ = lp_strings(body, 24, 2)
    return {'u16_0': fields[0], 'format_word': fields[1],
            'unknown_word': fields[2], 'width': fields[3], 'height': fields[4],
            'count_fields': [fields[5], fields[6], fields[7]],
            'name': name, 'version': version}


def parse_rate(data, lo, hi):
    """RATE nodes: four float32 cubic-bezier control values and a curve name."""
    curves, offset = [], lo
    while offset + 8 <= hi and data[offset:offset + 4] == b'RATE':
        size = u32(data, offset + 4)
        body = data[offset + 8:offset + 8 + size]
        if size < 18 or offset + 8 + size > hi:
            raise ValueError('malformed RATE node')
        x1, y1, x2, y2 = struct.unpack_from('<4f', body, 0)
        (name,), _ = lp_strings(body, 16, 1)
        curves.append({'name': name,
                       'bezier': [round(v, 6) for v in (x1, y1, x2, y2)]})
        offset += 8 + size
    terminator = data[offset:offset + 4]
    return curves, terminator == b'LEND'


def parse_damr(data, lo, hi):
    """DAMR data model: u32 count, then (u16 type, key, value, change-event)."""
    count, offset, rows = u32(data, lo), lo + 4, []
    body = data[:hi]
    for _ in range(count):
        if offset + 2 > hi:
            raise ValueError('DAMR entry overruns section')
        kind = u16(data, offset)
        (key, value, event), offset = lp_strings(body, offset + 2, 3)
        rows.append((kind, key, value, event))
    padding = data[offset:hi]
    if offset > hi or any(padding):
        raise ValueError('DAMR does not end on its section boundary')
    return count, rows, len(padding)


def parse_step(body):
    """STEP keyframe: two u16 header words, then six strings."""
    words = (u16(body, 0), u16(body, 2))
    fields, used = lp_strings(body, 4, 6)
    if used not in (len(body), len(body) - 1):
        raise ValueError('STEP strings do not fill the node')
    return dict(zip(('header', 'target', 'from', 'to', 'duration_ms',
                     'easing', 'offset_ms'), (words, *fields)))


INST_HEADER = 19


def parse_inst(body):
    """INST: a 19-byte header, the instanced layer name, then optional children."""
    if len(body) < INST_HEADER + 2:
        raise ValueError('INST too short')
    (layer,), _ = lp_strings(body, INST_HEADER, 1)
    return {'lead_byte': body[0], 'flags': body[1], 'index': body[3],
            'candidate_x': u16(body, 11), 'candidate_y': u16(body, 13),
            'layer': layer}


BUILTIN_EASINGS = ('linear', 'easeinout')


def inspect(data):
    sections = walk_sections(data)
    by_name = {name: (start, end) for name, start, end in sections}
    report = {'sections': [{'name': n, 'start': s, 'end': e, 'size': e - s}
                           for n, s, e in sections]}
    tags, drawables, events = (collections.Counter() for _ in range(3))
    arg_keys, bindings, scopes = (collections.Counter() for _ in range(3))
    container_names, depth_hist = collections.Counter(), collections.Counter()
    scene_names, animation_names, layer_names = [], [], set()
    steps, insts, section_trees = [], [], {}
    for section in TREE_SECTIONS:
        if section not in by_name:
            continue
        lo, hi = by_name[section]
        forest = parse_tree(data, lo, hi)
        section_trees[section] = {'roots': len(forest), 'bytes': hi - lo}
        for node, depth in _with_depth(forest):
            tags[node.tag] += 1
            depth_hist[depth] += 1
            if node.tag == 'REXT':
                name = read_name(node.body)
                if name:
                    drawables[name] += 1
            elif node.tag in ('LAYR', 'GRUP', 'CNTL'):
                name = read_name(node.body)
                if name:
                    container_names[name] += 1
                    if node.tag == 'LAYR' and depth == 0:
                        layer_names.add(name)
            elif node.tag == 'SCEN':
                name = read_name(node.body)
                if name:
                    scene_names.append(name)
            elif node.tag == 'ANIM':
                name = read_name(node.body)
                if name:
                    animation_names.append(name)
            elif node.tag == 'STEP':
                steps.append(parse_step(node.body))
            elif node.tag == 'INST':
                insts.append(parse_inst(node.body))
            elif node.tag == 'ACT':
                names = _ascii_strings(node.body[:64])
                if len(names) >= 2:
                    events[names[1]] += 1
            elif node.tag == 'ARGS':
                for key, value in parse_args(node.body)[1]:
                    arg_keys[key] += 1
                    for text in (key, value or ''):
                        if text.startswith('${') and text.endswith('}') and ':' in text:
                            bindings[text] += 1
                            scopes[text[2:text.index(':')]] += 1
    report['section_trees'] = section_trees
    report['node_tag_counts'] = dict(sorted(tags.items()))
    report['total_nodes'] = sum(tags.values())
    report['depth_histogram'] = dict(sorted(depth_hist.items()))
    report['drawable_types'] = dict(drawables)
    report['event_types'] = dict(events)
    report['event_type_count'] = len(events)
    report['arg_keys_top'] = dict(arg_keys.most_common(60))
    report['arg_key_count'] = len(arg_keys)
    report['binding_scopes'] = dict(scopes)
    report['binding_expression_count'] = len(bindings)
    report['binding_expressions_top'] = dict(bindings.most_common(40))
    report['container_names_top'] = dict(container_names.most_common(40))
    report['scene_count'] = len(scene_names)
    report['scene_names'] = sorted(scene_names)
    report['animation_count'] = len(animation_names)
    report['animation_names'] = sorted(animation_names)

    if 'APP' in by_name:
        lo, hi = by_name['APP']
        report['app_header'] = decode_app_header(data[lo:hi])
    if 'RATE' in by_name:
        curves, terminated = parse_rate(data, *by_name['RATE'])
        report['rate_curves'] = curves
        report['rate_lend_terminated'] = terminated
    curve_names = {c['name'] for c in report.get('rate_curves', [])}
    easing = collections.Counter(step['easing'] for step in steps)
    report['steps'] = {
        'count': len(steps),
        'header_words': {f'{a},{b}': n for (a, b), n in
                         sorted(collections.Counter(s['header'] for s in steps).items())},
        'easing': dict(easing),
        'easing_unresolved': sorted(set(easing) - curve_names - set(BUILTIN_EASINGS)),
        'targets_are_app_bindings': sum(s['target'].startswith('${app:') for s in steps),
    }
    unresolved = sorted({i['layer'] for i in insts} - layer_names)
    report['instances'] = {
        'count': len(insts),
        'distinct_layers': len({i['layer'] for i in insts}),
        'resolved_to_layer': sum(i['layer'] in layer_names for i in insts),
        'unresolved_layers': unresolved,
        'lead_bytes': dict(collections.Counter(i['lead_byte'] for i in insts)),
    }
    if 'DAMR' in by_name:
        count, rows, padding = parse_damr(data, *by_name['DAMR'])
        keys = [k for _, k, _, _ in rows]
        app_paths = {b[6:-1] for b in bindings if b.startswith('${app:')}
        app_paths |= {s['target'][6:-1] for s in steps if s['target'].startswith('${app:')}
        report['data_model'] = {
            'count': count,
            'trailing_padding_bytes': padding,
            'types': dict(collections.Counter(kind for kind, _, _, _ in rows)),
            'distinct_keys': len(set(keys)),
            'duplicate_keys': len(keys) - len(set(keys)),
            'translation_keys': sum(k.startswith('translations.') for k in keys),
            'change_events': dict(collections.Counter(e for _, _, _, e in rows if e)),
            'app_binding_paths': len(app_paths),
            'app_binding_paths_defined': len(app_paths & set(keys)),
        }
    return report


def _with_depth(forest):
    stack = [(node, 0) for node in reversed(forest)]
    while stack:
        node, depth = stack.pop()
        yield node, depth
        stack.extend((child, depth + 1) for child in reversed(node.children))


def _ascii_strings(body):
    out, offset = [], 0
    while offset + 2 <= len(body):
        length = u16(body, offset)
        end = offset + 2 + length
        if 2 <= length <= 64 and end <= len(body) and body[end - 1] == 0 \
                and all(32 <= c < 127 for c in body[offset + 2:end - 1]):
            out.append(body[offset + 2:end - 1].decode('ascii'))
            offset = end
        else:
            offset += 2
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(MEMBER)
    report = inspect(data)
    report['member'] = MEMBER
    report['member_size'] = len(data)
    report['member_sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
