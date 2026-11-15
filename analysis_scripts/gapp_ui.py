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
TREE_SECTIONS = ('LAYR', 'SCEN', 'ANIM')


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
    """(count, [(key, value), ...]) for an ARGS body, bounded and validated."""
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
            pairs.append((key.decode('ascii'), value.decode('ascii')))
        except UnicodeDecodeError:
            pairs.append((key.decode('latin1'), None))
    return count, pairs


class Node:
    __slots__ = ('tag', 'start', 'end', 'body', 'children')

    def __init__(self, tag, start, end, body):
        self.tag = tag
        self.start = start
        self.end = end
        self.body = body
        self.children = []


def _candidate_nodes(data, lo, hi):
    """All tag positions whose declared size keeps them inside [lo, hi)."""
    found = {}
    for tag in CONTAINER_TAGS:
        start = lo
        while True:
            at = data.find(tag, start, hi)
            if at < 0:
                break
            end = at + 8 + u32(data, at + 4)
            if end <= hi:
                found[at] = (tag.rstrip(b'\0').decode('ascii'), end)
            start = at + 1
    return found


def parse_tree(data, lo, hi):
    """Parse the node forest in [lo, hi) by flat scan and size containment.

    A candidate is a known tag whose end lands on another candidate's start or
    on the region end, which rejects tag bytes that fall inside string data.
    The surviving nodes nest strictly by their [start, end) ranges.
    """
    candidates = _candidate_nodes(data, lo, hi)
    boundaries = set(candidates) | {hi}
    valid = {at: info for at, info in candidates.items() if info[1] in boundaries}
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


def inspect(data):
    sections = walk_sections(data)
    by_name = {name: (start, end) for name, start, end in sections}
    report = {'sections': [{'name': n, 'start': s, 'end': e, 'size': e - s}
                           for n, s, e in sections]}
    tags = collections.Counter()
    drawables = collections.Counter()
    events = collections.Counter()
    arg_keys = collections.Counter()
    bindings = collections.Counter()
    container_names = collections.Counter()
    scene_names, animation_names = [], []
    depth_hist = collections.Counter()
    section_trees = {}
    for section in TREE_SECTIONS:
        if section not in by_name:
            continue
        lo, hi = by_name[section]
        forest = parse_tree(data, lo, hi)
        section_trees[section] = {'roots': len(forest),
                                  'bytes': hi - lo}
        for node in _with_depth(forest):
            node_obj, depth = node
            tags[node_obj.tag] += 1
            depth_hist[depth] += 1
            if node_obj.tag == 'REXT':
                name = read_name(node_obj.body)
                if name:
                    drawables[name] += 1
            elif node_obj.tag in ('LAYR', 'GRUP', 'CNTL'):
                name = read_name(node_obj.body)
                if name:
                    container_names[name] += 1
            elif node_obj.tag == 'SCEN':
                name = read_name(node_obj.body)
                if name:
                    scene_names.append(name)
            elif node_obj.tag == 'ANIM':
                name = read_name(node_obj.body)
                if name:
                    animation_names.append(name)
            elif node_obj.tag == 'ACT':
                names = _ascii_strings(node_obj.body[:64])
                if len(names) >= 2:
                    events[names[1]] += 1
            elif node_obj.tag == 'ARGS':
                for key, value in parse_args(node_obj.body)[1]:
                    arg_keys[key] += 1
                    if value and value.startswith('${') and value.endswith('}'):
                        bindings[value] += 1
    report['section_trees'] = section_trees
    report['node_tag_counts'] = dict(sorted(tags.items()))
    report['total_nodes'] = sum(tags.values())
    report['depth_histogram'] = dict(sorted(depth_hist.items()))
    report['drawable_types'] = dict(drawables.most_common())
    report['event_types'] = dict(events.most_common())
    report['arg_keys'] = dict(arg_keys.most_common(60))
    report['binding_expressions'] = dict(bindings.most_common(40))
    report['container_names'] = dict(container_names.most_common(40))
    report['scene_count'] = len(scene_names)
    report['scene_names'] = sorted(scene_names)
    report['animation_count'] = len(animation_names)
    report['animation_names'] = sorted(animation_names)
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
