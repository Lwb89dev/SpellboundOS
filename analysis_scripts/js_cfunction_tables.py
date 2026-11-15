#!/usr/bin/env python3
"""Inventory QuickJS C function tables stored as data in the main firmware.

QuickJS describes native properties with arrays of ``JSCFunctionListEntry``.
On this 32-bit image an entry is 16 bytes: a name pointer, property flags, a
definition type, a magic value and an 8-byte union (arity and function
pointer, getter and setter, nested table and length, or a constant).

The tool reads data only:

- it scans the image for runs of well-formed entries;
- it reads the embedded bootstrap source that imports each native module and
  assigns it to a global of the same name;
- optionally, with a local Ghidra export directory, it takes exact table
  lengths from calls whose last two arguments are a table address and a count;
- optionally, with the published API JSON files, it labels tables by the
  module whose known method names they contain.

Addresses assume the image is mapped with file offset 0 at 0x70160000. Entries
are names, arities, constants and addresses, not behavior.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import zipfile

FIRMWARE = 'META/firmware_sign.bin'
BASE = 0x70160000
ENTRY = 16
MAX_COUNT = 2048
NAME = re.compile(rb'[A-Za-z_$][\w$]{0,63}')
KINDS = {0: 'function', 1: 'getset', 2: 'getset_magic', 3: 'string', 4: 'int32',
         5: 'int64', 6: 'double', 7: 'undefined', 8: 'object', 9: 'alias'}
BOOTSTRAP = re.compile(rb"import \* as (\w+) from '(\w+)';\nglobalThis\.(\w+) = (\w+);\n")
TABLE_ARG = re.compile(r'&PTR_\w*_ram_([0-9a-f]{8}),\s*(0x[0-9a-f]+|\d+)\s*\)')
CALLEE = re.compile(r'(FUN_ram_[0-9a-f]{8})\(')


class Image:
    def __init__(self, data, base=BASE):
        self.data, self.base = data, base

    def inside(self, address):
        return self.base <= address < self.base + len(self.data)

    def name(self, address):
        offset = address - self.base
        if not 0 <= offset < len(self.data):
            return None
        end = self.data.find(b'\0', offset, offset + 65)
        if end < 0:
            return None
        text = self.data[offset:end]
        return text.decode() if NAME.fullmatch(text) else None

    def text(self, address):
        offset = address - self.base
        if not 0 <= offset < len(self.data):
            return None
        end = self.data.find(b'\0', offset, offset + 257)
        if end < 0:
            return None
        raw = self.data[offset:end]
        return raw.decode('latin1') if all(32 <= c < 127 for c in raw) else None

    def entry(self, offset):
        """Decode one entry, or return None when the bytes are not well formed."""
        if offset < 0 or offset + ENTRY > len(self.data):
            return None
        pointer, flags, kind, magic = struct.unpack_from('<IBBh', self.data, offset)
        name = self.name(pointer)
        if name is None or flags > 7 or kind not in KINDS:
            return None
        first, second = struct.unpack_from('<II', self.data, offset + 8)
        out = {'name': name, 'kind': KINDS[kind]}
        if magic:
            out['magic'] = magic
        if kind == 0:
            arity, proto = self.data[offset + 8], self.data[offset + 9]
            if proto > 12 or not self.inside(second):
                return None
            out.update(arity=arity, address=second)
            if proto:
                out['cproto'] = proto
        elif kind in (1, 2):
            if not (first or second):
                return None
            if (first and not self.inside(first)) or (second and not self.inside(second)):
                return None
            out.update(getter=first or None, setter=second or None)
        elif kind == 3:
            value = self.text(first)
            if value is None:
                return None
            out['value'] = value
        elif kind == 4:
            out['value'] = struct.unpack_from('<i', self.data, offset + 8)[0]
        elif kind == 5:
            out['value'] = struct.unpack_from('<q', self.data, offset + 8)[0]
        elif kind == 6:
            value = struct.unpack_from('<d', self.data, offset + 8)[0]
            out['value'] = value if value == value and abs(value) != float('inf') \
                else repr(value)
        elif kind == 7:
            if first or second:
                return None
        elif kind == 8:
            if not self.inside(first) or first % 8 or not 0 < second < MAX_COUNT:
                return None
            out.update(table=first, count=second)
        elif kind == 9:
            target = self.name(first)
            if target is None:
                return None
            out['target'] = target
        return out

    def runs(self, minimum=2):
        """Maximal runs of consecutive well-formed entries at 8-byte alignment."""
        found, offset = [], 0
        while offset + ENTRY <= len(self.data):
            if self.entry(offset) is None:
                offset += 8
                continue
            start, entries = offset, []
            while (item := self.entry(offset)) is not None:
                entries.append(item)
                offset += ENTRY
            if len(entries) >= minimum:
                found.append((self.base + start, entries))
        return found

    def table(self, address, count):
        entries = [self.entry(address - self.base + i * ENTRY) for i in range(count)]
        return entries if all(entries) else None


def bootstrap_modules(data):
    """Module names from the embedded ``import * as X from 'X'`` bootstrap."""
    modules = []
    for alias, module, target, value in BOOTSTRAP.findall(data):
        if alias == target == value:
            modules.append({'global': target.decode(), 'module': module.decode()})
    return modules


def corpus_calls(directory):
    """(table address) -> {count, callees, callers} from Ghidra C exports."""
    calls = {}
    for path in sorted(pathlib.Path(directory).glob('*.c')):
        text = path.read_text(errors='replace')
        if '&PTR_' not in text:
            continue
        for match in TABLE_ARG.finditer(text):
            statement = text[text.rfind(';', 0, match.start()) + 1:match.start()]
            callees = CALLEE.findall(statement)
            count = int(match.group(2), 0)
            if not callees or not 0 < count < MAX_COUNT:
                continue
            info = calls.setdefault(int(match.group(1), 16),
                                    {'counts': set(), 'callees': set(), 'callers': set()})
            info['counts'].add(count)
            info['callees'].add(callees[-1])
            info['callers'].add(path.stem)
    return calls


def known_methods(paths):
    """module -> method names, from js-runtime-api.json / zos-api-table.json."""
    known = collections.defaultdict(set)
    for path in paths:
        document = json.loads(pathlib.Path(path).read_text())
        for module, names in document.get('native_modules', {}).items():
            known[module].update(names)
        known['hmBle'].update(document.get('ble_wrapper_methods', []))
        for spec in document.get('modules', {}).values():
            for method in spec.get('methods', []):
                if '.' in method.get('native', ''):
                    module, name = method['native'].split('.', 1)
                    known[module].add(name)
    return known


def label(entries, known):
    names = {e['name'] for e in entries}
    scores = sorted(((len(names & methods), module) for module, methods in known.items()),
                    reverse=True)
    if scores and scores[0][0] >= 2 and (len(scores) == 1 or scores[0][0] > scores[1][0]):
        return {'module': scores[0][1], 'matched_known_methods': scores[0][0],
                'known_methods': len(known[scores[0][1]])}
    return None


def inventory(data, calls=None, known=None, base=BASE):
    image = Image(data, base)
    runs = image.runs()
    tables, covered = [], set()
    for address, info in sorted((calls or {}).items()):
        if len(info['counts']) != 1:
            continue
        count = next(iter(info['counts']))
        entries = image.table(address, count)
        if entries is None:
            continue
        covered.add(address)
        tables.append({'address': address, 'count': count, 'count_source': 'call-site',
                       'callees': sorted(info['callees']), 'callers': sorted(info['callers']),
                       'entries': entries})
    # Nested tables carry their own exact length in the parent entry.
    queue = [e for t in tables for e in t['entries'] if e['kind'] == 'object']
    for start, entries in runs:
        queue.extend(e for e in entries if e['kind'] == 'object')
    while queue:
        item = queue.pop()
        if item['table'] in covered:
            continue
        entries = image.table(item['table'], item['count'])
        if entries is None:
            continue
        covered.add(item['table'])
        tables.append({'address': item['table'], 'count': item['count'],
                       'count_source': 'parent-entry', 'entries': entries})
        queue.extend(e for e in entries if e['kind'] == 'object')
    # Keep the parts of each run that no exact-length table accounts for.
    spans = sorted((t['address'], t['address'] + t['count'] * ENTRY) for t in tables)
    for start, entries in runs:
        taken = [False] * len(entries)
        for low, high in spans:
            first = max(0, (low - start) // ENTRY)
            last = min(len(entries), (high - start + ENTRY - 1) // ENTRY)
            for index in range(first, last):
                taken[index] = True
        index = 0
        while index < len(entries):
            if taken[index]:
                index += 1
                continue
            stop = index
            while stop < len(entries) and not taken[stop]:
                stop += 1
            tables.append({'address': start + index * ENTRY, 'count': stop - index,
                           'count_source': 'run', 'entries': entries[index:stop]})
            index = stop
    tables.sort(key=lambda t: t['address'])
    if known:
        for table in tables:
            match = label(table['entries'], known)
            if match:
                table['label'] = match
    return runs, tables


def summarize(runs, tables, modules, known=None):
    kinds = collections.Counter(e['kind'] for t in tables for e in t['entries'])
    functions = {e['address'] for t in tables for e in t['entries'] if e['kind'] == 'function'}
    best = {}
    for table in tables:
        match = table.get('label')
        if match and match['matched_known_methods'] > best.get(match['module'], (0,))[0]:
            best[match['module']] = (match['matched_known_methods'], match['known_methods'],
                                     table['address'], table['count'])
    present = {e['name'] for t in tables for e in t['entries']}
    absent = {module: sorted(names - present) for module, names in sorted((known or {}).items())
              if names - present}
    return {
        'known_methods_not_found': absent,
        'bootstrap_modules': modules,
        'runs_found': len(runs),
        'run_entries': sum(len(e) for _, e in runs),
        'tables': len(tables),
        'tables_by_count_source': dict(collections.Counter(t['count_source'] for t in tables)),
        'entries_by_kind': dict(sorted(kinds.items())),
        'distinct_native_functions': len(functions),
        'best_table_per_module': {m: {'matched_known_methods': v[0], 'known_methods': v[1],
                                      'address': v[2], 'count': v[3]}
                                  for m, v in sorted(best.items())},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', help='local Ghidra export directory (optional)')
    parser.add_argument('--known', nargs='*', default=[],
                        help='published API JSON files used to label tables')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(FIRMWARE)
    calls = corpus_calls(args.decompiled) if args.decompiled else None
    known = known_methods(args.known) if args.known else None
    runs, tables = inventory(data, calls, known)
    print(json.dumps({'member': FIRMWARE, 'member_sha256': hashlib.sha256(data).hexdigest(),
                      'image_base': BASE, 'used_call_sites': calls is not None,
                      'summary': summarize(runs, tables, bootstrap_modules(data), known),
                      'tables': tables}, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
