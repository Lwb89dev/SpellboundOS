#!/usr/bin/env python3
"""Read and disassemble the packaged app bytecode (QuickJS 2020-07-05 format).

This is an independent Python implementation of the 2020-07-05 ``JS_ReadObject``
bytecode layout (see analysis/QUICKJS_ENGINE.md for why that release applies).
It never executes bytecode. Every read is bounds-checked and the disassembler
validates its own result. Instructions must tile each function's bytecode
exactly, branch targets must land on instruction boundaries, and
local/argument/closure/constant indices must be in range.

Inputs:
- builtin atoms are taken from the firmware's own ``js_atom_init`` blob;
- opcode sizes and operand formats come from the firmware's ``opcode_info[]``
  table. Opcode *names* are read from an upstream 2020-07-05
  ``quickjs-opcode.h``. They are used only after the table built from that header
  is found byte-for-byte in the firmware.

Full listings contain vendor-derived content and are written only to a new
private directory on request. The standard output is a statistical summary.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from quickjs_fingerprint import (FIRMWARE, firmware_atoms,  # noqa: E402
                                 opcode_table_bytes, upstream_opcodes)

BC_VERSION = 1
BYTECODE_DIRS = ('META/js_apps/', 'META/js_watchfaces/')
TAGS = {1: 'null', 2: 'undefined', 3: 'false', 4: 'true', 5: 'int32',
        6: 'float64', 7: 'string', 8: 'object', 9: 'array', 10: 'big_int',
        11: 'big_float', 12: 'big_decimal', 13: 'template_object',
        14: 'function_bytecode', 15: 'module', 16: 'typed_array',
        17: 'array_buffer', 18: 'shared_array_buffer', 19: 'date',
        20: 'object_value', 21: 'object_reference'}
FUNC_FLAGS = (('has_prototype', 1), ('has_simple_parameter_list', 1),
              ('is_derived_class_constructor', 1), ('need_home_object', 1),
              ('func_kind', 2), ('new_target_allowed', 1),
              ('super_call_allowed', 1), ('super_allowed', 1),
              ('arguments_allowed', 1), ('has_debug', 1),
              ('backtrace_barrier', 1))
ATOM_TAG_INT = 1 << 31
MAX_DEPTH = 200


class BytecodeError(ValueError):
    pass


def _bits(value, layout):
    out, shift = {}, 0
    for name, width in layout:
        out[name] = (value >> shift) & ((1 << width) - 1)
        shift += width
    return out


class Reader:
    def __init__(self, data, builtin_atoms):
        self.data, self.pos = data, 0
        self.builtins = builtin_atoms  # index 0 is JS_ATOM_NULL
        self.first_atom = len(builtin_atoms)
        self.atoms = []
        self.object_count = 0

    def need(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise BytecodeError(f'read past end at {self.pos} (+{n})')

    def u8(self):
        self.need(1)
        self.pos += 1
        return self.data[self.pos - 1]

    def unpack(self, fmt):
        size = struct.calcsize(fmt)
        self.need(size)
        value = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos += size
        return value

    def leb128(self):
        value = 0
        for i in range(5):
            byte = self.u8()
            value |= (byte & 0x7f) << (7 * i)
            if byte < 0x80:
                return value & 0xffffffff
        raise BytecodeError(f'overlong leb128 ending at {self.pos}')

    def sleb128(self):
        value = self.leb128()
        result = (value >> 1) ^ -(value & 1)
        return result

    def raw(self, n):
        self.need(n)
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def string(self):
        header = self.leb128()
        wide, length = header & 1, header >> 1
        payload = self.raw(length << wide)
        return payload.decode('utf-16-le' if wide else 'latin1')

    def atom_from_index(self, idx):
        if idx & ATOM_TAG_INT:
            return {'int': idx & ~ATOM_TAG_INT}
        if idx < self.first_atom:
            # Index 0 is JS_ATOM_NULL, which the upstream reader also accepts
            # (for example as the name of an anonymous function).
            return {'builtin': self.builtins[idx] if idx else '<null>'}
        idx -= self.first_atom
        if idx >= len(self.atoms):
            raise BytecodeError(f'invalid atom index {idx + self.first_atom}')
        return {'file': idx}

    def atom(self):
        value = self.leb128()
        if value & 1:
            return {'int': value >> 1}
        return self.atom_from_index(value >> 1)

    def atom_text(self, ref):
        if 'int' in ref:
            return str(ref['int'])
        if 'builtin' in ref:
            return ref['builtin']
        return self.atoms[ref['file']]

    # ---- objects -------------------------------------------------------
    def read_file(self):
        version = self.u8()
        if version != BC_VERSION:
            raise BytecodeError(f'unsupported version byte {version}')
        count = self.leb128()
        if count > len(self.data):
            raise BytecodeError('atom count exceeds input size')
        self.atoms = [self.string() for _ in range(count)]
        root = self.value(0)
        return root

    def value(self, depth):
        if depth > MAX_DEPTH:
            raise BytecodeError('object nesting too deep')
        at = self.pos
        tag = self.u8()
        kind = TAGS.get(tag)
        if kind in ('null', 'undefined'):
            return {'type': kind}
        if kind in ('false', 'true'):
            return {'type': 'bool', 'value': kind == 'true'}
        if kind == 'int32':
            return {'type': 'int32', 'value': self.sleb128()}
        if kind == 'float64':
            return {'type': 'float64', 'value': self.unpack('<d')}
        if kind == 'string':
            return {'type': 'string', 'value': self.string()}
        if kind == 'function_bytecode':
            return self.function(depth)
        if kind == 'module':
            return self.module(depth)
        if kind == 'object':
            self.object_count += 1
            props = []
            for _ in range(self.leb128()):
                name = self.atom()
                props.append((name, self.value(depth + 1)))
            return {'type': 'object', 'properties': props}
        if kind in ('array', 'template_object'):
            self.object_count += 1
            items = [self.value(depth + 1) for _ in range(self.leb128())]
            out = {'type': kind, 'items': items}
            if kind == 'template_object':
                out['raw'] = self.value(depth + 1)
            return out
        if kind == 'object_reference':
            index = self.leb128()
            if index >= self.object_count:
                raise BytecodeError(f'invalid object reference {index}')
            return {'type': 'object_reference', 'index': index}
        raise BytecodeError(f'unsupported tag {tag} ({kind}) at {at}')

    def function(self, depth):
        start = self.pos - 1
        flags = self.unpack('<H')
        fn = {'type': 'function', 'offset': start, 'flags': flags}
        fn.update(_bits(flags, FUNC_FLAGS))
        fn['js_mode'] = self.u8()
        fn['name'] = self.atom()
        for key in ('arg_count', 'var_count', 'defined_arg_count',
                    'stack_size', 'closure_var_count', 'cpool_count',
                    'bytecode_length', 'local_count'):
            fn[key] = self.leb128()
        for key in ('arg_count', 'var_count', 'defined_arg_count', 'stack_size'):
            if fn[key] > 0xffff:
                raise BytecodeError(f'{key} exceeds uint16')
        if fn['local_count'] and fn['local_count'] != fn['arg_count'] + fn['var_count']:
            raise BytecodeError('local count differs from args + vars')
        fn['vardefs'] = []
        for _ in range(fn['local_count']):
            var = {'name': self.atom(), 'scope_level': self.leb128(),
                   'scope_next': self.leb128() - 1}
            var.update(_bits(self.u8(), (('var_kind', 4), ('is_func_var', 1),
                                         ('is_const', 1), ('is_lexical', 1),
                                         ('is_captured', 1))))
            fn['vardefs'].append(var)
        fn['closure_vars'] = []
        for _ in range(fn['closure_var_count']):
            var = {'name': self.atom(), 'var_idx': self.leb128()}
            var.update(_bits(self.u8(), (('is_local', 1), ('is_arg', 1),
                                         ('is_const', 1), ('is_lexical', 1),
                                         ('var_kind', 4))))
            fn['closure_vars'].append(var)
        fn['bytecode_offset'] = self.pos
        fn['bytecode'] = self.raw(fn['bytecode_length'])
        if fn['has_debug']:
            fn['debug_filename'] = self.atom()
            fn['debug_line'] = self.leb128()
            fn['pc2line'] = self.raw(self.leb128())
        fn['cpool'] = [self.value(depth + 1) for _ in range(fn['cpool_count'])]
        fn['end'] = self.pos
        return fn

    def module(self, depth):
        mod = {'type': 'module', 'name': self.atom()}
        mod['requires'] = [self.atom() for _ in range(self.leb128())]
        exports = []
        for _ in range(self.leb128()):
            kind = self.u8()
            entry = {'export_type': kind}
            if kind == 0:  # JS_EXPORT_TYPE_LOCAL
                entry['var_idx'] = self.leb128()
            else:
                entry['req_module_idx'] = self.leb128()
                entry['local_name'] = self.atom()
            entry['export_name'] = self.atom()
            exports.append(entry)
        mod['exports'] = exports
        mod['star_exports'] = [self.leb128() for _ in range(self.leb128())]
        mod['imports'] = [{'var_idx': self.leb128(), 'import_name': self.atom(),
                           'req_module_idx': self.leb128()}
                          for _ in range(self.leb128())]
        mod['function'] = self.value(depth + 1)
        return mod


# ---- opcode table and disassembly -------------------------------------------
def final_opcodes(entries):
    """Opcode byte -> descriptor: the non-temporary entries in table order."""
    return [e for e in entries if not e['temporary']]


def verified_opcodes(firmware, opcode_header):
    formats, entries = upstream_opcodes(opcode_header)
    table = opcode_table_bytes(formats, entries)
    offset = firmware.find(table)
    if offset < 0:
        raise BytecodeError('opcode table from header not present in firmware')
    return offset, final_opcodes(entries)


def _first_index(ops, name):
    return next(i for i, e in enumerate(ops) if e['name'] == name)


def disassemble(fn, ops, reader):
    """Decode one function's bytecode and validate it structurally."""
    code = fn['bytecode']
    args = fn['vardefs'][:fn['arg_count']]
    local_vars = fn['vardefs'][fn['arg_count']:]
    base = {name: _first_index(ops, name) for name in
            ('push_0', 'call0', 'get_loc0', 'get_arg0', 'get_var_ref0')
            if any(e['name'] == name for e in ops)}
    out, pos, starts, targets = [], 0, set(), []
    while pos < len(code):
        op = code[pos]
        if op >= len(ops) or ops[op]['name'] == 'invalid':
            raise BytecodeError(f'invalid opcode 0x{op:02x} at {pos}')
        info = ops[op]
        if pos + info['size'] > len(code):
            raise BytecodeError(f'truncated {info["name"]} at {pos}')
        starts.add(pos)
        operand = pos + 1
        fmt, text = info['format'], []

        def u(fmt_, off=0):
            return struct.unpack_from(fmt_, code, operand + off)[0]

        def atom_at(off=0):
            return reader.atom_text(reader.atom_from_index(u('<I', off)))

        def check(kind, idx, limit):
            if idx >= limit:
                raise BytecodeError(f'{kind} index {idx} out of range at {pos}')
            return idx

        def name_of(var):
            return reader.atom_text(var['name'])

        if fmt == 'none_int':
            text.append(str(op - base['push_0']))
        elif fmt == 'npopx':
            text.append(str(op - base['call0']))
        elif fmt in ('u8',):
            text.append(str(u('<B')))
        elif fmt == 'i8':
            text.append(str(u('<b')))
        elif fmt in ('u16', 'npop'):
            text.append(str(u('<H')))
        elif fmt == 'npop_u16':
            text.append(f'{u("<H")},{u("<H", 2)}')
        elif fmt == 'i16':
            text.append(str(u('<h')))
        elif fmt == 'i32':
            text.append(str(u('<i')))
        elif fmt == 'u32':
            text.append(str(u('<I')))
        elif fmt in ('label8', 'label16', 'label', 'label_u16'):
            rel = {'label8': '<b', 'label16': '<h'}.get(fmt, '<I')
            delta = u(rel)
            if rel == '<I':
                delta = struct.unpack('<i', struct.pack('<I', delta))[0]
            target = operand + delta
            targets.append((pos, target))
            text.append(f'@{target}')
            if fmt == 'label_u16':
                text.append(str(u('<H', 4)))
        elif fmt in ('const8', 'const'):
            idx = check('constant', u('<B') if fmt == 'const8' else u('<I'),
                        fn['cpool_count'])
            text.append(f'cpool[{idx}]:{fn["cpool"][idx]["type"]}')
        elif fmt == 'atom':
            text.append(atom_at())
        elif fmt in ('atom_u8', 'atom_u16'):
            text.append(atom_at())
            text.append(str(u('<B' if fmt == 'atom_u8' else '<H', 4)))
        elif fmt in ('atom_label_u8', 'atom_label_u16'):
            text.append(atom_at())
            delta = struct.unpack('<i', code[operand + 4:operand + 8])[0]
            target = operand + 4 + delta
            targets.append((pos, target))
            text.append(f'@{target}')
            text.append(str(u('<B' if fmt == 'atom_label_u8' else '<H', 8)))
        elif fmt in ('none_loc', 'loc8', 'loc'):
            idx = {'none_loc': lambda: (op - base['get_loc0']) % 4,
                   'loc8': lambda: u('<B'), 'loc': lambda: u('<H')}[fmt]()
            text.append(f'{check("local", idx, len(local_vars))}:'
                        f'{name_of(local_vars[idx])}')
        elif fmt in ('none_arg', 'arg'):
            idx = ((op - base['get_arg0']) % 4 if fmt == 'none_arg'
                   else u('<H'))
            text.append(f'{check("argument", idx, len(args))}:{name_of(args[idx])}')
        elif fmt in ('none_var_ref', 'var_ref'):
            idx = ((op - base['get_var_ref0']) % 4 if fmt == 'none_var_ref'
                   else u('<H'))
            check('closure', idx, len(fn['closure_vars']))
            text.append(f'{idx}:{name_of(fn["closure_vars"][idx])}')
        elif fmt != 'none':
            raise BytecodeError(f'unhandled operand format {fmt}')
        out.append({'pc': pos, 'op': info['name'], 'operands': text})
        pos += info['size']
    if pos != len(code):
        raise BytecodeError('instructions overrun the bytecode length')
    for at, target in targets:
        if target not in starts and target != len(code):
            raise BytecodeError(f'branch at {at} targets non-boundary {target}')
    return out


def functions(root):
    """All function objects in the tree, depth-first, root first."""
    stack, seen = [root], []
    while stack:
        node = stack.pop()
        if node.get('type') == 'module':
            stack.append(node['function'])
        elif node.get('type') == 'function':
            seen.append(node)
            stack.extend(reversed(node['cpool']))
        elif node.get('type') in ('array', 'template_object'):
            stack.extend(reversed(node['items']))
        elif node.get('type') == 'object':
            stack.extend(reversed([v for _, v in node['properties']]))
    return seen


GLOBAL_READ_OPS = ('get_var', 'get_var_undef', 'with_get_var', 'with_get_ref')
GLOBAL_WRITE_OPS = ('put_var', 'put_var_init', 'put_var_strict', 'make_var_ref',
                    'with_put_var', 'with_make_ref', 'define_var',
                    'check_define_var')


def name_usage(listings):
    """Free-variable names read/assigned and '@zos/' module specifiers used."""
    reads, writes, modules = (collections.Counter() for _ in range(3))
    for fn, listing in listings:
        for ins in listing:
            if ins['op'] in GLOBAL_READ_OPS:
                reads[ins['operands'][0]] += 1
            elif ins['op'] in GLOBAL_WRITE_OPS:
                writes[ins['operands'][0]] += 1
            modules.update(o for o in ins['operands'] if o.startswith('@zos/'))
        modules.update(c['value'] for c in fn['cpool']
                       if c['type'] == 'string' and c['value'].startswith('@zos/'))
    return reads, writes, modules


def analyze(data, builtin_atoms, ops):
    reader = Reader(data, builtin_atoms)
    root = reader.read_file()
    funcs = functions(root)
    listings, histogram = [], collections.Counter()
    for fn in funcs:
        listing = disassemble(fn, ops, reader)
        histogram.update(ins['op'] for ins in listing)
        listings.append((fn, listing))
    return reader, root, listings, histogram


def write_listing(path, reader, listings):
    lines = []
    for fn, listing in listings:
        lines.append(f'function {reader.atom_text(fn["name"])} @{fn["offset"]} '
                     f'args={fn["arg_count"]} vars={fn["var_count"]} '
                     f'closures={fn["closure_var_count"]} cpool={fn["cpool_count"]} '
                     f'stack={fn["stack_size"]}')
        for ins in listing:
            lines.append(f'  {ins["pc"]:5d}  {ins["op"]} {" ".join(ins["operands"])}'.rstrip())
        lines.append('')
    path.write_text('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--opcode-header', required=True, type=pathlib.Path,
                        help='upstream QuickJS 2020-07-05 quickjs-opcode.h')
    parser.add_argument('--listing-dir', type=pathlib.Path,
                        help='new private directory for full listings')
    args = parser.parse_args()
    if args.listing_dir:
        args.listing_dir.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(args.archive) as archive:
        firmware = archive.read(FIRMWARE)
        _, atoms = firmware_atoms(firmware)
        builtin = [None] + atoms  # JS_ATOM_NULL at 0
        table_offset, ops = verified_opcodes(
            firmware, args.opcode_header.read_text('latin1'))
        members, total = [], collections.Counter()
        reads, writes, modules = (collections.Counter() for _ in range(3))
        module_apps = collections.defaultdict(set)
        for name in sorted(archive.namelist()):
            if not (name.startswith(BYTECODE_DIRS) and name.endswith('.bin')):
                continue
            data = archive.read(name)
            entry = {'member': name, 'size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
            try:
                reader, root, listings, histogram = analyze(data, builtin, ops)
            except BytecodeError as error:
                entry['error'] = str(error)
                members.append(entry)
                continue
            total.update(histogram)
            r, w, m = name_usage(listings)
            reads.update(r)
            writes.update(w)
            modules.update(m)
            for module in m:
                module_apps[module].add(name.split('/')[2])
            entry.update(root_type=root['type'], functions=len(listings),
                         instructions=sum(len(x) for _, x in listings),
                         bytecode_bytes=sum(f['bytecode_length'] for f, _ in listings),
                         trailing_bytes=len(data) - reader.pos)
            members.append(entry)
            if args.listing_dir:
                write_listing(args.listing_dir / (entry['sha256'] + '.txt'),
                              reader, listings)
    ok = [m for m in members if 'error' not in m]
    print(json.dumps({
        'engine': 'QuickJS 2020-07-05 (see QUICKJS_ENGINE.md)',
        'opcode_table_offset': table_offset,
        'final_opcodes': len(ops),
        'members': members,
        'members_parsed': len(ok),
        'members_failed': len(members) - len(ok),
        'total_functions': sum(m['functions'] for m in ok),
        'total_instructions': sum(m['instructions'] for m in ok),
        'distinct_opcodes_used': len(total),
        'opcode_histogram': dict(sorted(total.items())),
        'free_variable_reads': dict(sorted(reads.items())),
        'free_variable_writes': dict(sorted(writes.items())),
        'zos_modules': {k: {'references': v, 'apps': len(module_apps[k])}
                        for k, v in sorted(modules.items())},
    }, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
