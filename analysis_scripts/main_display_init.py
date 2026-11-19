#!/usr/bin/env python3
"""ICNA3311 display bring-up and the real panel init command tables.

This completes the panel driver contract in
[MAIN_DISPLAY_PANEL.md](MAIN_DISPLAY_PANEL.md) by executing:

- the power/reset bring-up ``0x702c8ae2``: enable the 1.8 V rail, 5 ms, enable
  the 3.3 V rail, configure the bus, drive the reset line low (12 ms) then high
  (12 ms);
- the DCS command-table player ``0x702c8314`` over the **real** ICNA3311 init
  table embedded in a panel descriptor, so every init DCS command the panel
  receives is captured from the firmware's own data.

Each ICNA3311 variant descriptor carries its init table (pointer at ``+0xc``,
length at ``+8``); the nine embedded tables and their recovered geometry are in
the evidence.  The rail/bus/reset leaves, the delay, the DCS write and the
logger are supplied stubs.  No panel, rail, bus or timer is driven; ``mret`` is
not executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_trap_irq as trap
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_freertos_kernel as kernel
    import main_trap_irq as trap
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000

BRINGUP = 0x702c8ae2           # power/reset bring-up
INTERP = 0x702c8314            # DCS command-table player (shared with the panel block)
RAIL_ON = 0x702b66c8           # regulator enable
BUS_CFG = 0x702c8208           # bus configure
RESET_GPIO = 0x702bd77e        # reset line set
WRITE = 0x702c81f4             # DCS write
DELAY = 0x80d369ee             # millisecond delay
INTERP_ERROR = 0xfffffff6

# Globals the bring-up reads (zero-init RAM, authored here).
RAIL_1V8 = 0x70f9a560
RAIL_3V3 = 0x70f9a564
DESCRIPTOR = 0x70f9a55c

# Panel variant descriptors: id, init-table length (+8) and pointer (+0xc).
VARIANTS = (
    (0x250905, 0x70a2e20c), (0x5a0905, 0x70a2e1c4), (0x250906, 0x70a2e17c),
    (0x1b0909, 0x70a2e134), (0x4b090d, 0x70a2e0ec), (0x5c0913, 0x70a2e084),
    (0x5b0913, 0x70a2e03c), (0x250914, 0x70a2dff4), (0x2c0914, 0x70a2dfac),
)
# Real init table for variant 0x1b0909 (416x416), 0x6a bytes.
V3_TABLE = bytes.fromhex(
    '0002fe200002f45a0002f5590002c6000002fe80000200f80002f4a50002f5a50002fe80'
    '0002f4000002f5000002fe000002fe000002350000025320000251ff000263ff00023a55'
    '00052a001201b100052b0000019f0002fe000002fe800002f4ac0002f5e10002fe00')
# Real init table for variant 0x250905 (192x490), 0x46 bytes.
V0_TABLE_LEN = 0x46

CODE = (
    (BRINGUP, 0x66, 'fe0d62ca7d81b0ce25e912e1a1575e03318a55ecf05b963dbcd876462d37f158'),
    (INTERP, 0x62, 'f51e288589c5b2518570056258f10f297065668eff292566806407df07050db4'),
)
CALL_SITES = (
    (0x702c8af4, RAIL_ON), (0x702c8b04, RAIL_ON), (0x702c8b10, BUS_CFG),
    (0x702c8b1c, RESET_GPIO), (0x702c8b32, RESET_GPIO), (0x702c833c, WRITE),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)
DESC_BASE = 0x81400000         # authored panel descriptor
CMD_BASE = 0x81410000          # authored init table
RAIL_1V8_HANDLE = 0x70001111
RAIL_3V3_HANDLE = 0x70002222
RESET_PIN = 0x2a
BUS_VALUE = 0x1234


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(v):
    return v & MASK


def copied(memory, address, n):
    """Read firmware bytes, mapping the 0x70f60000 copy region to its load image."""
    if 0x70f60000 <= address < 0x70f60000 + 0x2df04:
        src = 0x70d9daf4 + (address - 0x70f60000)
        return memory.data[src - 0x70160000:src - 0x70160000 + n]
    return memory.read(address, n)


class Model(kernel.Model):
    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def dcs_write(self, payload):
        self.actions.append('call:%d' % WRITE)
        self.actions.append('cap:' + bytes(payload).hex())

    def bringup(self):
        self.leaf(RAIL_ON, self.read(RAIL_1V8))
        self.leaf(DELAY, 5)
        self.leaf(RAIL_ON, self.read(RAIL_3V3))
        self.leaf(BUS_CFG)
        pin = self.read(self.read(DESCRIPTOR) + 8, 2)
        self.leaf(RESET_GPIO, pin, 0)
        self.leaf(DELAY, 0xc)
        self.leaf(RESET_GPIO, pin, 1)
        self.leaf(DELAY, 0xc)
        return None

    def interp(self, table, length):
        if table == 0 or length == 0:
            return INTERP_ERROR
        offset = 0
        while offset < length:
            entry = word(table + offset)
            kind = self.read(entry, 1)
            nargs = self.read(entry + 1, 1)
            if kind == 0:
                self.dcs_write([self.read(entry + 2 + k, 1) for k in range(nargs)])
            elif kind == 1:
                self.leaf(DELAY, self.read(entry + 2, 1))
            offset += nargs + 2
        return 0

    def operation(self, op):
        name, args = op['name'].split('#')[0], op['args']
        if name == 'bringup':
            return self.bringup()
        if name == 'init_table':
            return self.interp(*args)
        raise ValueError('operation')


def contract(case):
    if case['scope'] not in ('bringup', 'init_table'):
        raise ValueError('display init scope')
    if len(case['operations']) != 1:
        raise ValueError('bounded operations')
    return Model(case).run()


def op(name, *args):
    entry = {'bringup': BRINGUP, 'init_table': INTERP}[name.split('#')[0]]
    return dict(name=name, entry=entry, call=True, args=list(args), registers=False,
                result=name.startswith('init_table'), result_high=False)


def stubs():
    return {
        str(RAIL_ON): dict(kind='return', args=1), str(BUS_CFG): dict(kind='return', args=0),
        str(RESET_GPIO): dict(kind='return', args=2), str(DELAY): dict(kind='return', args=1),
        str(WRITE): dict(kind='transfer', cmd_arg=0, len_arg=1, args=0),
    }


def case(name, scope, operations, memory):
    return dict(
        name='main_display_init_' + name, scope=scope, supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(), stops={}, snapshot=[], operations=operations, memory=[list(m) for m in memory])


def bringup_memory():
    desc = bytearray(0x14)
    struct.pack_into('<H', desc, 8, RESET_PIN)
    struct.pack_into('<I', desc, 0x10, BUS_VALUE)
    return [
        [RAIL_1V8, struct.pack('<I', RAIL_1V8_HANDLE).hex()],
        [RAIL_3V3, struct.pack('<I', RAIL_3V3_HANDLE).hex()],
        [DESCRIPTOR, struct.pack('<I', DESC_BASE).hex()],
        [DESC_BASE, desc.hex()],
    ]


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('power_reset_bringup', 'bringup', [op('bringup')], bringup_memory()))
    add(case('real_icna3311_416_init', 'init_table', [op('init_table', CMD_BASE, len(V3_TABLE))],
             [[CMD_BASE, V3_TABLE.hex()]]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def decode_table(data):
    """Return the entry list and recovered geometry of a {type,nargs,payload} table."""
    entries, off, cols, rows = [], 0, None, None
    while off < len(data):
        kind, nargs = data[off], data[off + 1]
        payload = data[off + 2:off + 2 + nargs]
        entries.append((kind, payload))
        if kind == 0 and nargs >= 5 and payload[0] == 0x2a:
            cols = (payload[1] << 8 | payload[2], payload[3] << 8 | payload[4])
        if kind == 0 and nargs >= 5 and payload[0] == 0x2b:
            rows = (payload[1] << 8 | payload[2], payload[3] << 8 | payload[4])
        off += nargs + 2
    geometry = None
    if cols and rows:
        geometry = f'{cols[1] - cols[0] + 1}x{rows[1] - rows[0] + 1}'
    return entries, geometry


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in CODE:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
    # Decode the nine variant init tables from their descriptors.
    variants = []
    for pid, desc in VARIANTS:
        length = struct.unpack('<I', copied(memory, desc + 8, 4))[0]
        ptr = struct.unpack('<I', copied(memory, desc + 0xc, 4))[0]
        entries, geometry = decode_table(copied(memory, ptr, length))
        variants.append(dict(id=f'{pid:#08x}', table=f'{ptr:#010x}', length=f'{length:#x}',
                             entries=len(entries), geometry=geometry))
    if copied(memory, VARIANTS[3][1] + 0xc, 4) != struct.pack('<I', 0x70a2e5f0) or \
            copied(memory, 0x70a2e5f0, len(V3_TABLE)) != V3_TABLE:
        raise ValueError('variant-3 init table differs')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
    return dict(
        main_sha256=MAIN_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        panel='ICNA3311', bringup=f'{BRINGUP:#010x}', command_player=f'{INTERP:#010x}',
        bringup_sequence='rail 1.8V on, 5 ms, rail 3.3V on, bus config, reset low, 12 ms, reset high, 12 ms',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        variants=variants,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The power/reset bring-up and the DCS command-table player execute in an emulator over authored '
            'state; the regulator enable, bus config, reset-line set, delay, DCS write and logger are '
            'supplied. The write stub captures the real init bytes from the firmware descriptor, so the init '
            'DCS stream is verified, but no rail, reset line, bus or panel is driven.',
            'The nine variant geometries are decoded from the firmware descriptors; the device runs exactly '
            'one of them and the real variant is unknown offline. Sleep-out/display-on, the framebuffer and '
            'refresh path, tear-effect/vsync and backlight hardware are not executed here.',
            'Rail voltages, reset timing and panel bring-up remain unproved and need the device. This is a '
            'driver contract, not a working display driver.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', nargs='?')
    parser.add_argument('--vectors-output', type=Path)
    parser.add_argument('--vectors', type=Path)
    parser.add_argument('--validation', type=Path)
    args = parser.parse_args()
    try:
        if args.vectors_output:
            args.vectors_output.write_text(json.dumps(native_vectors(), indent=2, sort_keys=True) + '\n')
            return
        if not all((args.archive, args.vectors, args.validation)):
            parser.error('need archive, --vectors and --validation')
        with zipfile.ZipFile(args.archive) as archive:
            result = evidence(archive, args.vectors, args.validation)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, IndexError) as error:
        parser.exit(2, f'Cannot inspect display init: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
