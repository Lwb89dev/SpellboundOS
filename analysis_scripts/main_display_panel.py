#!/usr/bin/env python3
"""ICNA3311 display panel: DCS read-id, panel probe and command-table player.

The Bip 6 display is a Chipone ICNA3311 AMOLED panel driven over a MIPI DCS
command interface (strings `drv_display_init`, `display_panel_read_id`,
`icna3311_probe_success`).  This scope executes three original main-image
bodies end to end in the `main-runtime` project:

- ``display_panel_read_id`` (`0x702c8238`): issues the DCS Read-Display-ID
  commands 0xDA/0xDB/0xDC (RDID1/2/3) and accumulates the 24-bit panel id;
- the panel probe ``0x702c82d8``: reads the id and matches it against a table
  of nine ICNA3311 variants;
- the DCS command-table player ``0x702c8314``: walks a ``{type, nargs,
  payload...}`` sequence, issuing a DCS write (type 0) or a millisecond delay
  (type 1) for each entry.

The DCS read/write transfers, the delay and the logger are supplied stubs.  A
``transfer`` stub captures the exact command bytes the code emits and injects
scripted response bytes, so the DCS framing is verified rather than assumed.
No panel, bus or timer is driven; ``mret`` is not executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
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

READ_ID = 0x702c8238           # display_panel_read_id
PROBE = 0x702c82d8             # read id + match against the panel table
INTERP = 0x702c8314            # DCS command-table player
READ_TRANSFER = 0x702c81d8     # DCS read (dispatches through the device op +0x10)
WRITE = 0x702c81f4             # DCS write (device op +0xc)
DELAY = 0x80d369ee             # millisecond delay
LOGGER = 0x702b38a2            # formatted logger

DISPLAY_INIT = 0x702c8c70      # drv display init (static reference)
PANEL_TABLE = 0x70f62398       # runtime 9-entry ICNA3311 variant table
PANEL_IDS = (0x250905, 0x5a0905, 0x250906, 0x1b0909, 0x4b090d, 0x5c0913, 0x5b0913, 0x250914, 0x2c0914)
RDID = (0xda, 0xdb, 0xdc)      # MIPI DCS RDID1/2/3
INTERP_ERROR = 0xfffffff6      # returned for a null table or zero length

CODE = (
    (READ_ID, 0xa0, '1b19bc439141d393a2d7d465cdadf1cbdaef51367d3dfdf58bfee43e5e461bbd'),
    (PROBE, 0x3c, '3c26c8f6928ea2147ea8ce81b8e38aca75a9ab681aeef9b30e44586b25635d7e'),
    (INTERP, 0x62, 'f51e288589c5b2518570056258f10f297065668eff292566806407df07050db4'),
)
CALL_SITES = (
    (0x702c825e, READ_TRANSFER), (0x702c828c, LOGGER), (0x702c82e4, READ_ID), (0x702c833c, WRITE),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)
TABLE_BASE = 0x81400000        # authored panel table and descriptors
CMD_BASE = 0x81410000          # authored DCS command tables


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(v):
    return v & MASK


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.read_resp = list(case.get('read_resp', []))
        self.read_status = list(case.get('read_status', []))
        self._rn = 0

    # Supplied-callee helpers that mirror the runner's stub behaviour.
    def dcs_read(self, cmd):
        self.actions.append('call:%d' % READ_TRANSFER)
        self.actions.append('cap:%02x' % (cmd & 0xff))
        status = self.read_status[self._rn] if self._rn < len(self.read_status) else 0
        resp = self.read_resp[self._rn] if self._rn < len(self.read_resp) else 0
        self._rn += 1
        return status, resp

    def dcs_write(self, payload):
        self.actions.append('call:%d' % WRITE)
        self.actions.append('cap:' + bytes(payload).hex())

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    # Original bodies.
    def read_id(self):
        buf = [0, 0, 0]
        for i in range(3):
            cmd = (i - 0x26) & 0xff
            status, resp = self.dcs_read(cmd)
            if status != 0:
                self.leaf(LOGGER)
                return 0
            buf[i] = resp & 0xff
        self.leaf(LOGGER)
        return buf[0] << 16 | buf[1] << 8 | buf[2]

    def probe(self, table, count):
        found = self.read_id()
        if found == 0:
            return 0
        match = 0
        for i in range(count):
            desc = self.read(word(table + i * 4))
            if self.read(desc) == found:
                match = desc
        return match

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
        if name == 'read_id':
            return self.read_id()
        if name == 'probe':
            return self.probe(*args)
        if name == 'interp':
            return self.interp(*args)
        raise ValueError('operation')


def contract(case):
    if case['scope'] not in ('read_id', 'probe', 'interp'):
        raise ValueError('display scope')
    if len(case['operations']) != 1:
        raise ValueError('bounded operations')
    return Model(case).run()


def op(name, *args):
    entry = {'read_id': READ_ID, 'probe': PROBE, 'interp': INTERP}[name.split('#')[0]]
    return dict(name=name, entry=entry, call=True, args=list(args), registers=False,
                result=True, result_high=False)


def stubs(read_resp, read_status):
    read = dict(kind='transfer', cmd_arg=0, len_arg=1, resp_arg=2, args=0)
    if read_resp:
        read['resp'] = list(read_resp)
    if read_status:
        read['status'] = list(read_status)
    return {
        str(READ_TRANSFER): read,
        str(WRITE): dict(kind='transfer', cmd_arg=0, len_arg=1, args=0),
        str(DELAY): dict(kind='return', args=1),
        str(LOGGER): dict(kind='return', args=0),
    }


def case(name, scope, operations, memory=(), read_resp=(), read_status=()):
    return dict(
        name='main_display_panel_' + name, scope=scope, supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(read_resp, read_status), stops={}, snapshot=[], operations=operations,
        memory=[list(m) for m in memory], read_resp=list(read_resp), read_status=list(read_status))


def panel_table_memory():
    """Nine descriptor pointers at TABLE_BASE, each descriptor's first word its id."""
    memory = []
    pointers = b''
    for i, pid in enumerate(PANEL_IDS):
        desc = TABLE_BASE + 0x100 + i * 0x10
        pointers += desc.to_bytes(4, 'little')
        memory.append([desc, pid.to_bytes(4, 'little').hex()])
    memory.append([TABLE_BASE, pointers.hex()])
    return memory


def cmd_table(entries):
    """Serialize {type, nargs, payload} entries and return (bytes, length)."""
    data = bytearray()
    for kind, payload in entries:
        data += bytes([kind, len(payload)]) + bytes(payload)
    return bytes(data), len(data)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    # read_id: the 24-bit accumulation and the transfer-error path.
    add(case('read_id_accumulates_rdid', 'read_id', [op('read_id')],
             read_resp=[0x1b, 0x09, 0x09]))
    add(case('read_id_transfer_error_returns_zero', 'read_id', [op('read_id')],
             read_resp=[0x00], read_status=[5]))

    # probe: match a real ICNA3311 id, and a no-match id.
    table_mem = panel_table_memory()
    add(case('probe_matches_icna3311_variant', 'probe', [op('probe', TABLE_BASE, len(PANEL_IDS))],
             memory=table_mem, read_resp=[0x1b, 0x09, 0x09]))      # id 0x1b0909 -> index 3
    add(case('probe_unknown_id_returns_null', 'probe', [op('probe', TABLE_BASE, len(PANEL_IDS))],
             memory=table_mem, read_resp=[0xaa, 0xbb, 0xcc]))
    add(case('probe_read_id_failure_returns_null', 'probe', [op('probe', TABLE_BASE, len(PANEL_IDS))],
             memory=table_mem, read_resp=[0x00], read_status=[7]))

    # interp: a sleep-out/delay/display-on sequence, plus the null/empty guards.
    data, length = cmd_table([(0, [0x11, 0x00]), (1, [0x78]), (0, [0x29])])
    add(case('interp_writes_and_delays', 'interp', [op('interp', CMD_BASE, length)],
             memory=[[CMD_BASE, data.hex()]]))
    data2, length2 = cmd_table([(0, [0x51, 0xff]), (0, [0x53, 0x20]), (1, [0x0a]), (0, [0x29])])
    add(case('interp_brightness_then_on', 'interp', [op('interp', CMD_BASE, length2)],
             memory=[[CMD_BASE, data2.hex()]]))
    add(case('interp_null_table_errors', 'interp', [op('interp', 0, 8)]))
    add(case('interp_zero_length_errors', 'interp', [op('interp', CMD_BASE, 0)],
             memory=[[CMD_BASE, cmd_table([(0, [0x11])])[0].hex()]]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in CODE:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
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
        panel='ICNA3311', read_id=f'{READ_ID:#010x}', probe=f'{PROBE:#010x}',
        command_player=f'{INTERP:#010x}', display_init=f'{DISPLAY_INIT:#010x}',
        rdid_commands=[f'{c:#04x}' for c in RDID], panel_table=f'{PANEL_TABLE:#010x}',
        panel_ids=[f'{p:#08x}' for p in PANEL_IDS],
        dcs_read_op='device op + 0x10', dcs_write_op='device op + 0xc',
        command_table_format='{type, nargs, payload...}; type 0 = DCS write, type 1 = delay(ms); advance nargs+2',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'display_panel_read_id, the panel probe and the DCS command-table player execute in an emulator '
            'over authored state; the DCS read/write transfers, the delay and the logger are supplied. The '
            'transfer stub captures the command bytes the code emits and injects scripted response bytes, so '
            'the DCS framing and the 24-bit id accumulation are verified, but no panel or bus is driven.',
            'The panel table is authored with the nine real ICNA3311 variant ids read from the firmware; the '
            'probe selects by a full 24-bit id match. The actual device id, the full power/reset/ESD bring-up '
            'in 0x702c8c70, the real init command tables and the physical bus (device op behind +0xc/+0x10) '
            'are not executed here.',
            'Panel timing, electrical bring-up, the framebuffer/refresh path and backlight hardware remain '
            'unproved and need the device. This is a driver contract, not a working display driver.'])


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
        parser.exit(2, f'Cannot inspect display panel: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
