#!/usr/bin/env python3
"""Main-image ICNA3311 display: the DSI command-write packet dispatch (``mhs_dc_write_cmd``).

``0x701620f0(a0, buffer, length)`` sends a DCS command to the ICNA3311 panel
over the MIPI-DSI link.  When the DSI engine is active (``0x80c1220c`` and
``0x80c12208`` set) it serializes three semaphores (``_dsi_cmd_semaphore`` and
``_dsi_semaphore`` 1/2, each with a 10000-tick timeout) around the transfer and
runs the controller programming ``0x70161e66`` (0x9a000000 register block).
This scope executes the command dispatch with the DSI engine idle
(``0x80c1220c = 0``), so the semaphores are skipped and the packetization logic
runs with the controller programming and the low-level writer supplied:

- read the configured command kind at ``0x80c00c8c``; kind ``2`` forms a short
  packet (``cmd[0] << 8``, data type 2); otherwise the MIPI data type is chosen
  by length — ``0x05`` (1), ``0x15`` (2) or ``0x39`` (long) — and the low-level
  writer ``0x702a1eb0(config, type, byte0, &cmd[1], length-1)`` is called;
- a NULL buffer or zero length returns ``-10``; a writer failure logs
  ``write cmd fail`` and returns ``-1``; success returns 0.

Supplied (stubbed): the controller programming ``0x70161e66``, the low-level DSI
writer ``0x702a1eb0`` and the logger.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
else:
    import main_freertos_kernel as kernel

BOUND = 20000
M32 = 0xffffffff

WRITE_CMD = 0x701620f0
PREP = 0x70161e66               # DSI controller programming (0x9a000000 MMIO)
HW_WRITE = 0x702a1eb0           # low-level DSI packet writer
LOGGER = 0x702b38a2
DSI_ACTIVE = 0x80c1220c         # engine-active flag (kept 0 here to skip the semaphores)
CMD_KIND = 0x80c00c8c           # configured command kind byte
LOG_INFO = 6

BUF = 0x81003000
STACK = kernel.HARNESS_STACK
CSRS = kernel.CSRS

CODE = ((WRITE_CMD, 0x1ca, '8335becc7197bbcd4a208b1ac135c806047ac901284b289a8213434387980e56'),)


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(a & M32) for a in args]))

    def u8(self, a):
        return self.read(a, 1)

    def write_cmd(self, buffer, length):
        if buffer == 0 or length == 0:
            return M32 - 9              # -10
        self.leaf(PREP)
        kind = self.u8(CMD_KIND)
        byte0 = self.u8(buffer)
        if kind == 2:
            dtype, a2 = 2, (byte0 << 8) & M32
        else:
            dtype, a2 = {1: 0x05, 2: 0x15}.get(length, 0x39), byte0
        self.leaf(HW_WRITE, CMD_KIND, dtype, a2, buffer + 1, length - 1)
        if self.svc['hw'] != 0:
            self.leaf(LOGGER, LOG_INFO)
            return M32                  # -1
        return 0

    def operation(self, op):
        if op['name'] != 'write_cmd':
            raise ValueError('operation')
        return self.write_cmd(op['args'][1], op['args'][2])


def contract(case):
    if case['scope'] != 'display_dsi' or len(case['operations']) != 1:
        raise ValueError('display dsi scope')
    return Model(case).run()


def case(name, cmd=b'\x29', length=None, kind=0, hw=0):
    length = len(cmd) if length is None else length
    g = dict(hw=hw)
    buf = (cmd + b'\0' * 8)[:16]
    active = struct.pack('<I', 0)       # DSI engine idle -> skip semaphores
    kind_mem = bytes([kind])
    stubs = {
        str(PREP): dict(kind='return', args=0),
        str(HW_WRITE): dict(kind='return', args=5, value=g['hw']),
        str(LOGGER): dict(kind='return', args=1),
    }
    return dict(
        name='main_display_dsi_' + name, scope='display_dsi', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name='write_cmd', entry=WRITE_CMD, call=True, args=[0, BUF, length],
                                      registers=False, result=True, result_high=False)],
        memory=[[BUF, buf.hex()], [DSI_ACTIVE, active.hex()], [CMD_KIND, kind_mem.hex()]], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('long_write_one_param', cmd=b'\x51\xff', kind=0))       # type 0x15
    add(case('short_write_no_param', cmd=b'\x11', kind=0))           # type 0x05
    add(case('long_write_payload', cmd=b'\x2c\x01\x02\x03', kind=0))  # type 0x39
    add(case('short_packet_kind2', cmd=b'\x29', kind=2))             # type 2, cmd<<8
    add(case('writer_failure', cmd=b'\x51\xff', kind=0, hw=0x7))
    add(case('null_buffer', cmd=b'', length=0))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    results = {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        writes = [a for a in c['expected']['actions'] if a.startswith('call:' + str(HW_WRITE))]
        dtype = int(writes[0].split(':')[3]) if writes else None
        results[c['name'].removeprefix('main_display_dsi_')] = dict(ret=row['observed']['rows'][0]['a0'],
                                                                    data_type=dtype)
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        panel='ICNA3311 over MIPI-DSI (board_disp)',
        function=f'{WRITE_CMD:#010x} (mhs_dc_write_cmd)',
        packetization=dict(
            configured_kind_byte=f'{CMD_KIND:#010x}',
            kind2='short packet, byte0 << 8, MIPI data type 2',
            by_length='data type 0x05 (len 1), 0x15 (len 2), 0x39 (long)',
            writer=f'{HW_WRITE:#010x}(config, data_type, byte0, &cmd[1], length-1)'),
        concurrency=dict(
            engine_active_flag=f'{DSI_ACTIVE:#010x}',
            semaphores='when active: _dsi_cmd_semaphore then _dsi_semaphore 1 and 2, 10000-tick timeout each',
            controller_programming=f'{PREP:#010x} (0x9a000000 register block)'),
        return_codes=dict(null_or_zero=-10, writer_failure=-1, success=0),
        per_case=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The DSI engine is held idle (0x80c1220c = 0) so the three command semaphores are skipped; the '
            'controller programming 0x70161e66 (0x9a000000 MMIO) and the low-level writer 0x702a1eb0 are '
            'stubbed. Only the packetization dispatch runs as real code.',
            'The frame path (write_frame_work_out, the framebuffer DMA to DSI and the TE interrupt) and the '
            'semaphore-serialized active path are not executed.'])


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
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, IndexError, struct.error) as error:
        parser.exit(2, f'Cannot inspect DSI write: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
