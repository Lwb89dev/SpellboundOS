#!/usr/bin/env python3
"""Main-image gpio_key driver initialisation (``drv_key_init`` ``0x701e9cbe``).

Executes in ``main-runtime`` the keyboard driver setup: it finds the board
record ``gpio_key`` (``0x702b4f3e``), populates the driver object at
``0x70f92bf4`` with the per-key timing thresholds and the operations table
``0x70f60e2c``, then registers the driver as ``keyboard`` (``0x703192ca``).  The
two per-key configuration blocks (stride 0x30, the second at object ``+0x80``)
hold the debounce / press / long-press / repeat / double-click windows that the
[key state machine](HANDOFF) reads.

Recovered thresholds (words): ``0x7f``, ``0x0a`` (10), ``0x03``, ``0x50`` (80),
``0x1f4`` (500, long press ms), ``0x1e`` (30), ``0x1e``, ``0x0a`` and, in the
per-object double/combo fields, ``0x320`` (800) and ``0x0f`` (15).

Supplied (stubbed): the board lookup, the driver-register service and, for the
failure path, the assert logger and abort.
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

DRV_KEY_INIT = 0x701e9cbe
BOARD_FIND = 0x702b4f3e
REGISTER = 0x703192ca
ASSERT_LOG = 0x703191ac
ABORT = 0x80d364fa
NAME_GPIO_KEY = 0x709d1bf0          # "gpio_key"
NAME_KEYBOARD = 0x709d1f1c          # "keyboard"
NAME_DRV = 0x709d1f38               # "drv_key_init" (assert logger)
NAME_DRV2 = 0x709d1f28              # "drv_key_init" (abort)
ASSERT_MSG = 0x709d1aa0             # "OS_EOK == ret"
ASSERT_FALSE = 0x70a1d96c
OBJ = 0x70f92bf4                    # driver object (.bss)
OPS = 0x70f60e2c                    # keyboard operations table
REC = 0x80c01a00                    # board record (pointer only; stored, not dereferenced)

# Writes in execution order: (offset from OBJ, value).  OBJ+0x80 is the second key's config block.
WRITES = (
    (0x48, REC), (0x78, REC + 6),
    (0x94, 0x320), (0x9c, 0xf),            # cfg(+0x80) +0x14, +0x1c
    (0x64, 0x320), (0x6c, 0xf),
    (0x80, 0x7f), (0x84, 0xa), (0x88, 0x3), (0x8c, 0x50), (0x90, 0x1f4),
    (0x98, 0x1e), (0xa0, 0x1e), (0xa4, 0xa),
    (0x4c, OBJ),
    (0x50, 0x7f), (0x54, 0xa), (0x58, 0x3), (0x5c, 0x50), (0x60, 0x1f4),
    (0x68, 0x1e), (0x70, 0x1e), (0x74, 0xa),
    (0x7c, OBJ), (0x28, OPS),
)
CSRS = kernel.CSRS
STACK = kernel.HARNESS_STACK


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(a & M32) for a in args]))

    def put(self, a, v):
        self.write(a, 4, v & M32)

    def init(self):
        self.leaf(BOARD_FIND, NAME_GPIO_KEY)
        if self.svc['board'] == 0:
            return 1
        for offset, value in WRITES:
            self.put(OBJ + offset, value)
        self.leaf(REGISTER, OBJ, NAME_KEYBOARD, 7)
        ret = self.svc['register']
        if ret == 0:
            return 0
        self.leaf(ASSERT_LOG, ASSERT_MSG, NAME_DRV, 0x39)
        self.leaf(ABORT, ASSERT_FALSE, NAME_DRV2, 0x39)
        return ret & M32

    def operation(self, op):
        if op['name'] != 'init':
            raise ValueError('operation')
        return self.init()


def contract(case):
    if case['scope'] != 'key_init' or len(case['operations']) != 1:
        raise ValueError('key init scope')
    return Model(case).run()


def case(name, board=REC, register=0):
    g = dict(board=board, register=register)
    stubs = {
        str(BOARD_FIND): dict(kind='return', args=1, value=g['board']),
        str(REGISTER): dict(kind='return', args=3, value=g['register']),
        str(ASSERT_LOG): dict(kind='return', args=3), str(ABORT): dict(kind='return', args=3),
    }
    return dict(
        name='main_key_init_' + name, scope='key_init', supplied={}, quiet=[[0x81000000, 0x81002000]],
        csr_allowed=list(CSRS), ranges=[[DRV_KEY_INIT, DRV_KEY_INIT + 0xe4]],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name='init', entry=DRV_KEY_INIT, call=True, args=[], registers=False,
                                      result=True, result_high=False)],
        memory=[], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('register_ok', board=REC, register=0))
    add(case('board_record_missing', board=0))
    add(case('register_fails', board=REC, register=0xfffffff5))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=DRV_KEY_INIT, size=0xe4,
                             sha256='288769817cb060c32d670f7d9dfaeaf9d7251d8a77ede34ae27d86e88358d21d')],
                cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    if hashlib.sha256(memory.read(DRV_KEY_INIT, 0xe4)).hexdigest() != \
            '288769817cb060c32d670f7d9dfaeaf9d7251d8a77ede34ae27d86e88358d21d':
        raise ValueError('drv_key_init bytes differ')
    if memory.read(NAME_GPIO_KEY, 8) != b'gpio_key' or memory.read(NAME_KEYBOARD, 8) != b'keyboard':
        raise ValueError('names')
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
        results[c['name'].removeprefix('main_key_init_')] = row['observed']['rows'][0]['a0']
    per_key = dict(debounce=0x7f, press=0xa, hold=0x3, release=0x50, long_press_ms=0x1f4,
                   repeat_30=0x1e, double_window=0x320, double_count=0xf)
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        function=f'{DRV_KEY_INIT:#010x} (drv_key_init)',
        board_record='gpio_key (0x702b4f3e)',
        driver=dict(name='keyboard', register=f'{REGISTER:#010x}', ops_table=f'{OPS:#010x}',
                    object=f'{OBJ:#010x}'),
        config=dict(
            layout='two per-key blocks of stride 0x30 (second at object +0x80)',
            thresholds=per_key,
            note='0x1f4 = 500 ms long press; 0x320 = 800 ms double/combo window'),
        return_codes=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The board lookup, the driver-register service and the assert logger/abort are stubbed; '
            'drv_key_init runs as real code and every configuration write is recorded.',
            'The board record holds the key GPIO pins (two keys, pins 19 and 54 per the board scan); '
            'drv_key_init only wires the timing thresholds. The key state machine 0x701e923e that consumes '
            'this configuration is not executed here.'])


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
        parser.exit(2, f'Cannot inspect drv_key_init: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
