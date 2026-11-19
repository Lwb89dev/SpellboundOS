#!/usr/bin/env python3
"""Main GPIO pad multiplexer, shared IRQ handler and per-pin callback dispatch.

This scope executes three original main-image bodies that form a GPIO/pad
controller:

- the pad multiplexer ``0x80d42c84``, which writes a 4-bit field per pin into a
  bank register selected by the controller base;
- the GPIO interrupt dispatcher ``0x80d436b4``, which walks a 16-row callback
  table, acknowledges each pending pin and calls its registered handler;
- the shared interrupt handler ``0x70293d50``, which performs the clock/PM wake
  poke covered by [MAIN_PM_WAKE.md](MAIN_PM_WAKE.md) for two controller bases
  and then tail-calls the dispatcher.

Everything runs over authored controller structs, authored MMIO banks and an
authored callback table; registered handlers are supplied stubs.  Nothing here
executes vendor code outside the hash-guarded original ranges.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_trap_irq as trap
    from .main_freertos_kernel import direct_target
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_trap_irq as trap
    from main_freertos_kernel import direct_target
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000
END = trap.END

PADMUX = 0x80d42c84
DISPATCH = 0x80d436b4
SHARED = 0x70293d50
PAD_TABLE = 0x80d4744c           # bank bases for controllers 0x91003/0x91004/0x98005
CALLBACK_TABLE = 0x80c118c8      # 16 rows x 0x18: {base, bit, arg0, _, handler, arg1}
TRACE_FLAG = 0x80c07fac
TRACE_BIT = 0x80dff7bc
TRACE_PENDING = 0x80dff7c0
TRACE_BASE = 0x80dff7c4
PM_STATUS = 0x90008020
PM_CONTROL = 0x90008000
PM_ENABLE = 0x90008014
CLOCK = 0x91000004
ROW = 0x18
ROWS = 16
PAD_BANKS = {0x91003000: 0x91000080, 0x91004000: 0x91000090, 0x98005000: 0x910000a0,
             0x9a00a000: 0x910000b0}
PAD_DIRECT = 0x9a00a000          # uses 0x910000b0 directly and bounds the pin to <= 4

CODE = (
    (SHARED, 0x70, '8381861a1ec2afaa6dabf829aa0b78dee4939e93221e9d27cfdea44a7cc9fef4'),
    (PADMUX, 0x74, '06254faee62840d39299908ffd1ccba8d066058337928eefd5aba4a0217943ac'),
    (DISPATCH, 0xbe, 'a47a49e594fd994938a9f7c786277174a7d23dd008e45fef4bc937388b8dca08'),
)
DATA = (
    (PAD_TABLE, 0xc, '09fcec046d275d87d023153bc8f30d224c1f79215f8b22a9c47a02af41c96771'),
)
CSRS = trap.CSRS
HARNESS_STACK = trap.HARNESS_STACK
STUB = 0x70001000
CTRL = 0x81400000                # authored controller struct base in test memory
QUIET = ((0x81000000, 0x81002000),)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(trap.Model):
    """Independent model of the GPIO pad-mux, dispatcher and shared handler."""

    def __init__(self, case):
        self.c = case
        self.mem = {}
        for address, data in case['memory']:
            for i, b in enumerate(bytes.fromhex(data)):
                self.mem[address + i] = b
        self.csr = {int(k): v for k, v in case['csrs'].items()}
        self.regs = dict(case['registers'])
        self.fregs = dict(case['fregisters'])
        self.actions = []
        self.supplied = {int(k): list(v) for k, v in case['supplied'].items()}
        self.stubs = {int(k): v for k, v in case['stubs'].items()}
        self.quiet = [tuple(q) for q in case['quiet']]

    def original_byte(self, at):
        if PAD_TABLE <= at < PAD_TABLE + 0xc:
            value = (0x91000080, 0x91000090, 0x910000a0)[(at - PAD_TABLE) // 4]
            return (value >> (8 * ((at - PAD_TABLE) % 4))) & 255
        raise ValueError(f'model read of unauthored byte {at:#x}')

    def write(self, address, size, value, record=True):
        value &= (1 << (8 * size)) - 1
        address = word(address)
        for i in range(size):
            self.mem[address + i] = (value >> (8 * i)) & 255
        if record and not any(lo <= address < hi for lo, hi in self.quiet):
            self.actions.append(f'w:{address}:{size}:{value}')

    def read(self, address, size=4):
        return super().read(word(address), size)

    # Bodies.
    def padmux(self, base, pin, value):
        if base == PAD_DIRECT:
            if pin > 4:
                return 0
            bank = 0x910000b0
        elif base in (0x91003000, 0x91004000, 0x98005000):
            bank = self.read(PAD_TABLE + 4 * (0 if base == 0x91003000 else 1 if base == 0x91004000 else 2))
        else:
            return 0
        reg = word(bank + ((pin & 0x3ffffff8) >> 3) * 4)
        shift = (pin & 7) << 2
        current = self.read(reg)
        self.write(reg, 4, ((value & MASK) << shift | ~(0xf << shift) & current) & MASK)
        return 0

    def wake(self):
        control = self.read(PM_CONTROL)
        self.write(PM_CONTROL, 4, (control & ~0x1f0) | 0x70)
        self.write(PM_ENABLE, 4, self.read(PM_ENABLE) | 0x10)
        self.write(CLOCK, 4, self.read(CLOCK) | 0x10000)
        self.write(PM_ENABLE, 4, self.read(PM_ENABLE) & 0xffffffef)
        self.write(CLOCK, 4, self.read(CLOCK) & 0xfffeffff)
        self.write(PM_CONTROL, 4, control)

    def dispatch(self, base):
        pending = self.read(base + 0x28)
        if pending == 0:
            return 0
        trace = self.read(TRACE_FLAG, 1)
        if trace:
            self.write(TRACE_BASE, 4, base)
            self.write(TRACE_PENDING, 4, pending)
        for bit in range(32):
            mask = word(1 << bit)
            if not (mask & pending):
                continue
            for index in range(ROWS):
                row = CALLBACK_TABLE + ROW * index
                if self.read(row) == base and self.read(row + 4) == bit:
                    self.write(base + 0x30, 4, mask)
                    if self.read(TRACE_FLAG, 1):
                        self.write(TRACE_BIT, 4, bit)
                    handler = self.read(row + 0x10)
                    if handler:
                        self.call(handler, self.read(row + 8), self.read(row + 0x14))
                    break
        return 0

    def shared(self, base):
        if base in (0x91003000, 0x91004000) and (self.read(PM_STATUS) & 0x1000):
            self.wake()
        return self.dispatch(base)

    def operation(self, op):
        kind, args = op['name'].split('#')[0], op['args']
        if kind == 'padmux':
            return self.padmux(*args)
        if kind == 'dispatch':
            return self.dispatch(*args)
        if kind == 'shared':
            return self.shared(*args)
        raise ValueError('operation')

    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            result = self.operation(op)
            row = dict(stopped=None, csrs={str(n): self.csr[n] for n in CSRS})
            if op['result']:
                row['a0'] = word(result)
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if case['scope'] not in ('padmux', 'dispatch', 'shared'):
        raise ValueError('gpio scope')
    if not 1 <= len(case['operations']) <= 8 or sum(len(v) for v in case['supplied'].values()) > 8:
        raise ValueError('bounded operations')
    return Model(case).run()


def words(*values):
    return trap.words(*values)


def op(name, *args, result=True):
    targets = dict(padmux=PADMUX, dispatch=DISPATCH, shared=SHARED)
    return dict(name=name, entry=targets[name.split('#')[0]], call=True, args=list(args), result=result,
                registers=False, result_high=False)


def base_case(name, scope, operations, memory, snapshot=(), trace=0, stubs=None):
    csrs = {str(n): v for n, v in zip(CSRS, (0x20, 0x1808, 0x888, 0, 0, 0, 0, 0, 0))}
    mem = [[TRACE_FLAG, '%02x' % trace], [TRACE_BIT, words(0, 0, 0)]] + [list(m) for m in memory]
    return dict(
        name='main_gpio_' + name, scope=scope, supplied={},
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE + trap.CODE],
        csrs=csrs, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs or {str(STUB): dict(kind='return', args=2)}, stops={},
        snapshot=[list(s) for s in snapshot], operations=operations, memory=mem)


def controller(base, pending=0, ack=0):
    """Authored GPIO controller struct: pending at +0x28, ack target at +0x30."""
    data = bytearray(0x40)
    struct.pack_into('<I', data, 0x28, pending & MASK)
    struct.pack_into('<I', data, 0x30, ack & MASK)
    return [base, data.hex()]


def callbacks(entries):
    """entries: dict index -> (base, bit, handler, arg0, arg1)."""
    data = bytearray(ROW * ROWS)
    for index, (base, bit, handler, arg0, arg1) in entries.items():
        struct.pack_into('<IIII', data, ROW * index, base & MASK, bit, arg0 & MASK, 0)
        struct.pack_into('<II', data, ROW * index + 0x10, handler & MASK, arg1 & MASK)
    return [CALLBACK_TABLE, data.hex()]


def pad_bank(bank, *values):
    return [bank, words(*values)]


def native_vectors():
    cases = []

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    # Pad multiplexer: field write per pin into the selected bank.
    for name, base, bank in (('padmux_bank0_pin0', 0x91003000, 0x91000080),
                             ('padmux_bank1_pin5', 0x91004000, 0x91000090),
                             ('padmux_bank2_pin8', 0x98005000, 0x910000a0),
                             ('padmux_direct_pin3', 0x9a00a000, 0x910000b0)):
        pin = {'padmux_bank0_pin0': 0, 'padmux_bank1_pin5': 5, 'padmux_bank2_pin8': 8,
               'padmux_direct_pin3': 3}[name]
        reg = bank + (pin >> 3) * 4
        mem = [pad_bank(bank, 0x89abcdef, 0x89abcdef)]
        add(base_case(name, 'padmux', [op('padmux#%s' % name, base, pin, 0xa, result=False)], mem,
                      snapshot=[[reg, 4]]))
    add(base_case('padmux_direct_pin_out_of_range', 'padmux',
                  [op('padmux#oob', 0x9a00a000, 5, 0xf, result=False)],
                  [pad_bank(0x910000b0, 0x11111111)], snapshot=[[0x910000b0, 4]]))
    add(base_case('padmux_unknown_base_ignored', 'padmux',
                  [op('padmux#unk', 0x90000000, 0, 0xf, result=False)],
                  [pad_bank(0x910000b0, 0x22222222)], snapshot=[[0x910000b0, 4]]))
    add(base_case('padmux_high_pin_selects_word', 'padmux',
                  [op('padmux#word', 0x91003000, 9, 0x5, result=False)],
                  [pad_bank(0x91000080, 0, 0)], snapshot=[[0x91000080, 8]]))
    add(base_case('padmux_overwrites_only_nibble', 'padmux',
                  [op('padmux#nib', 0x91003000, 1, 0x3, result=False)],
                  [pad_bank(0x91000080, 0xffffffff)], snapshot=[[0x91000080, 4]]))

    # Dispatcher: iterate pending bits, acknowledge and call the registered handler.
    cb_snap = [[CTRL + 0x30, 4], [TRACE_BIT, 4], [TRACE_PENDING, 4], [TRACE_BASE, 4]]
    single = callbacks({3: (CTRL, 5, STUB, 0xa0a0, 0xb0b0)})
    add(base_case('dispatch_no_pending', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=0), single], snapshot=cb_snap))
    add(base_case('dispatch_one_pending_registered', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=1 << 5), single], snapshot=cb_snap))
    add(base_case('dispatch_one_pending_traced', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=1 << 5), single], snapshot=cb_snap, trace=1))
    add(base_case('dispatch_pending_unregistered_bit', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=1 << 6), single], snapshot=cb_snap))
    add(base_case('dispatch_registered_handler_null', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=1 << 5), callbacks({3: (CTRL, 5, 0, 0xa0a0, 0xb0b0)})],
                  snapshot=cb_snap))
    multi = callbacks({0: (CTRL, 0, STUB, 0x11, 0x12), 7: (CTRL, 31, STUB, 0x71, 0x72),
                       9: (0x91234000, 5, STUB, 0, 0)})
    add(base_case('dispatch_two_pending_in_bit_order', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=(1 << 0) | (1 << 31)), multi], snapshot=cb_snap))
    add(base_case('dispatch_wrong_base_row_skipped', 'dispatch', [op('dispatch', CTRL, result=False)],
                  [controller(CTRL, pending=1 << 5),
                   callbacks({3: (0x91234000, 5, STUB, 0, 0)})], snapshot=cb_snap))

    # Shared handler: wake for the two bases with status bit 12, then dispatch.
    def pm_mem(status):
        return [[PM_CONTROL, words(0xdeadbe00)], [PM_ENABLE, words(0x00000001)],
                [PM_STATUS, words(status)], [CLOCK, words(0x00000002)]]
    sh_snap = [[PM_CONTROL, 4], [PM_ENABLE, 4], [CLOCK, 4]]
    add(base_case('shared_wake_then_dispatch', 'shared', [op('shared', 0x91003000, result=False)],
                  [controller(0x91003000, pending=1 << 5),
                   callbacks({0: (0x91003000, 5, STUB, 0x1, 0x2)})] + pm_mem(1 << 12),
                  snapshot=sh_snap + [[0x91003000 + 0x30, 4]]))
    add(base_case('shared_bit12_clear_dispatch_only', 'shared', [op('shared', 0x91004000, result=False)],
                  [controller(0x91004000, pending=1 << 5),
                   callbacks({0: (0x91004000, 5, STUB, 0x1, 0x2)})] + pm_mem(0),
                  snapshot=sh_snap + [[0x91004000 + 0x30, 4]]))
    add(base_case('shared_other_base_dispatch_only', 'shared', [op('shared', 0x98005000, result=False)],
                  [controller(0x98005000, pending=1 << 5),
                   callbacks({0: (0x98005000, 5, STUB, 0x1, 0x2)})] + pm_mem(1 << 12),
                  snapshot=sh_snap + [[0x98005000 + 0x30, 4]]))

    guards = trap.CODE + trap.DATA + CODE + DATA
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in guards], cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in trap.CODE + trap.DATA + CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    copy = trap.COPY
    for address, size, _ in CODE:
        if address >= copy['destination']:
            source = copy['source'] + address - copy['destination']
            if memory.data[source - 0x70160000:source - 0x70160000 + size] != memory.read(address, size):
                raise ValueError('copied code differs from its load image')
    if tuple(struct.unpack('<3I', memory.read(PAD_TABLE, 0xc))) != (0x91000080, 0x91000090, 0x910000a0):
        raise ValueError('pad bank table')
    # The shared handler tail-calls the dispatcher on both paths (auipc + jr).
    for site in (0x70293d60, 0x70293db4):
        auipc = struct.unpack('<I', memory.read(site, 4))[0]
        jalr = struct.unpack('<I', memory.read(site + 4, 4))[0]
        if auipc & 0x7f != 0x17 or jalr & 0x7f != 0x67:
            raise ValueError(f'shared tail call encoding at {site:#x}')
        hi = auipc & 0xfffff000
        lo = jalr >> 20
        lo -= 1 << 12 if lo & 0x800 else 0
        if word(site + hi + lo) != DISPATCH:
            raise ValueError(f'shared tail call target at {site:#x}')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, case in zip(report['cases'], vector_doc['cases']):
        if row['name'] != case['name'] or row['observed'] != case['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + case['name'])
    return dict(
        main_sha256=MAIN_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        pad_banks={f'{base:#010x}': f'{bank:#010x}' for base, bank in PAD_BANKS.items()},
        callback_table=f'{CALLBACK_TABLE:#010x}', callback_rows=ROWS, callback_row_bytes=f'{ROW:#x}',
        dispatcher=f'{DISPATCH:#010x}', pad_multiplexer=f'{PADMUX:#010x}', shared_handler=f'{SHARED:#010x}',
        trace=dict(flag=f'{TRACE_FLAG:#010x}', pending=f'{TRACE_PENDING:#010x}', base=f'{TRACE_BASE:#010x}',
                   bit=f'{TRACE_BIT:#010x}'),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The pad multiplexer, GPIO interrupt dispatcher and shared interrupt handler execute in an '
            'emulator over authored controller structs, authored MMIO pad/clock banks and an authored '
            '16-row callback table. No hardware GPIO edge, pin level or interrupt is delivered.',
            'The registered per-pin handlers are supplied return stubs. The controller struct layout '
            '(pending at +0x28, acknowledge at +0x30), the pad banks and the clock/PM registers are '
            'interpreted from their access pattern, not from a datasheet.',
            'Which handlers populate the callback table, the physical pin assignments and the real edge/'
            'level behavior are runtime/hardware properties and remain unproved.'])


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
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect main GPIO dispatch paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
