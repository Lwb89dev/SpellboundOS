#!/usr/bin/env python3
"""Main GPIO pull/drive pad writer and the interrupt enable/commit routine.

This scope extends [MAIN_GPIO_DISPATCH.md](MAIN_GPIO_DISPATCH.md) with two more
original main-image bodies of the GPIO/pad controller:

- the pull/drive pad writer ``0x80d42fcc``, which writes a 2-bit field per pin
  (four pins per 32-bit register) into a second bank table at ``0x80d4745c``;
- the interrupt enable/commit routine ``0x80d43774``, which walks the 16-row
  callback table, acknowledges each registered pin and enables it on its
  controller through a handshake on ``0x900080b0``, wrapped in a critical
  section only when the scheduler state requires it.

Both run over authored controller structs, authored MMIO banks and an authored
callback table.  The configuration gate, the scheduler-state reader and the
critical save/restore wrappers (covered in [MAIN_PM_WAKE.md](MAIN_PM_WAKE.md)
and [MAIN_RTOS_CRITICAL_SECTIONS.md](MAIN_RTOS_CRITICAL_SECTIONS.md)) are
supplied stubs.  Nothing here executes vendor code outside the hash-guarded
original ranges.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_trap_irq as trap
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_trap_irq as trap
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000
END = trap.END

PADCFG = 0x80d42fcc              # pull/drive 2-bit field writer
ENABLE = 0x80d43774             # interrupt enable/commit over the callback table
PULL_TABLE = 0x80d4745c          # bank bases for the pull/drive writer
CALLBACK_TABLE = 0x80c118c8      # 16 rows x 0x18 (shared with the dispatcher)
STATE_WORD = 0x80c11730          # iRam80c11730: scheduler-state snapshot
SAVED_FLAG = 0x80c11734          # arg passed to the critical save/restore wrappers
HANDSHAKE = 0x900080b0           # commit handshake register
GATE = 0x80d341d8                # CSR 0xfc1 gate (covered in MAIN_PM_WAKE)
STATE = 0x80d362b0               # scheduler-state reader
SAVE = 0x80d379ee                # critical save wrapper (covered in critical-section scope)
RESTORE = 0x80d37a1a             # critical restore wrapper
PULL_BANKS = {0x91003000: 0x91000100, 0x91004000: 0x91000120, 0x98005000: 0x91000140,
              0x9a00a000: 0x91000160}
PULL_DIRECT = 0x9a00a000
ROW = 0x18
ROWS = 16

CODE = (
    (PADCFG, 0x78, 'c3e166e5cdedd3b072c9e82a3669516ad9fd8019d26904d104ebe08c4d34dcd3'),
    (ENABLE, 0xec, '651822fc11b7f09312ac7cfdef97288e829098873fb9a47645ef904c6f701977'),
)
DATA = (
    (PULL_TABLE, 0xc, '4ef9163470f03240b436ee3e6680b4334c19e843858265309b917188830d5663'),
)
CSRS = trap.CSRS
HARNESS_STACK = trap.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)
CTRL = 0x81400000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(trap.Model):
    """Independent model of the pull/drive writer and the enable/commit routine."""

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
        self.returns = {int(k): list(v) for k, v in case.get('returns', {}).items()}

    def original_byte(self, at):
        if PULL_TABLE <= at < PULL_TABLE + 0xc:
            value = (0x91000100, 0x91000120, 0x91000140)[(at - PULL_TABLE) // 4]
            return (value >> (8 * ((at - PULL_TABLE) % 4))) & 255
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

    def call(self, address, *args):
        parts = ['call', str(address)] + [str(word(a)) for a in args]
        self.actions.append(':'.join(parts))
        if address in self.returns:
            return self.returns[address].pop(0)
        return 0

    # Bodies.
    def padcfg(self, base, pin, value, base0):
        if base == base0:
            bank = self.read(PULL_TABLE)
        elif base == 0x91004000:
            bank = self.read(PULL_TABLE + 4)
        elif base == 0x98005000:
            bank = self.read(PULL_TABLE + 8)
        elif base == PULL_DIRECT:
            if pin > 4:
                return 0
            bank = 0x91000160
        else:
            return 0
        reg = word(bank + (pin & 0x1ffffffc))
        shift = (pin & 3) << 3
        current = self.read(reg)
        self.write(reg, 4, ((value & 0x30) << shift | ~(0x30 << shift) & current) & MASK)
        return 0

    def commit(self, base, bit, gate):
        """The controller update shared by both scheduler-state branches."""
        handshake = 2 if gate else 1
        while self.read(HANDSHAKE):
            pass
        self.write(HANDSHAKE, 4, handshake)
        while self.read(HANDSHAKE) != handshake:
            self.write(HANDSHAKE, 4, handshake)
        mask = word(1 << bit)
        self.write(base + 0x20, 4, ~mask & self.read(base + 0x20))
        self.write(base + 0x2c, 4, mask | self.read(base + 0x2c))
        self.write(HANDSHAKE, 4, 0)

    def enable(self):
        row = CALLBACK_TABLE
        while row != CALLBACK_TABLE + ROW * ROWS:
            if self.read(row + 0x10):
                base, bit = self.read(row), self.read(row + 4)
                self.write(base + 0x30, 4, word(1 << bit))
                gate = self.call(GATE)
                state = self.call(STATE)
                self.write(STATE_WORD, 4, state)
                if state:
                    self.call(SAVE, SAVED_FLAG)        # critical enter, saves to SAVED_FLAG
                    state = self.read(STATE_WORD)
                self.commit(base, bit, gate)
                if state:
                    self.call(RESTORE, self.read(SAVED_FLAG))     # critical exit
            row += ROW
        return 0

    def operation(self, op):
        kind, args = op['name'].split('#')[0], op['args']
        if kind == 'padcfg':
            return self.padcfg(args[0], args[1], args[2], args[5])
        if kind == 'enable':
            return self.enable()
        raise ValueError('operation')

    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            self.operation(op)
            row = dict(stopped=None, csrs={str(n): self.csr[n] for n in CSRS})
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if case['scope'] not in ('padcfg', 'enable'):
        raise ValueError('gpio-config scope')
    if not 1 <= len(case['operations']) <= 4 or sum(len(v) for v in case.get('returns', {}).values()) > 64:
        raise ValueError('bounded operations')
    return Model(case).run()


def words(*values):
    return trap.words(*values)


def op(name, *args):
    return dict(name=name, entry=PADCFG if name.split('#')[0] == 'padcfg' else ENABLE,
                call=True, args=list(args), result=False, registers=False, result_high=False)


def base_case(name, scope, operations, memory, snapshot=(), returns=None):
    csrs = {str(n): v for n, v in zip(CSRS, (0x20, 0x1808, 0x888, 0, 0, 0, 0, 0, 0))}
    stub = {str(GATE): dict(kind='return', args=0), str(STATE): dict(kind='return', args=0),
            str(SAVE): dict(kind='return', args=1), str(RESTORE): dict(kind='return', args=1)}
    return dict(
        name='main_gpio_cfg_' + name, scope=scope, supplied={},
        returns={str(k): list(v) for k, v in (returns or {}).items()},
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE + trap.CODE],
        csrs=csrs, registers={'sp': HARNESS_STACK}, fregisters={}, stubs=stub, stops={},
        snapshot=[list(s) for s in snapshot], operations=operations,
        memory=[[STATE_WORD, words(0, 0)]] + [list(m) for m in memory])


def controller(base, enable_mask=0, enable2=0):
    data = bytearray(0x40)
    struct.pack_into('<I', data, 0x20, enable_mask & MASK)
    struct.pack_into('<I', data, 0x2c, enable2 & MASK)
    return [base, data.hex()]


def callbacks(entries):
    data = bytearray(ROW * ROWS)
    for index, (base, bit, handler) in entries.items():
        struct.pack_into('<II', data, ROW * index, base & MASK, bit)
        struct.pack_into('<I', data, ROW * index + 0x10, handler & MASK)
    return [CALLBACK_TABLE, data.hex()]


def pad_bank(bank, *values):
    return [bank, words(*values)]


def native_vectors():
    cases = []

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    # Pull/drive writer: a 2-bit field per pin, four pins per 32-bit register.
    for name, base, bank, pin in (('bank0_pin0', 0x91003000, 0x91000100, 0),
                                  ('bank1_pin2', 0x91004000, 0x91000120, 2),
                                  ('bank2_pin4', 0x98005000, 0x91000140, 4),
                                  ('direct_pin1', 0x9a00a000, 0x91000160, 1)):
        reg = bank + (pin >> 2) * 4
        add(base_case('padcfg_' + name, 'padcfg', [op('padcfg#%s' % name, base, pin, 0x30, 0, 0, 0x91003000)],
                      [pad_bank(bank, 0x77777777, 0x77777777)], snapshot=[[reg, 4]]))
    add(base_case('padcfg_direct_out_of_range', 'padcfg',
                  [op('padcfg#oob', 0x9a00a000, 5, 0x30, 0, 0, 0x91003000)],
                  [pad_bank(0x91000160, 0x11111111)], snapshot=[[0x91000160, 4]]))
    add(base_case('padcfg_unknown_base', 'padcfg', [op('padcfg#unk', 0x90000000, 0, 0x30, 0, 0, 0x91003000)],
                  [pad_bank(0x91000160, 0x22222222)], snapshot=[[0x91000160, 4]]))
    add(base_case('padcfg_value_masked_to_bits_4_5', 'padcfg',
                  [op('padcfg#mask', 0x91003000, 3, 0xff, 0, 0, 0x91003000)],
                  [pad_bank(0x91000100, 0, 0)], snapshot=[[0x91000100, 8]]))

    # Enable/commit: walk the table, acknowledge and enable each registered pin.
    def enable_case(name, table, controllers, returns, snapshot):
        mem = [callbacks(table), [HANDSHAKE, words(0)]] + controllers
        add(base_case(name, 'enable', [op('enable')], mem, snapshot=snapshot, returns=returns))

    hs = [[HANDSHAKE, 4]]
    enable_case('enable_no_registered_rows', {}, [], {}, hs)
    enable_case('enable_one_row_state_zero',
                {0: (CTRL, 5, 0x70001000)}, [controller(CTRL, enable_mask=0xffffffff, enable2=0)],
                {GATE: [0], STATE: [0]},
                hs + [[CTRL + 0x20, 4], [CTRL + 0x2c, 4], [CTRL + 0x30, 4], [STATE_WORD, 4]])
    enable_case('enable_one_row_gate_set_handshake_two',
                {0: (CTRL, 5, 0x70001000)}, [controller(CTRL, enable_mask=0xffffffff, enable2=0)],
                {GATE: [1], STATE: [0]},
                hs + [[CTRL + 0x20, 4], [CTRL + 0x2c, 4]])
    enable_case('enable_one_row_state_nonzero_wraps_critical',
                {0: (CTRL, 7, 0x70001000)}, [controller(CTRL, enable_mask=0xffffffff, enable2=0)],
                {GATE: [0], STATE: [2]},
                hs + [[CTRL + 0x20, 4], [CTRL + 0x2c, 4], [CTRL + 0x30, 4]])
    enable_case('enable_skips_unregistered_rows',
                {2: (CTRL, 3, 0x70001000)}, [controller(CTRL, enable_mask=0xffffffff)],
                {GATE: [1], STATE: [0]},
                hs + [[CTRL + 0x20, 4], [CTRL + 0x2c, 4], [CTRL + 0x30, 4]])
    other = 0x81400100
    enable_case('enable_two_rows_distinct_controllers',
                {0: (CTRL, 1, 0x70001000), 5: (other, 30, 0x70001000)},
                [controller(CTRL, enable_mask=0xffffffff), controller(other, enable_mask=0xffffffff)],
                {GATE: [0, 1], STATE: [0, 2]},
                hs + [[CTRL + 0x2c, 4], [other + 0x2c, 4], [other + 0x20, 4]])

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
        source = copy['source'] + address - copy['destination']
        if memory.data[source - 0x70160000:source - 0x70160000 + size] != memory.read(address, size):
            raise ValueError('copied code differs from its load image')
    if tuple(struct.unpack('<3I', memory.read(PULL_TABLE, 0xc))) != (0x91000100, 0x91000120, 0x91000140):
        raise ValueError('pull bank table')
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
        pull_banks={f'{base:#010x}': f'{bank:#010x}' for base, bank in PULL_BANKS.items()},
        pad_writer=f'{PADCFG:#010x}', enable_routine=f'{ENABLE:#010x}',
        callback_table=f'{CALLBACK_TABLE:#010x}', handshake_register=f'{HANDSHAKE:#010x}',
        controller_fields=dict(acknowledge='0x30', disable_mask='0x20', enable='0x2c'),
        supplied_callees=dict(gate=f'{GATE:#010x}', state_reader=f'{STATE:#010x}',
                              critical_save=f'{SAVE:#010x}', critical_restore=f'{RESTORE:#010x}'),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The pull/drive pad writer and the interrupt enable/commit routine execute in an emulator over '
            'authored controller structs, authored MMIO pad/handshake banks and an authored 16-row callback '
            'table. No hardware GPIO pin, interrupt or commit acknowledgement is delivered.',
            'The configuration gate 0x80d341d8, the scheduler-state reader 0x80d362b0 and the critical '
            'save/restore wrappers 0x80d379ee/0x80d37a1a are supplied return stubs; their own behavior is '
            'covered by MAIN_PM_WAKE and MAIN_RTOS_CRITICAL_SECTIONS. The commit handshake on 0x900080b0 '
            'reads authored memory, so no real hardware acknowledgement latency is modeled.',
            'The controller struct layout (acknowledge +0x30, disable mask +0x20, enable +0x2c), the pull '
            'banks and the handshake register are interpreted from the access pattern, not a datasheet.'])


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
        parser.exit(2, f'Cannot inspect main GPIO config paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
