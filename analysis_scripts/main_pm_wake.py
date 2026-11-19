#!/usr/bin/env python3
"""Main power-management wake gate, dynamic IRQ re-registration and wake body.

The deep-sleep routine at 0x80d34470 saves the full integer/FP/CSR context,
switches to a dedicated stack and executes ``fence``/``wfi``; its resume twin
at 0x80d343a0 restores that context.  Those two are documented statically only
(the emulator cannot execute ``wfi``/``fence`` meaningfully, and the earlier
cache scope already supplies the ``fence`` userop).

This scope executes the wake path that is ordinary code: the configuration
gate ``0x80d341d8`` (CSR 0xfc1), the conditional re-registration routine
``0x80d4217c`` that re-points PLIC sources 0xe/0xc/0xb at RAM handlers through
the original register/enable bodies, the three identical RAM handlers, and the
wake body ``0x80d41fb8`` that pokes the 0x90008000 clock/PM block and
0x91000004 with a bounded delay and then restores them.  Nothing here executes
vendor code outside the hash-guarded original ranges.
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

GATE = 0x80d341d8               # reads CSR 0xfc1, returns 1 when the field is zero
REREG = 0x80d4217c             # conditional re-registration of 0xe/0xc/0xb
WAKE = 0x80d41fb8             # clock/PM poke-and-restore body
HANDLERS = (0x80d42004, 0x80d42018, 0x80d4202c)   # RAM handlers for 0xe/0xc/0xb
REGISTER = trap.REGISTER       # 0x80d35c6c
ENABLE = trap.ENABLE          # 0x80d35bcc
CFG_CSR = 0xfc1

PM_BLOCK = 0x90008000          # control / status / enable block
PM_CONTROL = 0x90008000
PM_STATUS = 0x90008020         # bit 12 gates the wake body
PM_ENABLE = 0x90008014
CLOCK = 0x91000004
RAM_HANDLERS = {0xe: HANDLERS[0], 0xc: HANDLERS[1], 0xb: HANDLERS[2]}

CODE = (
    (GATE, 0xe, '8fd6437ad6baaa8ff3e3877df7af6c08cb0b0d703504c652b61f0956715e6009'),
    (REREG, 0x5e, '31d84a8758752022e8fc42977fbcb1498bdef93efd6ff841e9599c3fba6e2ab4'),
    (WAKE, 0x4c, '39238acb6450222fc376808bd1b505b50125b52ab0b66c0e0f74bee5cff324c9'),
    (HANDLERS[0], 0x3a, 'a7a5770501b7ddee1b93db086b7c67d839e88e56cd91f143eb19e007567885cf'),
)
CSRS = trap.CSRS + (CFG_CSR,)
HARNESS_STACK = trap.HARNESS_STACK
EXTERNAL_TABLE = trap.EXTERNAL_TABLE
PLIC_ENABLE = trap.PLIC_ENABLE
PLIC_PRIORITY = trap.PLIC_PRIORITY
QUIET = ((0x81000000, 0x81002000),)
WAKE_DELAY = 10


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(trap.Model):
    """Independent model of the wake path, reusing the trap PLIC register/enable."""

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

    def supply(self, address):
        value = self.supplied[address].pop(0)
        self.actions.append(f'r:{address}:4:{value}')
        return value

    # Bodies.
    def gate(self):
        field = (self.csr[CFG_CSR] >> 6) & 7
        value = 1 if field == 0 else 0
        self.actions.append(f'csr:{CFG_CSR}:{self.csr[CFG_CSR]}:{self.csr[CFG_CSR]}')
        return value

    def rereg(self):
        if self.gate() != 1:
            return 0
        for irq in (0xe, 0xc, 0xb):
            self.register(irq, RAM_HANDLERS[irq], 0)
            self.enable(irq)
        return 0

    def wake(self):
        control = self.supply(PM_CONTROL)
        self.write(PM_CONTROL, 4, (control & ~0x1f0) | 0x70)
        self.write(PM_ENABLE, 4, self.supply(PM_ENABLE) | 0x10)
        self.write(CLOCK, 4, self.supply(CLOCK) | 0x10000)
        self.write(PM_ENABLE, 4, self.supply(PM_ENABLE) & ~0x10)
        self.write(CLOCK, 4, self.supply(CLOCK) & 0xfffeffff)
        self.write(PM_CONTROL, 4, control)
        return 0

    def handler(self, address, argument=0):
        status = self.supply(PM_STATUS)
        if status & (1 << 12):
            return self.wake()
        return 0

    def operation(self, op):
        kind = op['name'].split('#')[0]
        if kind == 'gate':
            return self.gate()
        if kind == 'rereg':
            return self.rereg()
        if kind == 'wake':
            return self.wake()
        if kind == 'handler':
            return self.handler(op['args'][0])
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
    if case['scope'] not in ('gate', 'rereg', 'handler', 'wake'):
        raise ValueError('pm scope')
    if not 1 <= len(case['operations']) <= 8 or sum(len(v) for v in case['supplied'].values()) > 24:
        raise ValueError('bounded operations')
    return Model(case).run()


def words(*values):
    return trap.words(*values)


def op(name, *args, entry=None, result=True):
    targets = dict(gate=GATE, rereg=REREG, wake=WAKE, handler=HANDLERS[0])
    kind = name.split('#')[0]
    return dict(name=name, entry=entry or targets[kind], call=True, args=list(args), result=result,
                registers=False, result_high=False)


def base_case(name, scope, operations, csr_cfg=0, supplied=None, snapshot=(), memory=()):
    csrs = {str(n): v for n, v in zip(trap.CSRS, (0x20, 0x1808, 0x888, 0, 0, 0, 0, 0, 0))}
    csrs[str(CFG_CSR)] = csr_cfg
    return dict(
        name='main_pm_wake_' + name, scope=scope,
        supplied={str(k): list(v) for k, v in (supplied or {}).items()},
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE + trap.CODE],
        csrs=csrs, registers={'sp': HARNESS_STACK}, fregisters={}, stubs={}, stops={},
        snapshot=[list(s) for s in snapshot], operations=operations,
        memory=[list(m) for m in memory])


def native_vectors():
    cases = []

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    for name, cfg in (('gate_field_zero', 0x00000000), ('gate_field_bit6', 0x00000040),
                      ('gate_field_bit8', 0x00000100), ('gate_field_high_bits_only', 0xfffff03f),
                      ('gate_field_full', 0x000001c0)):
        add(base_case(name, 'gate', [op('gate')], csr_cfg=cfg))

    table = {irq: (0x80d41188, 0, 0, 0) for irq in (0xb, 0xc, 0xe)}
    rereg_mem = [[EXTERNAL_TABLE, trap.external_table(table)], [PLIC_ENABLE, words(0, 0, 0)],
                 [PLIC_PRIORITY, words(*[0] * 84)]]
    snap = [[EXTERNAL_TABLE + 16 * irq, 16] for irq in (0xb, 0xc, 0xe)] + \
           [[PLIC_ENABLE, 12], [PLIC_PRIORITY + 4 * 0xb, 4], [PLIC_PRIORITY + 4 * 0xc, 4],
            [PLIC_PRIORITY + 4 * 0xe, 4]]
    add(base_case('rereg_gate_on', 'rereg', [op('rereg', result=False)], csr_cfg=0, memory=rereg_mem, snapshot=snap))
    add(base_case('rereg_gate_off', 'rereg', [op('rereg', result=False)], csr_cfg=0x40, memory=rereg_mem, snapshot=snap))

    wake_snap = [[PM_CONTROL, 4], [PM_ENABLE, 4], [CLOCK, 4]]
    wake_mem = [[PM_BLOCK, words(*([0] * 10))], [CLOCK, words(0)]]
    for name, control, enable, clock in (('wake_zero', 0, 0, 0),
                                         ('wake_sets_and_restores', 0x12345abc, 0x0000ff0f, 0x0001ffff),
                                         ('wake_preserves_other_bits', 0xffffffff, 0xffffffef, 0xfffeffff)):
        supplied = {PM_CONTROL: [control], PM_ENABLE: [enable, enable | 0x10], CLOCK: [clock, clock | 0x10000]}
        add(base_case(name, 'wake', [op('wake', result=False)], supplied=supplied, memory=wake_mem,
                      snapshot=wake_snap))

    handler_mem = wake_mem
    for name, status, calls in (('handler_bit12_set_runs_wake', 1 << 12, True),
                                ('handler_bit12_clear_returns', 0, False),
                                ('handler_other_bits_ignored', 0xffffefff, False)):
        supplied = {PM_STATUS: [status]}
        if calls:
            supplied.update({PM_CONTROL: [0x0f0], PM_ENABLE: [0x1, 0x11], CLOCK: [0x2, 0x10002]})
        add(base_case(name, 'handler', [op('handler', 0, result=True)], supplied=supplied,
                      memory=handler_mem, snapshot=[[PM_CONTROL, 4], [PM_ENABLE, 4], [CLOCK, 4]]))

    guards = trap.CODE + trap.DATA + CODE
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in guards], cases=cases)


# Static evidence for the deep-sleep save/restore twins (documented, not executed).
SLEEP_SAVE = 0x80d34470
SLEEP_RESTORE = 0x80d343a0


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in trap.CODE + trap.DATA + CODE:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    copy = trap.COPY
    for address, size, _ in CODE:
        source = copy['source'] + address - copy['destination']
        if memory.data[source - 0x70160000:source - 0x70160000 + size] != memory.read(address, size):
            raise ValueError('copied code differs from its load image')
    # The gate reads CSR 0xfc1; the re-registration far-calls register/enable.
    for site, target in ((0x80d4219c, REGISTER), (0x80d421a4, ENABLE), (0x80d421b4, REGISTER),
                         (0x80d421bc, ENABLE), (0x80d421cc, REGISTER), (0x80d421d6, ENABLE)):
        from .main_freertos_kernel import direct_target
        if direct_target(memory, site) != target:
            raise ValueError(f're-registration call site {site:#x}')
    # The three handlers tail-jump to the wake body.
    for handler in HANDLERS:
        from .main_freertos_kernel import direct_target
        if direct_target(memory, handler + 0xc) != WAKE:
            raise ValueError(f'handler {handler:#x} tail jump')
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
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        config_csr=f'{CFG_CSR:#05x}', pm_block=f'{PM_BLOCK:#010x}', clock_register=f'{CLOCK:#010x}',
        wake_status_bit=12, wake_delay_iterations=WAKE_DELAY,
        ram_handlers={f'{irq:#x}': f'{addr:#010x}' for irq, addr in RAM_HANDLERS.items()},
        deep_sleep=dict(save=f'{SLEEP_SAVE:#010x}', restore=f'{SLEEP_RESTORE:#010x}',
                        note='full integer/FP/CSR save then fence+wfi; resume restores; not executed here'),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The configuration gate, conditional re-registration, the three RAM handlers and the clock/PM '
            'wake body execute in an emulator over authored CSRs and supplied MMIO reads. No hardware '
            'power-management event, clock change or wake interrupt is delivered.',
            'The gate reads custom CSR 0xfc1 and treats a three-bit field as an enable; the register at '
            '0x91000004 and the 0x90008000 block are interpreted as clock/power-management control from '
            'their access pattern, not from a datasheet.',
            'The deep-sleep save/restore twins at 0x80d34470/0x80d343a0 are recorded statically only; '
            'fence/wfi and the dedicated sleep stack are not executed, and the real sleep current, wake '
            'latency and the dynamically registered device sources remain unproved.'])


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
        parser.exit(2, f'Cannot inspect main PM wake paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
