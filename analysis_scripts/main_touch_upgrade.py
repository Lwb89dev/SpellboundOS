#!/usr/bin/env python3
"""Main-image ZTW622 TP firmware-upgrade worker (input task body ``0x701eca9c``).

The input task entry started by [ztw622_open](MAIN_TOUCH_OPEN.md) dispatches on
the state byte at ``0x70f8e100`` (``0x70f8e0fc[4]``): state 1 is the TP firmware
upgrade / ODR worker (``ztw622_uprgade_process`` / ``upgrade_odr_process``),
state 2 is the work/config-reset process (``0x701ec2a4``), any other value
returns.  This scope executes the worker itself; the already-verified register /
reset / version / dispatch helpers (see [MAIN_TOUCH_CONTROL.md](MAIN_TOUCH_CONTROL.md),
[MAIN_TOUCH_REPORT.md](MAIN_TOUCH_REPORT.md), [MAIN_TOUCH_DISPATCH.md](MAIN_TOUCH_DISPATCH.md))
are stubbed.

State 1 (upgrade), recovered:

- publish progress with ``ztw622_process_event 0x701eac38`` (modes 0..5), stop
  the poll timer (``0x701eae1e``), disable the touch interrupt (``0x702bdac6``)
  and mark the context upgrading (``+0x2c = 5``);
- enter the bootloader: soft reset, then program registers
  ``0x1d5``, ``0xc000 = 1``, ``0xc004``, ``0xc002 = 1``, ``0xc003 = 1``,
  ``0x104 = 1``, ``0x1d0`` with 10 ms gaps;
- stream the image in 0x40-byte chunks: for each 8-byte group build a 10-byte
  packet ``[0x01d1, data[k:k+8]]`` (``malloc``/``I2C write`` ``0x701ead14`` /
  ``free``), raising the per-chunk and per-group progress events;
- leave the bootloader (``0xc003 = 0``, ``0x104 = 0``, ``0x1d0``) and verify each
  0x40-byte block by reading register ``0x1d2`` back and ``memcmp`` against the
  source (``0x70947ab0``);
- finalize: version read, re-enable the interrupt (``0x702bda0c``), mark normal
  (``+0x2c = 1``) and restart the poll timer.

Supplied (stubbed): the register/reset/version/dispatch helpers, malloc/free,
memcmp, the GPIO interrupt enable/disable, the timer stop/start and the logger.
The I2C-write packets are captured so the streamed payload is checked.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_touch_control as ctrl
else:
    import main_freertos_kernel as kernel
    import main_touch_control as ctrl

BOUND = 20000
word = ctrl.word

WORKER = 0x701eca9c
PROCESS = 0x701eac38                 # ztw622_process_event(dev, mode, value_ptr)
REG_SELECT, REG_WRITE, REG_READ = 0x701eadce, 0x701eae04, 0x701eaf30
I2C_WRITE = 0x701ead14
RESET, VERSION = 0x701eb702, 0x701ebc50
TIMER_STOP = 0x701eae1e
POST_VERSION = 0x701ebdf0
CONFIG_RESET = 0x701ec2a4
TIMER_START_WRAP = 0x701eb102
GPIO_IRQ_DISABLE, GPIO_IRQ_ENABLE = 0x702bdac6, 0x702bda0c
MALLOC, FREE = 0x80d3c2f4, 0x80d3c35a
MEMCMP = 0x70947ab0
DELAY = ctrl.DELAY                    # 0x80d369ee
LOGGER = 0x702b38a2

CTX = 0x70f92d10
BSD = ctrl.BSD
BSD_RECORD = ctrl.BSD_RECORD
INPUT_MSG_SLOT = 0x70f8e0fc            # [0]=device, [4]=state, [8]=timer, [c]=length, [10]=data ptr
STATE_BYTE = 0x70f8e100
TIMER_HANDLE = 0x70f8e104
LENGTH_SLOT = 0x70f8e108
DATA_SLOT = 0x70f8e10c
EVENT_VALUE_A, EVENT_VALUE_B = 0x70f92d30, 0x70f92d34
PACKET_HEADER = 0x01d1
LOG_ERROR, LOG_INFO = 3, 6

NAME_INPUT = 0x709d1e98               # "drivers_input"
DEVICE = 0x81005000
DATA_PTR = 0x81007000
MALLOC_BUF = 0x81001900               # within the quiet window: packet build is not recorded
TIMER_OBJ = 0x0e0e0001
STACK = kernel.HARNESS_STACK
CSRS = kernel.CSRS

CODE = (
    (WORKER, 0x462, '279378d3b64354b69ae70b759343e3b94bf0c45d112f8b02524694e0411f5095'),
)
DATA = ((BSD, 0x14, ctrl.DATA[-1][2]),)


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def u32(self, a):
        return self.read(a, 4)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    def capture(self, addr, size):
        self.actions.append('cap:' + bytes(self.u8(addr + i) for i in range(size)).hex())

    def process(self, dev, mode, ptr):
        self.leaf(PROCESS, dev, mode, ptr)
        return self.svc['process']

    def delay(self, ms):
        self.leaf(DELAY, ms)

    def reg_select(self, reg):
        self.leaf(REG_SELECT, reg)
        return self.svc['reg']

    def reg_write(self, reg, value):
        self.leaf(REG_WRITE, reg, value)
        return self.svc['reg']

    def worker(self):
        state = self.u8(STATE_BYTE)
        if state == 1:
            return self.upgrade()
        if state == 2:
            return self.work_process()
        return None

    def work_process(self):
        self.leaf(LOGGER, LOG_ERROR)                # "reset tp from e..." (ztw622_work_process)
        self.leaf(CONFIG_RESET)
        if self.svc['config_reset']:
            # The failure path tail-calls the logger, so the result is the log level left in a0.
            self.leaf(LOGGER, LOG_ERROR)
            return LOG_ERROR
        return 0

    def restart(self):
        self.leaf(TIMER_START_WRAP, self.u32(TIMER_HANDLE))
        return word(self.svc['timer'])

    def upgrade(self):
        dev = self.u32(INPUT_MSG_SLOT)
        length = self.u32(LENGTH_SLOT)
        self.put(EVENT_VALUE_B, 4, 0)
        self.put(CTX + 0x20, 4, length >> 6)
        if self.process(dev, 0, EVENT_VALUE_A):
            return self.restart()
        record = self.u32(CTX)
        self.leaf(GPIO_IRQ_DISABLE, self.u16(record + 2))
        if self.svc['gpio']:
            return self.restart()
        self.leaf(TIMER_STOP, self.u32(TIMER_HANDLE))
        if self.svc['timer_stop']:
            return self.restart()
        self.put(CTX + 0x2c, 1, 5)
        if self.reset_fail():
            return self.restart()
        # Enter the bootloader.
        for step in (('s', 0x1d5), ('d', 50), ('w', 0xc000, 1), ('d', 10), ('s', 0xc004), ('d', 10),
                     ('w', 0xc002, 1), ('d', 10), ('w', 0xc003, 1), ('d', 10), ('w', 0x104, 1), ('d', 10),
                     ('s', 0x1d0), ('d', 10)):
            if self.sequence_step(step):
                return self.restart()
        if self.process(dev, 1, EVENT_VALUE_A):
            return self.restart()
        # Stream the image in 0x40-byte chunks.  (The firmware's data-pointer/offset != 0
        # guards never trigger for a mapped buffer and emit no observable action.)
        data = self.u32(DATA_SLOT)
        offset = 0
        while offset < length:
            end = offset + 0x40
            while offset < end:
                self.leaf(MALLOC, 6, NAME_INPUT, 0xa)
                buf = self.svc['malloc']
                if buf == 0:
                    return self.restart()
                self.put(buf, 2, PACKET_HEADER)
                self.put(buf + 2, 4, self.u32(data + offset))
                self.put(buf + 6, 4, self.u32(data + offset + 4))
                self.leaf(I2C_WRITE, buf, 0xa)
                self.capture(buf, 0xa)
                self.leaf(FREE, 6, NAME_INPUT, buf)
                if self.svc['i2c']:
                    return self.restart()
                offset += 8
                self.delay(1)
            self.put(CTX + 0x24, 4, self.u32(CTX + 0x24) + 1)
            if self.process(dev, 2, EVENT_VALUE_B):
                return self.restart()
            self.delay(10)
        # Leave the bootloader and verify.
        self.delay(10)
        if self.process(dev, 3, EVENT_VALUE_A):
            return self.restart()
        if self.reg_write(0xc003, 0) or self.reg_write(0x104, 0) or self.reg_select(0x1d0):
            return self.restart()
        verify = 0
        count = self.u32(CTX + 0x20)
        while verify < count:
            self.leaf(REG_READ, 0x1d2, STACK - 0x48, 8)
            if self.svc['reg']:
                return self.restart()
            self.leaf(MEMCMP, data + verify * 8, STACK - 0x48, 8)
            if self.svc['memcmp']:
                self.leaf(LOGGER, LOG_ERROR)            # "verify flash fa..."
                return self.restart()
            verify += 1
        if self.reset_fail():
            return self.restart()
        # Finalize.
        self.leaf(VERSION)
        if self.svc['reg']:
            return self.restart()
        self.leaf(POST_VERSION, self.u32(DATA_SLOT))
        if self.svc['post_version']:
            return self.restart()
        if self.process(dev, 4, EVENT_VALUE_B):
            return self.restart()
        self.put(CTX + 0x2c, 1, 1)
        self.leaf(GPIO_IRQ_ENABLE, self.u16(self.u32(CTX) + 2))
        if self.svc['gpio']:
            return self.restart()
        return self.restart()

    def reset_fail(self):
        self.leaf(RESET, 1)
        if self.svc['reset']:
            self.leaf(LOGGER, LOG_ERROR)
            return True
        return False

    def sequence_step(self, step):
        if step[0] == 'd':
            self.delay(step[1])
            return False
        if step[0] == 's':
            return bool(self.reg_select(step[1]))
        return bool(self.reg_write(step[1], step[2]))

    def operation(self, op):
        if op['name'] != 'worker':
            raise ValueError('operation')
        return self.worker()


def contract(case):
    if case['scope'] != 'touch_upgrade' or len(case['operations']) != 1:
        raise ValueError('touch upgrade scope')
    return Model(case).run()


def case(name, state=1, length=0x40, **over):
    g = dict(process=0, gpio=0, timer_stop=0, reset=0, reg=0, i2c=0, malloc=MALLOC_BUF,
             memcmp=0, post_version=0, timer=0, config_reset=0)
    g.update(over)
    ctx = bytearray(0x40)
    struct.pack_into('<I', ctx, 0, BSD)
    slot = bytearray(0x14)                       # 0x70f8e0fc .. 0x70f8e110
    struct.pack_into('<I', slot, 0x00, DEVICE)   # device
    slot[0x04] = state                           # state byte at 0x70f8e100
    struct.pack_into('<I', slot, 0x08, TIMER_OBJ)
    struct.pack_into('<I', slot, 0x0c, length)   # 0x70f8e108 length
    struct.pack_into('<I', slot, 0x10, DATA_PTR) # 0x70f8e10c data pointer
    data = bytes((0x11 + i) & 0xff for i in range(max(length, 0x40)))
    stubs = {
        str(PROCESS): dict(kind='return', args=3, value=g['process']),
        str(GPIO_IRQ_DISABLE): dict(kind='return', args=1, value=g['gpio']),
        str(GPIO_IRQ_ENABLE): dict(kind='return', args=1, value=g['gpio']),
        str(TIMER_STOP): dict(kind='return', args=1, value=g['timer_stop']),
        str(RESET): dict(kind='return', args=1, value=g['reset']),
        str(REG_SELECT): dict(kind='return', args=1, value=g['reg']),
        str(REG_WRITE): dict(kind='return', args=2, value=g['reg']),
        str(REG_READ): dict(kind='return', args=3, value=g['reg']),
        str(VERSION): dict(kind='return', args=0, value=g['reg']),
        str(I2C_WRITE): dict(kind='capture', ptr_arg=0, size=0xa, value=g['i2c'], args=2),
        str(MALLOC): dict(kind='return', args=3, value=g['malloc']),
        str(FREE): dict(kind='return', args=3, value=0),
        str(MEMCMP): dict(kind='return', args=3, value=g['memcmp']),
        str(POST_VERSION): dict(kind='return', args=1, value=g['post_version']),
        str(TIMER_START_WRAP): dict(kind='return', args=1, value=g['timer']),
        str(CONFIG_RESET): dict(kind='return', args=0, value=g['config_reset']),
        str(DELAY): dict(kind='return', args=1), str(LOGGER): dict(kind='return', args=1),
    }
    return dict(
        name='main_touch_upgrade_' + name, scope='touch_upgrade', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name='worker', entry=WORKER, call=True, args=[INPUT_MSG_SLOT],
                                      registers=False, result=True, result_high=False)],
        memory=[[CTX, bytes(ctx).hex()], [BSD, BSD_RECORD.hex()], [INPUT_MSG_SLOT, bytes(slot).hex()],
                [DATA_PTR, data.hex()]], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('upgrade_one_chunk', state=1, length=0x40))
    add(case('upgrade_two_chunks', state=1, length=0x80))
    add(case('work_process_state2', state=2))
    add(case('work_process_state2_reset_fails', state=2, config_reset=0xfffffff1))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
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
    packets = None
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        results[c['name'].removeprefix('main_touch_upgrade_')] = row['observed']['rows'][0]['a0']
        if c['name'].endswith('upgrade_one_chunk'):
            packets = [a[4:] for a in c['expected']['actions'] if a.startswith('cap:')]
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        worker=f'{WORKER:#010x} (ztw622 input-task body)',
        dispatch=dict(state_byte=f'{STATE_BYTE:#010x}', state_1='TP firmware upgrade / ODR worker',
                      state_2=f'work/config-reset process ({CONFIG_RESET:#010x})'),
        upgrade=dict(
            enter_bootloader=['soft reset', 'register 0x1d5', '0xc000 = 1', '0xc004', '0xc002 = 1',
                              '0xc003 = 1', '0x104 = 1', '0x1d0'],
            stream='0x40-byte chunks; each 8-byte group -> 10-byte I2C packet [0x01d1, data[k:k+8]]',
            leave_bootloader=['0xc003 = 0', '0x104 = 0', '0x1d0'],
            verify=f'read register 0x1d2 back and memcmp ({MEMCMP:#010x}) against the source per 0x40 block',
            finalize=['version read', 're-enable interrupt', 'context +0x2c = 1', 'restart poll timer'],
            progress_events='ztw622_process_event 0x701eac38 modes 0..5',
            sample_packets=packets),
        return_codes=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The register/reset/version/dispatch helpers, malloc/free, memcmp, the GPIO interrupt '
            'enable/disable, the timer stop/start and the logger are stubbed; the worker itself runs as real '
            'code and the streamed I2C packets are captured.',
            'The flash read-back comparison is stubbed (memcmp returns match); the on-device verify of the '
            'written image is not executed.  The up-to-three-attempt retry on an error path is covered by the '
            'malloc-failure case only at its first failure.'])


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
        parser.exit(2, f'Cannot inspect TP upgrade worker: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
