#!/usr/bin/env python3
"""Main-image ZTW622 touch open: bus/GPIO bring-up, check-mode probe and task/timer start.

Executes in ``main-runtime`` the original device-open ioctl ``ztw622_open``
``0x701ebed8`` with the already-verified register/reset/version layer of
:mod:`main_touch_control` and :mod:`main_touch_report`:

- find the board record ``dev_ztw622``, open and configure the I2C bus, zero a
  GPIO descriptor and configure the interrupt pin, attach the interrupt handler
  ``0x701eacae`` (``0x702bd834``);
- set the rotation flag (``0x701eb44a``) and run the **check-mode probe**: up to
  three attempts reading register ``0x13`` and ``0x121`` (``0x701eaf56``); a read
  failure resets (``0x701eb702(1)``) and retries. If both reads return
  ``0x13``/``0x121`` the device is taken as normal mode (context ``+0x1c = 1``);
  otherwise the version block ``0x701ebc50`` runs and the mode is recorded as
  bootloader (``+0x1c = 2``);
- write register ``0xd4 = 0x3c``, soft reset (``0x701eb702(2)``), clear the
  interrupt, enable the GPIO interrupt (``0x702bda0c``), allocate and start the
  input task (``0x80d3ddd8``, entry ``0x701eca9c``), program the charge
  active-nap delay register ``0xe3`` (``0x701ebe74``) and create the poll timer
  (``0x80d36b96``, callback ``0x701eb154``); on success mark the context opened
  (``+0x2b = +0x28 = 1``).

Supplied (stubbed) services: board lookup, I2C get/config, GPIO config/enable,
interrupt attach, malloc, task create, timer create, memset, logger, delay and
the bus transfers.  The register, reset, clear-interrupt and version bodies run
as real code; their I2C leaf transfers are driven by the scripted bus.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_touch_report as rpt
    from . import main_touch_control as ctrl
else:
    import main_freertos_kernel as kernel
    import main_touch_report as rpt
    import main_touch_control as ctrl

BOUND = 20000
word = rpt.word

OPEN = 0x701ebed8
SET_ROTATE = 0x701eb44a
NAP_DELAY = 0x701ebe74
ATTACH_IRQ, GPIO_ENABLE_IRQ = 0x702bd834, 0x702bda0c
MALLOC, THREAD_CREATE, TIMER_CREATE = 0x80d3c2f4, 0x80d3ddd8, 0x80d36b96
IRQ_HANDLER, THREAD_ENTRY, TIMER_CB = 0x701eacae, 0x701eca9c, 0x701eb154
NAME_DEV = 0x709bd040
NAME_INPUT, NAME_ZTW = 0x709d1e98, 0x709bd044   # "drivers_input", "ztw622"

CTX = rpt.CTX
BSD = ctrl.BSD
BSD_RECORD = ctrl.BSD_RECORD
ROTATE_FLAG, ZERO_BYTE = 0x70f92d3a, 0x70f92d3c
INPUT_MSG_SLOT, INPUT_OPEN_BYTE, INPUT_TASK_SLOT = 0x70f8e0fc, 0x70f8e100, 0x70f8e110
TIMER_HANDLE = rpt.TIMER_HANDLE          # 0x70f8e104
LOG_ERROR, LOG_INFO = 3, 6

MSG = 0x81001c00            # authored input device message object (within the quiet stack window)
THREAD_OBJ = 0x81001800     # malloc result (quiet window, so the memset is not recorded)
NAP = 0x0032                # msg[0x3a] charge active-nap delay
STACK = ctrl.STACK
CSRS = kernel.CSRS

CODE = rpt.CODE + ctrl.CODE[len(rpt.CODE):] + (
    (SET_ROTATE, 0x34, 'cba22e8bf0d61c85634c836fbc9a8bb0d4616993168f13ea57565a07093b0c33'),
    (NAP_DELAY, 0x64, '593c5442a3d13e4e11e7ccf2d7b2d1bb8e3a0989e8c38149f8faf82702032f04'),
    (OPEN, 0x2de, '153633ece76444df124c2d3259d80b61b58bc4c79757fac5ea465d7b92524249'),
)
DATA = ctrl.DATA


class Model(ctrl.Model):
    def __init__(self, case):
        super().__init__(case)
        # ctrl.Model reads case['services']; open adds its own stub return codes.
        self.g = case['services']

    # 0x701eaf56 reg read (16-bit): select then read two bytes.
    def read_reg16(self, reg):
        scratch = STACK - 0x200
        status = self.reg_select(reg, scratch)
        if status:
            return status, 0
        self.put(scratch + 0x10, 2, 0)
        status = self.i2c(rpt.BUS_READ, scratch + 0x10, 2)
        value = self.u16(scratch + 0x10) if status == 0 else 0
        return status, value

    # 0x701eb44a set rotate flag (a0) then log.
    def set_rotate(self, flag):
        self.put(ROTATE_FLAG, 1, flag)
        self.leaf(rpt.LOGGER, LOG_INFO)

    # 0x701ebe74 charge active-nap delay: log then write register 0xe3.
    def nap_delay(self, value):
        self.leaf(rpt.LOGGER, LOG_INFO)
        status = self.write_reg(0xe3, value)
        if status:
            self.leaf(rpt.LOGGER, LOG_ERROR)
        return status

    def check_mode(self):
        """Up to three attempts; returns True for normal mode, False for the version path."""
        attempts = 3
        while attempts:
            s13, v13 = self.read_reg16(0x13)
            if s13 == 0:
                s121, v121 = self.read_reg16(0x121)
                if s121 == 0:
                    matched = v13 == 0x13 and v121 == 0x121
                    if matched:
                        self.leaf(rpt.LOGGER, LOG_ERROR)
                    return matched
            # read failed: reset and retry
            if self.reset(1):
                self.leaf(rpt.LOGGER, LOG_ERROR)
            attempts -= 1
        return True        # all attempts failed -> proceed as normal mode

    def open_(self, msg):
        if self.u8(CTX + 0x2c) == 5:
            return word(-7)
        self.leaf(ctrl.BOARD_FIND, NAME_DEV)
        self.put(CTX, 4, BSD)
        record = BSD
        self.leaf(ctrl.I2C_GET, self.u32(record + 8), CTX + 4)
        if self.g['i2c_get']:
            return word(self.g['i2c_get'])
        self.write(CTX + 4, 4, rpt.I2C_HANDLE, record=False)
        self.leaf(ctrl.I2C_CONFIG, rpt.I2C_HANDLE, 1)
        if self.g['i2c_config']:
            return word(self.g['i2c_config'])
        self.leaf(rpt.MEMSET, STACK - 0x40, 0, 0x20)
        self.leaf(ctrl.GPIO_CONFIG, self.u16(record + 2))
        self.actions.append('cap:' + struct.pack('<4I', 0, 0, self.u8(record + 4), self.u8(record + 5)).hex())
        if self.g['gpio_config']:
            return word(self.g['gpio_config'])
        self.leaf(ATTACH_IRQ, self.u16(record + 2), self.u8(record + 6), IRQ_HANDLER, msg)
        if self.g['attach_irq']:
            return word(self.g['attach_irq'])
        self.put(ZERO_BYTE, 1, 0)
        self.put(CTX + 0x29, 1, 1)
        self.set_rotate(0)
        normal = self.check_mode()
        if normal:
            self.put(CTX + 0x1c, 1, 1)
        else:
            self.put(CTX + 0x1c, 1, 2)
            status = self.version()
            if status:
                return word(status)
            self.put(CTX + 0x2c, 1, 1)
        # Post check-mode bring-up.
        self.write_reg(0xd4, 0x3c)
        self.reset(2)
        status = self.clear_int()
        if status:
            return word(status)
        self.leaf(GPIO_ENABLE_IRQ, self.u16(record + 2))
        if self.g['gpio_enable']:
            return word(self.g['gpio_enable'])
        self.put(INPUT_MSG_SLOT, 4, msg)
        self.put(INPUT_OPEN_BYTE, 1, 0)
        self.leaf(MALLOC, 6, NAME_INPUT, 0x28)
        task = self.g['malloc']
        self.put(INPUT_TASK_SLOT, 4, task)
        if task == 0:
            return word(-5)
        self.leaf(rpt.MEMSET, task, 0, 0x28)
        self.leaf(THREAD_CREATE, task, THREAD_ENTRY, INPUT_MSG_SLOT, 0x64)
        if self.g['thread_create']:
            return word(self.g['thread_create'])
        status = self.nap_delay(self.u16(CTX + 0x3a))
        if status:
            return word(status)
        self.leaf(TIMER_CREATE, TIMER_CB, 0, NAME_ZTW, 0, 0)
        timer = self.g['timer_create']
        self.put(TIMER_HANDLE, 4, timer)
        if timer == 0:
            return word(-6)
        self.leaf(rpt.LOGGER, LOG_INFO)
        self.put(CTX + 0x2b, 1, 1)
        self.put(CTX + 0x28, 1, 1)
        return 0

    def operation(self, op):
        if op['name'] != 'open':
            raise ValueError('operation')
        return self.open_(op['args'][0])


def put32(buf, off, value):
    struct.pack_into('<I', buf, off, value & 0xffffffff)


def contract(case):
    if case['scope'] != 'touch_open' or len(case['operations']) != 1:
        raise ValueError('touch open scope')
    model = Model(case)
    result = model.run()
    if model.bus[rpt.BUS_WRITE] or model.bus[rpt.BUS_READ] or model.resets:
        raise ValueError('unused scripted inputs')
    return result


def case(name, writes=(), reads=(), resets=(), **over):
    g = dict(i2c_get=0, i2c_config=0, gpio_config=0, attach_irq=0, gpio_enable=0,
             malloc=THREAD_OBJ, thread_create=0, timer_create=0x0e0e0001, gpio_write=[])
    g.update(over)
    ctx = bytearray(0x40)
    put32(ctx, 0, BSD)
    struct.pack_into('<H', ctx, 0x3a, NAP)       # charge active-nap delay (read at open)
    msg = bytearray(0x40)
    stubs = {
        str(rpt.BUS_WRITE): dict(kind='bus', buf_arg=2, len_arg=3, write=True, seq=list(writes)),
        str(rpt.BUS_READ): dict(kind='bus', buf_arg=2, len_arg=3, write=False, seq=list(reads)),
        str(rpt.BUS_RESET): dict(kind='return', args=0, seq=list(resets)),
        str(rpt.LOGGER): dict(kind='return', args=1), str(rpt.MEMSET): dict(kind='memset', args=3),
        str(ctrl.DELAY): dict(kind='return', args=1),
        str(ctrl.BOARD_FIND): dict(kind='return', args=1, value=BSD),
        str(ctrl.I2C_GET): dict(kind='store', out_arg=1, size=4, value=rpt.I2C_HANDLE, value_ret=g['i2c_get'], args=2),
        str(ctrl.I2C_CONFIG): dict(kind='return', args=2, value=g['i2c_config']),
        str(ctrl.GPIO_CONFIG): dict(kind='capture', ptr_arg=1, size=16, value=g['gpio_config'], args=1),
        str(ATTACH_IRQ): dict(kind='return', args=4, value=g['attach_irq']),
        str(GPIO_ENABLE_IRQ): dict(kind='return', args=1, value=g['gpio_enable']),
        str(MALLOC): dict(kind='return', args=3, value=g['malloc']),
        str(THREAD_CREATE): dict(kind='return', args=4, value=g['thread_create']),
        str(TIMER_CREATE): dict(kind='return', args=5, value=g['timer_create']),
    }
    return dict(
        name='main_touch_open_' + name, scope='touch_open', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name='open', entry=OPEN, call=True, args=[MSG], registers=False,
                                      result=True, result_high=False)],
        memory=[[CTX, bytes(ctx).hex()], [BSD, BSD_RECORD.hex()], [MSG, bytes(msg).hex()]],
        bus_write=list(writes), bus_read=list(reads), bus_reset=list(resets), services=g)


OK = ctrl.OK


def check_mode_reads(reg13=0x13, reg121=0x121):
    return [dict(status=0, rx=struct.pack('<H', reg13).hex()), dict(status=0, rx=struct.pack('<H', reg121).hex())]


VERSION_READS = [dict(status=0, rx=v) for v in
                 ('0300', '0102', '2a00', 'a001', 'a001', '1000', '1200', '0100')]


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    # Normal mode: check-mode matches first try, then 0xd4 write, soft reset, clear int, nap write.
    # Bus writes: select 0x13, select 0x121, write 0xd4, reset(2) select 0x0000, clear-int select 0x0003, nap 0xe3.
    add(case('normal_mode', writes=[OK] * 6, reads=check_mode_reads()))
    # Bootloader mode: register 0x121 does not read back 0x121 -> version block then the common bring-up.
    add(case('bootloader_mode', writes=[OK] * 15,
             reads=check_mode_reads(0x13, 0x9999) + VERSION_READS))
    # First read fails once (bus reset returns an error); the second attempt matches.
    add(case('read_retry_then_ok',
             writes=[OK] * 8, resets=[7],
             reads=[dict(status=2)] + check_mode_reads()))
    # Early failures return the service error with no teardown.
    add(case('i2c_get_fails', i2c_get=3))
    add(case('i2c_config_fails', i2c_config=2))
    add(case('gpio_config_fails', gpio_config=0xb))
    add(case('attach_irq_fails', attach_irq=0xa))
    add(case('gpio_enable_fails', writes=[OK] * 5, reads=check_mode_reads(), gpio_enable=0xc))
    add(case('task_alloc_fails', writes=[OK] * 5, reads=check_mode_reads(), malloc=0))
    add(case('timer_create_fails', writes=[OK] * 6, reads=check_mode_reads(), timer_create=0))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    if memory.read(NAME_DEV, 10) != b'dev_ztw622':
        raise ValueError('board name')
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
        results[c['name'].removeprefix('main_touch_open_')] = row['observed']['rows'][0]['a0']
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        function=f'{OPEN:#010x} (ztw622_open)',
        device='ZTW622 (dev_ztw622, I2C address 0x20, chip id 0xe622)',
        bring_up=[
            'find dev_ztw622, open and configure the I2C bus',
            'zero a GPIO descriptor and configure the interrupt pin',
            f'attach the interrupt handler {IRQ_HANDLER:#010x} ({ATTACH_IRQ:#010x})',
            'set the rotation flag (0x701eb44a)'],
        check_mode=dict(
            function='0x701eaf56 register read of 0x13 and 0x121, up to three attempts',
            on_read_failure='soft reset 0x701eb702(1) and retry',
            normal='both reads 0x13/0x121 -> context +0x1c = 1 (normal mode)',
            bootloader='otherwise run the version block 0x701ebc50 and set +0x1c = 2 (bootloader mode)'),
        enable=[
            'write register 0xd4 = 0x3c', 'soft reset 0x701eb702(2)', 'clear interrupt',
            f'enable the GPIO interrupt ({GPIO_ENABLE_IRQ:#010x})',
            f'allocate and start the input task ({THREAD_CREATE:#010x}, entry {THREAD_ENTRY:#010x})',
            'program the charge active-nap delay register 0xe3 (0x701ebe74)',
            f'create the poll timer ({TIMER_CREATE:#010x}, callback {TIMER_CB:#010x})',
            'mark the context opened (+0x2b = +0x28 = 1)'],
        return_codes=dict(
            normal_mode=results['normal_mode'], bootloader_mode=results['bootloader_mode'],
            i2c_get_fails=results['i2c_get_fails'], attach_irq_fails=results['attach_irq_fails'],
            task_alloc_fails=results['task_alloc_fails'], timer_create_fails=results['timer_create_fails']),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The board lookup, I2C get/config, GPIO config/enable, interrupt attach, malloc, task create and '
            'timer create are stubbed; ztw622_open and the register/reset/clear-interrupt/version bodies run as '
            'real code with the I2C leaf transfers driven by the scripted bus.',
            'The input task body (entry 0x701eca9c) and the poll-timer callback (0x701eb154) are not executed.'])


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
        parser.exit(2, f'Cannot inspect ZTW622 open: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
