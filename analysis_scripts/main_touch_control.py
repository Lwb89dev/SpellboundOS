#!/usr/bin/env python3
"""Main-image ZTW622 touch control: attach/probe, rail switching, reset, mode, version.

Executes in ``main-runtime`` the original:

- attach/probe ``0x701eb88a``: board record ``dev_ztw622`` (the real record at
  ``0x80c0158c``), mutex, I2C handle for the record's bus, reset/interrupt GPIO
  configuration, power-up (vdda off, vdda discharge check, 100 ms, vddd on,
  vdda on, 1 ms), hardware reset, then the probe: command ``0x01f8``, 100 ms,
  ``0xc000 = 1``, 22-byte information block from ``0x09d2``, soft reset
  ``0x0ff8`` and the chip id (from the information block when the soft reset
  succeeds, else from register ``0x0120``; must be ``0xe622``).  Success returns
  the device object ``0x70f60efc``; failures log a code, power down, release
  GPIO/I2C/mutex, clear the context and return 0;
- rail switch ``0x701eb4dc(rail, on)`` (0 vdda ``LDO2_TP``, 1 vddd ``TP_1V8``);
- reset ``0x701eb702(type)`` (0 hardware GPIO sequence, 1 command ``0x0ff8``,
  2 command ``0x0000``);
- mode set ``0x701eb7c8(mode)`` and version read ``0x701ebc50``;
- the I2C register layer of :mod:`main_touch_report`.

Supplied: board lookup, mutex, I2C/GPIO/regulator services, trace, delay,
memset, logger and the bus transfers.
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
else:
    import main_freertos_kernel as kernel
    import main_touch_report as rpt

BOUND = 20000
word = rpt.word

ATTACH, POWER, RESET, MODE, VERSION = 0x701eb88a, 0x701eb4dc, 0x701eb702, 0x701eb7c8, 0x701ebc50
BOARD_FIND, MUTEX_CREATE, MUTEX_DELETE = 0x702b4f3e, 0x80d36fcc, 0x80d371cc
I2C_GET, I2C_CONFIG, I2C_RELEASE = 0x702b58ec, 0x702b591e, 0x702b599a
BUS_SUSPEND, BUS_RESUME = 0x702b5d22, 0x702b5d40
GPIO_CONFIG, GPIO_WRITE, GPIO_DEINIT = 0x702bd522, 0x702bd77e, 0x702bd60a
REG_GET, REG_ENABLE, REG_DISABLE, REG_DISCHARGED = 0x702b662e, 0x702b66c8, 0x702b679c, 0x702b6944
TRACE, DELAY = 0x702bef1c, 0x80d369ee
MEMSET, LOGGER = rpt.MEMSET, rpt.LOGGER
CTX = rpt.CTX
BSD = 0x80c0158c               # original dev_ztw622 record (.data)
NAME_DEV, TRACE_TP, TRACE_SWITCH = 0x709bd040, 0x709d28c4, 0x709d28bc
DEVICE = 0x70f60efc            # returned device object
# The original 20-byte dev_ztw622 record (reset pin 15, interrupt pin 21, bus/rail name pointers);
# authored into each case and checked against the image by evidence().
BSD_RECORD = bytes.fromhex('0f0015000000030098cf9b702cd19b7024d19b70')
CHIP_ID = 0xe622
REG_HANDLE = 0x0f0f0001
LOG_ERROR, LOG_INFO = 3, 6

CODE = rpt.CODE + (
    (POWER, 0x14e, '7b05776904991345c4f8535c735d65c3556abdd96a4c32505196a9317dfc9be2'),
    (RESET, 0x188, '89b189694f122647f29777d53d2b2ad33a9dd7a070e654aa83f63c2918f16fff'),
    (ATTACH, 0x3c6, '1da296a41c390ae57bd128a8bfa30c7d90e2bffc61211c7e29334545a8310bb3'),
    (VERSION, 0x1a0, 'b73714ed8bc4e0d82e920b805de0075de3e3b364e8b927537fd354c18754328c'),
)
DATA = rpt.DATA + (
    (BSD, 0x14, '3e2e2e5af5c57c9c421f0bffff5c434cffa9079002ab2134b0a2a01a6eaff3f7'),
)
CALL_SITES = (
    (0x701eb8b2, BOARD_FIND), (0x701eb944, I2C_GET), (0x701eb950, I2C_CONFIG), (0x701eb974, GPIO_CONFIG),
    (0x701eb984, GPIO_WRITE), (0x701eb9a2, GPIO_CONFIG), (0x701eb9aa, POWER), (0x701eb9b6, POWER),
    (0x701eb9c4, GPIO_DEINIT), (0x701eb9dc, I2C_RELEASE), (0x701eba46, REG_GET), (0x701eba7a, REG_DISCHARGED),
    (0x701ebaae, rpt.REG_SELECT), (0x701ebac4, rpt.REG_WRITE), (0x701ebad4, rpt.REG_READ), (0x701ebadc, RESET),
    (0x701ebb16, rpt.REG_READ16), (0x701ebc06, RESET), (0x701eb508, REG_GET), (0x701eb59e, REG_ENABLE),
    (0x701eb5c0, REG_DISABLE), (0x701eb588, TRACE), (0x701eb74c, GPIO_WRITE), (0x701eb75e, BUS_SUSPEND),
    (0x701eb78c, BUS_RESUME), (0x701eb7e0, rpt.REG_WRITE), (0x701eb810, RESET), (0x701eb82c, rpt.CLEAR_INT),
    (0x701ebc5a, RESET), (0x701ebca0, rpt.REG_READ16),
)
CSRS = kernel.CSRS
STACK = kernel.HARNESS_STACK


class Model(rpt.Model):
    def __init__(self, case):
        super().__init__(case)
        self.g = case['services']
        self.gpio = list(self.g['gpio_write'])

    def delay(self, ms):
        self.leaf(DELAY, ms)

    def gpio_write(self, pin, value):
        self.leaf(GPIO_WRITE, pin, value)
        return self.gpio.pop(0) if self.gpio else 0

    def bsd(self):
        return self.u32(CTX)

    # 0x701eb4dc
    def power(self, rail, on):
        status = word(-10)
        if rail in (0, 1):
            record = self.bsd()
            status = word(-4)
            if record:
                name = self.u32(record + (0x10 if rail else 0xc))
                status = word(-6)
                if name:
                    self.leaf(REG_GET, name)
                    status = self.g['reg_get']
                    if status:
                        self.leaf(LOGGER, LOG_ERROR)
                    else:
                        self.leaf(REG_ENABLE if on else REG_DISABLE, REG_HANDLE)
                        status = self.g['reg_switch']
                        if status:
                            self.leaf(LOGGER, LOG_ERROR)
        self.leaf(TRACE, TRACE_TP, TRACE_SWITCH, status, 2, on, rail)
        return status

    # 0x701eb702
    def reset(self, kind):
        self.leaf(LOGGER, LOG_INFO)
        if kind == 1:
            status = self.reg_select(0x0ff8, STACK - 0x200)
            if status == 0:
                self.delay(100)
            return status
        if kind == 2:
            return self.reg_select(0x0000, STACK - 0x200)
        if kind != 0:
            return word(-10)
        pin = self.u16(self.bsd())
        self.delay(1)
        total = self.gpio_write(pin, 1)
        self.delay(10)
        self.leaf(BUS_SUSPEND, self.u32(CTX + 4))
        total += self.gpio_write(pin, 0)
        self.delay(100)
        total += self.gpio_write(pin, 1)
        self.leaf(BUS_RESUME, self.u32(CTX + 4))
        self.delay(200)
        return word(total)

    def write_reg(self, reg, value):
        return self.reg_write(reg, value, STACK - 0x200)

    # 0x701eb7c8
    def mode(self, mode):
        if mode == 0xb:
            total = (self.write_reg(0x122, 0x1f) + self.write_reg(0x135, 9) + self.write_reg(0x100, 0x25) +
                     self.write_reg(0x7f, 0x64) + self.reset(2))
            self.delay(25)
            total += self.write_reg(0x10, 0xb)
        else:
            total = 0
            if mode != 0xe:
                total = self.write_reg(0x122, 0xd) + self.write_reg(0x135, 0) + self.write_reg(0x100, 0x3c)
            total += self.write_reg(0x10, mode)
            total += self.reset(2)
        for _ in range(5):
            total += self.clear_int()
            self.delay(50)
        return word(total)

    def read16(self, reg, out):
        status = self.reg_select(reg, STACK - 0x200)
        if status:
            return status
        self.put(STACK - 0x1f0, 2, 0)
        status = self.i2c(rpt.BUS_READ, STACK - 0x1f0, 2)
        if status == 0:
            self.put(out, 2, self.u16(STACK - 0x1f0))
        return status

    # 0x701ebc50
    def version(self):
        if self.reset(2):
            self.leaf(LOGGER, LOG_ERROR)
            return word(-1)
        for group in (((0x12, 0xa), (0x121, 0xc), (0x13, 0xe)), ((0xc0, 0x18), (0xc1, 0x1a)),
                      ((0x60, 0x10), (0x61, 0x12))):
            for reg, off in group:
                status = self.read16(reg, CTX + off)
                if status:
                    return status
            self.leaf(LOGGER, LOG_INFO)
        status = self.read16(0x11f, STACK - 0x30 + 0x1e)     # glove command register
        self.leaf(LOGGER, LOG_INFO)
        return status

    # 0x701eb88a
    def attach(self):
        self.leaf(MEMSET, CTX, 0, 0x3c)
        for i in range(0x3c):
            self.write(CTX + i, 1, 0, record=False)
        self.leaf(BOARD_FIND, NAME_DEV)
        self.put(CTX, 4, BSD)
        self.leaf(MUTEX_CREATE, 0)
        self.put(CTX + 0x30, 4, rpt.MUTEX)
        record = BSD
        self.leaf(I2C_GET, self.u32(record + 8), CTX + 4)
        if self.g['i2c_get']:
            return self.tail(1, 'e4')
        self.write(CTX + 4, 4, rpt.I2C_HANDLE, record=False)
        self.leaf(I2C_CONFIG, rpt.I2C_HANDLE, 1)
        if self.g['i2c_config']:
            return self.tail(2, 'e4')
        reset_pin, int_pin = self.u16(record), self.u16(record + 2)
        self.leaf(MEMSET, STACK - 0x60 + 0x30, 0, 0x20)
        self.leaf(GPIO_CONFIG, reset_pin)
        self.actions.append('cap:' + struct.pack('<4I', 0, 1, 0, 0).hex())
        if self.gpio_write(reset_pin, 0):
            return self.tail(4, 'cc')
        self.leaf(GPIO_CONFIG, int_pin)
        self.actions.append('cap:' + struct.pack('<4I', 0, 0, self.u8(record + 4), self.u8(record + 5)).hex())
        if self.power(0, 0):
            return self.tail(7, 'b2')
        self.leaf(REG_GET, self.u32(record + 0xc))
        if self.g['reg_get']:
            self.leaf(LOGGER, LOG_ERROR)
            return self.tail(7, 'b2')
        self.leaf(REG_DISCHARGED, REG_HANDLE, 5)
        if self.g['discharged']:
            self.leaf(LOGGER, LOG_ERROR)
            return self.tail(7, 'b2')
        self.delay(100)
        if self.power(1, 1):
            return self.tail(6, 'be')
        if self.power(0, 1):
            return self.tail(7, 'b2')
        self.delay(1)
        if self.reset(0):
            self.leaf(LOGGER, LOG_ERROR)
            return self.power_down(8)
        return self.probe()

    def probe(self):
        info = STACK - 0x60 + 0x18
        for i in range(0x16):
            self.write(info + i, 1, 0, record=False)
        parsed = False
        if self.reg_select(0x01f8, STACK - 0x200) == 0:
            self.delay(100)
            if self.write_reg(0xc000, 1) == 0:
                if self.reg_select(0x09d2, STACK - 0x200) == 0 and self.i2c(rpt.BUS_READ, info, 0x16) == 0:
                    if self.reset(1) == 0:
                        b = bytes(self.u8(info + i) for i in range(0x16))
                        self.put(CTX + 0x14, 4, b[8] << 16 | b[0xd] << 8 | b[0xc])
                        self.put(CTX + 8, 2, struct.unpack_from('<H', b, 0xa)[0])
                        self.leaf(LOGGER, LOG_INFO)
                        parsed = True
                    else:
                        self.leaf(LOGGER, LOG_ERROR)
        if not parsed and self.read16(0x120, CTX + 8):
            return self.power_down(9)
        if self.u16(CTX + 8) != CHIP_ID:
            if self.read16(0x120, CTX + 8):
                return self.power_down(9)
            if self.u16(CTX + 8) != CHIP_ID:
                self.leaf(LOGGER, LOG_ERROR)
                return self.power_down(10)
        self.leaf(LOGGER, LOG_INFO)
        return DEVICE

    def power_down(self, code):
        """0x701ebc42: vdda off (failure overrides the code with 7), then the common tail."""
        return self.tail(7 if self.power(0, 0) else code, 'b2')

    def tail(self, code, start):
        """Failure tail entered at 0x701eb9b2 ('b2'), 0x701eb9be ('be'), 0x701eb9cc ('cc'),
        0x701eb9da ('da') or 0x701eb9e4 ('e4')."""
        stage = ('b2', 'be', 'cc', 'da', 'e4').index(start)
        record = self.bsd()
        if stage <= 0 and self.power(1, 0):
            code = 6
        if stage <= 1:
            self.leaf(GPIO_DEINIT, self.u16(record + 2))
            if self.g['gpio_deinit']:
                code = 0xb
        if stage <= 2:
            self.leaf(GPIO_DEINIT, self.u16(record))
            if self.g['gpio_deinit']:
                code = 0xc
        if stage <= 3:
            self.leaf(I2C_RELEASE, rpt.I2C_HANDLE)
            if self.g['i2c_release']:
                code = 0xd
        self.leaf(LOGGER, LOG_ERROR)
        self.leaf(MUTEX_DELETE, rpt.MUTEX)
        self.leaf(MEMSET, CTX, 0, 0x3c)
        for i in range(0x3c):
            self.write(CTX + i, 1, 0, record=False)
        return 0

    def operation(self, op):
        name, args = op['name'], op['args']
        if name == 'attach':
            return self.attach()
        if name == 'power':
            return self.power(*args)
        if name == 'reset':
            return self.reset(args[0])
        if name == 'mode':
            return self.mode(args[0])
        if name == 'version':
            return self.version()
        raise ValueError('operation')


def contract(case):
    if case['scope'] != 'touch_control' or len(case['operations']) != 1:
        raise ValueError('touch control scope')
    model = Model(case)
    result = model.run()
    if model.bus[rpt.BUS_WRITE] or model.bus[rpt.BUS_READ] or model.resets or model.gpio:
        raise ValueError('unused scripted inputs')
    return result


OK = dict(status=0)


def info_block(chip=CHIP_ID, ium=(0x11, 0x22, 0x33)):
    b = bytearray(0x16)
    b[8], b[0xd], b[0xc] = ium
    struct.pack_into('<H', b, 0xa, chip)
    return bytes(b)


def case(name, op, args=(), writes=(), reads=(), resets=(), bsd=True, **over):
    g = dict(i2c_get=0, i2c_config=0, gpio_write=[], reg_get=0, reg_switch=0,
             discharged=0, gpio_deinit=0, i2c_release=0)
    g.update(over)
    ctx = bytearray(0x40)
    if op != 'attach':
        struct.pack_into('<II', ctx, 0, BSD if bsd else 0, rpt.I2C_HANDLE)
        struct.pack_into('<I', ctx, 0x30, rpt.MUTEX)
    stubs = {
        str(rpt.BUS_WRITE): dict(kind='bus', buf_arg=2, len_arg=3, write=True, seq=list(writes)),
        str(rpt.BUS_READ): dict(kind='bus', buf_arg=2, len_arg=3, write=False, seq=list(reads)),
        str(rpt.BUS_RESET): dict(kind='return', args=0, seq=list(resets)),
        str(LOGGER): dict(kind='return', args=1), str(MEMSET): dict(kind='memset', args=3),
        str(DELAY): dict(kind='return', args=1), str(BOARD_FIND): dict(kind='return', args=1, value=BSD),
        str(MUTEX_CREATE): dict(kind='return', args=1, value=rpt.MUTEX),
        str(MUTEX_DELETE): dict(kind='return', args=1),
        str(I2C_GET): dict(kind='store', out_arg=1, size=4, value=rpt.I2C_HANDLE, value_ret=g['i2c_get'], args=2),
        str(I2C_CONFIG): dict(kind='return', args=2, value=g['i2c_config']),
        str(I2C_RELEASE): dict(kind='return', args=1, value=g['i2c_release']),
        str(BUS_SUSPEND): dict(kind='return', args=1), str(BUS_RESUME): dict(kind='return', args=1),
        str(GPIO_CONFIG): dict(kind='capture', ptr_arg=1, size=16, value=0, args=1),
        str(GPIO_WRITE): dict(kind='return', args=2, seq=list(g['gpio_write']) or None),
        str(GPIO_DEINIT): dict(kind='return', args=1, value=g['gpio_deinit']),
        str(REG_GET): dict(kind='store', out_arg=1, size=4, value=REG_HANDLE, value_ret=g['reg_get'], args=1),
        str(REG_ENABLE): dict(kind='return', args=1, value=g['reg_switch']),
        str(REG_DISABLE): dict(kind='return', args=1, value=g['reg_switch']),
        str(REG_DISCHARGED): dict(kind='return', args=2, value=g['discharged']),
        str(TRACE): dict(kind='return', args=6),
    }
    if stubs[str(GPIO_WRITE)]['seq'] is None:
        del stubs[str(GPIO_WRITE)]['seq']
        stubs[str(GPIO_WRITE)]['value'] = 0
    entry = dict(attach=ATTACH, power=POWER, reset=RESET, mode=MODE, version=VERSION)[op]
    return dict(
        name='main_touch_control_' + name, scope='touch_control', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name=op, entry=entry, call=True, args=list(args), registers=False,
                                      result=True, result_high=False)],
        memory=[[CTX, bytes(ctx).hex()], [BSD, BSD_RECORD.hex()]],
        bus_write=list(writes), bus_read=list(reads), bus_reset=list(resets), services=g)


def attach_ok_script(info=None, chip_reads=()):
    """select 0x1f8, write 0xc000, select 0x9d2 + read info, soft reset select 0x0ff8."""
    writes = [OK, OK, OK, OK] + [OK] * len(chip_reads)
    reads = [dict(status=0, rx=(info or info_block()).hex())] + [dict(status=0, rx=struct.pack('<H', c).hex())
                                                                 for c in chip_reads]
    return dict(writes=writes, reads=reads)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('attach_probe_info_block', 'attach', **attach_ok_script()))
    add(case('attach_info_block_wrong_id_then_register', 'attach',
             **attach_ok_script(info_block(chip=0x1234), chip_reads=(CHIP_ID,))))
    add(case('attach_wrong_chip_id_powers_down', 'attach',
             **attach_ok_script(info_block(chip=0x1234), chip_reads=(0x5555,))))
    add(case('attach_soft_reset_fails_reads_register', 'attach',
             writes=[OK, OK, OK, dict(status=4), OK], reads=[dict(status=0, rx=info_block().hex()),
                                                              dict(status=0, rx='22e6')], resets=[8]))
    add(case('attach_i2c_handle_missing', 'attach', i2c_get=3))
    add(case('attach_i2c_config_fails', 'attach', i2c_config=2))
    add(case('attach_vdda_not_discharged', 'attach', discharged=1))
    add(case('attach_hardware_reset_fails', 'attach', gpio_write=[0, 1, 0, 0]))
    add(case('power_vddd_on', 'power', (1, 1)))
    add(case('power_vdda_off', 'power', (0, 0)))
    add(case('power_invalid_rail', 'power', (2, 1)))
    add(case('power_regulator_missing', 'power', (1, 1), reg_get=5))
    add(case('power_without_record', 'power', (0, 1), bsd=False))
    add(case('reset_hardware', 'reset', (0,)))
    add(case('reset_command_0ff8', 'reset', (1,), writes=[OK]))
    add(case('reset_command_0000', 'reset', (2,), writes=[OK]))
    add(case('reset_invalid_type', 'reset', (5,)))
    add(case('mode_0b', 'mode', (0xb,), writes=[OK] * 11))
    add(case('mode_0e', 'mode', (0xe,), writes=[OK] * 7))
    add(case('mode_01', 'mode', (1,), writes=[OK] * 10))
    add(case('version', 'version', writes=[OK] * 9,
             reads=[dict(status=0, rx=v) for v in ('0300', '0102', '2a00', 'a001', 'a001', '1000', '1200', '0100')]))
    add(case('version_glove_read_fails', 'version', writes=[OK] * 8 + [dict(status=2)], resets=[6],
             reads=[dict(status=0, rx=v) for v in ('0300', '0102', '2a00', 'a001', 'a001', '1000', '1200')]))
    add(case('version_reset_fails', 'version', writes=[dict(status=1)], resets=[4]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
    if memory.read(BSD, 20) != BSD_RECORD:
        raise ValueError('board record')
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
        image='main firmware (OTA 4.6.0.3)', vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        entries=dict(attach=f'{ATTACH:#010x}', power=f'{POWER:#010x}', reset=f'{RESET:#010x}',
                     mode=f'{MODE:#010x}', version=f'{VERSION:#010x}'),
        power_up=['vdda (LDO2_TP) off', 'wait until vdda discharged', '100 ms', 'vddd (TP_1V8) on',
                  'vdda (LDO2_TP) on', '1 ms', 'hardware reset'],
        hardware_reset=['1 ms', 'reset pin high', '10 ms', 'I2C suspend', 'reset pin low', '100 ms',
                        'reset pin high', 'I2C resume', '200 ms'],
        probe=['command 0x01f8', '100 ms', 'write 0xc000 = 1', 'read 22-byte information block at 0x09d2',
               'soft reset (command 0x0ff8, 100 ms)',
               'chip id = info[0x0a..0x0b] (else register 0x0120, read up to twice), must be 0xe622',
               'ium info = info[8] << 16 | info[0xd] << 8 | info[0xc]'],
        reset_types={'0': 'hardware GPIO sequence', '1': 'command 0x0ff8 + 100 ms', '2': 'command 0x0000'},
        modes={'0x0b': [['0x122', '0x1f'], ['0x135', '0x09'], ['0x100', '0x25'], ['0x7f', '0x64'],
                        'reset 2', '25 ms', ['0x10', '0x0b']],
               '0x0e': [['0x10', '0x0e'], 'reset 2'],
               'other': [['0x122', '0x0d'], ['0x135', '0x00'], ['0x100', '0x3c'], ['0x10', 'mode'], 'reset 2'],
               'then': 'five clear-interrupt commands, 50 ms apart'},
        version_registers={'major': '0x0012', 'minor': '0x0121', 'release': '0x0013', 'x_resolution': '0x00c0',
                           'y_resolution': '0x00c1', 'x_channels': '0x0060', 'y_channels': '0x0061',
                           'glove': '0x011f'},
        attach_result=f'device object {DEVICE:#010x} on success, 0 on failure (after power-down and release)',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Attach, rail switch, reset, mode, version and the register layer execute in the main-image emulator '
            'over the original dev_ztw622 record; board lookup, mutex, I2C/GPIO/regulator, trace, delay, memset, '
            'logger and bus transfers are supplied with authored results.',
            'Register values written by the mode setter are recorded, not interpreted; the information-block '
            'layout beyond the chip id and ium bytes is not decoded.',
            'Rail voltages, reset timing tolerance and the fitted controller are unverified on hardware.'])


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
        parser.exit(2, f'Cannot inspect touch control: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
