#!/usr/bin/env python3
"""Main-image AW32012 charger: I2C register layer and every register-level control.

The alternative charger driver to CW6305 (see :mod:`main_charger_cw6305`), on
the same ``sens_i2c1`` bus.  This scope executes, in ``main-runtime``, the
original AW32012 bodies:

- register read ``0x702b7976`` / write ``0x702b7aea``: I2C address ``0x49``,
  8-bit registers, handle word ``0x70f8e5b0`` (-10 when absent);
- power off ``0x702b7b1c``: ``0x06`` bit 5;
- fast charge current ``0x702b7d40(mA)``: ``0x02`` bits 5:0 = ``(mA - 8) / 8``
  (``0x3f`` above 519 mA), written only on change;
- pre-charge/termination current set/check ``0x702b7e0c`` / ``0x702b7ea8``:
  ``0x03`` bits 3:0 = ``(mA - 1) / 2`` (``0xf`` above 32 mA);
- charge control ``0x702b7f68(on)``: ``0x01`` bit 3 is charge *disable*;
  hibernate enable/disable ``0x702b8018`` / ``0x702b807c`` (mode 3 only);
- switch mode ``0x702b80e0(v)``: ``0x0d`` bit 0;
- charge state ``0x702b818e``: ``0x08`` bits 4:3; system status ``0x08``,
  fault ``0x09`` and id ``0x0a`` reads;
- register tables ``0x702b822c`` (registers 0x00..0x0c, used at init with the
  original table) and ``0x702b83ac`` (0x00..0x0d);
- VBUS reset configuration ``0x702b82d2(on)``: unlock ``0x69 = 0xc2``, set or
  clear ``0x21`` bit 7, then relock ``0x69 = 0``.

Only the I2C register transfer helpers and the logger are supplied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_charger_cw6305 as cw
else:
    import main_freertos_kernel as kernel
    import main_charger_cw6305 as cw

BOUND = 20000
word = cw.word
READ_REG, WRITE_REG = 0x702b7976, 0x702b7aea
POWER_OFF, CURRENT, TERM_SET, TERM_CHECK = 0x702b7b1c, 0x702b7d40, 0x702b7e0c, 0x702b7ea8
CHG_CTRL, HIB_ON, HIB_OFF, SWITCH = 0x702b7f68, 0x702b8018, 0x702b807c, 0x702b80e0
CHG_STAT, ALL_CONFIG, VBUS_RESET, CHG_CONFIG = 0x702b818e, 0x702b822c, 0x702b82d2, 0x702b83ac
SYS_STATUS, FAULT, ID_GET = 0x702b8452, 0x702b84da, 0x702b85d4
BUS_READ, BUS_WRITE, LOGGER = cw.BUS_READ, cw.BUS_WRITE, cw.LOGGER
HANDLE_WORD, TABLE = 0x70f8e5b0, 0x70f61cfc
ADDRESS, TIMEOUT, HANDLE = 0x49, 1000, 0x49490001
OUT, ALT_TABLE = 0x81004000, 0x81004100
# Original register table written at init (registers 0x00..0x0c), checked against the image by evidence().
INIT_TABLE = bytes.fromhex('6f6c2198de1a423700400041c0')

CODE = (
    (READ_REG, 0x22, '5cd3e57ef555cc7843483854fed0b822a1d5c0b4125d090dfbc19ebbb5fbffdc'),
    (WRITE_REG, 0x32, '98b617237a64f3b06b7f87c140e982449fb0a5018db75f4a265093a51444a66c'),
    (POWER_OFF, 0x80, '1b473c9fa0301354097d9d1a129f568c47b355b50c69ea00575fc0e95f202324'),
    (CURRENT, 0x822, '63af90827295fc81889419c3d95b714a518d2ac442a3238b02992c31970a8915'),
    (ID_GET, 0xa0, '3325e40da40c138191737f9f2d2051de03c75c5144eadca9f8f12446ecf2a943'),
)
DATA = ((TABLE, 0xd, '77775d1c41f18105dbc414551ff5c366f4d62e736a8fbc39b4cb402577e8472d'),)
CSRS = kernel.CSRS


def tdiv(a, b):
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b > 0) else -q


def current_code(ma):
    return 0x3f if ma > 0x207 else tdiv(ma - 8, 8) & 0xff


def term_code(ma):
    return 0xf if ma > 0x20 else tdiv(ma - 1, 2) & 0xf


class Model(cw.Model):
    def read_reg(self, reg, out):
        if not self.read(HANDLE_WORD, 4):
            return word(-10)
        self.actions.append(f'bus:{BUS_READ}:{HANDLE}:{ADDRESS}:{reg}:1:1:{TIMEOUT}:')
        t = self.reads.pop(0)
        if 'rx' in t:
            self.write(out, 1, int(t['rx'], 16), record=False)
        return t['status']

    def write_reg(self, reg, value):
        if not self.read(HANDLE_WORD, 4):
            return word(-10)
        self.actions.append(f'bus:{BUS_WRITE}:{HANDLE}:{ADDRESS}:{reg}:1:1:{TIMEOUT}:{value & 0xff:02x}')
        return self.writes.pop(0)['status']

    def update(self, reg, compute, skip_same=None, log_change=False, log_success=False):
        scratch = kernel.HARNESS_STACK - 0x40
        self.write(scratch, 1, 0)
        status = self.read_reg(reg, scratch)
        if status:
            self.log_error()
            return status
        old = self.read(scratch, 1)
        if skip_same is not None and skip_same(old):
            return 0
        if log_change:
            self.leaf(LOGGER, 6)
        status = self.write_reg(reg, compute(old))
        if status:
            self.log_error()
        elif log_success:
            self.leaf(LOGGER, 6)
        return status

    def operation(self, op):
        e, a = op['entry'], op['args']
        if e == READ_REG:
            return self.read_reg(a[0], a[1])
        if e == WRITE_REG:
            return self.write_reg(a[0], a[1])
        if e == POWER_OFF:
            return self.update(6, lambda v: v | 0x20)
        if e == CURRENT:
            code = current_code(a[0])
            return self.update(2, lambda v: (v & 0xc0) | (code & 0x3f), skip_same=lambda v: v & 0x3f == code,
                               log_change=True)
        if e == TERM_SET:
            code = term_code(a[0])
            return self.update(3, lambda v: (v & 0xf0) | code)
        if e == TERM_CHECK:
            if a[1] == 0:
                self.log_error()
                return word(-10)
            scratch = kernel.HARNESS_STACK - 0x30 + 0x1c
            self.write(scratch, 1, 0)
            status = self.read_reg(3, scratch)
            if status:
                self.log_error()
                return status
            self.write(a[1], 1, 1 if self.read(scratch, 1) & 0xf == term_code(a[0]) else 0)
            return 0
        if e == CHG_CTRL:
            disable = 1 if a[0] == 0 else 0
            return self.update(1, lambda v: (v & ~8 & 0xff) | (disable << 3),
                               skip_same=lambda v: (v >> 3) & 1 == disable, log_change=True)
        if e in (HIB_ON, HIB_OFF):
            if a[0] != 3:
                return 0
            status = self.operation(dict(entry=CHG_CTRL, args=[1 if e == HIB_ON else 0]))
            self.leaf(LOGGER, 6 if status == 0 else 3)
            return status
        if e == SWITCH:
            return self.update(0xd, lambda v: (v & ~1 & 0xff) | (a[0] & 1), skip_same=lambda v: v & 1 == a[0],
                               log_success=True)
        if e == CHG_STAT:
            if a[0] == 0:
                self.log_error()
                return word(-10)
            scratch = kernel.HARNESS_STACK - 0x30 + 0x1c
            self.write(scratch, 1, 0)
            status = self.read_reg(8, scratch)
            if status:
                self.log_error()
                return status
            self.write(a[0], 1, (self.read(scratch, 1) >> 3) & 3)
            return 0
        if e in (SYS_STATUS, FAULT):
            return self.getter(8 if e == SYS_STATUS else 9, a[0])
        if e == ID_GET:
            if a[0] == 0:
                self.log_error()
                return word(-10)
            scratch = kernel.HARNESS_STACK - 0x30 + 0x1f
            self.write(scratch, 1, 0xff)
            status = self.read_reg(0xa, scratch)
            if status:
                self.log_error()
            else:
                self.write(a[0], 1, self.read(scratch, 1))
            return status
        if e in (ALL_CONFIG, CHG_CONFIG):
            if a[0] == 0:
                self.log_error()
                return word(-10)
            failed = 0
            for reg in range(0xd if e == ALL_CONFIG else 0xe):
                if self.write_reg(reg, self.read(a[0] + reg, 1)):
                    self.log_error()
                    failed = 1
            return word(-failed)
        if e == VBUS_RESET:
            status = self.write_reg(0x69, 0xc2)
            if status:
                self.log_error()
            else:
                scratch = kernel.HARNESS_STACK - 0x30 + 0x1f
                self.write(scratch, 1, 0)
                status = self.read_reg(0x21, scratch)
                if status:
                    self.log_error()
                else:
                    old = self.read(scratch, 1)
                    status = self.write_reg(0x21, (old & 0x7f) if a[0] else (old | 0x80))
            if self.write_reg(0x69, 0):
                self.log_error()
                status = word(-1)
            return status
        raise ValueError('entry')


def contract(case):
    if case['scope'] != 'aw32012' or len(case['operations']) != 1:
        raise ValueError('aw32012 scope')
    model = Model(case)
    result = model.run()
    if model.reads or model.writes:
        raise ValueError('unused scripted inputs')
    return result


rx, OK, FAIL = cw.rx, cw.OK, cw.FAIL


def case(name, entry, args=(), reads=(), writes=(), handle=True):
    c = cw.case(name, entry, args, reads, writes, handle)
    c['name'] = 'main_charger_aw32012_' + name
    c['scope'] = 'aw32012'
    c['ranges'] = [[a, a + n] for a, n, _ in CODE]
    c['memory'] = [[HANDLE_WORD, struct.pack('<I', HANDLE if handle else 0).hex()], [OUT, '00'],
                   [TABLE, INIT_TABLE.hex()], [ALT_TABLE, bytes(range(0x30, 0x3e)).hex()]]
    return c


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('read_reg', READ_REG, (0x08, OUT), reads=[rx(0x5a)]))
    add(case('no_handle', WRITE_REG, (0x01, 0), handle=False))
    add(case('power_off', POWER_OFF, reads=[rx(0x00)], writes=[OK]))
    add(case('power_off_read_fails', POWER_OFF, reads=[FAIL]))
    for ma in (0, 4, 8, 16, 100, 260, 512, 519, 520, 1000):
        add(case(f'current_{ma}ma', CURRENT, (ma,), reads=[rx(0xc5)],
                 writes=[OK] if current_code(ma) != 5 else []))
    add(case('current_unchanged', CURRENT, (48,), reads=[rx(0x05)]))
    for ma in (0, 1, 2, 10, 31, 32, 33):
        add(case(f'term_set_{ma}ma', TERM_SET, (ma,), reads=[rx(0xa5)], writes=[OK]))
    add(case('term_check_match', TERM_CHECK, (10, OUT), reads=[rx(0x04)]))
    add(case('term_check_differs', TERM_CHECK, (10, OUT), reads=[rx(0x05)]))
    add(case('term_check_null', TERM_CHECK, (10, 0)))
    for on, old in ((1, 0x08), (0, 0x00), (1, 0x00), (0, 0xff)):
        disable = 1 if on == 0 else 0
        add(case(f'chg_ctrl_{on}_from_{old:02x}', CHG_CTRL, (on,), reads=[rx(old)],
                 writes=[OK] if (old >> 3) & 1 != disable else []))
    add(case('hibernate_enable_mode3', HIB_ON, (3,), reads=[rx(0x08)], writes=[OK]))
    add(case('hibernate_disable_mode3', HIB_OFF, (3,), reads=[rx(0x00)], writes=[OK]))
    add(case('hibernate_other_mode', HIB_OFF, (1,)))
    add(case('switch_mode_1', SWITCH, (1,), reads=[rx(0xf0)], writes=[OK]))
    add(case('switch_mode_unchanged', SWITCH, (0,), reads=[rx(0xf0)]))
    add(case('switch_mode_write_fails', SWITCH, (1,), reads=[rx(0x00)], writes=[FAIL]))
    add(case('charge_state', CHG_STAT, (OUT,), reads=[rx(0x18)]))
    add(case('charge_state_null', CHG_STAT, (0,)))
    add(case('sys_status', SYS_STATUS, (OUT,), reads=[rx(0x33)]))
    add(case('fault', FAULT, (OUT,), reads=[rx(0x80)]))
    add(case('id', ID_GET, (OUT,), reads=[rx(0x49)]))
    add(case('all_config_original_table', ALL_CONFIG, (TABLE,), writes=[OK] * 13))
    add(case('all_config_one_failure', ALL_CONFIG, (TABLE,), writes=[OK] * 3 + [FAIL] + [OK] * 9))
    add(case('chg_config_fourteen_registers', CHG_CONFIG, (ALT_TABLE,), writes=[OK] * 14))
    add(case('vbus_reset_on', VBUS_RESET, (1,), reads=[rx(0xff)], writes=[OK, OK, OK]))
    add(case('vbus_reset_off', VBUS_RESET, (0,), reads=[rx(0x01)], writes=[OK, OK, OK]))
    add(case('vbus_reset_unlock_fails', VBUS_RESET, (0,), writes=[FAIL, OK]))
    add(case('vbus_reset_relock_fails', VBUS_RESET, (0,), reads=[rx(0x01)], writes=[OK, OK, FAIL]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    if kernel.direct_target(memory, 0x702b7b0e) != BUS_WRITE or kernel.direct_target(memory, 0x702b7830) != ALL_CONFIG:
        raise ValueError('call sites')
    if memory.read(TABLE, 13) != INIT_TABLE:
        raise ValueError('init table')
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
        bus=dict(name='sens_i2c1', address=f'{ADDRESS:#04x}', register_width=8, timeout=TIMEOUT,
                 handle_word=f'{HANDLE_WORD:#010x}'),
        registers={'0x01': 'bit 3 charge disable', '0x02': 'bits 5:0 fast-charge current (mA - 8) / 8',
                   '0x03': 'bits 3:0 pre-charge/termination current (mA - 1) / 2', '0x06': 'bit 5 power off',
                   '0x08': 'system status; bits 4:3 charge state', '0x09': 'fault', '0x0a': 'id',
                   '0x0d': 'bit 0 switch mode', '0x21': 'bit 7 VBUS reset behaviour (set when off)',
                   '0x69': 'unlock 0xc2 / lock 0x00 around 0x21'},
        fast_charge_current=dict(step_ma=8, offset_ma=8, max_code=0x3f, saturates_above_ma=519,
                                 samples={str(m): current_code(m) for m in (8, 16, 100, 260, 512)}),
        termination_current=dict(step_ma=2, offset_ma=1, max_code=0xf, saturates_above_ma=32),
        init_table={f'{r:#04x}': f'{v:#04x}' for r, v in enumerate(INIT_TABLE)},
        init_sequence=['interrupt control on', 'register table 0x00..0x0c (up to three attempts)',
                       'VBUS reset configuration (bit 7 of 0x21 set)'],
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The AW32012 register layer and controls execute in the main-image emulator; only the I2C register '
            'transfer helpers and the logger are supplied, with authored register bytes.',
            'Which charger (AW32012 or CW6305) is fitted is decided at runtime by the id test; the init table '
            'values are recorded, not interpreted without the datasheet.',
            'Interrupt handling, charge-done handling and the power-supply framework are not executed.'])


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
        parser.exit(2, f'Cannot inspect AW32012: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
