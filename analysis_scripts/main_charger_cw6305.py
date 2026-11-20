#!/usr/bin/env python3
"""Main-image CW6305 charger: I2C register layer and every register-level control.

The Bip 6 main image carries two alternative charger drivers on ``sens_i2c1``
(AW32012 and CW6305; the fitted one is selected by an id test).  This scope
executes, in ``main-runtime``, the original CW6305 bodies:

- register read ``0x702b95dc(reg, out)`` / write ``0x702b9720(reg, value)``:
  I2C address ``0x0b``, 8-bit registers, one byte, timeout 1000, handle word
  ``0x70f8e5cc`` (-10 when absent);
- power off ``0x702b9750``: clear ``0x08`` bit 7, clear ``0x08`` bit 6, set
  ``0x07`` bit 7;
- charge control ``0x702b9992(on)``: ``0x01`` bit 6, written only on change;
  hibernate enable/disable ``0x702b9a42`` / ``0x702b9aa6`` (mode 3 only);
- fast charge current ``0x702b9b0a(mA)``: 10..470 mA to the 6-bit code of
  ``0x04`` in four segments, written only on change;
- safety timer ``0x702b9c3a(v)``: ``0x06`` bits 6:5;
- interrupt source ``0x0b`` read and clear (write 0), status ``0x0d`` and
  status 2 ``0x0e`` reads, id ``0x00`` read;
- configuration ``0x702b9fbc(table)`` (registers 0x00..0x0a) and its
  three-attempt wrapper ``0x702b8c8e`` over the original table.

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
else:
    import main_freertos_kernel as kernel

BOUND = 20000
M32 = 0xffffffff
READ_REG, WRITE_REG = 0x702b95dc, 0x702b9720
POWER_OFF, CHG_CTRL, HIB_ON, HIB_OFF = 0x702b9750, 0x702b9992, 0x702b9a42, 0x702b9aa6
CURRENT, SAFETY, IRQ_GET, IRQ_CLEAR = 0x702b9b0a, 0x702b9c3a, 0x702b9cc6, 0x702b9d4e
STATUS, STATUS2, ID_GET = 0x702b9da2, 0x702b9e2a, 0x702ba0d4
CONFIG, CONFIG_RETRY = 0x702b9fbc, 0x702b8c8e
BUS_READ, BUS_WRITE, LOGGER = 0x702b5c5e, 0x702b5b9a, 0x702b38a2
HANDLE_WORD = 0x70f8e5cc
TABLE = 0x70f61db8
ADDRESS, TIMEOUT = 0x0b, 1000
HANDLE = 0x0b0b0001
OUT = 0x81004000
# Original initial configuration for registers 0x00..0x0a (checked against the image by evidence()).
INIT_TABLE = bytes.fromhex('14038fbdeb115a1d138fc3')

CODE = (
    (CONFIG_RETRY, 0x2c, '740b15366da1e60b7703174eae23ce2031e831f2d1314ed002b6a5ea4c26e268'),
    (READ_REG, 0x20, 'b7922a2a3b31a16a6373ed14c44c6e069142709b10993b0f763c56f0e89b0a62'),
    (WRITE_REG, 0x30, '955720410fe53986787f5d6e7302a4ba9b3daeb046b642c358852b7bf3986c9f'),
    (POWER_OFF, 0x154, 'd9c0eea1d857bd0a3aec350fd554e31316a25e2cbe89e7c6b760cb4f51250dea'),
    (CHG_CTRL, 0x178, '705c2739a24e4979d5276f51f6a8b357e4147f356e56baec027b64036dbeadea'),
    (CURRENT, 0x298, 'bf2c0ff753076989c70540e62e2ce3f59b90716dc5f350f72c7759f1369f2917'),
    (STATUS, 0x110, 'cbbf60efc9a62e8dab60594b51d81a81b33faa9b912861f368bd2391b21899fa'),
    (CONFIG, 0xa6, '35a86e574e659e9a14c8d287f7c262d6f1d08abbca01ddf3eb1fc96b200a5a0e'),
    (ID_GET, 0xa0, '8417bd230d1966fba66edf7c17dba72c4c2d3fbfb09da50f6b1334f077becb03'),
)
DATA = ((TABLE, 0xb, '3f8fdcbd835cebdacaf5bbb0987ee6697634c75b876011bb46d248d286f9fc28'),)
CALL_SITES = ((0x702b95f4, BUS_READ), (0x702b9742, BUS_WRITE), (0x702b8ca2, CONFIG), (0x702b9fee, WRITE_REG),
              (0x702b9a50, CHG_CTRL), (0x702b9ab4, CHG_CTRL), (0x702b9b4c, READ_REG), (0x702b9c24, WRITE_REG),
              (0x702b9d58, WRITE_REG), (0x702ba128, READ_REG))
CSRS = kernel.CSRS


def word(v):
    return v & M32


def current_code(ma):
    """Fast-charge current (mA) to the 6-bit code, or None when out of range."""
    x = (ma * 100) & 0xffff
    if ((x - 1000) & 0xffff) > 46000:
        return None
    if x <= 2000:
        code = (x - 1000) // 125
    elif x <= 4000:
        code = (x - 2000) // 250 + 8
    elif x <= 8000:
        code = (x - 4000) // 500 + 16
    else:
        code = (x - 8000) // 1000 + 24
    return code & 0xff


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.reads, self.writes = list(case['bus_read']), list(case['bus_write'])

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def handle(self):
        return self.read(HANDLE_WORD, 4)

    def read_reg(self, reg, out):
        if not self.handle():
            return word(-10)
        self.actions.append(f'bus:{BUS_READ}:{HANDLE}:{ADDRESS}:{reg}:1:1:{TIMEOUT}:')
        t = self.reads.pop(0)
        if 'rx' in t:
            self.write(out, 1, int(t['rx'], 16), record=False)   # stub write, seen in the snapshot
        return t['status']

    def write_reg(self, reg, value):
        if not self.handle():
            return word(-10)
        self.actions.append(f'bus:{BUS_WRITE}:{HANDLE}:{ADDRESS}:{reg}:1:1:{TIMEOUT}:{value & 0xff:02x}')
        return self.writes.pop(0)['status']

    def log_error(self):
        self.leaf(LOGGER, 3)

    def rmw(self, reg, update, scratch):
        self.write(scratch, 1, 0)
        status = self.read_reg(reg, scratch)
        if status:
            self.log_error()
            return status, None
        return 0, self.read(scratch, 1)

    def power_off(self):
        scratch = kernel.HARNESS_STACK - 0x30 + 0x1c
        steps = ((8, lambda v: v & 0x7f), (8, lambda v: v & ~0x40 & 0xff), (7, lambda v: v | 0x80))
        self.write(kernel.HARNESS_STACK - 0x30 + 0x18, 1, 0)
        status = 0
        for reg, update in steps:
            status, value = self.rmw(reg, update, scratch)
            if status:
                if reg == 7:
                    return status
                continue
            status = self.write_reg(reg, update(value))
            if status:
                self.log_error()
                if reg == 7:
                    return status
        return status

    def chg_ctrl(self, on):
        scratch = kernel.HARNESS_STACK - 0x30 + 0x1c
        status, value = self.rmw(1, None, scratch)
        if status:
            return status
        if (value >> 6) & 1 == on:
            return 0
        self.leaf(LOGGER, 6)
        status = self.write_reg(1, (value & ~0x40 & 0xff) | ((on & 1) << 6))
        if status:
            self.log_error()
        return status

    def hibernate(self, mode, on):
        if mode != 3:
            return 0
        status = self.chg_ctrl(1 if on else 0)
        self.leaf(LOGGER, 6 if status == 0 else 3)
        return status

    def current(self, ma):
        code = current_code(ma)
        if code is None:
            return word(-1)
        scratch = kernel.HARNESS_STACK - 0x30 + 0x1c
        status, value = self.rmw(4, None, scratch)
        if status:
            return status
        if value & 0x3f == code:
            return 0
        self.leaf(LOGGER, 6)
        status = self.write_reg(4, (value & 0xc0) | code)
        if status:
            self.log_error()
        return status

    def safety(self, v):
        scratch = kernel.HARNESS_STACK - 0x30 + 0x1c
        status, value = self.rmw(6, None, scratch)
        if status:
            return status
        status = self.write_reg(6, (value & ~0x60 & 0xff) | ((v & 3) << 5))
        if status:
            self.log_error()
        return status

    def getter(self, reg, out):
        if out == 0:
            self.log_error()
            return word(-10)
        status = self.read_reg(reg, out)
        if status:
            self.log_error()
        return status

    def clear_irq(self):
        status = self.write_reg(0xb, 0)
        if status:
            self.log_error()
        return status

    def get_id(self, out):
        if out == 0:
            self.log_error()
            return word(-10)
        scratch = kernel.HARNESS_STACK - 0x30 + 0x1f
        self.write(scratch, 1, 0xff)
        status = self.read_reg(0, scratch)
        if status:
            self.log_error()
        else:
            self.write(out, 1, self.read(scratch, 1))
        return status

    def config(self, table):
        if table == 0:
            self.log_error()
            return word(-10)
        failed = 0
        for reg in range(0xb):
            if self.write_reg(reg, self.read(table + reg, 1)):
                self.log_error()
                failed = 1
        return word(-failed)

    def config_retry(self):
        for _ in range(3):
            if self.config(TABLE) == 0:
                return
        return

    def operation(self, op):
        e, a = op['entry'], op['args']
        handlers = {
            POWER_OFF: lambda: self.power_off(), CHG_CTRL: lambda: self.chg_ctrl(a[0]),
            HIB_ON: lambda: self.hibernate(a[0], True), HIB_OFF: lambda: self.hibernate(a[0], False),
            CURRENT: lambda: self.current(a[0]), SAFETY: lambda: self.safety(a[0]),
            IRQ_GET: lambda: self.getter(0xb, a[0]), STATUS: lambda: self.getter(0xd, a[0]),
            STATUS2: lambda: self.getter(0xe, a[0]), IRQ_CLEAR: lambda: self.clear_irq(),
            ID_GET: lambda: self.get_id(a[0]), CONFIG: lambda: self.config(a[0]),
            CONFIG_RETRY: lambda: self.config_retry(), READ_REG: lambda: self.read_reg(a[0], a[1]),
            WRITE_REG: lambda: self.write_reg(a[0], a[1]),
        }
        return handlers[e]()


def contract(case):
    if case['scope'] != 'cw6305' or len(case['operations']) != 1:
        raise ValueError('cw6305 scope')
    model = Model(case)
    result = model.run()
    if model.reads or model.writes:
        raise ValueError('unused scripted inputs')
    return result


def rx(v):
    return dict(status=0, rx=f'{v:02x}')


OK = dict(status=0)
FAIL = dict(status=5)


def case(name, entry, args=(), reads=(), writes=(), handle=True, result=True):
    rec = [0, 1, 2, 3, 5, 6]
    stubs = {
        str(BUS_READ): dict(kind='bus', buf_arg=4, len_arg=5, write=False, rec=rec, seq=list(reads)),
        str(BUS_WRITE): dict(kind='bus', buf_arg=4, len_arg=5, write=True, rec=rec, seq=list(writes)),
        str(LOGGER): dict(kind='return', args=1),
    }
    return dict(
        name='main_charger_cw6305_' + name, scope='cw6305', supplied={}, quiet=[[0x81000000, 0x81002000]],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': kernel.HARNESS_STACK}, fregisters={}, stubs=stubs, stops={}, snapshot=[[OUT, 1]],
        operations=[dict(name='cw6305', entry=entry, call=True, args=list(args), registers=False,
                         result=result, result_high=False)],
        memory=[[HANDLE_WORD, struct.pack('<I', HANDLE if handle else 0).hex()], [OUT, '00'],
                [TABLE, INIT_TABLE.hex()]],
        bus_read=list(reads), bus_write=list(writes))


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('read_reg', READ_REG, (0x0d, OUT), reads=[rx(0x42)]))
    add(case('write_reg', WRITE_REG, (0x05, 0xa5), writes=[OK]))
    add(case('no_handle', READ_REG, (0x0d, OUT), handle=False))
    add(case('power_off', POWER_OFF, reads=[rx(0xff), rx(0xff), rx(0x00)], writes=[OK, OK, OK]))
    add(case('power_off_first_read_fails', POWER_OFF, reads=[FAIL, rx(0xc0), rx(0x01)], writes=[OK, OK]))
    for on, old in ((1, 0x00), (0, 0xff), (1, 0x40), (0, 0x00)):
        add(case(f'chg_ctrl_{on}_from_{old:02x}', CHG_CTRL, (on,), reads=[rx(old)],
                 writes=[OK] if ((old >> 6) & 1) != on else []))
    add(case('chg_ctrl_write_fails', CHG_CTRL, (1,), reads=[rx(0)], writes=[FAIL]))
    add(case('hibernate_enable_mode3', HIB_ON, (3,), reads=[rx(0)], writes=[OK]))
    add(case('hibernate_disable_mode3', HIB_OFF, (3,), reads=[rx(0x40)], writes=[OK]))
    add(case('hibernate_other_mode', HIB_ON, (2,)))
    for ma in (10, 15, 20, 30, 40, 60, 80, 100, 250, 470):
        add(case(f'current_{ma}ma', CURRENT, (ma,), reads=[rx(0xd5)], writes=[OK] if current_code(ma) != 0x15 else []))
    add(case('current_unchanged_skips_write', CURRENT, (100,), reads=[rx(0xc0 | current_code(100))]))
    add(case('current_below_range', CURRENT, (9,)))
    add(case('current_above_range', CURRENT, (471,)))
    add(case('safety_timer_2', SAFETY, (2,), reads=[rx(0xff)], writes=[OK]))
    add(case('safety_timer_read_fails', SAFETY, (1,), reads=[FAIL]))
    add(case('irq_source', IRQ_GET, (OUT,), reads=[rx(0x81)]))
    add(case('irq_source_null', IRQ_GET, (0,)))
    add(case('irq_clear', IRQ_CLEAR, writes=[OK]))
    add(case('status', STATUS, (OUT,), reads=[rx(0x24)]))
    add(case('status2', STATUS2, (OUT,), reads=[rx(0x09)]))
    add(case('id', ID_GET, (OUT,), reads=[rx(0x31)]))
    add(case('id_read_fails', ID_GET, (OUT,), reads=[FAIL]))
    add(case('config_original_table', CONFIG, (TABLE,), writes=[OK] * 11))
    add(case('config_null_table', CONFIG, (0,)))
    add(case('config_retry_second_attempt', CONFIG_RETRY, writes=[OK] * 5 + [FAIL] + [OK] * 5 + [OK] * 11,
             result=False))
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
    if memory.read(TABLE, 11) != INIT_TABLE:
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
        registers={'0x00': 'id', '0x01': 'bit 6 charge enable', '0x04': 'bits 5:0 fast-charge current code',
                   '0x06': 'bits 6:5 safety timer', '0x07': 'bit 7 power off',
                   '0x08': 'bit 7 charge watchdog, bit 6 discharge watchdog (cleared at power off)',
                   '0x0b': 'interrupt source (cleared by writing 0)', '0x0d': 'status', '0x0e': 'status 2'},
        fast_charge_current=dict(range_ma=[10, 470], segments=[
            dict(ma='10-20', step_ma=1.25, codes='0-8'), dict(ma='20-40', step_ma=2.5, codes='8-16'),
            dict(ma='40-80', step_ma=5, codes='16-24'), dict(ma='80-470', step_ma=10, codes='24-63')],
            samples={str(ma): current_code(ma) for ma in (10, 20, 40, 80, 100, 250, 470)}),
        init_table={f'{r:#04x}': f'{v:#04x}' for r, v in enumerate(INIT_TABLE)}, init_attempts=3,
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The CW6305 register layer and controls execute in the main-image emulator; only the I2C register '
            'transfer helpers and the logger are supplied, with authored register bytes.',
            'Register meanings are those used by this driver; voltages/limits encoded by the init table are '
            'not decoded without the datasheet. Which of the two charger drivers is fitted (AW32012 or '
            'CW6305) is decided at runtime by the id test and is not established here.',
            'Interrupt handling, JEITA control, the periodic charge work and the power-supply framework '
            'integration are not executed.'])


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
        parser.exit(2, f'Cannot inspect CW6305: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
