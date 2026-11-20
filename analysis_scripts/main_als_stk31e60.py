#!/usr/bin/env python3
"""Main-image STK31E60 ambient-light sensor: register layer, init, gain, timing and ALS read.

The ALS (``dev_stk31e60``, ``i2c3``, rail ``TP_1V8``) is driven at I2C address
``0x48`` with 8-bit registers.  This scope executes, in ``main-runtime``, the
original:

- register read ``0x701e9e4a`` / write ``0x701e9f9c`` (three attempts, 2 ms
  apart, logged after the last failure);
- integration time ``0x701ea028(ms)``: code ``trunc(ms * 1000 / 99 - 1)``
  written to ``0x6e`` (high) and ``0x6f`` (low);
- rail switch ``0x701ea0e8(on)`` (40 ms after enabling), chip id
  ``0x701ea148`` (``0x3e`` must read ``0xe0``) and the vendor register
  normalisation ``0x701ea190`` (``0xe3/0xe5/0xea/0xec`` forced to ``0x80``);
- gain ratio ``0x701ea3b0(code)`` over the 16-entry code/factor table at
  ``0x709d24e4`` and the gain apply ``0x701ea414``;
- init ``0x701ea444``: rail on, normalisation, ``0x07=3``, ``0x08=0xe7``,
  ``0x3d=0``, ``0x6a &= ~0x10``, ``0x6b=1``, ``0x17=0xb0``, 16.6 ms
  integration, gain ratio, initialised flag;
- data-ready wait ``0x701ea60c`` (``0x10`` bit 7, three reads 200 ms apart) and
  the ALS read ``0x701ea670`` (wait out the integration period, then
  ``0x13 << 8 | 0x14``, falling back to the cached value on a read error).

Supplied: bus transfers, regulator enable/disable, delays, tick/time
conversion, the register-dump debug helper and the logger.  Two
``fcvt.wu.s`` sites are repaired in the runner (Ghidra SLEIGH drops ``rd``),
and the ``c.fsw`` of the gain ratio is recorded as the emulator's 8-byte store.
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
READ, WRITE = 0x701e9e4a, 0x701e9f9c
INTEG_MS, POWER, CHIP_ID, NORMALISE = 0x701ea028, 0x701ea0e8, 0x701ea148, 0x701ea190
GAIN_SET, GAIN_APPLY, INIT, WAIT_READY, READ_ALS = 0x701ea3b0, 0x701ea414, 0x701ea444, 0x701ea60c, 0x701ea670
BUS_READ, BUS_WRITE, LOGGER = 0x702b5c5e, 0x702b5b9a, 0x702b38a2
REG_ENABLE, REG_DISABLE = 0x702b66c8, 0x702b679c
DELAY, DELAY2, TICK, TICKS_MS = 0x80d369ee, 0x701648f8, 0x80d362d6, 0x80d379e0
DUMP = 0x701e9ed6
FIX_INTEG, FIX_READ = 0x701ea072, 0x701ea716
CTX = 0x70f92ca0
GAIN = 0x70f8e0f4
CACHE = 0x70f8e0f0              # last ALS value (.bss)
ADDRESS, TIMEOUT = 0x48, 10
HANDLE, REG_HANDLE = 0x48480001, 0x0f0f0002
OUT = 0x81004000
VENDOR_REGS = (0xe3, 0xe5, 0xea, 0xec)
# The original gain table at 0x709d24e4: (code, factor); checked against the image by evidence().
GAIN_TABLE = ((0xf0, 4096.0), (0xe0, 2048.0), (0xd0, 1024.0), (0xc0, 512.0), (0xb0, 256.0), (0xa0, 64.0),
              (0x90, 16.0), (0x80, 4.0), (0x70, 2.0), (0x60, 1.0), (0x50, 0.5), (0x40, 0.25), (0x30, 0.125),
              (0x20, 0.0625), (0x10, 0.015625), (0x00, 0.003906))
GAIN_DEFAULT = 256.0
MODE_PERIODS = (16.6, 332.0, 2.0)     # 0x709d24c0, ms per mode
INIT_INTEG_MS = 16.6
EMULATED_FSW_BYTES = 8

CODE = (
    (READ, 0x8c, '1705744cbbd647fea31e1da9de0d2b3978cc6979b3c7f4aeb1e106549dfecfff'),
    (WRITE, 0x8c, 'ae6d1092b327a5e595fb0b317c533239361312a87f37423ddde2e6b13a4d9246'),
    (INTEG_MS, 0x1c0, '7e958292520fd17e2971d2131006968d5584f85e82b47f001ee7180faf184cc6'),
    (GAIN_SET, 0x418, '0a03b65d62608d2ca3b02e47c589c8c4be716c017d59c4c1189a2f00dcfb0fcc'),
)
DATA = (
    (0x709d24e4, 0x80, 'd0ce1dd1762203b7f37a8807d0c0fcceca42dcb82edb8fcd8e959df86755d761'),
    (0x709d20c8, 0x4, '9a104751a442e2dc132d887b7be7abf142fab85e6980dcda0b5ea3c1275d2f35'),
    (0x709c0638, 0x10, '024adb353032585dfbff2401ac15fdfb883d8d713b48b3101cb130632980ad6c'),
    (0x709d232c, 0x4, 'dcefb4750f6c994fe8132803f6d5b8d34b9d418afb5df50bdd55fb2a092e2b73'),
    (0x709d24c0, 0xc, '0c9f240cf9d09add39ccbf372ed781dd2ccac623eddddb4fd05da92af0c9c7c7'),
    (0x709cd6d0, 0x4, '07883481b5c147464597d44401db095d88c2a6b049fbbcd7b278de98a5ceeb71'),
    (0x709d2248, 0x4, 'c65c6602640bff581e75467aa3d034c2cb7487f01511ad9eb50ea0b8d087ac15'),
)
CSRS = kernel.CSRS
STACK = kernel.HARNESS_STACK


def word(v):
    return v & M32


def f32(v):
    return struct.unpack('<f', struct.pack('<f', v))[0]


def bits32(v):
    return struct.unpack('<I', struct.pack('<f', v))[0]


def trunc_u32(v):
    return 0 if v <= -1.0 else min(int(v), M32)


def integ_code(ms):
    return trunc_u32(f32(f32(f32(f32(ms) * f32(1000.0)) / f32(99.0)) - f32(1.0))) & 0xffff


def factor(code):
    for c, f in GAIN_TABLE:
        if c == code:
            return f32(f)
    return f32(GAIN_DEFAULT)


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.reads, self.writes = list(case['bus_read']), list(case['bus_write'])
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def bus(self, kind, reg, value=None, out=None):
        tx = '' if value is None else f'{value & 0xff:02x}'
        self.actions.append(f'bus:{kind}:{HANDLE}:{ADDRESS}:{reg}:1:1:{TIMEOUT}:{tx}')
        t = (self.reads if kind == BUS_READ else self.writes).pop(0)
        if 'rx' in t and out is not None:
            self.write(out, 1, int(t['rx'], 16), record=False)
        return t['status']

    def xfer(self, kind, reg, value=None, out=None):
        for attempt in range(3):
            status = self.bus(kind, reg, value, out)
            if status == 0:
                return 0
            self.leaf(DELAY, 2)
        self.leaf(LOGGER, 3)
        return status

    def rd(self, reg, out):
        return self.xfer(BUS_READ, reg, out=out)

    def wr(self, reg, value):
        return self.xfer(BUS_WRITE, reg, value=value)

    def integ(self, ms):
        code = integ_code(ms)
        self.actions.append(f'fix:{FIX_INTEG}:{code}')
        self.leaf(LOGGER, 6)
        if self.wr(0x6e, code >> 8) or self.wr(0x6f, code & 0xff):
            self.leaf(LOGGER, 3)
            return word(-1)
        return 0

    def power(self, on):
        handle = self.read(CTX + 4, 4)
        if not handle:
            return 0
        if on:
            self.leaf(REG_ENABLE, handle)
            status = self.svc['reg']
            self.leaf(DELAY, 40)
        else:
            self.leaf(REG_DISABLE, handle)
            status = self.svc['reg']
        if status:
            self.leaf(LOGGER, 3)
        return status

    def chip_id(self, out):
        status = self.rd(0x3e, out)
        if status:
            return status
        if self.read(out, 1) != 0xe0:
            self.leaf(LOGGER, 3)
            return word(-1)
        return 0

    def normalise(self):
        scratch = STACK - 0x20 + 0xb
        status = 0
        for reg in VENDOR_REGS:
            self.write(scratch, 1, 0)
            status = self.rd(reg, scratch)
            if self.read(scratch, 1) != 0x80:
                status = self.wr(reg, 0x80)
                if status:
                    return status
        return status

    def gain_set(self, code):
        ratio = f32(factor(0xb0) / factor(code))
        self.write(GAIN + 4, EMULATED_FSW_BYTES, bits32(ratio))

    def gain_apply(self):
        self.write(GAIN, 2, 0xb0b0)
        self.wr(0x17, 0xb0)
        self.gain_set(0xb0)

    def init(self):
        status = self.power(1)
        if status:
            self.leaf(LOGGER, 3)
            return status
        if self.normalise():
            self.leaf(LOGGER, 3)
        self.leaf(LOGGER, 6)
        for reg, value, double in ((0x07, 3, True), (0x08, 0xe7, True), (0x3d, 0, False)):
            status = self.wr(reg, value)
            if status:
                return self.init_fail(status, double)
        scratch = STACK - 0x40 + 0x2f
        self.write(scratch, 1, 0)
        status = self.rd(0x6a, scratch)
        if status:
            return self.init_fail(status, False)
        status = self.wr(0x6a, self.read(scratch, 1) & 0xef)
        if status:
            return self.init_fail(status, True)
        for reg, value in ((0x6b, 1), (0x17, 0xb0)):
            status = self.wr(reg, value)
            if status:
                return self.init_fail(status, False)
        status = self.integ(INIT_INTEG_MS)
        if status:
            return self.init_fail(status, False)
        self.write(GAIN, 2, 0xb0b0)
        self.gain_set(0xb0)
        self.leaf(LOGGER, 6)
        self.write(CTX + 0x69, 1, 1)
        return 0

    def init_fail(self, status, double):
        if double:
            status = word(-1)
            self.leaf(LOGGER, 3)
        self.leaf(LOGGER, 3)
        return status

    def wait_ready(self):
        scratch = STACK - 0x20 + 0xf
        self.write(scratch, 1, 0)
        for _ in range(3):
            if self.rd(0x10, scratch) == 0 and self.read(scratch, 1) & 0x80:
                return 0
            self.leaf(DELAY2, 200)
        self.leaf(LOGGER, 3)
        self.leaf(DUMP, 0)
        return word(-2)

    def read_als(self, out):
        if out == 0:
            self.leaf(LOGGER, 3)
            return word(-10)
        self.leaf(TICK)
        self.leaf(TICKS_MS, (self.svc['tick'] - self.read(CTX + 0xc, 4)) & M32)
        elapsed = self.svc['elapsed']
        mode = self.read(CTX + 0x68, 1)
        if mode > 2:
            self.leaf(LOGGER, 3)
            base = f32(16.6)
        else:
            base = f32(MODE_PERIODS[mode])
        fe = f32(float(elapsed))
        if fe < f32(base + f32(1.0)):
            wait = trunc_u32(f32(f32(f32(base - fe) + f32(2.0)) + f32(1.0)))
            self.actions.append(f'fix:{FIX_READ}:{wait}')
            self.leaf(DELAY, wait)
        status = self.wait_ready()
        if status:
            return status
        hi, lo = STACK - 0x20 + 0xe, STACK - 0x20 + 0xf
        self.write(hi, 1, 0)
        self.write(lo, 1, 0)
        if self.rd(0x13, hi) == 0 and self.rd(0x14, lo) == 0:
            self.write(out, 2, self.read(hi, 1) << 8 | self.read(lo, 1))
        else:
            self.write(out, 2, self.read(CACHE, 2))
            self.leaf(LOGGER, 3)
            self.leaf(DUMP, 0)
        self.write(CACHE, 2, self.read(out, 2))
        self.leaf(TICK)
        self.leaf(DUMP, 1)
        return 0

    def operation(self, op):
        e, a = op['entry'], op['args']
        return {
            READ: lambda: self.rd(a[0], a[1]), WRITE: lambda: self.wr(a[0], a[1]),
            POWER: lambda: self.power(a[0]), CHIP_ID: lambda: self.chip_id(a[0]),
            NORMALISE: lambda: self.normalise(), GAIN_SET: lambda: self.gain_set(a[0]),
            GAIN_APPLY: lambda: self.gain_apply(), INIT: lambda: self.init(),
            WAIT_READY: lambda: self.wait_ready(), READ_ALS: lambda: self.read_als(a[0]),
            INTEG_MS: lambda: self.integ(struct.unpack('<f', struct.pack('<I', a[0]))[0]),
        }[e]()


def contract(case):
    if case['scope'] != 'stk31e60' or len(case['operations']) != 1:
        raise ValueError('stk31e60 scope')
    model = Model(case)
    result = model.run()
    if model.reads or model.writes:
        raise ValueError('unused scripted inputs')
    return result


def rx(v):
    return dict(status=0, rx=f'{v:02x}')


OK, FAIL = dict(status=0), dict(status=5)


def case(name, entry, args=(), reads=(), writes=(), result=True, fa0=None, reg_handle=True, mode=0, **svc):
    s = dict(reg=0, tick=1000, elapsed=50)
    s.update(svc)
    rec = [0, 1, 2, 3, 5, 6]
    stubs = {
        str(BUS_READ): dict(kind='bus', buf_arg=4, len_arg=5, write=False, rec=rec, seq=list(reads)),
        str(BUS_WRITE): dict(kind='bus', buf_arg=4, len_arg=5, write=True, rec=rec, seq=list(writes)),
        str(LOGGER): dict(kind='return', args=1), str(DELAY): dict(kind='return', args=1),
        str(DELAY2): dict(kind='return', args=1), str(DUMP): dict(kind='return', args=1),
        str(REG_ENABLE): dict(kind='return', args=1, value=s['reg']),
        str(REG_DISABLE): dict(kind='return', args=1, value=s['reg']),
        str(TICK): dict(kind='return', args=0, value=s['tick']),
        str(TICKS_MS): dict(kind='return', args=1, value=s['elapsed']),
        str(FIX_INTEG): dict(kind='fcvt_wu_s', rd='s0', fs='fa5'),
        str(FIX_READ): dict(kind='fcvt_wu_s', rd='a0', fs='fa5'),
    }
    ctx = bytearray(0x70)
    struct.pack_into('<III', ctx, 0, HANDLE, REG_HANDLE if reg_handle else 0, 0)
    struct.pack_into('<I', ctx, 0xc, 400)
    ctx[0x68] = mode
    fregs = {} if fa0 is None else {'fa0': f'{fa0:016x}'}
    return dict(
        name='main_als_stk31e60_' + name, scope='stk31e60', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters=fregs, stubs=stubs, stops={},
        snapshot=[[OUT, 2]],
        operations=[dict(name='stk', entry=entry, call=True, args=list(args), registers=False, result=result,
                         result_high=False)],
        memory=[[CTX, bytes(ctx).hex()], [OUT, '0000'], [GAIN, '00' * 12], [CACHE, '3412']],
        bus_read=list(reads), bus_write=list(writes), services=s)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('read_ok', READ, (0x10, OUT), reads=[rx(0x80)]))
    add(case('read_retries_then_ok', READ, (0x10, OUT), reads=[FAIL, FAIL, rx(0x81)]))
    add(case('read_three_failures', READ, (0x10, OUT), reads=[FAIL, FAIL, FAIL]))
    add(case('write_ok', WRITE, (0x17, 0xb0), writes=[OK]))
    add(case('power_on', POWER, (1,)))
    add(case('power_off_fails', POWER, (0,), reg=3))
    add(case('power_without_rail', POWER, (1,), reg_handle=False))
    add(case('chip_id_ok', CHIP_ID, (OUT,), reads=[rx(0xe0)]))
    add(case('chip_id_wrong', CHIP_ID, (OUT,), reads=[rx(0x31)]))
    add(case('normalise', NORMALISE, reads=[rx(0x80), rx(0x00), rx(0x80), rx(0x7f)], writes=[OK, OK]))
    for ms in (16.6, 100.0, 1.0):
        bits = struct.unpack('<I', struct.pack('<f', ms))[0]
        add(case(f'integration_{str(ms).replace(".", "_")}ms', INTEG_MS, (bits,), writes=[OK, OK], fa0=bits))
    add(case('integration_low_write_fails', INTEG_MS, (struct.unpack('<I', struct.pack('<f', 16.6))[0],),
             writes=[OK, FAIL, FAIL, FAIL], fa0=struct.unpack('<I', struct.pack('<f', 16.6))[0]))
    add(case('gain_set_b0', GAIN_SET, (0xb0,), result=False))
    add(case('gain_set_f0', GAIN_SET, (0xf0,), result=False))
    add(case('gain_set_unknown', GAIN_SET, (0x3b,), result=False))
    add(case('gain_apply', GAIN_APPLY, writes=[OK], result=False))
    init_writes = [OK] * 9
    add(case('init', INIT, reads=[rx(0x80), rx(0), rx(0x80), rx(0x80), rx(0xff)], writes=init_writes))
    add(case('init_power_fails', INIT, reg=4))
    add(case('init_0x07_fails', INIT, reads=[rx(0x80)] * 4, writes=[FAIL] * 3))
    add(case('init_0x3d_fails', INIT, reads=[rx(0x80)] * 4, writes=[OK, OK] + [FAIL] * 3))
    add(case('wait_ready_ok', WAIT_READY, reads=[rx(0x00), rx(0x80)]))
    add(case('wait_ready_timeout', WAIT_READY, reads=[rx(0x00), FAIL, FAIL, FAIL, rx(0x01)]))
    add(case('read_als', READ_ALS, (OUT,), reads=[rx(0x80), rx(0x12), rx(0x34)]))
    add(case('read_als_waits_integration', READ_ALS, (OUT,), reads=[rx(0x80), rx(0x01), rx(0x02)], elapsed=5))
    add(case('read_als_mode_1', READ_ALS, (OUT,), reads=[rx(0x80), rx(0x01), rx(0x02)], mode=1, elapsed=100))
    add(case('read_als_bad_mode', READ_ALS, (OUT,), reads=[rx(0x80), rx(0x01), rx(0x02)], mode=7, elapsed=0))
    add(case('read_als_data_error_uses_cache', READ_ALS, (OUT,), reads=[rx(0x80), FAIL, FAIL, FAIL]))
    add(case('read_als_not_ready', READ_ALS, (OUT,), reads=[rx(0), rx(0), rx(0)]))
    add(case('read_als_null', READ_ALS, (0,)))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    raw = memory.read(0x709d24e4, 0x80)
    table = tuple((raw[i], struct.unpack_from('<f', raw, i + 4)[0]) for i in range(0, 0x80, 8))
    if [c for c, _ in table] != [c for c, _ in GAIN_TABLE] or \
            any(f32(f) != f32(g) for (_, f), (_, g) in zip(table, GAIN_TABLE)):
        raise ValueError('gain table')
    if struct.unpack('<3f', memory.read(0x709d24c0, 12)) != tuple(f32(v) for v in MODE_PERIODS):
        raise ValueError('mode periods')
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
        bus=dict(name='i2c3', address=f'{ADDRESS:#04x}', register_width=8, timeout=TIMEOUT, attempts=3,
                 retry_delay_ms=2),
        registers={'0x07': 'init 0x03', '0x08': 'init 0xe7', '0x10': 'bit 7 data ready', '0x13/0x14': 'ALS data '
                   '(high, low)', '0x17': 'gain code (0xb0)', '0x3d': 'init 0x00', '0x3e': 'chip id 0xe0',
                   '0x6a': 'bit 4 cleared at init', '0x6b': 'init 0x01', '0x6e/0x6f': 'integration code',
                   '0xe3/0xe5/0xea/0xec': 'vendor registers forced to 0x80'},
        integration=dict(formula='trunc(ms * 1000 / 99 - 1)', init_ms=INIT_INTEG_MS,
                         samples={str(ms): integ_code(ms) for ms in (1.0, 16.6, 100.0)}),
        gain_table=[dict(code=f'{c:#04x}', factor=f) for c, f in GAIN_TABLE], gain_reference='0xb0 (256)',
        mode_periods_ms=list(MODE_PERIODS),
        read_timing='wait (period - elapsed + 3) ms when elapsed < period + 1, then poll 0x10 bit 7 (3 x 200 ms)',
        emulator_artifacts=dict(fcvt_wu_s_repaired=[f'{FIX_INTEG:#010x}', f'{FIX_READ:#010x}'],
                                c_fsw_store_bytes=EMULATED_FSW_BYTES),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Register layer, init, integration, gain, data-ready wait and ALS read execute in the main-image '
            'emulator; bus transfers, regulator, delays, tick/time conversion, the dump helper and the logger '
            'are supplied.',
            'Two fcvt.wu.s sites are repaired with RISC-V semantics and the gain-ratio c.fsw is the emulator 8-byte '
            'store (see NATIVE_REPAIR.md).',
            'Lux conversion, auto-gain and the input/UI consumer are not executed; the vendor register meanings '
            'are recorded, not interpreted.'])


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
        parser.exit(2, f'Cannot inspect STK31E60: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
