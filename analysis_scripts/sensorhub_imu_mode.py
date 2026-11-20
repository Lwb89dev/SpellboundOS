#!/usr/bin/env python3
"""Sensor-hub LSM6DSO enable/disable: the configuration the hub actually applies.

``0x80f70da2(enable, gyro)`` switches the accelerometer and gyroscope on or
off.  This scope executes it in the ``sensor-runtime`` project together with
its original callees, all of them real:

- ``0x80f70aca(power_mode)``: software reset, embedded-function program
  selection (byte ``0x80f16b1e``; values above 7 are logged and cleared, 5/6
  select one of two 380-pair register programs), then ``i3c_disable_set(0)``,
  ``xl_power_mode_set(power_mode)``, ``block_data_update_set(1)`` and
  ``xl_full_scale_set(byte 0x80f16b2d)``;
- ``0x80f70b9a(enable, gyro, rate_hz)``: maps 26/52/104/208/417/833 Hz to
  ODR/batch code 2..7 (anything else -> 2), writes the FIFO batch and ODR
  fields of the accelerometer (and gyroscope) and stores the rate in the
  sensor descriptors (``+0x1a``);
- ``0x80f70192(odr)``: posts event ``{0x103, (u32)(odr * 100)}``;
- ``0x80f70a52(buffer)``: one-shot dump of registers 0x00..0x7f;
- every register accessor (see :mod:`sensorhub_imu_regs`) and the SPI
  callbacks of :mod:`sensorhub_imu_probe`.

Only the SPI transfer helper, memcpy, the delay, the logger and the event post
``0x80f63f6c`` are supplied.  The embedded-function programs are not executed
(the default selector is invalid and cleared); they are described by hash.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import sensorhub_imu_probe as probe
    from . import sensorhub_imu_regs as regs
    from .sensorhub_memory import StartupMemory, MEMBER
else:
    import main_freertos_kernel as kernel
    import sensorhub_imu_probe as probe
    import sensorhub_imu_regs as regs
    from sensorhub_memory import StartupMemory, MEMBER

BOUND = 20000

MODE_SET = 0x80f70da2
POWER_CFG = 0x80f70aca
RATE_SET = 0x80f70b9a
POST_ODR = 0x80f70192
DUMP = 0x80f70a52
EVENT_POST = 0x80f63f6c        # supplied
FCVT_SITE = 0x80f701a8         # fcvt.wu.s a5,fa0,rtz: repaired in the runner (SLEIGH drops rd)
LOGGER = probe.LOGGER

# accessor entries used by the mode code
XL_FS, XL_ODR, GY_FS, GY_ODR = 0x80f7291a, 0x80f72958, 0x80f72994, 0x80f729d2
BDU, XL_PM, GY_PM = 0x80f72a0e, 0x80f72a4e, 0x80f72abe
GY_LPF1, GY_LP1_BW, I3C = 0x80f72c7e, 0x80f72cbc, 0x80f72cf8
XL_BATCH, GY_BATCH, FIFO_MODE = 0x80f72d6a, 0x80f72da6, 0x80f72de2

# globals (.data/.bss) and their original initial values
ACCEL_POWER = 0x80f16b1c       # accelerometer-only power selector: 0 ULP, 2 HP + trimmed ODR, else low/normal; 1 in the image
PROGRAM_SEL = 0x80f16b1e       # 8 in the image: invalid, logged and cleared
DUMP_PENDING = 0x80f16b20      # 1 in the image: dump once
STATE = 0x80f16b21             # written 2 by a gyro enable, 1 by an accelerometer-only enable; 1 in the image
GY_FS_VALUE = 0x80f16b2c       # 6 in the image (2000 dps)
XL_FS_VALUE = 0x80f16b2d       # 3 in the image (+-8 g)
RATE = 0x80f16b2e              # u16, 26 in the image
ACTIVE = 0x80f17026            # set to 1 after an enable
ODR_FLOAT = 0x80f17028         # trimmed ODR written by attach
DUMP_BUFFER = 0x80f4fe80
ACC_RATE, GYR_RATE = 0x80f15538 + 0x1a, 0x80f15508 + 0x1a
PROGRAM_A, PROGRAM_B = 0x80fd8a88, 0x80fd8790   # selector 5 / 6, 380 (reg, value) pairs each

ORIGINAL = dict(accel_power=1, program=8, dump=1, state=1, gy_fs=6, xl_fs=3, rate=26)
RATE_CODES = {208: 5, 104: 4, 52: 3, 417: 6, 833: 7}
EVENT_ODR = 0x103
GY_LP1_BANDWIDTH, FIFO_CONTINUOUS = 7, 6
LOG_ERROR, LOG_WARN, LOG_INFO = 3, 4, 6

CODE = regs.CODE + (
    (DUMP, 0x350, 'c282f1ae9c6f30abda620b485674b31b2430feaa075b31c59dc91f075c91dfde'),
    (MODE_SET, 0x186, 'ddb803348c2318b22b4401e3fded5e20d44ede933d986476f3471d91bc24b07d'),
    (POST_ODR, 0x28, '294ed922c87d51a522caf0e3f3aea9433bd3d58231c917752704c797aa880fd6'),
)
DATA = regs.DATA + (
    (0x80fd52c8, 4, '2238f30df488055daf5e8f362cf904e370011a172d20df193c1b7ae8e5db8e01'),   # 100.0f
)
PROGRAMS = (
    (PROGRAM_A, 0x2f8, '81383a559a541f483b1e8affb334bfe48147b202997320023dbe4070a269d8a4'),
    (PROGRAM_B, 0x2f8, '0f902bf702bc576ed0a39f6de55289f5ed5f0e25d4b936795df67fb7df46e7a1'),
)
CALL_SITES = (
    (0x80f70df4, POWER_CFG), (0x80f70e02, GY_LP1_BW), (0x80f70e10, GY_LPF1), (0x80f70e1e, GY_PM),
    (0x80f70e32, GY_FS), (0x80f70e44, RATE_SET), (0x80f70e52, FIFO_MODE), (0x80f70e5e, POST_ODR),
    (0x80f70e82, DUMP), (0x80f70eb0, POWER_CFG), (0x80f70ec2, RATE_SET), (0x80f70ed0, FIFO_MODE),
    (0x80f70ed6, POST_ODR), (0x80f70f14, XL_ODR), (0x80f70f22, GY_ODR),
    (0x80f70ae0, probe.RESET), (0x80f70b3e, probe.CTX_WRITE), (0x80f70b50, I3C), (0x80f70b5e, XL_PM),
    (0x80f70b6c, BDU), (0x80f70b8c, XL_FS), (0x80f701b0, EVENT_POST), (0x80f70a96, probe.CTX_READ),
)
CSRS = kernel.CSRS


def digest(data):
    return hashlib.sha256(data).hexdigest()


def f32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


class Model(probe.Model):
    def u8(self, address):
        return self.read(address, 1)

    def setter(self, entry, val):
        status = 0
        for reg, update in regs.SETTERS[entry][1]:
            status, data = self.read_reg(reg)
            if status:
                return 1
            status = self.write_reg(reg, update(data[0], val))
            if status:
                return status
        return status

    def power_cfg(self, mode):
        self.reset()
        if self.u8(PROGRAM_SEL) > 7:
            self.write(PROGRAM_SEL, 1, 0)
            self.leaf(LOGGER, LOG_WARN)
        if self.u8(PROGRAM_SEL) in (5, 6):
            raise ValueError('embedded-function programs are not executed in these vectors')
        self.setter(I3C, 0)
        self.setter(XL_PM, mode)
        self.setter(BDU, 1)
        self.setter(XL_FS, self.u8(XL_FS_VALUE))

    def rate_set(self, enable, gyro, rate):
        if not enable:
            return
        code = RATE_CODES.get(rate, 2)
        self.setter(XL_BATCH, code)
        self.setter(XL_ODR, code)
        if gyro:
            self.setter(GY_BATCH, code)
            self.setter(GY_ODR, code)
            self.write(GYR_RATE, 2, rate)
        self.write(ACC_RATE, 2, rate)

    def post_odr(self, odr):
        product = f32(f32(odr) * f32(100.0))              # fmul.s
        value = 0 if product <= -1.0 else min(int(product), 0xffffffff)   # fcvt.wu.s rtz (repaired)
        self.actions.append(f'fix:{FCVT_SITE}:{value}')
        self.leaf(EVENT_POST)
        self.actions.append('cap:' + struct.pack('<II', EVENT_ODR, value & 0xffffffff).hex())

    def dump(self):
        for reg in range(0x80):
            status, data = self.read_reg(reg)
            if status:
                self.leaf(LOGGER, LOG_ERROR)
                self.write(DUMP_BUFFER + reg, 1, 0xff)
            else:
                self.write(DUMP_BUFFER + reg, 1, data[0], record=False)

    def odr(self):
        return struct.unpack('<f', bytes(self.read(ODR_FLOAT + i, 1) for i in range(4)))[0]

    def mode_set(self, enable, gyro):
        self.leaf(LOGGER, LOG_INFO)
        if not enable:
            if gyro:
                self.leaf(LOGGER, LOG_ERROR)
            else:
                self.setter(XL_ODR, 0)
                self.setter(GY_ODR, 0)
        elif gyro:
            self.power_cfg(0)
            self.setter(GY_LP1_BW, GY_LP1_BANDWIDTH)
            self.setter(GY_LPF1, 1)
            self.setter(GY_PM, 0)
            self.setter(GY_FS, self.u8(GY_FS_VALUE))
            self.write(STATE, 1, 2)
            self.rate_set(enable, gyro, self.read(RATE, 2))
            self.setter(FIFO_MODE, FIFO_CONTINUOUS)
            self.post_odr(self.odr())
            self.write(ACTIVE, 1, 1)
        else:
            selector = self.u8(ACCEL_POWER)
            if selector == 2:
                mode, odr = 0, self.odr()
            else:
                mode, odr = (2 if selector == 0 else 1), 0.0
            self.power_cfg(mode)
            self.write(STATE, 1, 1)
            self.rate_set(enable, 0, self.read(RATE, 2))
            self.setter(FIFO_MODE, FIFO_CONTINUOUS)
            self.post_odr(odr)
            self.write(ACTIVE, 1, 1)
        if self.u8(DUMP_PENDING):
            self.write(DUMP_PENDING, 1, 0)
            self.dump()
        return 0

    def operation(self, op):
        if op['name'] != 'mode':
            raise ValueError('operation')
        return self.mode_set(*op['args'])


def contract(case):
    if case['scope'] != 'mode' or len(case['operations']) != 1:
        raise ValueError('mode scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi transactions')
    return result


def memory(g):
    return [
        [ACCEL_POWER, f"{g['accel_power']:02x}"], [PROGRAM_SEL, f"{g['program']:02x}"], [DUMP_PENDING, f"{g['dump']:02x}{g['state']:02x}"],
        [GY_FS_VALUE, f"{g['gy_fs']:02x}{g['xl_fs']:02x}" + struct.pack('<H', g['rate']).hex()],
        [ACTIVE, '00'], [ODR_FLOAT, struct.pack('<f', g['odr']).hex()],
        [ACC_RATE, '0000'], [GYR_RATE, '0000'],
        [probe.SPI_HANDLE_PTR, struct.pack('<I', probe.SPI_HANDLE).hex()],
    ]


def script(enable, gyro, g, dump_fail=()):
    """SPI responses: every read returns 0x00 except the reset poll's clear bit; writes succeed."""
    ok, w = probe.read_rx(0), probe.write_ok()
    out = []
    setter = lambda entry: out.extend([ok, w] * len(regs.SETTERS[entry][1]))
    if not enable:
        if not gyro:
            setter(XL_ODR), setter(GY_ODR)
    else:
        out.extend(probe.reset_ok())
        for entry in (I3C, XL_PM, BDU, XL_FS):
            setter(entry)
        if gyro:
            for entry in (GY_LP1_BW, GY_LPF1, GY_PM, GY_FS):
                setter(entry)
        for entry in (XL_BATCH, XL_ODR) + ((GY_BATCH, GY_ODR) if gyro else ()):
            setter(entry)
        setter(FIFO_MODE)
    if g['dump']:
        out.extend(probe.fail(2) if reg in dump_fail else probe.read_rx(reg ^ 0x5a) for reg in range(0x80))
    return out


def case(name, enable, gyro, dump_fail=(), **over):
    g = dict(ORIGINAL, odr=26.04296875, dump=0)
    g.update(over)
    spi = script(enable, gyro, g, dump_fail)
    return dict(
        name='sensorhub_imu_mode_' + name, scope='mode', supplied={}, quiet=[list(q) for q in probe.QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': kernel.HARNESS_STACK}, fregisters={},
        stubs={str(probe.SPI_XFER): dict(kind='spi', seq=spi), str(probe.MEMCPY): dict(kind='memcpy', args=0),
               str(probe.DELAY): dict(kind='return', args=1), str(LOGGER): dict(kind='return', args=1),
               str(EVENT_POST): dict(kind='capture', ptr_arg=0, size=8, value=0, args=0),
               str(FCVT_SITE): dict(kind='fcvt_wu_s', rd='a5', fs='fa0')},
        stops={}, snapshot=[[ACC_RATE, 2], [GYR_RATE, 2], [STATE, 1], [DUMP_BUFFER, 8]],
        operations=[dict(name='mode', entry=MODE_SET, call=True, args=[enable, gyro], registers=False,
                         result=True, result_high=False)],
        memory=memory(g) + [[DUMP_BUFFER, '00' * 8]], spi=spi)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('gyro_enable_original_globals', 1, 1))
    add(case('gyro_enable_with_register_dump', 1, 1, dump=1))
    add(case('gyro_enable_dump_read_errors', 1, 1, dump=1, dump_fail=(0x00, 0x0f, 0x7f)))
    add(case('gyro_enable_valid_program_selector_kept', 1, 1, program=3))
    for rate in (52, 104, 208, 417, 833, 26, 100):
        add(case(f'gyro_enable_rate_{rate}', 1, 1, rate=rate))
        add(case(f'accel_enable_rate_{rate}', 1, 0, rate=rate))
    add(case('accel_enable_selector_0_ultra_low_power', 1, 0, accel_power=0))
    add(case('accel_enable_selector_1_low_normal_power', 1, 0, accel_power=1, state=2))
    add(case('accel_enable_selector_2_high_performance', 1, 0, accel_power=2, state=0))
    add(case('accel_enable_selector_7_low_normal_power', 1, 0, accel_power=7))
    add(case('gyro_enable_full_scales', 1, 1, gy_fs=4, xl_fs=1, odr=25.26168060302734))
    add(case('disable_both', 0, 0))
    add(case('disable_with_gyro_flag_logs_error', 0, 1))
    add(case('disable_runs_pending_dump', 0, 0, dump=1))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    data = archive.read(MEMBER)
    if digest(data) != probe.HUB_HASH:
        raise ValueError('unexpected sensor-hub image')
    memory_ = StartupMemory(data)
    for address, size, expected in CODE + DATA + PROGRAMS:
        if digest(memory_.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory_, site) != target:
            raise ValueError(f'call site {site:#x}')
    originals = dict(accel_power=memory_.read(ACCEL_POWER, 1)[0], program=memory_.read(PROGRAM_SEL, 1)[0], dump=memory_.read(DUMP_PENDING, 1)[0],
                     state=memory_.read(STATE, 1)[0], gy_fs=memory_.read(GY_FS_VALUE, 1)[0],
                     xl_fs=memory_.read(XL_FS_VALUE, 1)[0], rate=struct.unpack('<H', memory_.read(RATE, 2))[0])
    if originals != ORIGINAL:
        raise ValueError('original globals')
    programs = []
    for address, size, h in PROGRAMS:
        raw = memory_.read(address, size)
        pairs = [(raw[i], raw[i + 1]) for i in range(0, size, 2)]
        programs.append(dict(address=f'{address:#010x}', pairs=len(pairs), sha256=h,
                             page_value_writes=sum(1 for r, _ in pairs if r == 0x09),
                             registers=sorted({f'{r:#04x}' for r, _ in pairs})))
    a, b = (memory_.read(x, 0x2f8) for x in (PROGRAM_A, PROGRAM_B))
    differing = sum(1 for i in range(0, 0x2f8, 2) if a[i:i + 2] != b[i:i + 2])
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
        hub_sha256=probe.HUB_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        entries=dict(mode_set=f'{MODE_SET:#010x}', power_cfg=f'{POWER_CFG:#010x}', rate_set=f'{RATE_SET:#010x}',
                     post_odr=f'{POST_ODR:#010x}', dump=f'{DUMP:#010x}'),
        original_globals=dict(originals, meaning=dict(
            program='embedded-function program selector; 8 is invalid -> cleared, 5/6 select a program',
            gy_fs='6 = FS_G[3:1] code for 2000 dps', xl_fs='3 = FS_XL code for +-8 g',
            rate='26 Hz', state='last enable kind (2 gyro, 1 accelerometer only)',
            accel_power='accelerometer-only power selector (1 -> low/normal power)', dump='one-shot register dump pending')),
        rate_codes={str(k): v for k, v in sorted(RATE_CODES.items())} | {'other': 2},
        power_modes={'gyro enable': 0, 'accel selector 0': 2, 'accel selector 2': 0, 'accel other selector': 1},
        gyro_settings=dict(lp1_bandwidth=GY_LP1_BANDWIDTH, lpf1=1, power_mode=0),
        fifo_mode=FIFO_CONTINUOUS, i3c_disable_value=0, block_data_update=1,
        odr_event=dict(id=f'{EVENT_ODR:#x}', value='(u32)(trimmed ODR * 100); 0 for accel-only enables unless selector 2'),
        embedded_programs=dict(tables=programs, differing_pairs=differing, executed=False),
        byte_range_sha256={f'{a_:08x}_{n:x}': h for a_, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The mode setter, its configuration/rate/event/dump callees, every register accessor and the SPI '
            'callbacks execute in the sensor-hub emulator; the SPI transfer helper, memcpy, delay, logger and '
            'event post are supplied. Register reads return authored bytes (zero except the dump).',
            'The globals are authored per case, starting from their original image values. Which callers invoke '
            'the mode setter, and when, is not executed here.',
            'The two 380-pair embedded-function programs (FUNC_CFG_ACCESS/PAGE_SEL/PAGE_ADDRESS/PAGE_VALUE '
            'writes, FSM enable) are identified and hashed but not executed or redistributed; the image default '
            'selector (8) is invalid and cleared, so they are not loaded unless a caller sets 5 or 6.',
            'Ghidra 12.1.2 RV32 SLEIGH computes fcvt.wu.s into a temporary and never writes rd; the runner '
            'repairs the single site 0x80f701a8 with RISC-V semantics (round toward zero, saturating) and '
            'records it as a fix action. A step trace confirmed the dropped write.',
            'Nothing drives a real LSM6DSO; electrical timing and the fitted part remain unproved.'])


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
        parser.exit(2, f'Cannot inspect IMU mode: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
