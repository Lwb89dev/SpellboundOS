#!/usr/bin/env python3
"""Sensor-hub LSM6DSO ioctl command dispatch (accelerometer ``0x80f71d58`` and gyroscope ``0x80f716ec``).

Each sensor descriptor's control callback is a command dispatcher.  The
accelerometer (``0x80f71d58``) routes ~17 commands through a comparison chain and
two jump tables; the gyroscope (``0x80f716ec``) routes its commands through a
comparison chain.  Both log ``CMD%d unsupport`` for anything unrouted.  This
scope executes the dispatchers in the ``sensor-runtime`` project for the commands
that are directly resolvable, so the routing and the self-contained handlers are
verified:

- accelerometer: command ``0x01`` tail-calls ``0x80f62f90``, ``0xb2`` tail-calls
  ``0x80f6300e``, anything else logs ``CMD%d unsupport``;
- gyroscope: command ``0x01`` returns, command ``0xab`` computes the sample rate
  ``160000 / (ODR_code * multiplier)`` (reading ``0x80f16b2e`` and ``0x80f16b21``)
  into the output argument, anything else logs ``CMD%d unsupport``.

The full accelerometer command map is decoded from the two verified jump tables
at ``0x80fd8658`` and ``0x80fd8694``.
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
    from .sensorhub_memory import StartupMemory, MEMBER
else:
    import main_freertos_kernel as kernel
    import sensorhub_imu_probe as probe
    from sensorhub_memory import StartupMemory, MEMBER

BOUND = 20000
word = probe.word

ACC_IOCTL = 0x80f71d58
GYRO_IOCTL = 0x80f716ec
H_READ = 0x80f62f90            # accelerometer command 1 handler target
H_B2 = 0x80f6300e              # accelerometer command 0xb2 handler target
LOGGER = 0x80f86d34
JT1, JT1_CMD0, JT1_N = 0x80fd8658, 0x9d, 15
JT2, JT2_CMD0, JT2_N = 0x80fd8694, 0x81, 6
GY_ODR, GY_MULT = 0x80f16b2e, 0x80f16b21
RATE_CONST = 160000            # 0x27100
ARG = 0x80f17040               # output argument (a .bss word, so the store is recorded)
BSS_LO, BSS_HI = 0x80f16b20, 0x80f16b30
STACK = probe.HARNESS_STACK
CSRS = probe.CSRS

CODE = (
    (ACC_IOCTL, 0x718, '000d0dca90c0825d1a0de8c6d25205d5684708e6ceaff057143ef0ccb97bcfe3'),
    (GYRO_IOCTL, 0xd0, '7b4a338bd477cd3cc646955ecbccd29735e9568464ecab7d674c8a2e32e3b4a8'),
)
DIRECT = {0x01: H_READ, 0x02: 0x80f7217e, 0xb2: 0x80f6300e, 0x101: 0x80f722c2, 0x102: 0x80f723ac}


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    def acc_ioctl(self, command, arg):
        if command == 0x01:
            self.leaf(H_READ, arg)
            return word(self.svc['read'])
        if command == 0xb2:
            self.leaf(H_B2, arg)
            return word(self.svc['b2'])
        self.leaf(LOGGER, 6)
        return word(self.svc['log'])

    def gyro_ioctl(self, command, arg):
        if command == 0x01:
            return 1
        if command == 0xab:
            odr = self.u16(GY_ODR)
            mult = self.u8(GY_MULT)
            rate = 0 if odr == 0 else RATE_CONST // (odr * mult)
            self.put(arg, 4, rate)
            return 0xab
        self.leaf(LOGGER, 3)
        return word(self.svc['log'])

    def operation(self, op):
        if op['name'] == 'acc':
            return self.acc_ioctl(op['args'][0], op['args'][1])   # handler uses a1
        if op['name'] == 'gyro':
            return self.gyro_ioctl(op['args'][0], op['args'][2])  # handler uses a2
        raise ValueError('operation')


def contract(case):
    if case['scope'] != 'imu_ioctl' or len(case['operations']) != 1:
        raise ValueError('imu ioctl scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi')
    return result


def case(name, which, command, odr=0x10, mult=1, **svc_over):
    g = dict(read=0, b2=0, log=0)
    g.update(svc_over)
    bss = bytearray(BSS_HI - BSS_LO)
    struct.pack_into('<H', bss, GY_ODR - BSS_LO, odr)
    bss[GY_MULT - BSS_LO] = mult
    entry = ACC_IOCTL if which == 'acc' else GYRO_IOCTL
    stubs = {
        str(H_READ): dict(kind='return', args=1, value=g['read']),
        str(H_B2): dict(kind='return', args=1, value=g['b2']),
        str(LOGGER): dict(kind='return', args=1, value=g['log']),
    }
    return dict(
        name='sensorhub_imu_ioctl_' + name, scope='imu_ioctl', supplied={}, quiet=[list(q) for q in probe.QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={}, snapshot=[],
        operations=[dict(name=which, entry=entry, call=True, args=[command, ARG, ARG], registers=False,
                         result=True, result_high=False)],
        memory=[[BSS_LO, bytes(bss).hex()]], spi=[], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('acc_cmd_read', 'acc', 0x01))
    add(case('acc_cmd_b2', 'acc', 0xb2))
    add(case('acc_cmd_unsupported', 'acc', 0x30, log=6))
    add(case('acc_cmd_unsupported_high', 'acc', 0xc0, log=6))
    add(case('gyro_cmd_noop', 'gyro', 0x01))
    add(case('gyro_cmd_rate', 'gyro', 0xab, odr=0x10, mult=1))       # 160000/16 = 10000
    add(case('gyro_cmd_rate_scaled', 'gyro', 0xab, odr=0x08, mult=2))  # 160000/16 = 10000
    add(case('gyro_cmd_unsupported', 'gyro', 0x55, log=3))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def command_map(memory):
    unsupported = 0x80f71da6
    rows = {cmd: f'{handler:#010x}' for cmd, handler in DIRECT.items()}
    for base, cmd0, n in ((JT1, JT1_CMD0, JT1_N), (JT2, JT2_CMD0, JT2_N)):
        for i in range(n):
            off = struct.unpack('<i', memory.read(base + i * 4, 4))[0]
            target = (base + off) & 0xffffffff
            rows[cmd0 + i] = 'unsupported' if target == unsupported else f'{target:#010x}'
    return {f'{c:#04x}': rows[c] for c in sorted(rows)}


def evidence(archive, vectors, validation):
    memory = StartupMemory(archive.read(MEMBER))
    for address, size, expected in CODE:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    routed, rates = {}, {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        name = c['name'].removeprefix('sensorhub_imu_ioctl_')
        calls = [int(a.split(':')[1]) for a in c['expected']['actions'] if a.startswith('call:')]
        routed[name] = f'{calls[0]:#010x}' if calls else None
        writes = [a for a in c['expected']['actions'] if a.startswith('w:' + str(ARG) + ':')]
        if writes:
            rates[name] = int(writes[0].split(':')[3])
    if rates.get('gyro_cmd_rate') != 10000 or rates.get('gyro_cmd_rate_scaled') != 10000:
        raise ValueError('gyro rate computation')
    return dict(
        image='sensor-hub (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        dispatchers=dict(accelerometer=f'{ACC_IOCTL:#010x}', gyroscope=f'{GYRO_IOCTL:#010x}'),
        accelerometer=dict(jump_tables=[f'{JT1:#010x} (0x9d..0xab)', f'{JT2:#010x} (0x81..0x86)'],
                           command_map=command_map(memory)),
        gyroscope=dict(rate_formula='160000 / (ODR_code * multiplier) from 0x80f16b2e / 0x80f16b21',
                       sample_rates={k: v for k, v in rates.items()}),
        executed_routing=routed,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The directly-resolvable commands are executed (accelerometer routing for 0x01/0xb2/default, '
            'gyroscope 0x01/0xab/default); the other command handlers (rate/range/mode/self-test and the '
            'jump-table commands) are decoded into the accelerometer command map but not individually executed.'])


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
        parser.exit(2, f'Cannot inspect IMU ioctl: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
