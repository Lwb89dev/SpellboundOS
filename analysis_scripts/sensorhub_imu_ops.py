#!/usr/bin/env python3
"""Sensor-hub LSM6DSO descriptor operations: accelerometer/gyroscope enable, disable and control.

The accelerometer and gyroscope sensor descriptors registered by the attach
(:mod:`sensorhub_imu_init`) carry the operation callbacks the hub invokes for
open/close/control.  This scope executes them in the ``sensor-runtime`` project;
the already-verified mode setter (:mod:`sensorhub_imu_mode` ``0x80f70da2``) and
the FIFO drain (:mod:`sensorhub_imu_fifo` ``0x80f710ac``) are supplied, so only
the callbacks' own sequencing and state is executed:

- **accel enable** ``0x80f70f28``: mode set ``(1, odr@0x80f1702c)``; on failure
  return 2, else mark the accelerometer running (``0x80f17030 = 1``), clear the
  pending sample count (``0x80f17024``) and return 0;
- **gyro enable** ``0x80f70f62``: mode set ``(odr@0x80f17030, 1)``; same shape,
  marking ``0x80f1702c``;
- **accel disable** ``0x80f71046``: mode set ``(0, odr)``, latch the power
  selector (``0x80f16b1c = 1``), clear the running/sample state, log ``acc fs``
  and store the full-scale defaults (``0x80f16b28 = 0x1000``, ``0x80f16b2d = 3``);
- **gyro disable** ``0x80f71c24``: mirror for the gyroscope (``0x80f16b1d = 1``,
  ``0x80f16b24 = 0x596``, ``0x80f16b2c = 6``);
- **accel control** ``0x80f716b2``: command 0 runs the self-test query and posts
  a result event, command 2 flushes the FIFO, any other command is a no-op.

Supplied (stubbed): the mode setter, the FIFO drain, the self-test, the event
post, the enable/disable completion helpers and the logger.
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

ACC_ENABLE, GYRO_ENABLE = 0x80f70f28, 0x80f70f62
ACC_DISABLE, GYRO_DISABLE = 0x80f71046, 0x80f71c24
ACC_CONTROL = 0x80f716b2
MODE_SET = 0x80f70da2
FIFO_DRAIN = 0x80f710ac
SELF_TEST = 0x80f701d2
EVENT_POST = 0x80f63f6c
ENABLE_DONE, DISABLE_DONE, DISABLE_TAIL = 0x80f62dce, 0x80f62e82, 0x80f6fb9a
LOGGER = 0x80f86d34

ACC_ODR, GYRO_ODR = 0x80f1702c, 0x80f17030
SAMPLE_COUNT = 0x80f17024
ACC_PWR_SEL, GYRO_PWR_SEL = 0x80f16b1c, 0x80f16b1d
ACC_FS, GYRO_FS = 0x80f16b28, 0x80f16b24
ACC_FS_CODE, GYRO_FS_CODE = 0x80f16b2d, 0x80f16b2c
BSS_LO, BSS_HI = 0x80f16b1c, 0x80f17034     # authored .bss window
STACK = probe.HARNESS_STACK
CSRS = probe.CSRS
LOG_INFO = 6

CODE = (
    (ACC_ENABLE, 0x3a, '9a1b36fc3c302f038548b4181103f15f54694b890b98ce34868df81438fdf021'),
    (GYRO_ENABLE, 0x30, 'e46de177c583562ff1464d09d6bc6952bdcaa4a23e2c453696037d0012f7165b'),
    (ACC_DISABLE, 0x66, '4054188c2284f90ec33cb61cbd439036aca005218e47ad45869436762f7e9e7b'),
    (GYRO_DISABLE, 0x64, 'acce6c954cc8a83156d037cfb744290d889e2ab52774036f7015ea7d71b5574e'),
    (ACC_CONTROL, 0x3a, '09fb8d0abf0453582808da8713a541ab47125f1c1aa812cdaaf03e338a68a980'),
)


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def u32(self, a):
        return self.read(a, 4)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    def acc_enable(self):
        self.leaf(MODE_SET, 1, self.u32(ACC_ODR))
        if self.svc['mode'] != 0:
            return 2
        self.leaf(ENABLE_DONE)
        self.put(GYRO_ODR, 4, 1)
        self.put(SAMPLE_COUNT, 2, 0)
        return 0

    def gyro_enable(self):
        self.leaf(MODE_SET, self.u32(GYRO_ODR), 1)
        if self.svc['mode'] != 0:
            return 2
        self.put(ACC_ODR, 4, 1)
        self.put(SAMPLE_COUNT, 2, 0)
        return 0

    def acc_disable(self):
        self.leaf(MODE_SET, 0, self.u32(ACC_ODR))
        self.leaf(DISABLE_DONE)
        self.put(ACC_PWR_SEL, 1, 1)
        self.put(GYRO_ODR, 4, 0)
        self.put(SAMPLE_COUNT, 2, 0)
        self.leaf(LOGGER, LOG_INFO)
        self.put(ACC_FS, 4, 0x1000)
        self.put(ACC_FS_CODE, 1, 3)
        self.leaf(DISABLE_TAIL)
        return word(self.svc['tail'])

    def gyro_disable(self):
        self.leaf(MODE_SET, self.u32(GYRO_ODR), 0)
        self.put(GYRO_PWR_SEL, 1, 1)
        self.put(ACC_ODR, 4, 0)
        self.put(SAMPLE_COUNT, 2, 0)
        self.leaf(LOGGER, LOG_INFO)
        self.put(GYRO_FS, 4, 0x596)
        self.put(GYRO_FS_CODE, 1, 6)
        self.leaf(DISABLE_TAIL)
        return word(self.svc['tail'])

    def acc_control(self, command):
        if command == 0:
            self.leaf(SELF_TEST)
            # sp+8 = (self_test ? 8 : 5), sp+9 = 1 (stack is quiet); post the status event.
            self.leaf(EVENT_POST, STACK - 0x20 + 8)
            return word(self.svc['event'])
        if command == 2:
            self.leaf(FIFO_DRAIN, 0)
            return word(self.svc['fifo'])
        return command

    def operation(self, op):
        name = op['name']
        if name == 'acc_enable':
            return self.acc_enable()
        if name == 'gyro_enable':
            return self.gyro_enable()
        if name == 'acc_disable':
            return self.acc_disable()
        if name == 'gyro_disable':
            return self.gyro_disable()
        if name.startswith('acc_control'):
            return self.acc_control(op['args'][0])
        raise ValueError('operation')


ENTRIES = dict(acc_enable=ACC_ENABLE, gyro_enable=GYRO_ENABLE, acc_disable=ACC_DISABLE,
               gyro_disable=GYRO_DISABLE, acc_control=ACC_CONTROL)


def contract(case):
    if case['scope'] != 'imu_ops' or len(case['operations']) != 1:
        raise ValueError('imu ops scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi transactions')
    return result


def case(name, op_name, args=(), odr=0x10, **svc_over):
    g = dict(mode=0, tail=0, event=0, fifo=0, self_test=0)
    g.update(svc_over)
    bss = bytearray(BSS_HI - BSS_LO)
    struct.pack_into('<I', bss, ACC_ODR - BSS_LO, odr)
    struct.pack_into('<I', bss, GYRO_ODR - BSS_LO, odr)
    stubs = {
        str(MODE_SET): dict(kind='return', args=2, value=g['mode']),
        str(FIFO_DRAIN): dict(kind='return', args=1, value=g['fifo']),
        str(SELF_TEST): dict(kind='return', args=0, value=g['self_test']),
        str(EVENT_POST): dict(kind='return', args=1, value=g['event']),
        str(ENABLE_DONE): dict(kind='return', args=0),
        str(DISABLE_DONE): dict(kind='return', args=0),
        str(DISABLE_TAIL): dict(kind='return', args=0, value=g['tail']),
        str(LOGGER): dict(kind='return', args=1),
    }
    entry = ENTRIES[op_name]
    return dict(
        name='sensorhub_imu_ops_' + name, scope='imu_ops', supplied={}, quiet=[list(q) for q in probe.QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name=name.split('#')[0] if False else op_name, entry=entry, call=True,
                                      args=list(args), registers=False, result=True, result_high=False)],
        memory=[[BSS_LO, bytes(bss).hex()]], spi=[], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('acc_enable_ok', 'acc_enable'))
    add(case('acc_enable_mode_fails', 'acc_enable', mode=3))
    add(case('gyro_enable_ok', 'gyro_enable'))
    add(case('gyro_enable_mode_fails', 'gyro_enable', mode=3))
    add(case('acc_disable', 'acc_disable'))
    add(case('gyro_disable', 'gyro_disable'))
    add(case('control_self_test_pass', 'acc_control', (0,), self_test=0))
    add(case('control_self_test_fail', 'acc_control', (0,), self_test=1))
    add(case('control_fifo_flush', 'acc_control', (2,)))
    add(case('control_passthrough', 'acc_control', (7,)))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def cstr(memory, address, limit=24):
    return memory.read(address, limit).split(b'\0')[0].decode('ascii')


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
    results = {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        results[c['name'].removeprefix('sensorhub_imu_ops_')] = row['observed']['rows'][0]['a0']
    return dict(
        image='sensor-hub (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        callbacks=dict(
            accelerometer=dict(enable=f'{ACC_ENABLE:#010x}', disable=f'{ACC_DISABLE:#010x}',
                               control=f'{ACC_CONTROL:#010x}'),
            gyroscope=dict(enable=f'{GYRO_ENABLE:#010x}', disable=f'{GYRO_DISABLE:#010x}'),
            mode_setter=f'{MODE_SET:#010x} (executed in sensorhub_imu_mode)',
            fifo_drain=f'{FIFO_DRAIN:#010x} (executed in sensorhub_imu_fifo)'),
        state_words=dict(acc_running=f'{GYRO_ODR:#010x}', gyro_running=f'{ACC_ODR:#010x}',
                         sample_count=f'{SAMPLE_COUNT:#010x}', power_selector=f'{ACC_PWR_SEL:#010x}'),
        control_commands=dict(self_test=0, fifo_flush=2),
        return_codes=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The mode setter, FIFO drain, self-test, event post, enable/disable completion helpers and the '
            'logger are stubbed; the callbacks run as real code and their state-word writes are recorded.',
            'The shared FIFO read callback 0x80f714a0 and the full ioctl dispatchers 0x80f716ec / 0x80f71d58 '
            '(rate/range/mode commands) are not executed here.'])


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
        parser.exit(2, f'Cannot inspect IMU ops: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
