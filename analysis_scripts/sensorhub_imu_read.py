#!/usr/bin/env python3
"""Sensor-hub LSM6DSO FIFO read callback entry/empty handling (``0x80f714a0``).

``0x80f714a0`` is the shared accelerometer/gyroscope descriptor read callback:
it optionally re-arms the sensor (flag ``0x80f17026`` -> ``0x80f700b4``), drains
the FIFO (``0x80f710ac``), and when samples are present allocates a sensor event
(``0x80f6453e``) and fills it with timestamped samples using the ODR timing
(``0x80f16b2e`` ODR code).  It returns the event pointer, or NULL when the drain
fails or no samples are available.

This scope executes the **entry, drain and empty-return handling** (the drained
count at ``0x80f17024`` is zero, or the drain reports an error), with the FIFO
drain (verified in [SENSORHUB_IMU_FIFO.md](SENSORHUB_IMU_FIFO.md)) and the
re-arm supplied; it returns NULL on these paths.  The sample-delivery data path
(allocation and the per-sample loop) is not executed here.
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

READ_CB = 0x80f714a0
REARM = 0x80f700b4             # re-arm when the dirty flag is set
FIFO_DRAIN = 0x80f710ac        # verified in sensorhub_imu_fifo
REARM_FLAG = 0x80f17026
SAMPLE_COUNT = 0x80f17024
BSS_LO, BSS_HI = 0x80f17000, 0x80f17030
STACK = probe.HARNESS_STACK
CSRS = probe.CSRS

CODE = ((READ_CB, 0x212, 'a560198409347cb1970266b2b6d1e16ef978605dc4ed2d4076e4938260c90c94'),)


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def read_cb(self):
        if self.u8(REARM_FLAG) != 0:
            self.leaf(REARM, self.u8(0x80f1700d))
            self.write(REARM_FLAG, 1, 0)
        self.leaf(FIFO_DRAIN, STACK - 0x40 + 6)
        if self.svc['drain'] != 0:
            return 0
        if self.u16(SAMPLE_COUNT) == 0:
            return 0
        raise ValueError('sample-delivery path is not modelled')

    def operation(self, op):
        if op['name'] != 'read':
            raise ValueError('operation')
        return self.read_cb()


def contract(case):
    if case['scope'] != 'imu_read' or len(case['operations']) != 1:
        raise ValueError('imu read scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi')
    return result


def case(name, flag=0, drain=0, count=0):
    g = dict(drain=drain)
    bss = bytearray(BSS_HI - BSS_LO)
    struct.pack_into('<H', bss, SAMPLE_COUNT - BSS_LO, count)
    bss[REARM_FLAG - BSS_LO] = flag
    stubs = {
        str(REARM): dict(kind='return', args=1),
        str(FIFO_DRAIN): dict(kind='return', args=1, value=g['drain']),
    }
    return dict(
        name='sensorhub_imu_read_' + name, scope='imu_read', supplied={}, quiet=[list(q) for q in probe.QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={}, snapshot=[],
        operations=[dict(name='read', entry=READ_CB, call=True, args=[], registers=False,
                         result=True, result_high=False)],
        memory=[[BSS_LO, bytes(bss).hex()]], spi=[], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('empty_flag_clear', flag=0, drain=0, count=0))
    add(case('empty_flag_set_rearms', flag=1, drain=0, count=0))
    add(case('drain_error', flag=0, drain=5, count=0))
    add(case('drain_error_flag_set', flag=1, drain=5, count=0))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


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
        name = c['name'].removeprefix('sensorhub_imu_read_')
        rearmed = any(a.startswith('call:' + str(REARM)) for a in c['expected']['actions'])
        results[name] = dict(ret=row['observed']['rows'][0]['a0'], rearmed=rearmed)
    return dict(
        image='sensor-hub (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        callback=f'{READ_CB:#010x} (shared accelerometer/gyroscope FIFO read)',
        flow=dict(
            rearm=f'if the dirty flag {REARM_FLAG:#010x} is set, call {REARM:#010x} and clear it',
            drain=f'{FIFO_DRAIN:#010x}; a non-zero result returns NULL',
            count=f'the drained sample count {SAMPLE_COUNT:#010x}; zero returns NULL',
            delivery='when samples are present, allocate a sensor event (0x80f6453e) and fill it with '
                     'timestamped samples using the ODR code at 0x80f16b2e (not executed here)'),
        per_case=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Only the entry, re-arm, drain and empty/error return paths are executed (the callback returns NULL); '
            'the FIFO drain and the re-arm are stubbed. The sample-delivery data path (event allocation 0x80f6453e '
            'and the per-sample timestamp loop) is not executed.'])


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
        parser.exit(2, f'Cannot inspect IMU read callback: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
