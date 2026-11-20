#!/usr/bin/env python3
"""Sensor-hub LSM6DSO accelerometer ioctl command dispatch (``0x80f71d58``).

The accelerometer descriptor's control callback ``0x80f71d58(command, arg)`` is a
command dispatcher: a comparison chain plus two jump tables route ~17 commands to
their handlers, with everything else logging ``CMD%d unsupport``.  This scope
executes the dispatcher in the ``sensor-runtime`` project for the commands whose
handler is a direct tail-call, with the handler targets supplied, so the routing
itself is verified:

- command ``0x01`` tail-calls ``0x80f62f90`` (sample read);
- command ``0xb2`` tail-calls ``0x80f6300e``;
- any unrouted command logs ``CMD%d unsupport`` (``0x80f86d34``) and returns its
  result.

The full command map, decoded from the two verified jump tables at ``0x80fd8658``
(``0x9d..0xab``) and ``0x80fd8694`` (``0x81..0x86``) plus the direct comparisons,
is recorded in the evidence.
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

IOCTL = 0x80f71d58
H_READ = 0x80f62f90            # command 1 handler target
H_B2 = 0x80f6300e              # command 0xb2 handler target
LOGGER = 0x80f86d34
JT1, JT1_CMD0, JT1_N = 0x80fd8658, 0x9d, 15
JT2, JT2_CMD0, JT2_N = 0x80fd8694, 0x81, 6
ARG = 0x12345678
STACK = probe.HARNESS_STACK
CSRS = probe.CSRS

CODE = ((IOCTL, 0x718, '000d0dca90c0825d1a0de8c6d25205d5684708e6ceaff057143ef0ccb97bcfe3'),)

# Direct (non-jump-table) command handlers, decoded from the comparison chain.
DIRECT = {0x01: H_READ, 0x02: 0x80f7217e, 0xb2: 0x80f6300e, 0x101: 0x80f722c2, 0x102: 0x80f723ac}


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def ioctl(self, command, arg):
        if command == 0x01:
            self.leaf(H_READ, arg)
            return word(self.svc['read'])
        if command == 0xb2:
            self.leaf(H_B2, arg)
            return word(self.svc['b2'])
        self.leaf(LOGGER, 6)
        return word(self.svc['log'])

    def operation(self, op):
        if op['name'] != 'ioctl':
            raise ValueError('operation')
        return self.ioctl(op['args'][0], op['args'][1])


def contract(case):
    if case['scope'] != 'imu_ioctl' or len(case['operations']) != 1:
        raise ValueError('imu ioctl scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi')
    return result


def case(name, command, **svc_over):
    g = dict(read=0, b2=0, log=6)
    g.update(svc_over)
    stubs = {
        str(H_READ): dict(kind='return', args=1, value=g['read']),
        str(H_B2): dict(kind='return', args=1, value=g['b2']),
        str(LOGGER): dict(kind='return', args=1, value=g['log']),
    }
    return dict(
        name='sensorhub_imu_ioctl_' + name, scope='imu_ioctl', supplied={}, quiet=[list(q) for q in probe.QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={}, snapshot=[],
        operations=[dict(name='ioctl', entry=IOCTL, call=True, args=[command, ARG], registers=False,
                         result=True, result_high=False)],
        memory=[], spi=[], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('cmd_read', 0x01))
    add(case('cmd_b2', 0xb2))
    add(case('cmd_unsupported', 0x30))
    add(case('cmd_unsupported_high', 0xc0))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def cstr(memory, address, limit=24):
    return memory.read(address, limit).split(b'\0')[0].decode('ascii')


def command_map(memory):
    unsupported = 0x80f71da6
    rows = {}
    for cmd, handler in DIRECT.items():
        rows[cmd] = f'{handler:#010x}'
    for base, cmd0, n in ((JT1, JT1_CMD0, JT1_N), (JT2, JT2_CMD0, JT2_N)):
        for i in range(n):
            off = struct.unpack('<i', memory.read(base + i * 4, 4))[0]
            target = (base + off) & 0xffffffff
            cmd = cmd0 + i
            rows[cmd] = 'unsupported' if target == unsupported else f'{target:#010x}'
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
    routed = {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        calls = [int(a.split(':')[1]) for a in c['expected']['actions'] if a.startswith('call:')]
        routed[c['name'].removeprefix('sensorhub_imu_ioctl_')] = f'{calls[0]:#010x}' if calls else None
    return dict(
        image='sensor-hub (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        dispatcher=f'{IOCTL:#010x} (accelerometer ioctl)',
        jump_tables=dict(table1=f'{JT1:#010x} (0x9d..0xab)', table2=f'{JT2:#010x} (0x81..0x86)'),
        command_map=command_map(memory),
        executed_routing=routed,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Only the routing of the direct tail-call commands (0x01 read, 0xb2) and the unsupported default '
            'is executed; the remaining command handlers (rate/range/mode/self-test and the jump-table '
            'commands) are decoded into the command map but not individually executed.',
            'The gyroscope ioctl dispatcher 0x80f716ec has the same shape and is not covered here.'])


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
