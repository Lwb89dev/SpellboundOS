#!/usr/bin/env python3
"""Main-image vibration motor (``dev_NL_motor``): on/off, timed pulse and duration table.

Executes in ``main-runtime`` the original motor off ``0x702d4d44``, motor on
``0x702d4fb0``, pulse ``0x702d5034(mode, params)`` and duration query
``0x702d50d6(params)``.  The motor is a GPIO output (record ``+4``, pin 95);
each switch emits a ``MOTOR``/``SWITCH`` trace.  A pulse switches the motor on
and starts the one-shot ``nonlinear_motor`` timer for the duration of the
requested level (1..8 from the table at ``0x70a30a14``, else 1000 ms); the
timer work switches it off.  Mode 1 is a plain on.  GPIO, trace, timer and
logger are supplied.
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

BOUND = 5000
M32 = 0xffffffff
OFF, ON, PULSE, DURATION = 0x702d4d44, 0x702d4fb0, 0x702d5034, 0x702d50d6
GPIO_WRITE, TRACE, TIMER_START, LOGGER = 0x702bd77e, 0x702bef1c, 0x80d36ba0, 0x702b38a2
BSD_PTR, TIMER_PTR = 0x70f8e6d8, 0x70f8e6d4
BSD = 0x80c015ac
BSD_RECORD = bytes.fromhex('000000005f000000')       # original dev_NL_motor record (pin 95 at +4)
DURATIONS = (25, 25, 50, 50, 80, 130, 25, 25)      # 0x70a30a14, ms for levels 1..8
DEFAULT_MS = 1000
MOTOR, SWITCH = 0x70a5ef7c, 0x709d28bc
TIMER = 0x7e7e0001
PARAMS = 0x81004000

CODE = (
    (OFF, 0x9e, '8a3f8c4d9559b0277c1d4b5259e5a10a54ba911b0d40fe46e1185003d8e99742'),
    (ON, 0x156, 'f7ec55c8450adbb3b0443f7b9c73fda5d5ea1722306e01bb78e464ca904134fc'),
)
DATA = ((0x70a30a14, 0x8, '669a2750bf20cc631d0027caaf747d22d0b1c62ed9427207b98fc0d31a716127'),)
CSRS = kernel.CSRS


def word(v):
    return v & M32


def duration(level):
    index = (level - 1) & 0xff
    return DURATIONS[index] if index <= 7 else DEFAULT_MS


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.gpio = list(case['gpio'])

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def switch(self, value):
        record = self.read(BSD_PTR, 4)
        if not record:
            return word(-1)
        pin = self.read(record + 4, 2)
        self.leaf(GPIO_WRITE, pin, value)
        status = self.gpio.pop(0)
        self.leaf(TRACE, MOTOR, SWITCH, status, 1, value)
        return status

    def pulse(self, mode, params):
        if params == 0:
            return word(-1)
        if mode == 1:
            return self.switch(1)
        status = self.switch(1)
        if status:
            self.leaf(LOGGER, 3)
            return status
        self.leaf(TIMER_START, self.read(TIMER_PTR, 4), duration(self.read(params, 1)))
        self.leaf(TRACE, MOTOR, SWITCH, 0, 1, 1)
        return 0

    def query(self, params):
        if params == 0:
            return word(-4)
        self.write(params + 2, 2, duration(self.read(params, 1)))
        return 0

    def operation(self, op):
        e, a = op['entry'], op['args']
        return {OFF: lambda: self.switch(0), ON: lambda: self.switch(1),
                PULSE: lambda: self.pulse(a[0], a[1]), DURATION: lambda: self.query(a[0])}[e]()


def contract(case):
    if case['scope'] != 'motor' or len(case['operations']) != 1:
        raise ValueError('motor scope')
    model = Model(case)
    result = model.run()
    if model.gpio:
        raise ValueError('unused scripted inputs')
    return result


def case(name, entry, args=(), gpio=(), record=True, level=3):
    stubs = {str(GPIO_WRITE): dict(kind='return', args=2, seq=list(gpio)) if gpio else dict(kind='return', args=2,
                                                                                                   value=0),
             str(TRACE): dict(kind='return', args=5), str(TIMER_START): dict(kind='return', args=2, value=0),
             str(LOGGER): dict(kind='return', args=1)}
    return dict(
        name='main_motor_' + name, scope='motor', supplied={}, quiet=[[0x81000000, 0x81002000]],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': kernel.HARNESS_STACK}, fregisters={}, stubs=stubs, stops={}, snapshot=[],
        operations=[dict(name='motor', entry=entry, call=True, args=list(args), registers=False, result=True,
                         result_high=False)],
        memory=[[BSD_PTR, struct.pack('<I', BSD if record else 0).hex()], [BSD, BSD_RECORD.hex()],
                [TIMER_PTR, struct.pack('<I', TIMER).hex()], [PARAMS, bytes([level, 0, 0, 0]).hex()]],
        gpio=list(gpio) if gpio else ([0] if (entry in (OFF, ON) and record) or
                                      (entry == PULSE and args[1]) else []))


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('off', OFF))
    add(case('on', ON))
    add(case('on_gpio_error', ON, gpio=[6]))
    add(case('off_without_record', OFF, record=False))
    for level in range(0, 10):
        add(case(f'pulse_level_{level}', PULSE, (2, PARAMS), level=level))
    add(case('pulse_mode_1_plain_on', PULSE, (1, PARAMS)))
    add(case('pulse_null_params', PULSE, (2, 0)))
    add(case('pulse_on_fails', PULSE, (2, PARAMS), gpio=[3]))
    for level in (1, 6, 9):
        add(case(f'duration_level_{level}', DURATION, (PARAMS,), level=level))
    add(case('duration_null', DURATION, (0,)))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    if tuple(memory.read(0x70a30a14, 8)) != DURATIONS or memory.read(BSD, 8) != BSD_RECORD:
        raise ValueError('duration table or record')
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
        motor=dict(record='dev_NL_motor', gpio_pin=95, drive='GPIO high = on, low = off',
                   pulse='on, then one-shot timer for the level duration; the timer work switches off'),
        durations_ms={str(i + 1): d for i, d in enumerate(DURATIONS)} | {'other': DEFAULT_MS},
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=['GPIO, trace, timer and logger are supplied; the timer callback/work and the haptic pattern '
                     'layer above this driver are not executed. Drive strength and the motor part are unverified.'])


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
        parser.exit(2, f'Cannot inspect motor: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
