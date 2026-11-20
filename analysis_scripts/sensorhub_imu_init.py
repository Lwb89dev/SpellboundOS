#!/usr/bin/env python3
"""Sensor-hub LSM6DSO attach: board record, SPI bus, probe, ODR trim, IRQ, registration.

``0x80f726ee`` is the sensor-hub LSM6DSO attach routine.  This scope executes
it end to end in the ``sensor-runtime`` project, together with the original
probe chain of :mod:`sensorhub_imu_probe` and the ``INTERNAL_FREQ_FINE``
accessor ``0x80f72b5a``, over the **real** board record:

1. look up the board record ``dev_lsm6dso`` (``0x80f8748a``); missing -> 4;
2. find the SPI device handle by the record's bus name ``sens_spi1_dev0`` into
   ``0x80f17018`` (``0x80f894f6``); failure -> 4;
3. configure the SPI device (``0x80f89552``) with ``{8000000, 0x807, 0, 0, 0}``;
4. publish the record pointer at ``0x80f17014`` and run the probe; failure -> 1;
5. allocate a 0x605-byte ``drivers_sensor`` cache, zero it and publish it at
   ``0x80f17020`` with ``+0x460`` at ``0x80f1701c``; failure -> 10;
6. read ``INTERNAL_FREQ_FINE`` (``0x63``) and store the trimmed 26 Hz ODR
   ``6667 * (1 + 0.0015 * fine) / 256`` as a float at ``0x80f17028``;
7. initialize the interrupt GPIO (record pin 43), install the handler
   ``0x80f701ba`` with argument ``0x80f17014`` (record mode 4) and leave the
   interrupt disabled; GPIO failures are logged but still return 0;
8. register the accelerometer and gyroscope sensor descriptors.

The board-record lookup, SPI device find/configure, allocator, memset, GPIO
services, sensor registration, SPI transfer helper, memcpy, delay and logger
are supplied.  The board records themselves are decoded statically from the
original registration table at ``0x80f6257c``.
"""
import argparse
import hashlib
import json
import math
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

MASK = 0xffffffff
BOUND = 5000

ATTACH = 0x80f726ee
ODR_CAL_GET = 0x80f72b5a       # register accessor: read INTERNAL_FREQ_FINE (0x63)
BOARD_FIND = 0x80f8748a        # board record lookup by name (supplied)
SPI_FIND = 0x80f894f6          # spi_dev_find_handle(name, &handle) (supplied)
SPI_CONFIG = 0x80f89552        # SPI device configure(handle, cfg) (supplied)
MALLOC = 0x80f84cee            # tagged allocator (supplied)
MEMSET = 0x80fcdfcc            # memset (supplied)
GPIO_INIT = 0x80f88a4c         # gpio_dev_init(pin, cfg) (supplied)
GPIO_INSTALL_IRQ = 0x80f88be2  # gpio_dev_install_irq(pin, mode, handler, arg) (supplied)
GPIO_DISABLE_IRQ = 0x80f88e68  # gpio_dev_disable_irq(pin) (supplied)
SENSOR_REGISTER = 0x80f63fac   # sensor descriptor registration (supplied)
REGISTRATION = 0x80f6257c      # original board-record registration table
IRQ_HANDLER = 0x80f701ba

NAME_DEV = 0x80fd4514          # "dev_lsm6dso"
NAME_TAG = 0x80fd4868          # "drivers_sensor"
BSD = 0x80f16ae8               # real dev_lsm6dso board record (.data)
BUS_NAME = 0x80fd443c          # "sens_spi1_dev0"
IRQ_PIN, IRQ_MODE = 43, 4
DEV_PTR = 0x80f17014           # .bss: published board record pointer
HANDLE_PTR = probe.SPI_HANDLE_PTR
CACHE_PTR = 0x80f17020
CACHE_TAIL_PTR = 0x80f1701c
ODR_PTR = 0x80f17028
ACC_DESC, GYR_DESC = 0x80f15538, 0x80f15508

SPI_HZ, SPI_MODE_WORD = 8000000, 0x807
CACHE_SIZE, CACHE_TAIL = 0x605, 0x460
ALLOC_HEAP, ALLOC_ALIGN = 4, 4
FREQ_FINE = 0x63
CACHE_ADDRESS = 0x81010000     # authored allocation result
LOG_ERROR, LOG_WARN, LOG_INFO = 3, 4, 6
EMULATED_FSW_BYTES = 8           # emulator artifact; 4 on hardware

CODE = probe.CODE + (
    (ATTACH, 0x220, '625de7157e09cea0300593258947c2607de551462efa85d213a38feb1d2d59fc'),
    (ODR_CAL_GET, 0x28, 'bbb5870ce307f784be6ae6a188504054e9b2b3d23df2533498631b517a725d51'),
)
DATA = probe.DATA + (
    (BSD, 0x8, '9f886377f35b5e5bcde155dd7d9f4b3447c2693254fa5e7fa6be4958aaecc29f'),
    (GYR_DESC, 0x60, '55aa8ef2806a78f1cb74ba81c67346fedda9029fd15592eddf554969700a3a7b'),
    (0x80fd86f8, 0x18, '27fa7b23c2ebc5b79d18bdc53917d587ac9107739577e60dc3a35b1c62be083f'),
)
CALL_SITES = probe.CALL_SITES + (
    (0x80f72704, BOARD_FIND), (0x80f72740, SPI_FIND), (0x80f72778, SPI_CONFIG),
    (0x80f72780, probe.INIT), (0x80f727b4, MALLOC), (0x80f727c4, MEMSET), (0x80f727e8, ODR_CAL_GET),
    (0x80f7284e, MEMSET), (0x80f7285c, GPIO_INIT), (0x80f728e2, GPIO_INSTALL_IRQ),
    (0x80f728fc, GPIO_DISABLE_IRQ), (0x80f7289e, SENSOR_REGISTER), (0x80f728aa, SENSOR_REGISTER),
    (0x80f72b6e, probe.CTX_READ),
)
# (name, data, size) as registered by 0x80f6257c, decoded from the image.
REGISTRATION_ROWS = (
    ('system_info', 0x80f153f4, 0x1c), ('dev_virtual_pm', 0x80f16af8, 8), ('dev_ak09918', 0x80f16af4, 4),
    ('dev_mmc5603', 0x80f16af0, 4), ('dev_max8617x', 0x80f153dc, 0x18), ('dev_lsm6dso', BSD, 8),
    ('dev_bmi2xx', 0x80f16ae0, 8),
)
# (data auipc site, name auipc site, size) in 0x80f6257c; each auipc is followed by addi.
REGISTRATION_SITES = (
    (0x80f62584, 0x80f6258e, 0x1c), (0x80f6259e, 0x80f625a6, 8), (0x80f625b4, 0x80f625bc, 4),
    (0x80f625ca, 0x80f625d2, 4), (0x80f625e0, 0x80f625e8, 0x18), (0x80f625f6, 0x80f625fe, 8),
    (0x80f6260e, 0x80f62616, 8),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
FRAME = 0x50


def pc_pair(memory, site):
    """Address formed by an auipc at site and the addi that follows it (same rd)."""
    hi, lo = struct.unpack('<II', memory.read(site, 8))
    rd = (hi >> 7) & 31
    if hi & 0x7f != 0x17 or lo & 0x707f != 0x13 or (lo >> 7) & 31 != rd or (lo >> 15) & 31 != rd:
        raise ValueError(f'not auipc/addi at {site:#x}')
    imm = lo >> 20
    imm -= 0x1000 if imm & 0x800 else 0
    return word(site + (hi & 0xfffff000) + imm)


def registration_rows(memory):
    rows = []
    for data_site, name_site, size in REGISTRATION_SITES:
        rows.append((cstr(memory, pc_pair(memory, name_site)), pc_pair(memory, data_site), size))
    return tuple(rows)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(v):
    return v & MASK


def odr_hz(fine):
    """Trimmed 26 Hz ODR as the original computes it, rounded to binary32."""
    value = math.fma(fine * 0.0015, 6667.0, 6667.0) * 0.00390625
    unfused = (fine * 0.0015 * 6667.0 + 6667.0) * 0.00390625
    bits = struct.pack('<f', value)
    if bits != struct.pack('<f', unfused):
        raise ValueError('ODR trim sensitive to fused rounding')
    return struct.unpack('<I', bits)[0], struct.unpack('<f', bits)[0]


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = dict(case['services'])

    def attach(self):
        self.leaf(BOARD_FIND, NAME_DEV)
        if not self.svc['bsd']:
            self.leaf(probe.LOGGER, LOG_ERROR)
            return 4
        self.leaf(SPI_FIND, BUS_NAME, HANDLE_PTR)
        if self.svc['spi_find']:
            self.leaf(probe.LOGGER, LOG_ERROR)
            return 4
        self.leaf(SPI_CONFIG, probe.SPI_HANDLE)
        self.actions.append('cap:' + struct.pack('<5I', SPI_HZ, SPI_MODE_WORD, 0, 0, 0).hex())
        self.write(DEV_PTR, 4, BSD)
        if self.init():
            self.leaf(probe.LOGGER, LOG_INFO)
            return 1
        self.leaf(MALLOC, ALLOC_HEAP, NAME_TAG, CACHE_SIZE, ALLOC_ALIGN)
        cache = self.svc['malloc']
        if not cache:
            self.leaf(probe.LOGGER, LOG_WARN)
            return 10
        self.leaf(MEMSET, cache, 0, CACHE_SIZE)
        self.write(CACHE_PTR, 4, cache)
        self.write(CACHE_TAIL_PTR, 4, cache + CACHE_TAIL)
        status, data = self.read_reg(FREQ_FINE)
        fine = data[0] if status == 0 else 0          # the accessor pre-zeroes its buffer
        fine -= 0x100 if fine & 0x80 else 0            # read back with lb (signed)
        # c.fsw: the hardware stores 4 bytes; Ghidra's RV32 SLEIGH stores the whole FLEN=64
        # register, so the emulator records an 8-byte write with zero (non-NaN-boxed) upper half.
        self.write(ODR_PTR, EMULATED_FSW_BYTES, odr_hz(fine)[0])
        self.leaf(probe.LOGGER, LOG_INFO)
        self.leaf(MEMSET, HARNESS_STACK - FRAME + 0x20, 0, 0x20)
        self.leaf(GPIO_INIT, IRQ_PIN)
        self.actions.append('cap:' + '00' * 0x20)
        if self.svc['gpio_init']:
            self.leaf(probe.LOGGER, LOG_ERROR)
            self.leaf(probe.LOGGER, LOG_ERROR)
        else:
            self.leaf(GPIO_INSTALL_IRQ, IRQ_PIN, IRQ_MODE, IRQ_HANDLER, DEV_PTR)
            if self.svc['install']:
                self.leaf(probe.LOGGER, LOG_ERROR)
                self.leaf(probe.LOGGER, LOG_ERROR)
            else:
                self.leaf(GPIO_DISABLE_IRQ, IRQ_PIN)
                if self.svc['disable']:
                    self.leaf(probe.LOGGER, LOG_ERROR)
                    self.leaf(probe.LOGGER, LOG_ERROR)
        self.leaf(SENSOR_REGISTER, ACC_DESC)
        self.leaf(SENSOR_REGISTER, GYR_DESC)
        return 0

    def operation(self, op):
        if op['name'].split('#')[0] == 'attach':
            return self.attach()
        raise ValueError('operation')


def contract(case):
    if case['scope'] != 'attach' or len(case['operations']) != 1:
        raise ValueError('attach scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi transactions')
    return result


def stubs(spi, services):
    s = probe.stubs(spi)
    s.update({
        str(BOARD_FIND): dict(kind='return', args=1, value=BSD if services['bsd'] else 0),
        str(SPI_FIND): dict(kind='store', out_arg=1, size=4, value=probe.SPI_HANDLE,
                            value_ret=services['spi_find'], args=2),
        str(SPI_CONFIG): dict(kind='capture', ptr_arg=1, size=20, value=0, args=1),
        str(MALLOC): dict(kind='return', args=4, value=services['malloc']),
        str(MEMSET): dict(kind='memset', args=3),
        str(GPIO_INIT): dict(kind='capture', ptr_arg=1, size=0x20, value=services['gpio_init'], args=1),
        str(GPIO_INSTALL_IRQ): dict(kind='return', args=4, value=services['install']),
        str(GPIO_DISABLE_IRQ): dict(kind='return', args=1, value=services['disable']),
        str(SENSOR_REGISTER): dict(kind='return', args=1, value=0),
    })
    return s


def case(name, spi, **overrides):
    services = dict(bsd=True, spi_find=0, malloc=CACHE_ADDRESS, gpio_init=0, install=0, disable=0)
    services.update(overrides)
    return dict(
        name='sensorhub_imu_init_' + name, scope='attach', supplied={},
        quiet=[list(q) for q in probe.QUIET], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(spi, services), stops={}, snapshot=[],
        operations=[dict(name='attach', entry=ATTACH, call=True, args=[], registers=False,
                         result=True, result_high=False)],
        memory=[], spi=list(spi), services=services)


def probed(fine=None):
    script = probe.reset_ok() + [probe.read_rx(probe.LSM6DSO_WHOAMI)]
    return script + ([probe.fail(2)] if fine is None else [probe.read_rx(fine & 0xff)])


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('full_success', probed(0)))
    add(case('odr_trim_negative', probed(-20)))
    add(case('odr_trim_positive', probed(37)))
    add(case('odr_read_error_uses_zero', probed(None)))
    add(case('board_record_missing', [], bsd=False))
    add(case('spi_handle_not_found', [], spi_find=1))
    add(case('probe_fails', (probe.reset_ok() + [probe.read_rx(0x6a)]) * probe.INIT_ATTEMPTS))
    add(case('cache_alloc_fails', probe.reset_ok() + [probe.read_rx(probe.LSM6DSO_WHOAMI)], malloc=0))
    add(case('gpio_init_fails_still_registers', probed(0), gpio_init=5))
    add(case('irq_install_fails_still_registers', probed(0), install=5))
    add(case('irq_disable_fails_still_registers', probed(0), disable=5))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def cstr(memory, address):
    return memory.read(address, 32).split(b'\0')[0].decode('ascii')


def board_records(memory):
    out = {}
    for name, data, size in REGISTRATION_ROWS:
        raw = memory.read(data, size)
        out[name] = dict(address=f'{data:#010x}', size=size, bytes=raw.hex())
    lsm = memory.read(BSD, 8)
    bus, pin, mode = struct.unpack('<IHB', lsm[:7])
    out['dev_lsm6dso'].update(bus=cstr(memory, bus), irq_pin=pin, irq_mode=mode)
    bmi = memory.read(0x80f16ae0, 8)
    out['dev_bmi2xx'].update(bus=cstr(memory, struct.unpack('<I', bmi[:4])[0]), same_as_lsm6dso=bmi == lsm)
    for name in ('dev_ak09918', 'dev_mmc5603'):
        out[name]['bus'] = cstr(memory, struct.unpack('<I', memory.read(int(out[name]['address'], 16), 4))[0])
    ppg = struct.unpack('<6I', memory.read(0x80f153dc, 0x18))
    out['dev_max8617x'].update(bus=cstr(memory, ppg[0]), rails=[cstr(memory, ppg[1]), cstr(memory, ppg[2])],
                               word3=ppg[3], pin=ppg[4] & 0xffff, word5=ppg[5])
    info = struct.unpack('<7I', memory.read(0x80f153f4, 0x1c))
    out['system_info'].update(version=cstr(memory, info[0]), board=cstr(memory, info[1]))
    return out


def evidence(archive, vectors, validation):
    data = archive.read(MEMBER)
    if digest(data) != probe.HUB_HASH:
        raise ValueError('unexpected sensor-hub image')
    memory = StartupMemory(data)
    for address, size, expected in CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
    if registration_rows(memory) != REGISTRATION_ROWS:
        raise ValueError('board registration table')
    if (cstr(memory, NAME_DEV), cstr(memory, NAME_TAG), cstr(memory, BUS_NAME)) != \
            ('dev_lsm6dso', 'drivers_sensor', 'sens_spi1_dev0'):
        raise ValueError('names')
    if struct.unpack('<IHB', memory.read(BSD, 7)) != (BUS_NAME, IRQ_PIN, IRQ_MODE):
        raise ValueError('board record')
    if struct.unpack('<3d', memory.read(0x80fd86f8, 0x18)) != (0.0015, 6667.0, 0.00390625):
        raise ValueError('ODR trim constants')
    descriptors = {}
    for label, at in (('accelerometer', ACC_DESC), ('gyroscope', GYR_DESC)):
        w = struct.unpack('<12I', memory.read(at, 0x30))
        descriptors[label] = dict(address=f'{at:#010x}', name=cstr(memory, w[0]), type_word=f'{w[2]:#010x}',
                                  word3=w[3], callbacks=[f'{x:#010x}' for x in w[4:10] if x > 0x1000000])
    if (descriptors['accelerometer']['name'], descriptors['gyroscope']['name']) != ('lsm6dso A', 'lsm6dso G'):
        raise ValueError('sensor descriptors')
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
        attach=f'{ATTACH:#010x}', odr_cal_get=f'{ODR_CAL_GET:#010x}', irq_handler=f'{IRQ_HANDLER:#010x}',
        board_records=board_records(memory), registration=f'{REGISTRATION:#010x}',
        spi_config=dict(clock_hz=SPI_HZ, word1=f'{SPI_MODE_WORD:#x}', remaining_words=[0, 0, 0]),
        odr_trim=dict(register=f'{FREQ_FINE:#04x}', formula='6667 * (1 + 0.0015 * fine) / 256',
                      samples={str(f): odr_hz(f)[1] for f in (-128, -20, 0, 37, 127)}),
        emulator_artifacts=dict(c_fsw_store_bytes=EMULATED_FSW_BYTES, hardware_store_bytes=4,
                                address=f'{ODR_PTR:#010x}'),
        cache=dict(tag='drivers_sensor', size=CACHE_SIZE, tail_offset=f'{CACHE_TAIL:#x}'),
        results={'0': 'attached (GPIO failures are logged only)', '1': 'probe failed',
                 '4': 'board record or SPI handle missing', '10': 'cache allocation failed'},
        sensor_descriptors=descriptors,
        published=dict(board_record=f'{DEV_PTR:#010x}', spi_handle=f'{HANDLE_PTR:#010x}',
                       cache=f'{CACHE_PTR:#010x}', cache_tail=f'{CACHE_TAIL_PTR:#010x}', odr=f'{ODR_PTR:#010x}'),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The attach routine, the probe chain and the INTERNAL_FREQ_FINE accessor execute in the sensor-hub '
            'emulator; the board lookup, SPI device find/configure, allocator, memset, GPIO services, sensor '
            'registration, SPI transfer helper, memcpy, delay and logger are supplied with authored results.',
            'Board records are decoded statically from the original registration table; that the lookup returns '
            'this record is supplied. Pin 43 and mode 4 are hub GPIO driver values; the physical pad, edge/level '
            'meaning and the SPI configuration word 0x807 are not decoded here.',
            'The GPIO interrupt is installed but left disabled; enabling, the handler 0x80f701ba, FIFO/data '
            'reads and the registered sensor callbacks are not executed. The ODR trim formula matches the '
            'LSM6DSO 26 Hz coefficient; vectors avoid values whose binary32 result depends on fused rounding.',
            'Ghidra 12.1.2 RV32 SLEIGH stores 8 bytes for c.fsw (the full 64-bit FP register, upper half zero '
            'because it does not NaN-box); the hardware stores 4. The low 4 bytes are the IEEE binary32 result, '
            'and the extra 4 bytes at 0x80f1702c are an emulator artifact recorded as such.',
            'Nothing here proves the fitted part or its electrical behaviour; this is an attach contract, not a '
            'working IMU driver.'])


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
        parser.exit(2, f'Cannot inspect IMU attach: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
