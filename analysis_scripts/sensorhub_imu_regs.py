#!/usr/bin/env python3
"""Sensor-hub LSM6DSO register accessors: native sweep of every set/get body.

The hub LSM6DSO driver carries a block of ST ``lsm6dso_reg.c``-style register
accessors at ``0x80f7291a``-``0x80f72e86``.  This scope executes each original
accessor in isolation in the ``sensor-runtime`` project, through the original
context dispatch and SPI read/write callbacks of :mod:`sensorhub_imu_probe`,
with only the SPI transfer helper and memcpy supplied.  The ``spi`` stub
captures every transmitted byte, so each accessor's register, bit field and
read-modify-write behaviour is observed on the wire.

Setters read the register, replace their field and write it back; a failed
read skips the write and returns 1.  Getters store their field through the
output pointer and return the read status.  Some setters shift the argument
without masking it; bits that leave the byte are dropped by the byte store.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import sensorhub_imu_probe as probe
    from .sensorhub_memory import StartupMemory, MEMBER
else:
    import main_freertos_kernel as kernel
    import sensorhub_imu_probe as probe
    from sensorhub_memory import StartupMemory, MEMBER

BOUND = 5000
OUT = 0x81004000            # authored output buffer (outside the quiet stack)
OUT_SIZE = 8


def insert(lsb, width):
    mask = ((1 << width) - 1) << lsb
    return lambda old, val: (old & ~mask & 0xff) | ((val << lsb) & mask)


def shifted(lsb):
    """Field written as (val << lsb) | (old & low bits), val not masked (byte store drops overflow)."""
    low = (1 << lsb) - 1
    return lambda old, val: ((old & low) | (val << lsb)) & 0xff


# address: (ST name, [(register, update)]); two-step setters touch two registers.
SETTERS = {
    0x80f7291a: ('xl_full_scale_set', [(0x10, insert(2, 2))]),
    0x80f72958: ('xl_data_rate_set (ODR_XL field)', [(0x10, shifted(4))]),
    0x80f72994: ('gy_full_scale_set', [(0x11, insert(1, 3))]),
    0x80f729d2: ('gy_data_rate_set (ODR_G field)', [(0x11, shifted(4))]),
    0x80f72a0e: ('block_data_update_set', [(0x12, insert(6, 1))]),
    0x80f72a4e: ('xl_power_mode_set', [(0x14, lambda old, val: (old & 0x7f) | (((val >> 1) << 7) & 0xff)),
                                       (0x15, insert(4, 1))]),
    0x80f72abe: ('gy_power_mode_set', [(0x16, shifted(7))]),
    0x80f72bbe: ('reset_set', [(0x12, insert(0, 1))]),
    0x80f72c1c: ('boot_set', [(0x12, shifted(7))]),
    0x80f72c7e: ('gy_filter_lp1_set', [(0x13, insert(1, 1))]),
    0x80f72cbc: ('gy_lp1_bandwidth_set', [(0x15, insert(0, 3))]),
    0x80f72cf8: ('i3c_disable_set', [(0x18, lambda old, val: (old & ~2 & 0xff) | ((val >> 7) << 1 & 0xff)),
                                     (0x62, insert(3, 2))]),
    0x80f72d6a: ('fifo_xl_batch_set', [(0x09, insert(0, 4))]),
    0x80f72da6: ('fifo_gy_batch_set', [(0x09, shifted(4))]),
    0x80f72de2: ('fifo_mode_set', [(0x0a, insert(0, 3))]),
}
# address: (ST name, register, extractor) for single-byte field getters.
GETTERS = {
    0x80f72afc: ('xl_flag_data_ready_get', 0x1e, lambda v: v & 1),
    0x80f72b1e: ('gy_flag_data_ready_get', 0x1e, lambda v: (v >> 1) & 1),
    0x80f72b82: ('mem_bank_get', 0x01, lambda v: (v >> 6) if (v >> 6) in (1, 2) else 0),
    0x80f72bfa: ('reset_get', 0x12, lambda v: v & 1),
    0x80f72c5a: ('boot_get', 0x12, lambda v: v >> 7),
    0x80f72e60: ('fifo_ovr_flag_get', 0x3b, lambda v: (v >> 6) & 1),
}
RAW = {
    0x80f72b42: ('angular_rate_raw_get', 0x22, 6),
    0x80f72b4e: ('acceleration_raw_get', 0x28, 6),
    0x80f72bb4: ('device_id_get', 0x0f, 1),
}
ODR_CAL = 0x80f72b5a        # odr_cal_reg_get: pre-zeroed stack byte, then stored (0 on a failed read)
FIFO_LEVEL = 0x80f72e1e      # fifo_data_level_get: STATUS1 + (STATUS2[1:0] << 8)

CODE = probe.CODE + (
    (0x80f7291a, 0x29a, '59991e94d801493be5e6839aee56da9686803dde5a653156476e7b827a4f8294'),
    (0x80f72c1c, 0x26a, 'b8172c7d0b9783ab59d702e08e47b4cd808dec6147521e02bbb4aaeb0b9de6fa'),
)
DATA = probe.DATA
CSRS = kernel.CSRS


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Model(probe.Model):
    def raw_read(self, reg, n):
        status, data = self.read_reg(reg, n)
        if status == 0:
            for i, b in enumerate(data):
                self.write(OUT + i, 1, b, record=False)      # memcpy stub: no recorded write
        return status

    def operation(self, op):
        entry, val = op['entry'], op['args'][1]
        if entry in SETTERS:
            for reg, update in SETTERS[entry][1]:
                status, data = self.read_reg(reg)
                if status:
                    return 1
                status = self.write_reg(reg, update(data[0], val))
                if status:
                    return status
            return status
        if entry in GETTERS:
            _, reg, extract = GETTERS[entry]
            status, data = self.read_reg(reg)
            if status:
                raise ValueError('getter read failure reads stale stack; not modeled')
            self.write(OUT, 1, extract(data[0]))
            return status
        if entry in RAW:
            _, reg, n = RAW[entry]
            return self.raw_read(reg, n)
        if entry == ODR_CAL:
            status, data = self.read_reg(0x63)
            self.write(OUT, 1, data[0] if status == 0 else 0)
            return status
        if entry == FIFO_LEVEL:
            status, s1 = self.read_reg(0x3a)
            if status:
                return status
            status, s2 = self.read_reg(0x3b)
            if status:
                raise ValueError('second FIFO status read failure reads stale stack; not modeled')
            self.write(OUT, 2, s1[0] + ((s2[0] & 3) << 8))
            return status
        raise ValueError('accessor')


def contract(case):
    if case['scope'] != 'regs' or len(case['operations']) != 1:
        raise ValueError('regs scope')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi transactions')
    return result


def case(name, entry, val, spi):
    return dict(
        name='sensorhub_imu_regs_' + name, scope='regs', supplied={}, quiet=[list(q) for q in probe.QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': kernel.HARNESS_STACK}, fregisters={},
        stubs={str(probe.SPI_XFER): dict(kind='spi', seq=list(spi)), str(probe.MEMCPY): dict(kind='memcpy', args=0)},
        stops={}, snapshot=[[OUT, OUT_SIZE]],
        operations=[dict(name='regs', entry=entry, call=True, args=[probe.CTX, val], registers=False,
                         result=True, result_high=False)],
        memory=[[probe.SPI_HANDLE_PTR, probe.SPI_HANDLE.to_bytes(4, 'little').hex()], [OUT, '00' * OUT_SIZE]],
        spi=list(spi))


def setter_script(entry, old, fail_at=None):
    script = []
    for i, _ in enumerate(SETTERS[entry][1]):
        if fail_at == ('read', i):
            return script + [probe.fail(2)]
        script.append(probe.read_rx(old))
        if fail_at == ('write', i):
            return script + [probe.fail(2)]
        script.append(probe.write_ok())
    return script


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    for entry, (name, regs) in sorted(SETTERS.items()):
        label = name.split(' ')[0]
        add(case(f'{label}_set_from_zero', entry, 0xff, setter_script(entry, 0x00)))
        add(case(f'{label}_clear_from_ones', entry, 0x00, setter_script(entry, 0xff)))
        add(case(f'{label}_value_one', entry, 0x01, setter_script(entry, 0xa5)))
    add(case('xl_full_scale_set_read_error', 0x80f7291a, 2, setter_script(0x80f7291a, 0, ('read', 0))))
    add(case('xl_full_scale_set_write_error', 0x80f7291a, 2, setter_script(0x80f7291a, 0, ('write', 0))))
    add(case('xl_power_mode_set_second_read_error', 0x80f72a4e, 3,
             setter_script(0x80f72a4e, 0, ('read', 1))))
    add(case('i3c_disable_set_first_write_error', 0x80f72cf8, 0x81,
             setter_script(0x80f72cf8, 0, ('write', 0))))
    for entry, (name, reg, _) in sorted(GETTERS.items()):
        for value in (0x00, 0xff, 0x5a, 0x80, 0x42):
            add(case(f'{name}_{value:02x}', entry, OUT, [probe.read_rx(value)]))
    for entry, (name, reg, n) in sorted(RAW.items()):
        add(case(f'{name}_data', entry, OUT, [dict(status=0, rx='00' + bytes(range(0x11, 0x11 + n)).hex())]))
        add(case(f'{name}_error', entry, OUT, [probe.fail(n + 1)]))
    for value in (0x00, 0x7f, 0x80, 0xec):
        add(case(f'odr_cal_reg_get_{value:02x}', ODR_CAL, OUT, [probe.read_rx(value)]))
    add(case('odr_cal_reg_get_error_stores_zero', ODR_CAL, OUT, [probe.fail(2)]))
    for s1, s2 in ((0x34, 0x00), (0xff, 0xff), (0x00, 0x02), (0x10, 0xc1)):
        add(case(f'fifo_data_level_get_{s1:02x}_{s2:02x}', FIFO_LEVEL, OUT, [probe.read_rx(s1), probe.read_rx(s2)]))
    add(case('fifo_data_level_get_first_read_error', FIFO_LEVEL, OUT, [probe.fail(2)]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def accessor_table():
    rows = []
    for entry, (name, regs) in sorted(SETTERS.items()):
        fields = []
        for reg, update in regs:
            mask = update(0x00, 0xff) | (~update(0xff, 0x00) & 0xff)
            fields.append(dict(register=f'{reg:#04x}', field_mask=f'{mask:#04x}'))
        rows.append(dict(address=f'{entry:#010x}', name=name, kind='set', fields=fields))
    for entry, (name, reg, extract) in sorted(GETTERS.items()):
        rows.append(dict(address=f'{entry:#010x}', name=name, kind='get', fields=[dict(register=f'{reg:#04x}')]))
    for entry, (name, reg, n) in sorted(RAW.items()):
        rows.append(dict(address=f'{entry:#010x}', name=name, kind='raw', fields=[dict(register=f'{reg:#04x}',
                                                                                  length=n)]))
    rows.append(dict(address=f'{ODR_CAL:#010x}', name='odr_cal_reg_get', kind='get',
                     fields=[dict(register='0x63', note='zero on a failed read')]))
    rows.append(dict(address=f'{FIFO_LEVEL:#010x}', name='fifo_data_level_get', kind='get',
                     fields=[dict(register='0x3a'), dict(register='0x3b', bits='[1:0] -> level[9:8]')]))
    return sorted(rows, key=lambda r: r['address'])


def evidence(archive, vectors, validation):
    data = archive.read(MEMBER)
    if digest(data) != probe.HUB_HASH:
        raise ValueError('unexpected sensor-hub image')
    memory = StartupMemory(data)
    for address, size, expected in CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in probe.CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
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
        accessors=accessor_table(),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Each accessor executes in isolation through the original context dispatch and SPI callbacks; only '
            'the SPI transfer helper and memcpy are supplied, with authored receive bytes and statuses.',
            'Names follow the ST lsm6dso_reg.c accessor each body matches by register and bit field; the '
            'ODR setters here write only the raw ODR field (no ST-style power-mode bookkeeping).',
            'Getters with a failed read store a stale stack byte; those paths are not exercised. Which '
            'accessors the hub calls, in which order and with which values is a separate question (the '
            'activate/configure callbacks); nothing here drives a real LSM6DSO.'])


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
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, IndexError) as error:
        parser.exit(2, f'Cannot inspect IMU registers: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
