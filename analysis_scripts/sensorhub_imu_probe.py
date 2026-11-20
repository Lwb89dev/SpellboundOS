#!/usr/bin/env python3
"""Sensor-hub LSM6DSO IMU: probe, software reset, register access and SPI framing.

The Bip 6 motion sensor driver on the sensor hub is an ST **LSM6DSO** 6-axis
IMU driver laid out like ST's public ``lsm6dso_reg.c`` register layer: a
register context at ``0x80fd876c`` holds ``{write_reg, read_reg, handle}``
callbacks, and the reset/identity accessors read-modify-write ``CTRL3_C``
(``0x12``) and read ``WHO_AM_I`` (``0x0F``).  This scope executes, in the
``sensor-runtime`` project, every original body from the init/probe down to the
SPI read/write callbacks:

- init/probe ``0x80f71cb2``: reset, read WHO_AM_I, accept only ``0x6C``,
  otherwise log, wait 10 ms and retry, three attempts in total;
- software reset ``0x80f7021c``: set ``CTRL3_C.SW_RESET`` and poll it up to ten
  times, 1 ms apart, until it self-clears; log on timeout;
- WHO_AM_I wrapper ``0x80f71c88`` (caches the id byte at ``0x80f17027``);
- register accessors ``0x80f72bb4`` (WHO_AM_I), ``0x80f72bbe`` (reset set,
  read-modify-write of bit 0) and ``0x80f72bfa`` (reset get);
- context dispatch ``0x80f7290e`` (read via ``ctx+4``) / ``0x80f72914`` (write
  via ``ctx+0``), both passing ``ctx+8``;
- SPI callbacks ``0x80f6fafa`` (read: ``reg | 0x80`` followed by dummy bytes,
  ``n + 1`` byte transfer, data copied from the second received byte) and
  ``0x80f6fb60`` (write: ``reg, data[0]``, two byte transfer).

Only the SPI transfer helper ``0x80f898ae(handle, tx, rx, len, timeout)``, the
delay, memcpy and the logger are supplied.  An ``spi`` stub captures the bytes
each transfer sends and injects scripted receive bytes and statuses, so the
on-wire framing is observed rather than assumed.  No bus is driven.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from .sensorhub_memory import StartupMemory, MEMBER
else:
    import main_freertos_kernel as kernel
    from sensorhub_memory import StartupMemory, MEMBER

MASK = 0xffffffff
BOUND = 5000
HUB_HASH = '06f07541e8bb22b6118f081e791c3a4e40cbff2decd8ee478a7e82df826e9d0f'

INIT = 0x80f71cb2              # lsm6dso init/probe
RESET = 0x80f7021c            # software reset + poll
WHOAMI = 0x80f71c88           # WHO_AM_I wrapper (caches the id byte)
DEVICE_ID_GET = 0x80f72bb4    # register accessor: read WHO_AM_I
RESET_SET = 0x80f72bbe        # register accessor: CTRL3_C.SW_RESET read-modify-write
RESET_GET = 0x80f72bfa        # register accessor: read CTRL3_C.SW_RESET
CTX_READ = 0x80f7290e         # ctx->read_reg(ctx->handle, ...)
CTX_WRITE = 0x80f72914        # ctx->write_reg(ctx->handle, ...)
SPI_READ = 0x80f6fafa         # SPI read callback
SPI_WRITE = 0x80f6fb60        # SPI write callback
SPI_XFER = 0x80f898ae         # SPI transfer helper (supplied)
MEMCPY = 0x80fcddf0           # memcpy (supplied)
DELAY = 0x80f7ff0e            # millisecond delay (supplied)
LOGGER = 0x80f86d34           # logger (supplied)
CTX = 0x80fd876c              # register context {write_reg, read_reg, handle}
SPI_HANDLE_PTR = 0x80f17018   # .bss word holding the SPI bus handle (set at runtime)
WHOAMI_CACHE = 0x80f17027     # .bss byte the WHO_AM_I wrapper stores the id into

SPI_HANDLE = 0x5a5a0001       # authored bus handle value
SPI_TIMEOUT = 5000            # 0x1388, passed by both callbacks
CTRL3_C = 0x12
WHO_AM_I = 0x0f
READ_FLAG = 0x80
LSM6DSO_WHOAMI = 0x6c         # 'l'
CTRL3_C_DEFAULT = 0x04        # IF_INC set after reset
RESET_POLLS = 10
INIT_ATTEMPTS = 3
LOG_ERROR, LOG_INFO = 3, 6

CODE = (
    (INIT, 0xa6, '1a9a807bf460a8896a15cf25d48cc6721c72fb9a752842d0adf04300e3de2e8b'),
    (RESET, 0x62, '8e1e15ab4d8c5beda59876f2411cc55f4a0ebe49605898a07a3925907d3e08bc'),
    (WHOAMI, 0x2a, '4342faa71a79ed4c10ec82cb94b9ce486e1bfccb46f93d59c0e8b384e83af20d'),
    (DEVICE_ID_GET, 0x68, '2c97608f9526a7d6dcb5bae45284a02b7a74692d1ed6e2609dac8e0e26092f65'),
    (CTX_READ, 0xc, 'c2f4dced948b7ebbb847d6c9fd08096090d9a52cd37e82d076f46ee4a8c5ce0b'),
    (SPI_READ, 0xa0, 'cab8ea5d792ce63d6ec1daf02505b57f02de00c141216b43313c6716d22c7454'),
)
DATA = (
    (CTX, 0xc, '301bdbbde148ef12e7ebcb4144765c7f814aded95907606ed2993b288f624492'),
)
CALL_SITES = (
    (0x80f71cde, RESET), (0x80f71ce6, WHOAMI), (0x80f71d14, LOGGER), (0x80f71d34, LOGGER),
    (0x80f71d40, DELAY), (0x80f71d52, LOGGER),
    (0x80f70238, RESET_SET), (0x80f70242, RESET_GET), (0x80f70248, DELAY), (0x80f70270, LOGGER),
    (0x80f71c9a, DEVICE_ID_GET),
    (0x80f72bba, CTX_READ), (0x80f72bd0, CTX_READ), (0x80f72bec, CTX_WRITE), (0x80f72c08, CTX_READ),
    (0x80f6fb3e, SPI_XFER), (0x80f6fb4e, MEMCPY), (0x80f6fb8c, SPI_XFER),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(v):
    return v & MASK


def read_rx(value, n=1):
    """Receive bytes for an n-byte register read: one dummy byte then the data."""
    return dict(status=0, rx='00' + bytes([value] * n).hex())


def write_ok():
    return dict(status=0, rx='0000')


def fail(n):
    return dict(status=1, rx='00' * n)


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.spi = list(case['spi'])
        self.buf = None

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def transfer(self, tx):
        self.actions.append(f'spi:{SPI_HANDLE}:{len(tx)}:{SPI_TIMEOUT}:{bytes(tx).hex()}')
        if not self.spi:
            raise ValueError('spi sequence bound')
        t = self.spi.pop(0)
        rx = bytes.fromhex(t['rx'])
        if len(rx) != len(tx):
            raise ValueError('spi rx length')
        return t['status'], rx

    # SPI callbacks.
    def read_reg(self, reg, n=1):
        status, rx = self.transfer([reg | READ_FLAG] + [0] * n)
        if status != 0:
            return 1, None
        self.leaf(MEMCPY)
        return 0, rx[1:1 + n]

    def write_reg(self, reg, value):
        status, _ = self.transfer([reg, value])
        return 1 if status else 0

    # Register accessors.
    def reset_set(self, value):
        status, data = self.read_reg(CTRL3_C)
        if status:
            return status
        return self.write_reg(CTRL3_C, (data[0] & 0xfe) | (value & 1))

    def reset_get(self):
        status, data = self.read_reg(CTRL3_C)
        if status:
            # The accessor then reads an uninitialized stack byte; vectors avoid it.
            raise ValueError('reset poll read failure is not modeled')
        return data[0] & 1

    def reset(self):
        self.reset_set(1)
        for _ in range(RESET_POLLS):
            busy = self.reset_get()
            self.leaf(DELAY, 1)
            if busy == 0:
                return
        self.leaf(LOGGER, LOG_ERROR)

    def whoami(self):
        status, data = self.read_reg(WHO_AM_I)
        if status == 0:
            self.buf = data[0]
        # The wrapper caches the caller's buffer, stale or not.
        self.write(WHOAMI_CACHE, 1, self.buf)
        return status

    def init(self):
        self.buf = 0
        result = 0
        for _ in range(INIT_ATTEMPTS):
            self.reset()
            status = self.whoami()
            if status == 0 and self.buf == LSM6DSO_WHOAMI:
                self.leaf(LOGGER, LOG_INFO)
                return 0
            result = 4 if status else 1
            self.leaf(LOGGER, LOG_INFO)
            self.leaf(DELAY, 10)
        return result

    def operation(self, op):
        name = op['name'].split('#')[0]
        if name == 'init':
            return self.init()
        if name == 'reset':
            self.reset()
            return None
        raise ValueError('operation')


def contract(case):
    if case['scope'] not in ('init', 'reset'):
        raise ValueError('imu scope')
    if len(case['operations']) != 1:
        raise ValueError('bounded operations')
    model = Model(case)
    result = model.run()
    if model.spi:
        raise ValueError('unused spi transactions')
    return result


def op(name):
    entry = {'init': INIT, 'reset': RESET}[name]
    return dict(name=name, entry=entry, call=True, args=[], registers=False,
                result=name == 'init', result_high=False)


def stubs(spi):
    return {
        str(SPI_XFER): dict(kind='spi', seq=list(spi)),
        str(MEMCPY): dict(kind='memcpy', args=0),
        str(DELAY): dict(kind='return', args=1),
        str(LOGGER): dict(kind='return', args=1),
    }


def case(name, scope, spi):
    return dict(
        name='sensorhub_imu_probe_' + name, scope=scope, supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stubs(spi), stops={}, snapshot=[], operations=[op(scope)],
        memory=[[SPI_HANDLE_PTR, struct.pack('<I', SPI_HANDLE).hex()]], spi=list(spi))


def reset_ok(polls_busy=0, ctrl3=CTRL3_C_DEFAULT):
    """SPI script of a reset whose SW_RESET bit reads set polls_busy times, then clear."""
    return [read_rx(ctrl3), write_ok()] + [read_rx(ctrl3 | 1)] * polls_busy + [read_rx(ctrl3)]


def reset_timeout(ctrl3=CTRL3_C_DEFAULT):
    return [read_rx(ctrl3), write_ok()] + [read_rx(ctrl3 | 1)] * RESET_POLLS


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('reset_clears_immediately', 'reset', reset_ok()))
    add(case('reset_clears_on_third_poll', 'reset', reset_ok(polls_busy=2)))
    add(case('reset_preserves_other_ctrl3_bits', 'reset', reset_ok(ctrl3=0x44)))
    add(case('reset_times_out', 'reset', reset_timeout()))
    add(case('reset_rmw_read_error_skips_write', 'reset', [fail(2), read_rx(0)]))
    add(case('reset_write_error_still_polls', 'reset',
             [read_rx(CTRL3_C_DEFAULT), fail(2), read_rx(CTRL3_C_DEFAULT)]))
    add(case('probe_identifies_lsm6dso', 'init', reset_ok() + [read_rx(LSM6DSO_WHOAMI)]))
    add(case('probe_reset_timeout_then_id_ok', 'init', reset_timeout() + [read_rx(LSM6DSO_WHOAMI)]))
    add(case('probe_wrong_id_retries_three_times', 'init',
             (reset_ok() + [read_rx(0x6a)]) * INIT_ATTEMPTS))
    add(case('probe_read_error_retries_three_times', 'init',
             (reset_ok() + [fail(2)]) * INIT_ATTEMPTS))
    add(case('probe_read_error_keeps_stale_id', 'init',
             reset_ok() + [read_rx(0x6a)] + reset_ok() + [fail(2)] + reset_ok() + [read_rx(LSM6DSO_WHOAMI)]))
    add(case('probe_recovers_on_second_attempt', 'init',
             reset_ok() + [fail(2)] + reset_ok(polls_busy=1) + [read_rx(LSM6DSO_WHOAMI)]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    data = archive.read(MEMBER)
    if digest(data) != HUB_HASH:
        raise ValueError('unexpected sensor-hub image')
    memory = StartupMemory(data)
    for address, size, expected in CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    write_cb, read_cb, handle = struct.unpack('<III', memory.read(CTX, 12))
    if (write_cb, read_cb, handle) != (SPI_WRITE, SPI_READ, 0):
        raise ValueError('register context callbacks')
    names = memory.read(CTX + 0xc, 0x18)
    if names != b'lsm6dso G\0\0\0lsm6dso A\0\0\0':
        raise ValueError('device names after context')
    if any(memory.read(SPI_HANDLE_PTR, 4)):
        raise ValueError('SPI handle word is expected to start zero (.bss)')
    for site, target in CALL_SITES:
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
        hub_sha256=HUB_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        sensor='LSM6DSO', who_am_i=f'{LSM6DSO_WHOAMI:#04x}',
        registers=dict(CTRL3_C=f'{CTRL3_C:#04x}', WHO_AM_I=f'{WHO_AM_I:#04x}', sw_reset_bit=0),
        spi_framing=dict(
            read='tx = [reg | 0x80] + n dummy bytes, length n + 1; data = rx[1 : n + 1]',
            write='tx = [reg, data[0]], length 2 (only the first data byte is placed)',
            timeout=SPI_TIMEOUT, read_flag=f'{READ_FLAG:#04x}'),
        context=dict(address=f'{CTX:#010x}', write_reg=f'{SPI_WRITE:#010x}', read_reg=f'{SPI_READ:#010x}',
                     handle=0, names=['lsm6dso G', 'lsm6dso A'], spi_handle_word=f'{SPI_HANDLE_PTR:#010x}'),
        entries=dict(init=f'{INIT:#010x}', reset=f'{RESET:#010x}', whoami=f'{WHOAMI:#010x}',
                     device_id_get=f'{DEVICE_ID_GET:#010x}', reset_set=f'{RESET_SET:#010x}',
                     reset_get=f'{RESET_GET:#010x}', ctx_read=f'{CTX_READ:#010x}',
                     ctx_write=f'{CTX_WRITE:#010x}', spi_read=f'{SPI_READ:#010x}',
                     spi_write=f'{SPI_WRITE:#010x}'),
        reset_polls=RESET_POLLS, init_attempts=INIT_ATTEMPTS,
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Every body from the init/probe down to the SPI read/write callbacks executes in the sensor-hub '
            'emulator; only the SPI transfer helper 0x80f898ae, memcpy, the delay and the logger are supplied. '
            'The spi stub captures the transmitted bytes and injects authored receive bytes and statuses; no '
            'transfer reaches a real bus or LSM6DSO.',
            'The SPI handle word 0x80f17018 is .bss set at runtime by the caller 0x80f726ee; its value here is '
            'authored. The bus instance, chip select, SPI mode, clock and the helper internals are not executed.',
            'A failed CTRL3_C read during the reset poll makes the original accessor read an uninitialized '
            'stack byte; vectors do not exercise that path. A failed WHO_AM_I read leaves the caller buffer '
            'unchanged, so the cached id is the previous attempt value (zero before the first good read).',
            'Configuration beyond reset/identity (ODR, full scale, FIFO, interrupt routing, embedded '
            'functions), reset timing and the fitted part remain unproved and need the device. This is a '
            'probe and bus-framing contract, not a working IMU driver.'])


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
        parser.exit(2, f'Cannot inspect IMU probe: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
