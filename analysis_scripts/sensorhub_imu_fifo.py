#!/usr/bin/env python3
"""Sensor-hub LSM6DSO FIFO read: overrun/level, bulk tagged read, packet, decode, remap.

``0x80f710ac(remaining_out)`` drains the LSM6DSO FIFO.  This scope executes it
in the ``sensor-runtime`` project with its original callees:

- ``fifo_ovr_flag_get`` / ``fifo_data_level_get`` and, on overrun, the register
  dump, ``device_id_get`` and ``mem_bank_get`` (see :mod:`sensorhub_imu_regs`);
- the packet allocator ``0x80f6453e`` and release ``0x80f6462c``;
- the tagged-word decoder ``0x80f6fc42`` (tag = byte >> 3: 2 accelerometer,
  1 gyroscope; six data bytes; per-axis offsets at ``0x80f4ff00``);
- the orientation remap ``0x80f64660`` (8-entry signed 2x2 + z table at
  ``0x80fd4d0c``, optional wrist flip of x/y);
- the SPI callbacks of :mod:`sensorhub_imu_probe`.

A pass takes ``min(level, 160 - buffered)`` words (even when the gyroscope
flag is set), reads ``7 * n + 1`` bytes in one transfer whose first byte is
``0xf8`` (FIFO_DATA_OUT_TAG | read), appends the words to the driver cache,
builds one accelerometer packet (type 2, 4096 LSB/g, rate rounded down to a
multiple of 25, timestamp moved back by ``1000 / rate`` ms per word left in
the FIFO) and decodes, remaps and releases it.

Supplied: the SPI transfer helper, allocator/free, memset, memcpy, the
timestamp source ``0x80f63302``, the packet queue ``0x80f85d14``, the
algorithm hook ``0x80f63092``, the event post, the sensor restore
``0x80f70f92``, the dump comparator ``0x80f7092a``, delay and logger.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import sensorhub_imu_mode as mode
    from . import sensorhub_imu_probe as probe
    from . import sensorhub_imu_regs as regs
    from .sensorhub_memory import StartupMemory, MEMBER
else:
    import main_freertos_kernel as kernel
    import sensorhub_imu_mode as mode
    import sensorhub_imu_probe as probe
    import sensorhub_imu_regs as regs
    from sensorhub_memory import StartupMemory, MEMBER

BOUND = 20000
M16, M32 = 0xffff, 0xffffffff

FIFO_READ = 0x80f710ac
DECODE = 0x80f6fc42
PKT_ALLOC = 0x80f6453e
PKT_RELEASE = 0x80f6462c
REMAP = 0x80f64660
MALLOC, FREE, MEMSET = 0x80f84cee, 0x80f84d24, 0x80fcdfcc
TIMESTAMP = 0x80f63302
QUEUE = 0x80f85d14
ALGORITHM = 0x80f63092
EVENT_POST = mode.EVENT_POST
RESTORE = 0x80f70f92
DUMP_COMPARE = 0x80f7092a
LOGGER, MEMCPY = probe.LOGGER, probe.MEMCPY
FIFO_OVR_GET, FIFO_LEVEL_GET = 0x80f72e60, 0x80f72e1e
DEVICE_ID_GET, MEM_BANK_GET = 0x80f72bb4, 0x80f72b82

# globals
ACTIVE = 0x80f17030            # nonzero once enabled
BUFFERED = 0x80f17024          # u16 words already in the cache
GYRO_ON = 0x80f1702c           # nonzero: keep the word count even
CACHE_PTR, CACHE_TAIL_PTR = 0x80f17020, 0x80f1701c
OVERFLOWS = 0x80f1700e         # u8; a third consecutive overflow restores the sensor
DUMP2 = 0x80f16b1f             # one-shot overrun dump flag (1 in the image)
SENSITIVITY = 0x80f16b28       # 4096 in the image (LSB/g at +-8 g)
RATE = mode.RATE
ORIENT_XL = 0x80f16fb8         # .bss orientation index for types 2 and 4
WRIST = 0x80f16fb0             # .bss: 1 negates remapped x and y
OFFSETS = 0x80f4ff00           # .bss: 6 words, accelerometer [0..2], gyroscope [3..5]
DUMP_BUF_A, DUMP_BUF_B = 0x80f4fe00, 0x80f4fe80
ORIENT_TABLE = 0x80fd4d0c
TAG_STR = PKT_TAG_STR = 0x80fd4868   # "drivers_sensor"

CACHE = 0x81010000             # authored cache allocation (0x605 bytes, tail at +0x460)
BIG = 0x81020000               # authored bulk-read buffer (more than 60 words)
PACKET = 0x81030000            # authored packet allocation
OUT = 0x81004000
TS = 0x0000001234567890
MAX_WORDS, SMALL_WORDS = 160, 60
TAG_XL, TAG_GY = 2, 1
EVENT_ERROR, EVENT_ALGO = 0x102, 0x10e
LOG_WARN, LOG_INFO, LOG_ERROR = 4, 6, 3

CODE = mode.CODE + (
    (0x80f710ac, 0x3f4, '353bffed7e9b273eb3ea84319f0ab19be33b393bdec0cbd340746f4e8d8abc44'),
    (0x80f6fc42, 0x134, '06a5274e15181f585e72f2752369e74fef58f2692eebdffffa6bbac3f0868dac'),
    (0x80f6453e, 0xa4, 'afec2a8694f2248c350c858baf0b273909a3dfb1300a824909b7e1f5c2628acd'),
    (0x80f6462c, 0x34, 'e6985239fd7a4d5932b48394e729c0e6b4fd5bb33b5c36b1a6e63ec88732fc5e'),
    (0x80f64660, 0x27c, '8168d52780ae7d4e8d51910cb46e29f025007180e604b03193b55af05df031a8'),
)
DATA = mode.DATA + (
    (ORIENT_TABLE, 0x28, '7927054e1e3fddbec83d92bc01e994374aedf163f08f867f8f66588845787c1d'),
)
CALL_SITES = (
    (0x80f711a6, FIFO_OVR_GET), (0x80f711b6, FIFO_LEVEL_GET), (0x80f711fa, mode.DUMP),
    (0x80f71238, DEVICE_ID_GET), (0x80f71246, MEM_BANK_GET), (0x80f71144, RESTORE),
    (0x80f71304, MALLOC), (0x80f7132e, probe.SPI_XFER), (0x80f7136a, MEMCPY), (0x80f713b2, PKT_ALLOC),
    (0x80f71418, DECODE), (0x80f71422, REMAP), (0x80f7142e, ALGORITHM), (0x80f7146a, PKT_RELEASE),
    (0x80f712e6, FREE), (0x80f6456c, MALLOC), (0x80f645b6, TIMESTAMP), (0x80f6463a, QUEUE),
)
CSRS = kernel.CSRS


def digest(data):
    return hashlib.sha256(data).hexdigest()


def s8(b):
    return b - 0x100 if b & 0x80 else b


def remap_sample(x, y, z, entry, wrist):
    m0, m1, m2, m3, m4 = entry
    nx, ny, nz = (x * m0 + y * m1) & M16, (x * m2 + y * m3) & M16, (z * m4) & M16
    if wrist == 1:
        nx, ny = -nx & M16, -ny & M16
    return nx, ny, nz


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']
        self.table = [tuple(e) for e in case['orientation_table']]
        self.mallocs = list(self.svc['malloc'])
        self.frame = case['registers']['sp'] - 0x590

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def u32(self, a):
        return self.read(a, 4)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    def getter_byte(self, reg, extract):
        status, data = self.read_reg(reg)
        if status:
            raise ValueError('getter read failure not modeled')
        return extract(data[0])

    def malloc(self, *args):
        self.leaf(MALLOC, *args)
        return self.mallocs.pop(0)

    def event(self, event_id, value=0):
        self.leaf(EVENT_POST)
        self.actions.append('cap:' + struct.pack('<HHI', event_id, 0, value).hex())

    def overflow(self):
        count = (self.u8(OVERFLOWS) + 1) & 0xff
        self.put(OVERFLOWS, 1, count)
        if count > 2:
            self.leaf(RESTORE)
            self.put(OVERFLOWS, 1, 0)
        self.event(EVENT_ERROR)
        return 6

    def alloc_packet(self, size):
        if size == 0:
            return 0
        total = (size + 0x28) + 0x18
        p = self.malloc(4, PKT_TAG_STR, total, 4)
        if not p:
            self.leaf(LOGGER, LOG_ERROR)
            return 0
        self.leaf(MEMSET, p, 0, total)
        for i in range(total):
            self.put(p + i, 1, 0)
        self.put(p + 0x14, 4, p + 0x18)
        self.put(p + 0x10, 4, 1)
        self.put(p + 0, 2, 1)
        self.put(p + 2, 2, size)
        self.leaf(TIMESTAMP)
        hdr = p + 0x18
        self.put(hdr + 0x20, 4, p + 0x40)
        self.put(hdr + 8, 4, TS & M32)
        self.put(hdr + 0xc, 4, TS >> 32)
        return p

    def decode(self, words, n, hdr):
        count, xl = self.u16(hdr + 0x14), 0
        offsets = [self.u32(OFFSETS + 4 * i) for i in range(3)]
        for i in range(n):
            tag = self.u8(words + 7 * i) >> 3
            if tag == TAG_XL and xl < count:
                dst = self.u32(hdr + 0x20) + xl * 6
                for k in range(3):
                    v = self.u16(words + 7 * i + 1 + 2 * k)
                    self.put(dst + 2 * k, 2, v + offsets[k])
                xl += 1
            elif tag == TAG_XL:
                xl += 1
        if count != xl:
            self.leaf(LOGGER, LOG_WARN)
            return 7
        return 0

    def remap(self, hdr):
        index = self.u32(ORIENT_XL)
        if index > 7:
            self.leaf(LOGGER, LOG_WARN)
            return
        entry, wrist = self.table[index], self.u8(WRIST)
        data = self.u32(hdr + 0x20)
        for i in range(self.u16(hdr + 0x14)):
            x, y, z = (self.u16(data + 6 * i + 2 * k) for k in range(3))
            for k, v in enumerate(remap_sample(x, y, z, entry, wrist)):
                self.put(data + 6 * i + 2 * k, 2, v)

    def release(self, p):
        self.leaf(QUEUE)
        if self.svc['queue'] == 0:
            self.put(p + 0x14, 4, 0)
            self.leaf(FREE, 4, PKT_TAG_STR, p)

    def fifo_read(self, out):
        if not self.u32(ACTIVE):
            return 3
        if self.u16(BUFFERED) > MAX_WORDS - 1:
            self.leaf(LOGGER, LOG_WARN)
            return self.overflow()
        ovr = self.getter_byte(0x3b, lambda v: (v >> 6) & 1)
        status, s1 = self.read_reg(0x3a)
        status2, st2 = self.read_reg(0x3b)
        if status or status2:
            raise ValueError('level read failure not modeled')
        level = s1[0] + ((st2[0] & 3) << 8)
        if ovr:
            self.leaf(LOGGER, LOG_WARN)
            if self.u8(DUMP2):
                self.put(DUMP2, 1, 0)
                self.dump_into(DUMP_BUF_A)
                self.leaf(DUMP_COMPARE)
                self.leaf(DUMP_COMPARE)
            status, data = self.read_reg(0x0f, 1)
            if status == 0:
                self.write(self.frame + 0x14, 1, data[0], record=False)
            self.getter_byte(0x01, lambda v: v)
            self.leaf(LOGGER, LOG_INFO)
            return self.overflow()
        result = ovr
        take = min(level, MAX_WORDS - self.u16(BUFFERED))
        if self.u32(GYRO_ON):
            take &= ~1
        remaining = (level - take) & M16
        big = 0
        if take:
            nbytes = take * 7
            if take > SMALL_WORDS:
                big = buf = self.malloc(4, TAG_STR, nbytes + 1, 4)
            else:
                buf = self.u32(CACHE_TAIL_PTR)
            if not buf:
                self.leaf(LOGGER, LOG_WARN)
                result = 10
            else:
                self.put(buf, 1, 0xf8)
                st, rx = self.transfer_bulk(buf, nbytes + 1)
                if st:
                    self.leaf(LOGGER, LOG_WARN)
                    result = 4
                else:
                    result = self.consume(buf, take, remaining)
            if big:
                self.leaf(FREE, 4, TAG_STR, big)
        if out:
            self.put(out, 2, remaining)
        return result

    def transfer_bulk(self, buf, length):
        tx = bytes(self.u8(buf + i) for i in range(min(length, 16)))
        self.actions.append(f'spi:{probe.SPI_HANDLE}:{length}:{probe.SPI_TIMEOUT}:{tx.hex()}')
        t = self.spi.pop(0)
        rx = bytes.fromhex(t['rx'])
        if len(rx) != length:
            raise ValueError('spi rx length')
        for i, b in enumerate(rx):
            self.put(buf + i, 1, b)
        return t['status'], rx

    def consume(self, buf, take, remaining):
        buffered = self.u16(BUFFERED)
        cache = self.u32(CACHE_PTR) + buffered * 7
        self.leaf(MEMCPY)
        for i in range(take * 7):
            self.write(cache + i, 1, self.u8(buf + 1 + i), record=False)
        self.put(BUFFERED, 2, buffered + take)
        rate = self.u16(RATE)
        self.leaf(MEMSET, self.frame + 0x40, 0, 0x520)
        self.leaf(MEMSET, self.frame + 0x14, 0, 0x2c)
        if self.u32(GYRO_ON):
            xl, left = take >> 1, remaining >> 1
        else:
            xl, left = take, remaining
        p = self.alloc_packet((xl * 6) & M16)
        if not p:
            self.leaf(LOGGER, LOG_WARN)
            return 0
        hdr = self.u32(p + 0x14)
        self.put(hdr + 0x10, 4, self.u32(SENSITIVITY))
        self.put(hdr + 0, 4, 2)
        self.put(hdr + 4, 4, 0)
        self.put(hdr + 0x14, 2, xl)
        self.put(hdr + 0x16, 2, (rate // 25) * 25)
        period = int(1000 / rate) if rate else 0
        ts = (self.u32(hdr + 0xc) << 32 | self.u32(hdr + 8)) - period * left
        self.put(hdr + 8, 4, ts & M32)
        self.put(hdr + 0xc, 4, (ts >> 32) & M32)
        self.put(p + 8, 4, 2)
        self.put(p + 0xc, 4, 0)
        self.put(p + 4, 2, 1)
        if self.decode(buf + 1, take, hdr):
            self.event(EVENT_ERROR)
        else:
            self.remap(hdr)
            self.leaf(ALGORITHM)
            if self.svc['algorithm']:
                self.event(EVENT_ALGO, 0)
                self.leaf(LOGGER, LOG_INFO)
        self.release(p)
        return 0

    def dump_into(self, buf):
        for reg in range(0x80):
            status, data = self.read_reg(reg)
            if status:
                self.leaf(LOGGER, LOG_ERROR)
                self.put(buf + reg, 1, 0xff)
            else:
                self.write(buf + reg, 1, data[0], record=False)

    def operation(self, op):
        if op['name'] != 'fifo':
            raise ValueError('operation')
        return self.fifo_read(op['args'][0])


def contract(case):
    if case['scope'] != 'fifo' or len(case['operations']) != 1:
        raise ValueError('fifo scope')
    model = Model(case)
    result = model.run()
    if model.spi or model.mallocs:
        raise ValueError('unused scripted inputs')
    return result


def word(tag, x, y, z, cnt=0):
    return bytes([(tag << 3) | (cnt << 1)]) + struct.pack('<hhh', x, y, z)


def case(name, level, words=(), ovr=0, table=None, **over):
    g = dict(active=1, buffered=0, gyro=0, overflows=0, dump2=0, rate=26, orient=0, wrist=0,
             offsets=(0, 0, 0, 0, 0, 0), queue=1, algorithm=0, spi_fail=0, malloc=None, bulk=True)
    g.update(over)
    take = min(level, MAX_WORDS - g['buffered'])
    if g['gyro']:
        take &= ~1
    spi = []
    if g['active'] and g['buffered'] <= MAX_WORDS - 1:
        spi += [probe.read_rx(ovr << 6), probe.read_rx(level & 0xff), probe.read_rx((level >> 8) & 3 | ovr << 6)]
        if ovr:
            if g['dump2']:
                spi += [probe.read_rx(r ^ 0x33) for r in range(0x80)]
            spi += [probe.read_rx(0x6c), probe.read_rx(0x00)]
        elif take and g['bulk']:
            payload = b''.join(words)[:take * 7].ljust(take * 7, b'\0')
            spi.append(dict(status=g['spi_fail'], rx='00' + payload.hex()))
    if g['malloc'] is None:
        mallocs = []
        if take and not ovr and g['active'] and g['buffered'] <= MAX_WORDS - 1:
            if take > SMALL_WORDS:
                mallocs.append(BIG)
            if not g['spi_fail']:
                mallocs.append(PACKET)
    else:
        mallocs = list(g['malloc'])
    mem = [
        [ACTIVE, struct.pack('<I', g['active']).hex()], [BUFFERED, struct.pack('<H', g['buffered']).hex()],
        [GYRO_ON, struct.pack('<I', g['gyro']).hex()], [CACHE_PTR, struct.pack('<I', CACHE).hex()],
        [CACHE_TAIL_PTR, struct.pack('<I', CACHE + 0x460).hex()], [OVERFLOWS, f"{g['overflows']:02x}"],
        [DUMP2, f"{g['dump2']:02x}"], [SENSITIVITY, struct.pack('<I', 0x1000).hex()],
        [RATE, struct.pack('<H', g['rate']).hex()], [ORIENT_XL, struct.pack('<I', g['orient']).hex()],
        [WRIST, f"{g['wrist']:02x}"], [OFFSETS, struct.pack('<6i', *g['offsets']).hex()],
        [probe.SPI_HANDLE_PTR, struct.pack('<I', probe.SPI_HANDLE).hex()], [OUT, '0000'],
        [CACHE, '00' * 0x605], [PACKET, '00' * 0x80], [BIG, '00' * 0x500],
    ]
    quiet = [list(q) for q in probe.QUIET] + [[CACHE, CACHE + 0x605], [BIG, BIG + 0x500],
                                              [PACKET, PACKET + 0x400], [DUMP_BUF_A, DUMP_BUF_A + 0x80]]
    stubs = {
        str(probe.SPI_XFER): dict(kind='spi', seq=spi), str(MEMCPY): dict(kind='memcpy', args=0),
        str(probe.DELAY): dict(kind='return', args=1), str(LOGGER): dict(kind='return', args=1),
        str(MALLOC): dict(kind='return', args=4, seq=mallocs), str(FREE): dict(kind='return', args=3),
        str(MEMSET): dict(kind='memset', args=3), str(TIMESTAMP): dict(kind='return', args=0, value=TS & M32,
                                                                       value_a1=TS >> 32),
        str(QUEUE): dict(kind='return', args=0, value=g['queue']),
        str(ALGORITHM): dict(kind='store', out_arg=2, size=1, value=g['algorithm'], args=0),
        str(EVENT_POST): dict(kind='capture', ptr_arg=0, size=8, value=0, args=0),
        str(RESTORE): dict(kind='return', args=0), str(DUMP_COMPARE): dict(kind='return', args=0),
    }
    return dict(
        name='sensorhub_imu_fifo_' + name, scope='fifo', supplied={}, quiet=quiet, csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': kernel.HARNESS_STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[[PACKET, 0x40 + 0x40], [CACHE, 0x38]],
        operations=[dict(name='fifo', entry=FIFO_READ, call=True, args=[OUT], registers=False,
                         result=True, result_high=False)],
        memory=mem, spi=spi, services=dict(queue=g['queue'], algorithm=g['algorithm'], malloc=mallocs),
        orientation_table=[list(t) for t in (table or ORIENTATION)])


# The 8 orientation entries (m00, m01, m10, m11, mz) as decoded from 0x80fd4d0c;
# evidence() checks this against the image.
ORIENTATION = (
    (1, 0, 0, 1, 1), (1, 0, 0, -1, -1), (-1, 0, 0, 1, -1), (-1, 0, 0, -1, 1),
    (0, 1, 1, 0, -1), (0, 1, -1, 0, 1), (0, -1, 1, 0, 1), (0, -1, -1, 0, -1),
)


def xl_words(n, base=100):
    return [word(TAG_XL, base + i, -2 * (base + i), 4096 - i) for i in range(n)]


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('inactive_returns_3', 4, xl_words(4), active=0))
    add(case('three_accel_words', 3, xl_words(3)))
    add(case('level_zero_reports_nothing', 0))
    for o in range(8):
        add(case(f'orientation_{o}', 2, xl_words(2, 1000), orient=o))
    add(case('wrist_flip_negates_xy', 2, xl_words(2, 1000), wrist=1))
    add(case('orientation_out_of_range_logged', 2, xl_words(2), orient=9))
    add(case('calibration_offsets_added', 2, xl_words(2), offsets=(10, -20, 0x10030, 7, 8, 9)))
    add(case('mixed_tags_gyro_skipped_count_mismatch', 4,
             [word(TAG_XL, 1, 2, 3), word(TAG_GY, 4, 5, 6), word(TAG_XL, 7, 8, 9), word(7, 1, 1, 1)]))
    add(case('gyro_flag_even_pairs', 5,
             [word(TAG_GY, 1, 2, 3), word(TAG_XL, 4, 5, 6), word(TAG_GY, 7, 8, 9), word(TAG_XL, 10, 11, 12),
              word(TAG_GY, 13, 14, 15)], gyro=1))
    add(case('timestamp_backdated_by_remaining', 40, xl_words(40), buffered=150, rate=104))
    add(case('large_read_uses_heap_buffer', 61, xl_words(61)))
    add(case('large_read_heap_failure', 61, xl_words(61), malloc=[0], bulk=False))
    add(case('packet_alloc_failure', 2, xl_words(2), malloc=[0]))
    add(case('spi_failure', 2, xl_words(2), spi_fail=1))
    add(case('cache_full_overflow_event', 2, buffered=160))
    add(case('cache_full_third_overflow_restores', 2, buffered=200, overflows=2))
    add(case('fifo_overrun_event', 3, ovr=1))
    add(case('fifo_overrun_with_dump', 3, ovr=1, dump2=1))
    add(case('algorithm_flag_posts_event', 2, xl_words(2), algorithm=1))
    add(case('queue_refused_packet_freed', 2, xl_words(2), queue=0))
    add(case('rate_833_rounded', 3, xl_words(3), rate=833))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


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
    raw = memory.read(ORIENT_TABLE, 0x28)
    table = tuple(tuple(s8(b) for b in raw[i * 5:i * 5 + 5]) for i in range(8))
    if table != ORIENTATION:
        raise ValueError('orientation table')
    if struct.unpack('<I', memory.read(SENSITIVITY, 4))[0] != 0x1000:
        raise ValueError('sensitivity')
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
        entries=dict(fifo_read=f'{FIFO_READ:#010x}', decode=f'{DECODE:#010x}', packet_alloc=f'{PKT_ALLOC:#010x}',
                     packet_release=f'{PKT_RELEASE:#010x}', remap=f'{REMAP:#010x}'),
        fifo=dict(max_buffered_words=MAX_WORDS, heap_buffer_above_words=SMALL_WORDS, word_bytes=7,
                  read_command='0xf8 (FIFO_DATA_OUT_TAG 0x78 | 0x80)', tags={'1': 'gyroscope (dropped here)',
                                                                             '2': 'accelerometer'}),
        packet=dict(layout={'+0x00': 'u16 streams', '+0x02': 'u16 bytes per stream', '+0x04': 'u16 1',
                            '+0x08': 'u64 2', '+0x10': 'u32 1 (reference)', '+0x14': 'header pointer',
                            '+0x18': 'stream header (0x28 bytes)', '+0x40': 'samples'},
                    header={'+0x00': 'u64 type (2 accelerometer, 4 gyroscope, 8 magnetometer)',
                            '+0x08': 'u64 timestamp', '+0x10': 'u32 sensitivity (4096 LSB/g)',
                            '+0x14': 'u16 samples', '+0x16': 'u16 rate rounded down to a multiple of 25',
                            '+0x20': 'sample pointer (int16 x, y, z)'},
                    timestamp='source timestamp - (1000 / rate) * words left in the FIFO'),
        orientation=dict(table=f'{ORIENT_TABLE:#010x}', entries=[list(t) for t in ORIENTATION],
                         formula="x' = m00*x + m01*y, y' = m10*x + m11*y, z' = mz*z (16-bit)",
                         wrist_flip='byte 0x80f16fb0 == 1 negates x and y',
                         index_words={'accelerometer/gyroscope': '0x80f16fb8', 'magnetometer': '0x80f16fb4'}),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The FIFO read, register getters, packet allocation/release, decoder, orientation remap and SPI '
            'callbacks execute in the sensor-hub emulator; transfer, heap, memset/memcpy, timestamp, packet '
            'queue, algorithm hook, events, restore, dump comparator, delay and logger are supplied.',
            'This caller builds an accelerometer-only packet: gyroscope-tagged words are skipped by the decoder '
            '(no gyroscope header is passed); the gyroscope delivery path is elsewhere.',
            'Orientation index, wrist flag and calibration offsets are .bss values set at runtime by other '
            'code; the cases author them. The transmitted bulk-read bytes are recorded up to 16 bytes.',
            'FIFO contents are synthetic tagged words; no real LSM6DSO FIFO, timing or interrupt delivery '
            'is observed.'])


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
        parser.exit(2, f'Cannot inspect IMU FIFO: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
