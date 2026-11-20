#!/usr/bin/env python3
"""Execute the shared LSM6DSO read callback with supplied drained FIFO words."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import sensorhub_imu_fifo as fifo
    from . import sensorhub_imu_probe as probe
    from .sensorhub_memory import StartupMemory, MEMBER
else:
    import main_freertos_kernel as kernel
    import sensorhub_imu_fifo as fifo
    import sensorhub_imu_probe as probe
    from sensorhub_memory import StartupMemory, MEMBER

BOUND = 20000

READ_CB = 0x80f714a0
REARM = 0x80f700b4             # re-arm when the dirty flag is set
FIFO_DRAIN = 0x80f710ac        # verified in sensorhub_imu_fifo
REARM_FLAG = 0x80f17026
SAMPLE_COUNT = 0x80f17024
BSS_LO, BSS_HI = 0x80f17000, 0x80f17030
STACK = probe.HARNESS_STACK
CSRS = probe.CSRS
GYRO_SENSITIVITY = 0x80f16b24
MOVE = 0x80fcdeec
CACHE, PACKET = fifo.CACHE, fifo.PACKET
PACKET_SIZE = 0x180
TS = 0x0000001200000005
OFFSETS = (10, -20, 30, -40, 50, -60)

CODE = ((READ_CB, 0x212, 'a560198409347cb1970266b2b6d1e16ef978605dc4ed2d4076e4938260c90c94'),) + tuple(
    item for item in fifo.CODE if item[0] in (fifo.DECODE, fifo.PKT_ALLOC, fifo.PKT_RELEASE))
CALL_SITES = (
    (0x80f714d4, REARM), (0x80f714e4, FIFO_DRAIN), (0x80f71548, fifo.PKT_ALLOC),
    (0x80f715e4, fifo.DECODE), (0x80f715ec, fifo.PKT_RELEASE),
    (0x80f715fa, fifo.EVENT_POST), (0x80f71618, fifo.PKT_ALLOC), (0x80f71694, MOVE),
)


class Model(probe.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def put_bytes(self, address, data):
        for offset, byte in enumerate(data):
            self.write(address + offset, 1, byte, record=False)

    def allocate(self, streams, stride):
        if not stride:
            return 0
        size = 0x18 + streams * (0x28 + stride)
        self.leaf(fifo.MALLOC, 4, fifo.PKT_TAG_STR, size, 4)
        if not self.svc['allocated']:
            self.leaf(fifo.LOGGER, fifo.LOG_ERROR)
            return 0
        self.leaf(fifo.MEMSET, PACKET, 0, size)
        self.put_bytes(PACKET, bytes(size))
        headers = PACKET + 0x18
        self.write(PACKET, 2, streams)
        self.write(PACKET + 2, 2, stride)
        self.write(PACKET + 0x10, 4, 1)
        self.write(PACKET + 0x14, 4, headers)
        self.leaf(fifo.TIMESTAMP)
        for i in range(streams):
            header = headers + i * 0x28
            self.write(header + 8, 8, TS)
            self.write(header + 0x20, 4, headers + streams * 0x28 + i * stride)
        return headers

    def decode(self, words, headers, samples):
        counts = [0] * len(headers)
        tag_stream = {fifo.TAG_XL: 0}
        if len(headers) == 2:
            tag_stream[fifo.TAG_GY] = 1
        for i in range(words):
            address = CACHE + 7 * i
            stream = tag_stream.get(self.u8(address) >> 3)
            if stream is None:
                continue
            sample = counts[stream]
            if sample < samples:
                dest = self.read(headers[stream] + 0x20, 4) + sample * 6
                for axis in range(3):
                    offset = self.read(fifo.OFFSETS + 4 * (stream * 3 + axis), 4)
                    self.write(dest + 2 * axis, 2, self.u16(address + 1 + 2 * axis) + offset)
            counts[stream] += 1
        if any(count != samples for count in counts):
            self.leaf(fifo.LOGGER, fifo.LOG_WARN)
            return False
        return True

    def read_cb(self):
        if self.u8(REARM_FLAG) != 0:
            self.leaf(REARM, self.u8(0x80f1700d))
            self.write(REARM_FLAG, 1, 0)
        self.leaf(FIFO_DRAIN, STACK - 0x40 + 6)
        if self.svc['drain'] != 0:
            return 0
        buffered = self.u16(SAMPLE_COUNT)
        if not buffered:
            return 0

        rate = self.u16(fifo.RATE)
        streams = 2 if self.read(fifo.GYRO_ON, 4) else 1
        words = min(buffered, (rate * 1200 // 1000) * streams)
        samples = words // streams
        header = self.allocate(streams, samples * 6)
        if not header:
            return 0

        headers = [header + i * 0x28 for i in range(streams)]
        backdate = ((buffered - words + self.svc['remaining']) // streams) * (1000 // rate)
        for i, at in enumerate(headers):
            self.write(at, 4, (2, 4)[i])
            self.write(at + 8, 8, TS - backdate)
            self.write(at + 0x10, 4, self.read((fifo.SENSITIVITY, GYRO_SENSITIVITY)[i], 4))
            self.write(at + 0x14, 2, samples)
            self.write(at + 0x16, 2, rate // 25 * 25)
        if not self.decode(words, headers, samples):
            self.leaf(fifo.QUEUE)
            if not self.svc['retained']:
                self.write(PACKET + 0x14, 4, 0)
                self.leaf(fifo.FREE, 4, fifo.PKT_TAG_STR, PACKET)
            self.leaf(fifo.EVENT_POST)
            self.actions.append('cap:' + struct.pack('<HHI', fifo.EVENT_ERROR, 0, 0).hex())
            return 0

        leftover = buffered - words
        self.write(SAMPLE_COUNT, 2, leftover)
        if leftover:
            start = CACHE + words * 7
            size = leftover * 7
            self.leaf(MOVE, CACHE, start, size)
            self.put_bytes(CACHE, bytes(self.u8(start + i) for i in range(size)))
        return PACKET

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


def case(name, flag=0, drain=0, words=(), remaining=0, gyro=False, rate=26,
         allocated=True, retained=False):
    g = dict(drain=drain, remaining=remaining, allocated=allocated, retained=retained)
    bss = bytearray(BSS_HI - BSS_LO)
    struct.pack_into('<H', bss, SAMPLE_COUNT - BSS_LO, len(words))
    bss[REARM_FLAG - BSS_LO] = flag
    struct.pack_into('<I', bss, fifo.CACHE_PTR - BSS_LO, CACHE)
    struct.pack_into('<I', bss, fifo.GYRO_ON - BSS_LO, gyro)
    raw = b''.join(words)
    memory = [[BSS_LO, bss.hex()], [fifo.RATE, struct.pack('<H', rate).hex()],
              [fifo.SENSITIVITY, struct.pack('<I', 4096).hex()],
              [GYRO_SENSITIVITY, struct.pack('<I', 16).hex()],
              [fifo.OFFSETS, struct.pack('<6i', *OFFSETS).hex()],
              [CACHE, raw.hex() or '00'], [PACKET, 'a5' * PACKET_SIZE]]
    quiet = [list(q) for q in probe.QUIET] + [[PACKET, PACKET + PACKET_SIZE]]
    stubs = {
        str(REARM): dict(kind='return', args=1),
        str(FIFO_DRAIN): dict(kind='store', args=1, out_arg=0, size=2,
                              value=remaining, value_ret=drain),
        str(fifo.MALLOC): dict(kind='return', args=4, value=PACKET if allocated else 0),
        str(fifo.MEMSET): dict(kind='memset', args=3),
        str(fifo.TIMESTAMP): dict(kind='return', value=TS & fifo.M32, value_a1=TS >> 32),
        str(fifo.LOGGER): dict(kind='return', args=1),
        str(fifo.QUEUE): dict(kind='return', value=int(retained)),
        str(fifo.FREE): dict(kind='return', args=3),
        str(fifo.EVENT_POST): dict(kind='capture', ptr_arg=0, size=8, value=0),
        str(MOVE): dict(kind='memcpy', args=3),
    }
    return dict(
        name='sensorhub_imu_read_' + name, scope='imu_read', supplied={}, quiet=quiet,
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[[SAMPLE_COUNT, 3], [CACHE, len(raw) or 1], [PACKET, PACKET_SIZE]] if words else [],
        operations=[dict(name='read', entry=READ_CB, call=True, args=[], registers=False,
                         result=True, result_high=False)],
        memory=memory, spi=[], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('empty_flag_clear'))
    add(case('empty_flag_set_rearms', flag=1))
    add(case('drain_error', drain=5))
    add(case('drain_error_flag_set', flag=1, drain=5))
    xl = fifo.xl_words(65)
    gy = [fifo.word(fifo.TAG_GY, -300 - i, 400 + i, -500 + i) for i in range(3)]
    add(case('accel_delivery', words=xl[:2]))
    add(case('accel_capped_and_compacted', flag=1, words=xl, remaining=3))
    add(case('gyro_delivery', words=[xl[0], gy[0], gy[1], xl[1]], gyro=True, remaining=3))
    add(case('gyro_odd_unknown_tag_ignored',
             words=[xl[0], gy[0], xl[1], gy[1], fifo.word(7, 0, 0, 0)], gyro=True))
    add(case('gyro_odd_extra_sample_rejected',
             words=[xl[0], gy[0], xl[1], gy[1], gy[2]], gyro=True))
    add(case('allocation_failed', words=xl[:2], allocated=False))
    add(case('gyro_single_word_zero_stride', words=xl[:1], gyro=True))
    add(case('missing_accel_releases_packet', words=[xl[0], gy[0]]))
    add(case('missing_gyro_retains_packet', words=[xl[0], xl[1]], gyro=True, retained=True))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def describe_case(observed):
    row = observed['rows'][0]
    actions = observed['actions']
    result = dict(ret=row['a0'], rearmed=any(a.startswith(f'call:{REARM}:') for a in actions))
    if not row['snapshot']:
        return result

    snapshots = row['snapshot']
    result['buffered_after'] = struct.unpack_from('<H', bytes.fromhex(snapshots[str(SAMPLE_COUNT)]))[0]
    result['error_event'] = 'cap:0201000000000000' in actions
    result['packet_freed'] = any(a.startswith(f'call:{fifo.FREE}:') for a in actions)
    if result['ret']:
        packet = bytes.fromhex(snapshots[str(PACKET)])
        streams, stride = struct.unpack_from('<HH', packet)
        result['streams'] = []
        for i in range(streams):
            header = 0x18 + 0x28 * i
            kind, _, timestamp, sensitivity, count, hz = struct.unpack_from('<IIQIHH', packet, header)
            data = struct.unpack_from('<I', packet, header + 0x20)[0] - PACKET
            result['streams'].append(dict(kind=kind, timestamp=timestamp, sensitivity=sensitivity,
                                          count=count, hz=hz, stride=stride,
                                          first_xyz=list(struct.unpack_from('<hhh', packet, data))))
    return result


def evidence(archive, vectors, validation):
    data = archive.read(MEMBER)
    if hashlib.sha256(data).hexdigest() != probe.HUB_HASH:
        raise ValueError('unexpected sensor-hub image')
    memory = StartupMemory(data)
    for address, size, expected in CODE:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
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
    results = {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        name = c['name'].removeprefix('sensorhub_imu_read_')
        results[name] = describe_case(row['observed'])
    return dict(
        image='sensor-hub (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        callback=f'{READ_CB:#010x} (shared accelerometer/gyroscope FIFO read)',
        flow=dict(
            rearm=f'if the dirty flag {REARM_FLAG:#010x} is set, call {REARM:#010x} and clear it',
            drain=f'{FIFO_DRAIN:#010x}; a non-zero result returns NULL',
            count=f'the drained sample count {SAMPLE_COUNT:#010x}; zero returns NULL',
            delivery='cap words using the configured rate, allocate one or two streams, backdate packet '
                     'headers, decode tagged XYZ with offsets and compact the cache after successful decoding'),
        per_case=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The callback, packet allocator, tagged-word decoder and release wrapper execute original code. '
            'Re-arm, FIFO drain, heap, timestamp, queue, logger, event and memory helper effects are supplied.',
            'Cases use authored FIFO contents and service results. They do not establish live sensor timing, '
            'cache concurrency or downstream packet consumption.'])


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
