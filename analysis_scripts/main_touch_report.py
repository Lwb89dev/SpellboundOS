#!/usr/bin/env python3
"""Main-image ZTW622 touch: I2C register layer and the touch event/report handler.

The Bip 6 touch controller driver (``dev_ztw622``, chip id ``0xe622``) talks
I2C to address ``0x20`` with 16-bit little-endian register numbers.  This
scope executes, in the ``main-runtime`` project, the original:

- I2C write ``0x701ead14`` / read ``0x701eae7a`` (bus transfer with 10
  retries; on failure reset the bus and retry once), register select
  ``0x701eadce``, register write ``0x701eae04`` (``reg, value`` as four
  bytes), register read ``0x701eaf30`` / ``0x701eaf56`` and the clear-interrupt
  command ``0x701eade4`` (register ``0x0003``, up to three attempts);
- the report timer start ``0x701eb102`` (5000 ms) and the event dispatcher
  ``0x701eaca2`` (``dev->callback(dev, event, dev->arg)``);
- the event handler ``0x701eb18a`` with its state machine (state byte at
  context ``+0x2c``): state 1 reads the 16-byte point status at ``0x0080``,
  decodes up to the configured number of 6-byte points, applies rotation
  (``+0x2e``: 0/90/180/270) and the 180-degree flip (``+0x2a``), and handles
  the large-object (``TP LO``) and no-change statuses; state 3 reads the wake
  gesture register ``0x0126``, clears it and reports a wake event when it
  matches the gesture mask (``+0x2d``); state 6 and out-of-range states return
  -10; the other states only clear the interrupt.

Supplied: the bus write/read/reset services, the mutex, memset, the timer
service, the tick source, the logger and the report callback.
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

BOUND = 20000
M32 = 0xffffffff

HANDLER = 0x701eb18a
DISPATCH = 0x701eaca2
I2C_WRITE, I2C_READ = 0x701ead14, 0x701eae7a
REG_SELECT, REG_WRITE, REG_READ, REG_READ16, CLEAR_INT = 0x701eadce, 0x701eae04, 0x701eaf30, 0x701eaf56, 0x701eade4
TIMER_START_WRAP = 0x701eb102
BUS_WRITE, BUS_READ, BUS_RESET = 0x702b5a36, 0x702b5ae8, 0x702b59ea
LOGGER, MEMSET = 0x702b38a2, 0x70947ce8
MUTEX_TAKE, MUTEX_GIVE = 0x80d37058, 0x80d370fc
TIMER_START, TICK = 0x80d36ba0, 0x80d362d6

CTX = 0x70f92d10               # s_ztw622_cxt (.bss)
TIMER_HANDLE = 0x70f8e104      # report timer handle (.bss)
I2C_ADDRESS, RETRIES, TIMER_MS = 0x20, 10, 5000
POINT_STATUS, GESTURE, CLEAR_INT_CMD = 0x0080, 0x0126, 0x0003
STATUS_LARGE_OBJECT, STATUS_POINTS, STATUS_NO_CHANGE = 0x0010, 0x080e, 0x1000
LOG_ERROR, LOG_INFO = 3, 6

DEV = 0x81005000               # authored input device object
CALLBACK = 0x81006000          # authored report callback (supplied stub)
EVT = 0x81007000               # authored caller event buffer
USER_ARG = 0x0bad0001
I2C_HANDLE, MUTEX, TIMER = 0x0c0c0001, 0x0d0d0001, 0x0e0e0001
TICK_VALUE = 0x00123456
EVENT_SIZE = 0x38
STACK = kernel.HARNESS_STACK - 0x70
LOCAL_EVT, POINT_BUF = STACK + 0x18, STACK + 0x8

STATES = {0: 'clear', 1: 'report', 2: 'clear', 3: 'gesture', 4: 'clear', 5: 'clear', 6: 'busy', 7: 'clear'}

CODE = (
    (DISPATCH, 0xc, '07e6746a3d5a1ce38e6fa587a527624c2a449dd1927aa8bb10bc6ac44a5154a0'),
    (I2C_WRITE, 0x26e, '87bd8dc8f16a2a311d97d467c8cae907c2be8bd8ee090cc6c7e9e09de7015da4'),
    (TIMER_START_WRAP, 0x52, 'a8091619e1020247f7081b104e9066ec2f5f218a961a6453487f0849d121d859'),
    (HANDLER, 0x2b6, 'b9e1cd700f71fe7bc65cf86d706dad527ee3283f19a9937ada16828a84cda1fe'),
)
DATA = (
    (0x709d2704, 0x20, '4daf0f33e309a1f722c5ef27222a5dc6dce649c49fc4286ec31e25f830e413e7'),   # state jump table
)
CALL_SITES = (
    (0x701ead3e, BUS_WRITE), (0x701ead4a, BUS_RESET), (0x701eada2, BUS_WRITE), (0x701eaea0, BUS_READ),
    (0x701eaeac, BUS_RESET), (0x701eaf04, BUS_READ), (0x701eadda, I2C_WRITE), (0x701eadee, REG_SELECT),
    (0x701eae14, I2C_WRITE), (0x701eaf3a, REG_SELECT), (0x701eaf4a, I2C_READ), (0x701eaf5e, REG_SELECT),
    (0x701eaf6c, I2C_READ), (0x701eb1fa, TIMER_START_WRAP), (0x701eb20a, REG_READ), (0x701eb28a, REG_WRITE),
    (0x701eb292, DISPATCH), (0x701eb380, REG_READ16), (0x701eb38e, REG_WRITE), (0x701eb438, CLEAR_INT),
)
CSRS = kernel.CSRS


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(v):
    return v & M32


def point_status(status, count, points, stamp=0x5a):
    """16-byte point status: u16 status, u8 count, u8 time stamp, two 6-byte points."""
    raw = struct.pack('<HBB', status, count, stamp)
    for x, y, width, sub in points:
        raw += struct.pack('<HHBB', x, y, width, sub)
    return raw.ljust(16, b'\0')[:16]


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.bus = {BUS_WRITE: list(case['bus_write']), BUS_READ: list(case['bus_read'])}
        self.resets = list(case['bus_reset'])
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def u32(self, a):
        return self.read(a, 4)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    # Bus and register layer.
    def transfer(self, kind, buf, length):
        tx = bytes(self.u8(buf + i) for i in range(min(length, 16))).hex() if kind == BUS_WRITE else ''
        self.actions.append(f'bus:{kind}:{I2C_HANDLE}:{I2C_ADDRESS}:{length}:{RETRIES}:{tx}')
        t = self.bus[kind].pop(0)
        if 'rx' in t:
            for i, b in enumerate(bytes.fromhex(t['rx'])):
                self.put(buf + i, 1, b)
        return t['status']

    def i2c(self, kind, buf, length):
        if buf == 0:
            return word(-10)
        status = self.transfer(kind, buf, length)
        if status == 0:
            return 0
        self.leaf(BUS_RESET)
        reset = self.resets.pop(0)
        if reset:
            self.leaf(LOGGER, LOG_ERROR)
            return reset
        status = self.transfer(kind, buf, length)
        if status:
            self.leaf(LOGGER, LOG_ERROR)
        return status

    def reg_select(self, reg, scratch):
        self.put(scratch, 2, reg)
        return self.i2c(BUS_WRITE, scratch, 2)

    def reg_write(self, reg, value, scratch):
        self.put(scratch, 2, reg)
        self.put(scratch + 2, 2, value)
        return self.i2c(BUS_WRITE, scratch, 4)

    def clear_int(self):
        status = 0
        for _ in range(3):
            status = self.reg_select(CLEAR_INT_CMD, STACK - 0x10 - 0x20 + 0xc)
            if status == 0:
                break
        return status

    def start_timer(self):
        timer = self.u32(TIMER_HANDLE)
        if timer == 0:
            return word(-4)
        self.leaf(TIMER_START, timer, TIMER_MS)
        if self.svc['timer']:
            self.leaf(LOGGER, LOG_ERROR)
            return word(-14)
        return 0

    def dispatch(self, evt):
        callback = self.u32(DEV + 0x3c)
        if callback == 0:
            return word(-4)
        self.leaf(callback, DEV, evt, self.u32(DEV + 0x40))
        self.actions.append('cap:' + bytes(self.u8(evt + i) for i in range(EVENT_SIZE)).hex())
        return self.svc['callback']

    def finish(self, status):
        self.leaf(MUTEX_GIVE, MUTEX)
        return status

    def handler(self, evt_arg):
        self.leaf(MUTEX_TAKE, MUTEX, M32)
        state = self.u8(CTX + 0x2c)
        if state > 7 or STATES[state] == 'busy':
            return self.finish(word(-10))
        if STATES[state] == 'clear':
            return self.finish(self.clear_int())
        self.put(CTX + 0x38, 2, self.u16(CTX + 0x38) + 1)
        if STATES[state] == 'gesture':
            return self.gesture(evt_arg)
        self.leaf(MEMSET, LOCAL_EVT, 0, EVENT_SIZE)
        for i in range(EVENT_SIZE):
            self.put(LOCAL_EVT + i, 1, 0)
        evt = evt_arg or LOCAL_EVT
        status = self.start_timer()
        if status:
            return self.finish(status)
        frame = STACK - 0x20      # REG_READ frame: select scratch at +0xc
        status = self.reg_select(POINT_STATUS, frame + 0xc)
        if status == 0:
            status = self.i2c(BUS_READ, POINT_BUF, 16)
        if status:
            return self.finish(status)
        raw = bytes(self.u8(POINT_BUF + i) for i in range(16))
        code = struct.unpack_from('<H', raw)[0]
        if code == 0:
            return self.finish(self.clear_int())
        self.put(evt + 0, 1, 1)
        self.put(evt + 8, 1, 0)
        self.leaf(TICK)
        xres, yres = self.u16(CTX + 0x18), self.u16(CTX + 0x1a)
        self.put(evt + 4, 4, TICK_VALUE)
        self.put(evt + 0x2e, 2, 0)
        self.put(evt + 0x30, 2, xres)
        self.put(evt + 0x32, 2, 0)
        self.put(evt + 0x34, 2, yres)
        if code & STATUS_LARGE_OBJECT:
            if not self.u8(CTX + 0x29):
                return self.finish(self.clear_int())
            self.leaf(LOGGER, LOG_INFO)
            self.put(evt + 0x2c, 1, 1)
            self.put(evt + 0x10, 4, 0)
            self.put(evt + 0x14, 4, 0)
            self.put(evt + 0xc, 1, 2)
            self.put(evt + 0x18, 1, 0)
            status = self.reg_write(GESTURE, 0, STACK - 0x20 + 0xc)
        elif code & STATUS_POINTS:
            n = min(raw[2], self.u8(CTX + 0x2b))
            self.put(evt + 0x2c, 1, n)
            flip, rot = self.u8(CTX + 0x2a), self.u8(CTX + 0x2e)
            for i in range(n):
                x, y, _, sub = struct.unpack_from('<HHBB', raw, 4 + 6 * i)
                if not sub & 0xf:
                    continue
                pt = evt + 0xc + 0x10 * i
                px, py = {1: (y, xres - x), 2: (xres - x, yres - y), 3: (yres - y, x)}.get(rot, (x, y))
                if flip:
                    px, py = xres - px, yres - py
                self.put(pt + 4, 4, px)
                self.put(pt + 8, 4, py)
                self.put(pt + 0xc, 1, i)
                self.put(pt + 0, 1, ((sub ^ 8) >> 3) & 1)
        elif code & STATUS_NO_CHANGE:
            self.put(evt + 0x2c, 1, 0)
            self.put(evt + 0x10, 4, 0)
            self.put(evt + 0x14, 4, 0)
            self.put(evt + 0xc, 1, 0)
            self.put(evt + 0x18, 1, 0)
        else:
            return self.finish(self.clear_int())
        status = self.dispatch(evt)
        if status == 0:
            status = self.clear_int()
        return self.finish(status)

    def gesture(self, evt_arg):
        frame = STACK - 0x20
        self.put(POINT_BUF, 2, 0)
        status = self.reg_select(GESTURE, frame + 0xc)
        if status == 0:
            self.put(frame + 0xc, 2, 0)
            status = self.i2c(BUS_READ, frame + 0xc, 2)
            if status == 0:
                self.put(POINT_BUF, 2, self.u16(frame + 0xc))
        if status:
            return self.finish(status)
        status = self.reg_write(GESTURE, 0, frame + 0xc)
        if status:
            return self.finish(status)
        value = self.u16(POINT_BUF)
        self.leaf(LOGGER, LOG_INFO)
        if not value & self.u8(CTX + 0x2d):
            return self.finish(self.clear_int())
        self.leaf(LOGGER, LOG_INFO)
        self.leaf(MEMSET, LOCAL_EVT, 0, EVENT_SIZE)
        for i in range(EVENT_SIZE):
            self.put(LOCAL_EVT + i, 1, 0)
        evt = evt_arg or LOCAL_EVT
        self.put(evt + 0, 1, 1)
        self.put(evt + 0x2c, 1, 1)
        self.put(evt + 8, 1, 0)
        self.put(evt + 0x18, 1, 0)
        self.put(evt + 0x10, 4, 0)
        self.put(evt + 0x14, 4, 0)
        self.put(evt + 0xc, 1, 3)
        self.leaf(TICK)
        self.put(evt + 4, 4, TICK_VALUE)
        status = self.dispatch(evt)
        if status == 0:
            status = self.clear_int()
        return self.finish(status)

    def operation(self, op):
        if op['name'] != 'touch':
            raise ValueError('operation')
        return self.handler(op['args'][1])


def contract(case):
    if case['scope'] != 'touch' or len(case['operations']) != 1:
        raise ValueError('touch scope')
    model = Model(case)
    result = model.run()
    if model.bus[BUS_WRITE] or model.bus[BUS_READ] or model.resets:
        raise ValueError('unused scripted inputs')
    return result


OK = dict(status=0)


def case(name, state=1, raw=None, writes=None, reads=None, resets=(), evt=EVT, **over):
    g = dict(xres=416, yres=416, lo=0, flip=0, maxf=2, gmask=0, rot=0, timer_handle=TIMER, timer=0,
             callback=0, cb_present=1)
    g.update(over)
    if reads is None:
        reads = [dict(status=0, rx=raw.hex())] if raw is not None else []
    if writes is None:
        writes = []
    ctx = bytearray(0x40)
    struct.pack_into('<I', ctx, 4, I2C_HANDLE)
    struct.pack_into('<HH', ctx, 0x18, g['xres'], g['yres'])
    ctx[0x29], ctx[0x2a], ctx[0x2b], ctx[0x2c], ctx[0x2d], ctx[0x2e] = (
        g['lo'], g['flip'], g['maxf'], state, g['gmask'], g['rot'])
    struct.pack_into('<I', ctx, 0x30, MUTEX)
    dev = bytearray(0x44)
    struct.pack_into('<II', dev, 0x3c, CALLBACK if g['cb_present'] else 0, USER_ARG)
    stubs = {
        str(BUS_WRITE): dict(kind='bus', buf_arg=2, len_arg=3, write=True, seq=list(writes)),
        str(BUS_READ): dict(kind='bus', buf_arg=2, len_arg=3, write=False, seq=list(reads)),
        str(BUS_RESET): dict(kind='return', args=0, seq=list(resets)),
        str(LOGGER): dict(kind='return', args=1), str(MEMSET): dict(kind='memset', args=3),
        str(MUTEX_TAKE): dict(kind='return', args=2, value=0), str(MUTEX_GIVE): dict(kind='return', args=1),
        str(TIMER_START): dict(kind='return', args=2, value=g['timer']),
        str(TICK): dict(kind='return', args=0, value=TICK_VALUE),
        str(CALLBACK): dict(kind='capture', ptr_arg=1, size=EVENT_SIZE, value=g['callback'], args=3),
    }
    return dict(
        name='main_touch_report_' + name, scope='touch', supplied={},
        quiet=[[0x81000000, 0x81002000], [EVT, EVT + EVENT_SIZE]], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': kernel.HARNESS_STACK}, fregisters={}, stubs=stubs, stops={}, snapshot=[],
        operations=[dict(name='touch', entry=HANDLER, call=True, args=[DEV, evt], registers=False,
                         result=True, result_high=False)],
        memory=[[CTX, bytes(ctx).hex()], [DEV, bytes(dev).hex()], [EVT, '00' * EVENT_SIZE],
                [TIMER_HANDLE, struct.pack('<I', g['timer_handle']).hex()]],
        bus_write=list(writes), bus_read=list(reads), bus_reset=list(resets),
        services=dict(timer=g['timer'], callback=g['callback']))


def report(raw, **kw):
    """A state-1 report whose dispatch succeeds and clears the interrupt."""
    return dict(raw=raw, writes=[OK, OK], **kw)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    one = point_status(0x0802, 1, [(100, 50, 3, 0x03)])
    two = point_status(0x0806, 2, [(100, 50, 3, 0x03), (300, 400, 5, 0x05)])
    add(case('state_0_clears_interrupt', 0, writes=[OK]))
    add(case('state_6_busy', 6))
    add(case('state_out_of_range', 9))
    add(case('status_zero_clears_interrupt', raw=point_status(0, 0, []), writes=[OK, OK]))
    add(case('one_finger_down', **report(one)))
    for rot in (1, 2, 3):
        add(case(f'two_fingers_rotation_{rot * 90}', rot=rot, **report(two)))
    add(case('two_fingers_flip_180', flip=1, **report(two)))
    add(case('rotation_90_and_flip', rot=1, flip=1, **report(two)))
    add(case('finger_up_bit', **report(point_status(0x0808, 1, [(10, 20, 1, 0x09)]))))
    add(case('empty_slot_skipped', **report(point_status(0x0802, 2, [(1, 2, 0, 0x00), (7, 8, 1, 0x01)]))))
    add(case('count_clamped_to_max_fingers', maxf=1, **report(two)))
    add(case('large_object_reported', lo=1, raw=point_status(0x0010, 0, []), writes=[OK, OK, OK]))
    add(case('large_object_ignored_when_disabled', raw=point_status(0x0010, 0, []), writes=[OK, OK]))
    add(case('no_change_report', **report(point_status(0x1000, 0, []))))
    add(case('unknown_status_clears_interrupt', raw=point_status(0x0020, 0, []), writes=[OK, OK]))
    add(case('timer_handle_missing', timer_handle=0))
    add(case('timer_start_fails', timer=1))
    add(case('read_fails_then_reset_retry_succeeds', writes=[OK, OK],
             reads=[dict(status=5), dict(status=0, rx=one.hex())], resets=[0]))
    add(case('read_fails_and_reset_fails', writes=[OK], reads=[dict(status=5)], resets=[7]))
    add(case('select_fails_twice', writes=[dict(status=5), dict(status=6)], resets=[0]))
    add(case('callback_missing', cb_present=0, raw=one, writes=[OK]))
    add(case('callback_error_skips_clear', callback=3, raw=one, writes=[OK]))
    add(case('clear_interrupt_fails_three_times', raw=point_status(0, 0, []),
             writes=[OK, dict(status=1), dict(status=1), dict(status=1)], resets=[9, 9, 9]))
    add(case('null_event_uses_local_buffer', evt=0, **report(one)))
    add(case('gesture_matches_mask', 3, gmask=0x04, writes=[OK, OK, OK],
             reads=[dict(status=0, rx='0400')]))
    add(case('gesture_no_match_clears', 3, gmask=0x01, writes=[OK, OK, OK],
             reads=[dict(status=0, rx='0400')]))
    add(case('gesture_null_event', 3, gmask=0x04, evt=0, writes=[OK, OK, OK],
             reads=[dict(status=0, rx='0400')]))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
    table = [(0x709d2704 + struct.unpack('<i', memory.read(0x709d2704 + 4 * i, 4))[0]) & M32 for i in range(8)]
    targets = {0x701eb438: 'clear', 0x701eb1cc: 'report', 0x701eb36c: 'gesture', 0x701eb41a: 'busy'}
    if [targets[t] for t in table] != [STATES[i] for i in range(8)]:
        raise ValueError('state table')
    if memory.read(0x709bd040, 11) != b'dev_ztw622\0':
        raise ValueError('board record name')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report_ = json.loads(validation.read_bytes())
    if report_['hardware_execution'] is not False or report_['bound_per_case'] != BOUND or \
            report_['case_count'] != len(vector_doc['cases']) or len(report_['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, c in zip(report_['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
    return dict(
        image='main firmware (OTA 4.6.0.3)', vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        bus=dict(address=f'{I2C_ADDRESS:#04x}', register_width=16, byte_order='little-endian', retries=RETRIES,
                 recovery='bus reset then one retry'),
        registers={'0x0003': 'clear interrupt command', '0x0080': 'point status (16 bytes)',
                   '0x0126': 'wake gesture (read, then cleared by writing 0)', '0x0120': 'chip id (0xe622)'},
        point_status=dict(layout='u16 status, u8 count, u8 time stamp, then 6-byte points {u16 x, u16 y, '
                                 'u8 width, u8 sub_status}', max_points_read=2,
                          status_bits={'0x0010': 'large object (TP LO)', '0x080e': 'point data',
                                       '0x1000': 'no change'},
                          sub_status='bits 3:0 nonzero = slot used; bit 3 = up (event down = !bit 3)'),
        event=dict(size=EVENT_SIZE, layout={'+0x00': 'u8 1', '+0x04': 'u32 tick', '+0x0c': 'points (0x10 each: '
                                            'u8 down, u32 x @+4, u32 y @+8, u8 id @+0xc); for non-point '
                                            'events +0x0c is the kind (0 none, 2 large object, 3 wake gesture)',
                                            '+0x2c': 'u8 count', '+0x30': 'u16 x resolution',
                                            '+0x34': 'u16 y resolution'}),
        rotation={'0': '(x, y)', '1': '(y, xres - x)', '2': '(xres - x, yres - y)', '3': '(yres - y, x)',
                  'flip_180': '(xres - x, yres - y) after rotation'},
        states={str(k): v for k, v in STATES.items()},
        context=dict(address=f'{CTX:#010x}', fields={'+0x04': 'I2C handle', '+0x18/+0x1a': 'x/y resolution',
                                                       '+0x29': 'large-object enable', '+0x2a': '180-degree flip',
                                                       '+0x2b': 'max fingers', '+0x2c': 'state',
                                                       '+0x2d': 'wake gesture mask', '+0x2e': 'rotation',
                                                       '+0x30': 'mutex', '+0x38': 'event counter'}),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        native_case_count=len(report_['cases']), native_steps=sum(r['steps'] for r in report_['cases']),
        native_validation=report_,
        limitations=[
            'The handler, register layer, timer wrapper and dispatcher execute in the main-image emulator; bus '
            'services, mutex, memset, timer, tick, logger and the report callback are supplied. Point status '
            'bytes are authored; no transfer reaches a real ZTW622.',
            'Context values (resolution, flags, state, rotation, gesture mask) are authored; the probe/attach '
            'that sets them, power/reset sequencing, interrupt wiring and firmware upgrade are not executed here.',
            'Only two points fit the 16-byte read; the physical controller configuration is unverified.'])


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
        parser.exit(2, f'Cannot inspect touch report: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
