#!/usr/bin/env python3
"""Main-image ICNA3311 panel operations: dimming, brightness, sawtooth, gamma, HBM, register access.

Executes in ``main-runtime`` the original ICNA3311 panel operations, which
all play DCS command tables through the already-validated table player
``0x702c8314`` (see :mod:`main_display_panel`):

- dimming off/on ``0x702c850c`` / ``0x702c851c`` (``53 = 20`` / ``53 = 28``);
- brightness ``0x702c854c(level)`` (``51 = level``);
- sawtooth enable/disable ``0x702c85b4`` / ``0x702c85ec`` (page ``0x90``
  register ``4E = 1F`` / ``00``);
- gamma write ``0x702c8624(value)`` (page ``0x50`` registers ``38``/``39``);
- high-brightness mode enable/disable ``0x702c8e7a`` / ``0x702c8ed0``
  (variant table when present, else ``66 = 02`` / ``66 = 00``);
- register read/write ``0x702c8f22(info)`` (unlock, page select ``FE page``,
  read through the DCS read transfer or write ``reg value``, relock).

Every table wraps its command in the vendor unlock/lock sequences
(``FE 80 / F4 00 / F5 00`` ... ``FE 80 / F4 AC / F5 E1 / FE 00`` for page 0,
``FE 20 / F4 5A / F5 59`` ... ``FE 20 / F4 A5 / F5 A5`` for the vendor pages).
The DCS write/read transfers and the logger are supplied; the write stub
captures every command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_display_panel as dp
else:
    import main_freertos_kernel as kernel
    import main_display_panel as dp

BOUND = 20000
M32 = 0xffffffff
DIM_OFF, DIM_ON, BRIGHTNESS = 0x702c850c, 0x702c851c, 0x702c854c
SAW_ON, SAW_OFF, GAMMA = 0x702c85b4, 0x702c85ec, 0x702c8624
HBM_ON, HBM_OFF, REG_OP = 0x702c8e7a, 0x702c8ed0, 0x702c8f22
WRITE, READ, LOGGER, PLAYER = dp.WRITE, dp.READ_TRANSFER, dp.LOGGER, dp.INTERP
STATE = 0x70f9a55c             # display driver state; +0x0c -> panel variant descriptor
TABLES = 0x70a2dd84            # original tables 0x70a2dd84..0x70a2deb4
TABLE_BYTES = bytes.fromhex(
    '0002fe800002f4000002f5000002fe000002fe00000266000002fe800002f4ac0002f5e10002fe00'
    '0002fe800002f4000002f5000002fe000002fe00000266020002fe800002f4ac0002f5e10002fe00'
    '0002fe200002f4a50002f5a50002fe000002fe800002f4ac0002f5e10002fe000002fe800002f400'
    '0002f5000002fe000002fe200002f45a0002f5590002fe500002fe200002f45a0002f5590002fe50'
    '0002fe9000024e000002fe200002f4a50002f5a50002fe000002fe200002f45a0002f5590002fe50'
    '0002fe9000024e1f0002fe200002f4a50002f5a50002fe000002fe800002f4000002f5000002fe00'
    '0002fe00000253200002fe800002f4ac0002f5e10002fe000002fe800002f4000002f5000002fe00'
    '0002fe00000253280002fe800002f4ac0002f5e10002fe00')
HBM_OFF_T, HBM_ON_T, RELOCK_T, UNLOCK_T = 0x70a2dd84, 0x70a2ddac, 0x70a2ddd4, 0x70a2ddf4
SAW_OFF_T, SAW_ON_T, DIM_OFF_T, DIM_ON_T = 0x70a2de14, 0x70a2de3c, 0x70a2de64, 0x70a2de8c
VARIANT = 0x81005000
CUSTOM = 0x81005100
INFO = 0x81005200

CODE = dp.CODE + (
    (DIM_OFF, 0x22a, '667260773b7153df85d80979fe66c1ddfe1f9ed1b03065b4f2d6c0987f83232e'),
    (HBM_ON, 0x1fe, '17720c63b0853b6384e03eda2e73e4862dab7679f8b62874e22826120a8cda27'),
)
CSRS = kernel.CSRS
STACK = kernel.HARNESS_STACK


def word(v):
    return v & M32


def entries(raw):
    out, i = [], 0
    while i + 1 < len(raw):
        kind, n = raw[i], raw[i + 1]
        out.append((kind, raw[i + 2:i + 2 + n]))
        i += n + 2
    return out


def table(*cmds):
    return b''.join(b'\x00' + bytes([len(c)]) + c for c in cmds)


UNLOCK0 = (b'\xfe\x80', b'\xf4\x00', b'\xf5\x00', b'\xfe\x00')
LOCK0 = (b'\xfe\x80', b'\xf4\xac', b'\xf5\xe1', b'\xfe\x00')


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.reads = list(case['dcs_read'])

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def play_bytes(self, raw):
        for kind, payload in entries(raw):
            if kind == 0:
                self.actions.append(f'bus:{WRITE}:{payload.hex()}')
            elif kind == 1:
                self.leaf(dp.DELAY, payload[0])
        return 0

    def play(self, address, length):
        if address == 0 or length == 0:
            return dp.INTERP_ERROR
        return self.play_bytes(bytes(self.read(address + i, 1) for i in range(length)))

    def brightness(self, level):
        return self.play_bytes(table(*UNLOCK0, b'\x51' + bytes([level & 0xff]), *LOCK0))

    def gamma(self, value):
        self.leaf(LOGGER, 6)
        return self.play_bytes(table(b'\xfe\x20', b'\xf4\x5a', b'\xf5\x59', b'\xfe\x50',
                                     b'\x38' + bytes([(value >> 8) & 0xff]), b'\x39' + bytes([value & 0xff]),
                                     b'\xfe\x20', b'\xf4\xa5', b'\xf5\xa5', b'\xfe\x00'))

    def hbm(self, on):
        variant = self.read(STATE + 0xc, 4)
        self.leaf(LOGGER, 6)
        length = self.read(variant + (0x20 if on else 0x28), 4)
        if length:
            self.play(self.read(variant + (0x24 if on else 0x2c), 4), length)
        else:
            self.play(HBM_ON_T if on else HBM_OFF_T, 0x28)
        return 0

    def reg_op(self, info):
        if info == 0:
            self.leaf(LOGGER, 6)
            return 1
        page, reg, value, op = (self.read(info, 2), self.read(info + 2, 2), self.read(info + 4, 2),
                                self.read(info + 6, 1))
        if op == 0:
            self.leaf(LOGGER, 6)
            self.play(UNLOCK_T, 0x20)
            self.play_bytes(table(b'\xfe' + bytes([page & 0xff])))
            self.actions.append(f'bus:{READ}:{reg & 0xff:02x}')
            t = self.reads.pop(0)
            self.write(info + 4, 2, t)
            self.play(RELOCK_T, 0x20)
        elif op == 1:
            self.leaf(LOGGER, 6)
            self.play(UNLOCK_T, 0x20)
            self.play_bytes(table(b'\xfe' + bytes([page & 0xff]), bytes([reg & 0xff, value & 0xff])))
            self.play(RELOCK_T, 0x20)
        return 0

    def operation(self, op):
        e, a = op['entry'], op['args']
        return {
            DIM_OFF: lambda: self.play(DIM_OFF_T, 0x28), DIM_ON: lambda: self.play(DIM_ON_T, 0x28),
            BRIGHTNESS: lambda: self.brightness(a[0]),
            SAW_ON: lambda: (self.leaf(LOGGER, 6), self.play(SAW_ON_T, 0x28))[1],
            SAW_OFF: lambda: (self.leaf(LOGGER, 6), self.play(SAW_OFF_T, 0x28))[1],
            GAMMA: lambda: self.gamma(a[0]), HBM_ON: lambda: self.hbm(True), HBM_OFF: lambda: self.hbm(False),
            REG_OP: lambda: self.reg_op(a[0]),
        }[e]()


def contract(case):
    if case['scope'] != 'panel_ops' or len(case['operations']) != 1:
        raise ValueError('panel ops scope')
    model = Model(case)
    result = model.run()
    if model.reads:
        raise ValueError('unused scripted inputs')
    return result


def case(name, entry, args=(), reads=(), custom=None, info=None, result=True):
    variant = bytearray(0x30)
    if custom is not None:
        struct.pack_into('<IIII', variant, 0x20, len(custom), CUSTOM, len(custom), CUSTOM)
    state = bytearray(0x10)
    struct.pack_into('<I', state, 0xc, VARIANT)
    mem = [[STATE, bytes(state).hex()], [VARIANT, bytes(variant).hex()], [TABLES, TABLE_BYTES.hex()]]
    if custom is not None:
        mem.append([CUSTOM, custom.hex()])
    if info is not None:
        mem.append([INFO, struct.pack('<HHHBx', *info).hex()])
    stubs = {
        str(WRITE): dict(kind='bus', buf_arg=0, len_arg=1, write=True, rec=[], seq=[dict(status=0)] * 64),
        str(READ): dict(kind='bus', buf_arg=2, len_arg=3, write=False, rec=[], cmd_arg=0, cmd_len_arg=1,
                        seq=[dict(status=0, rx=f'{r:02x}') for r in reads]),
        str(LOGGER): dict(kind='return', args=1),
    }
    return dict(
        name='main_display_panel_ops_' + name, scope='panel_ops', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name='panel', entry=entry, call=True, args=list(args), registers=False,
                                      result=result, result_high=False)],
        memory=mem, dcs_read=list(reads))


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('dimming_off', DIM_OFF))
    add(case('dimming_on', DIM_ON))
    for level in (0x00, 0x80, 0xff):
        add(case(f'brightness_{level:02x}', BRIGHTNESS, (level,)))
    add(case('sawtooth_on', SAW_ON))
    add(case('sawtooth_off', SAW_OFF))
    add(case('gamma_0x1234', GAMMA, (0x1234,)))
    add(case('hbm_on_default', HBM_ON))
    add(case('hbm_off_default', HBM_OFF))
    add(case('hbm_on_variant_table', HBM_ON, custom=table(b'\x66\x03', b'\x29')))
    add(case('reg_read', REG_OP, (INFO,), reads=[0x5a], info=(0x40, 0x12, 0, 0)))
    add(case('reg_write', REG_OP, (INFO,), info=(0x40, 0x12, 0x77, 1)))
    add(case('reg_unknown_op', REG_OP, (INFO,), info=(0x40, 0x12, 0x77, 2)))
    add(case('reg_null', REG_OP, (0,)))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    if memory.read(TABLES, len(TABLE_BYTES)) != TABLE_BYTES:
        raise ValueError('panel tables')
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
    named = {'hbm_off': HBM_OFF_T, 'hbm_on': HBM_ON_T, 'relock_vendor_page': RELOCK_T, 'unlock_vendor_page':
             UNLOCK_T, 'sawtooth_off': SAW_OFF_T, 'sawtooth_on': SAW_ON_T, 'dimming_off': DIM_OFF_T,
             'dimming_on': DIM_ON_T}
    decoded = {}
    for label, address in named.items():
        off = address - TABLES
        size = 0x20 if label.endswith('page') else 0x28
        decoded[label] = [p.hex() for _, p in entries(TABLE_BYTES[off:off + size])]
    return dict(
        image='main firmware (OTA 4.6.0.3)', vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        panel='ICNA3311', tables=decoded,
        commands={'53': 'write_control_display (0x20 dimming off, 0x28 dimming on)',
                  '51': 'write_display_brightness', '66': 'high-brightness mode (0x02 on, 0x00 off)',
                  '4e (page 0x90)': 'sawtooth (0x1f on, 0x00 off)', '38/39 (page 0x50)': 'gamma high/low byte',
                  'fe': 'page select', 'f4/f5': 'vendor unlock/lock keys'},
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The panel operations and the original DCS table player execute in the main-image emulator; the DCS '
            'write/read transfers and the logger are supplied, so no byte reaches the DSI link.',
            'Command meanings follow MIPI DCS (51/53) and the driver function names (HBM, sawtooth, gamma); the '
            'vendor page semantics are not otherwise interpreted.',
            'The framebuffer/DSI refresh path, TE handling and the variant tables of the fitted panel are not '
            'executed.'])


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
        parser.exit(2, f'Cannot inspect panel ops: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
