#!/usr/bin/env python3
"""Main-image Airoha AG3335 GNSS: PAIR command framing, acknowledgement table and command catalog.

The GNSS (``dev_ag3335``, ``uart1``, rails ``GPS_1V8``/``GPS_0V8``) is an
Airoha AG3335M driven with proprietary NMEA "PAIR" sentences.  This tool:

- executes natively, in ``main-runtime``, the original XOR checksum
  ``0x704b5d74(buffer, length)``; the frame builder ``0x704b5d8e(body)`` formats
  ``"P%s%s"`` with ``"AIR"`` and the body, then ``"$%s*%02X\\r\\n"`` with that
  checksum, logs frames not containing ``"600"`` and hands the frame to the UART
  writer ``0x704bd530(frame, length, 1)`` (decoded statically: its libc
  ``vfprintf`` contains the word ``0xf33b89ff`` at ``0x7094d4c2`` that neither
  Ghidra nor LLVM decodes, so the builder is not executed);
- decodes the 43-entry acknowledgement table at ``0x70bfe258`` (command code,
  the two result characters and the event bit set when ``PAIR001,<code>,<r>``
  arrives) used by the ``PAIR001`` parser ``0x704b5c3c``;
- catalogs all 49 call sites of the send-with-retry helper ``0x704b5e60``
  (``"%s,%s"`` of code and parameter, three attempts, 2000 ms acknowledgement
  wait), each verified against the original ``auipc``/``addi`` operands.

Nothing is supplied to the native checksum cases.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from .sensorhub_imu_init import pc_pair
else:
    import main_freertos_kernel as kernel
    from sensorhub_imu_init import pc_pair

BOUND = 5000
BUILD, CHECKSUM, SEND_RETRY, ACK_PARSE = 0x704b5d8e, 0x704b5d74, 0x704b5e60, 0x704b5c3c
MEMSET, LOGGER, UART_WRITE = 0x70947ce8, 0x702b38a2, 0x704bd530
ACK_TABLE, ACK_COUNT = 0x70bfe258, 43
BODY = 0x81004000
STACK = kernel.HARNESS_STACK
FRAME = STACK - 0x130 + 0x98

CODE = (
    (CHECKSUM, 0xec, 'bd27fc9281c14e64aa38fdfdfaff8c1b28db6f73f292bf84cfb3883b169520e5'),
)
DATA = (
    (0x70bfdb54, 0x18, '136c2abc5a111334b4a3b5cdeeaa2f7920637e2d936790f1b23b7f6812993c39'),   # formats
    (0x70a75dd8, 0x4, 'bc510e608fc8bbe22c2ded88988b701c661adde1125489f5cf2467b70af9717e'),    # "AIR"
    (0x70bff85c, 0x4, '6f8628f40dd1f7f59f100ee42df59a09e7cde9f44de41a6d5445a6ac315bef6f'),    # "600"
    (ACK_TABLE, 0x2b0, '7867c472e7cb644010feefa26f92c4fb730923d22d56b27ddbefde247ed21109'),
)
# (call site, function label, code, parameter) for every jal to 0x704b5e60; parameter None = computed.
CALLS = (
    (0x704b4e32, 'epo', '470', '0'), (0x704b4fd8, 'epo', '470', '1'),
    (0x704b5474, 'gnss_epo_flash_aiding_for_other', '470', '3'),
    (0x704b5574, 'gnss_epo_flash_aiding_for_other', '470', None),
    (0x704b6084, 'gnss_pair_set_gnss_search_mode', '066', None),
    (0x704b6136, 'epo query', '533', None), (0x704b614a, 'epo query', '472', None),
    (0x704b615e, 'epo query', '553', None), (0x704b6172, 'epo query', '513', None),
    (0x704b6196, 'epo config', '470', '0'), (0x704b61ae, 'epo config', '470', '1'),
    (0x704b61c8, 'epo config', '530', '0,7200'), (0x704b61e2, 'epo config', '530', '1,7200'),
    (0x704b61fc, 'epo config', '530', '2,7200'), (0x704b6216, 'epo config', '530', '3,7200'),
    (0x704b6230, 'epo config', '530', '4,7200'), (0x704b624a, 'epo config', '550', '0,30'),
    (0x704b6264, 'epo config', '550', '1,30'), (0x704b627e, 'epo config', '550', '2,30'),
    (0x704b6298, 'epo config', '550', '3,30'),
    (0x704b6330, 'set_gnss_band_mode', '105', None), (0x704b637e, 'set_gnss_band_mode', '003', None),
    (0x704b63a6, 'set_gnss_band_mode', '104', '1'), (0x704b63ba, 'set_gnss_band_mode', '002', None),
    (0x704b63f6, 'set_gnss_band_mode', '003', None), (0x704b6410, 'set_gnss_band_mode', '104', '0'),
    (0x704b6424, 'set_gnss_band_mode', '002', None),
    (0x704b6542, 'set rate', '064', None),
    (0x704b69ea, 'gnss_set_glp_mode', '680', '0'), (0x704b6a3e, 'gnss_set_glp_mode', '680', '1'),
    (0x704b6a6a, 'gnss_set_glp_mode', '680', '0'), (0x704b6a92, 'gnss_set_glp_mode', '730', '0'),
    (0x704b6aec, 'query', '113', None),
    (0x704b6dd8, 'init', '112', None), (0x704b6dec, 'init', '513', None), (0x704b6e1c, 'init', '086', '0'),
    (0x704b6e3a, 'init', '778', '0'), (0x704b6e4e, 'init', '112', None), (0x704b6e62, 'init', '513', None),
    (0x704b71b6, 'config', '058', None),
    (0x704b721a, 'gnss_defconfig_cmd', '006', None), (0x704b722e, 'gnss_defconfig_cmd', '007', None),
    (0x704b725c, 'gnss_defconfig_cmd', '084', '1'), (0x704b7288, 'gnss_defconfig_cmd', '178', '0'),
    (0x704b72b0, 'gnss_defconfig_cmd', '007', None), (0x704b72ea, 'gnss_defconfig_cmd', '006', None),
    (0x704b730e, 'gnss_defconfig_cmd', '007', None), (0x704b733e, 'gnss_defconfig_cmd', '005', None),
    (0x704b73a4, 'gnss_defconfig_cmd', '778', '1'),
)
CSRS = kernel.CSRS


def frame(body):
    payload = b'PAIR' + body
    cs = 0
    for b in payload:
        cs ^= b
    return b'$' + payload + b'*%02X\r\n' % cs


def checksum(data):
    cs = 0
    for b in data:
        cs ^= b
    return cs


class Model(kernel.Model):
    def operation(self, op):
        buf, length = op['args']
        return checksum(bytes(self.read(buf + i, 1) for i in range(length)))


def contract(case):
    if case['scope'] != 'gnss_pair' or len(case['operations']) != 1:
        raise ValueError('gnss pair scope')
    return Model(case).run()


def case(name, data):
    return dict(
        name='main_gnss_pair_' + name, scope='gnss_pair', supplied={}, quiet=[[0x81000000, 0x81002000]],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': STACK}, fregisters={}, stubs={}, stops={}, snapshot=[],
        operations=[dict(name='checksum', entry=CHECKSUM, call=True, args=[BODY, len(data)], registers=False,
                         result=True, result_high=False)],
        memory=[[BODY, (data + b'\0').hex()]])


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    for name, body in (('power_on', b'002'), ('dual_band_on', b'104,1'), ('epo_validity', b'530,0,7200'),
                       ('search_mode', b'066,1,1,1,1,0,0'), ('glp_mode', b'680,1'), ('cold_start', b'006')):
        add(case(name, b'PAIR' + body))
    add(case('empty', b''))
    add(case('single_byte', b'A'))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def cstr(memory, address, limit=24):
    return memory.read(address, limit).split(b'\0')[0].decode('ascii')


def ack_table(memory):
    rows = []
    for i in range(ACK_COUNT):
        ptr, ok, fail, lo, hi = struct.unpack('<IbbxxII', memory.read(ACK_TABLE + 16 * i, 16))
        rows.append(dict(code=cstr(memory, ptr), result_chars=chr(ok) + chr(fail), event_bits=f'{hi << 32 | lo:#x}'))
    return rows


def operand(memory, site, reg, window=48):
    """Strings formed by auipc/addi pairs writing `reg` in the bytes before `site`."""
    found = []
    for pc in range(site - window, site, 2):
        try:
            hi, lo = struct.unpack('<II', memory.read(pc, 8))
        except (ValueError, IndexError):
            continue
        if hi & 0x7f == 0x17 and (hi >> 7) & 31 == reg and lo & 0x707f == 0x13 and (lo >> 7) & 31 == reg \
                and (lo >> 15) & 31 == reg:
            try:
                found.append(cstr(memory, pc_pair(memory, pc)))
            except (ValueError, UnicodeDecodeError):
                pass
    return found


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, _, code, param in CALLS:
        if kernel.direct_target(memory, site) != SEND_RETRY:
            raise ValueError(f'call site {site:#x}')
        if code not in operand(memory, site, 10):
            raise ValueError(f'code operand at {site:#x}')
        if param is not None and param not in operand(memory, site, 11):
            raise ValueError(f'parameter operand at {site:#x}')
    acks = ack_table(memory)
    called = sorted({c for _, _, c, _ in CALLS})
    without_ack = [c for c in called if c not in {a['code'] for a in acks}]
    if without_ack != ['113']:
        raise ValueError('unexpected codes without acknowledgement entry')
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
        receiver='Airoha AG3335M (dev_ag3335, uart1, rails GPS_1V8/GPS_0V8)',
        sample_frames={b.decode(): frame(b.encode() if isinstance(b, str) else b).decode().strip()
                       for b in (b'002', b'104,1', b'066,1,1,1,1,0,0')},
        framing=dict(format='$PAIR<code>[,<parameters>]*<XOR hex>\\r\\n',
                     checksum='XOR of every byte between $ and *', builder=f'{BUILD:#010x}',
                     uart_writer=f'{UART_WRITE:#010x}(frame, length, 1)',
                     send_with_retry=f'{SEND_RETRY:#010x}: "%s,%s" or "%s", 3 attempts, 2000 ms acknowledgement wait',
                     acknowledgement='PAIR001,<code>,<result> parsed by 0x704b5c3c against the table'),
        acknowledgement_table=acks,
        call_catalog=[dict(site=f'{s:#010x}', function=f, code=c, parameter=p) for s, f, c, p in CALLS],
        codes_used=called, codes_without_acknowledgement_entry=without_ack,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Only the XOR checksum executes natively; the frame builder is decoded statically (its libc vfprintf '
            'holds a word at 0x7094d4c2 that Ghidra and LLVM cannot decode). The catalog and acknowledgement '
            'table are decoded statically and every call operand is checked against the original auipc/addi pair.',
            'Command meanings are given only by the calling function names in the firmware; parameter semantics '
            'of computed parameters, responses beyond PAIR001 and the NMEA position path are not executed.',
            'EPO/ELPO aiding data formats, UART baud/flow settings and receiver behaviour are unverified.'])


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
        parser.exit(2, f'Cannot inspect GNSS PAIR: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
