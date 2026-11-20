#!/usr/bin/env python3
"""Main-image RTL8763 Bluetooth: the vendor HCI command CRC16 (``0x703ceb56``).

The RTL8763 controller firmware is downloaded with a vendor HCI protocol whose
commands carry a CRC16 (logged as ``cmd low:%x, cmd high:%x crc low:%x, crc
high:%x`` with the ``@RTL`` tag).  ``0x703ceb56(crc, buffer, length)`` is the
byte-at-a-time CRC16 update that produces it: ``crc = table[(crc ^ byte) & 0xff]
^ (crc >> 8)`` over the 256-entry table at ``0x70a806a8``.  The table is verified
to be the standard reflected **CRC16/MODBUS** table (polynomial ``0xA001``); the
protocol seeds the update with ``0xFFFF``, so the check value of ``"123456789"``
is ``0x4B37``.

This scope executes the CRC16 update natively over authored buffers and compares
it with an independent CRC16/MODBUS implementation; nothing else is supplied.
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
CRC16 = 0x703ceb56
CRC_TABLE, CRC_TABLE_LEN = 0x70a806a8, 512
BUF = 0x81004000
STACK = kernel.HARNESS_STACK
CSRS = kernel.CSRS

CODE = ((CRC16, 0x2a, 'dbcb722d28bfaffcc2fcf73e45da49a3d440d9845e8748f7cae43c2e79f6a0c3'),)
DATA = ((CRC_TABLE, CRC_TABLE_LEN, '961656eaf43bdf70937151a003627324be86c28ca32285f58edd5f5c73c51b79'),)

_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if _c & 1 else _c >> 1
    _TABLE.append(_c)


def crc16_update(crc, data):
    for b in data:
        crc = _TABLE[(crc ^ b) & 0xff] ^ (crc >> 8)
    return crc & 0xffff


class Model(kernel.Model):
    def operation(self, op):
        crc, buf, length = op['args']
        return crc16_update(crc, bytes(self.read(buf + i, 1) for i in range(length)))


def contract(case):
    if case['scope'] != 'bt_hci_crc' or len(case['operations']) != 1:
        raise ValueError('bt hci crc scope')
    return Model(case).run()


def case(name, crc, data):
    return dict(
        name='main_bt_hci_crc_' + name, scope='bt_hci_crc', supplied={}, quiet=[[0x81000000, 0x81008000]],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in CSRS},
        registers={'sp': STACK}, fregisters={}, stubs={}, stops={}, snapshot=[],
        operations=[dict(name='crc16', entry=CRC16, call=True, args=[crc, BUF, len(data)],
                         registers=False, result=True, result_high=False)],
        memory=[[BUF, (data + b'\0').hex()]])


def native_vectors():
    cases = []

    def add(crc, name, data):
        c = case(name, crc, data)
        c['expected'] = contract(c)
        cases.append(c)

    seed = 0xffff
    add(seed, 'empty', b'')
    add(seed, 'single', b'\xa5')
    add(seed, 'ascii', b'123456789')                     # CRC16/MODBUS check vector
    add(seed, 'hci_reset', bytes.fromhex('0103100000'))  # an HCI command frame
    add(seed, 'block_256', bytes((i * 29 + 5) & 0xff for i in range(256)))
    add(seed, 'block_1024', bytes((i * 131 + 7) & 0xff for i in range(1024)))
    first = crc16_update(seed, bytes(range(8)))
    add(first, 'chunk_chain', bytes(range(8, 16)))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def crc16_reference_table(memory):
    return struct.unpack('<256H', memory.read(CRC_TABLE, CRC_TABLE_LEN)) == tuple(_TABLE)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    if not crc16_reference_table(memory):
        raise ValueError('table is not CRC16/MODBUS')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    ascii_case = next(c for c in vector_doc['cases'] if c['name'].endswith('ascii'))
    if ascii_case['expected']['rows'][0]['a0'] != 0x4B37:
        raise ValueError('CRC16/MODBUS check vector')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        controller='Realtek RTL8763 (vendor HCI firmware download, @RTL)',
        crc16=dict(
            function=f'{CRC16:#010x}(crc, buffer, length)',
            algorithm='reflected CRC16/MODBUS (polynomial 0xA001), seed 0xFFFF',
            table=f'{CRC_TABLE:#010x} (256 entries, verified)',
            check_vector=dict(input='123456789', crc16='0x4b37'),
            usage='vendor HCI command, cmd low/high + crc low/high'),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Only the CRC16 update executes natively. The HCI command builder, the H5/three-wire UART transport '
            'on uart2, hci_send_any and the rtl8763_pack.bin patch-RAM loader are not executed here.'])


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
        parser.exit(2, f'Cannot inspect BT HCI CRC16: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
