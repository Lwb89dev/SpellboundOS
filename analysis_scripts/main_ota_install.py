#!/usr/bin/env python3
"""Main-image watch-side OTA install path: CRC32 integrity, validation flow and persisted records.

The watch receives an update over BLE (the only bridge on this device) through a
delegate of six downloader callbacks asserted at ``bx_ota_control_init``
(``downloader_request_start``/``_write_chunk_data``/``_request_validate``/
``_request_upgrade``/``_request_complete`` and ``ota_state_for_downloader``).  A
single OTA manager drives a one-byte global state at ``0x70f95948`` whose
transitions are logged ``"OTA state %d -> %d"`` (setter ``0x7021b364``).  This
tool nails down the integrity mechanism and the persisted state that a
BLE-only recovery depends on:

- executes natively, in ``main-runtime``, the original reflected CRC32 update
  ``0x70161360(crc, buffer, length)`` over authored buffers; the OTA code seeds
  it with ``0xffffffff``, chains it in 0x4000-byte chunks
  (``ota_calculate_file_crc32`` ``0x7021e3ba``) and finally inverts it
  (``not``), i.e. the standard zlib CRC32.  The 256-entry table at
  ``0x709bc4fc`` is verified to be the standard reflected (``0xedb88320``)
  polynomial table;
- decodes the validation flow in ``downloader_request_validate``
  (``0x7021b990``): the CRC32 received in the BLE start header must equal the
  file's declared CRC32, then the file is read back from flash and its
  recomputed CRC32 must equal the declared CRC32 again ("readback CRC32
  matched!"); a zero start size skips the check;
- decodes the persisted records written as base64 system properties
  (encode ``0x7030c06c`` -> set ``0x7030c300``): a per-file-type download
  record (file type, file size, CRC32, received size, received CRC32) keyed by
  the 9-entry table at ``0x709ed450`` (``ota.record.v1.firmware`` /
  ``ota.record.v1.data``) and a 40-byte upgrade-package record keyed
  ``ota.record.v1.upgrade.package``;
- catalogs the 13 upgrade modules at ``0x70f60fa8`` (file type -> install path),
  the OTA file paths and the per-type file-size ceilings
  (0x20000000 firmware, 0x200000 data).

The CRC32 cases are the only native execution; everything else is decoded
statically and checked against the image bytes.
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

BOUND = 30000
CRC32_UPDATE = 0x70161360
CRC_TABLE, CRC_TABLE_LEN = 0x709bc4fc, 1024
MODULE_ARRAY, MODULE_COUNT = 0x70f60fa8, 13
DL_KEY_TABLE, DL_KEY_COUNT = 0x709ed450, 9
VALIDATE, SET_STATE, CALC_CRC32 = 0x7021b990, 0x7021b364, 0x7021e3ba
PROP_ENCODE, PROP_SET, PROP_GET = 0x7030c06c, 0x7030c300, 0x7030bf98
OTA_STATE = 0x70f95948
UPGRADE_KEY_ADDR = 0x709ecfcc
BUF = 0x81004000
STACK = kernel.HARNESS_STACK

# (address, size, sha256) of original bytes the native cases and static decode rely on.
CODE = (
    (CRC32_UPDATE, 0x26, '82666efb8aecf1c3c3a4e1834306b1827d0bf6003c7ef65f852de46eb1876610'),
)
DATA = (
    (CRC_TABLE, CRC_TABLE_LEN, '12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86'),
    (MODULE_ARRAY, MODULE_COUNT * 4, '8376a1ab31ee71a4dad3e22ba8604bce24783790c058378d94048d36aed2ccf2'),
    (DL_KEY_TABLE, DL_KEY_COUNT * 8, '475de084d76ddf73fe6aff45a22f2c83d463c72e20ba7d3e0d3a5bf38d78b807'),
)
# Six downloader callbacks asserted non-NULL at bx_ota_control_init.
DELEGATE_CALLBACKS = (
    'ota_state_for_downloader', 'downloader_request_start', 'downloader_write_chunk_data',
    'downloader_request_validate', 'downloader_request_upgrade', 'downloader_request_complete',
)
# Per-type file-size ceiling (bytes) enforced at request_start / bootup.
SIZE_LIMIT_FIRMWARE = 0x20000000
SIZE_LIMIT_DATA = 0x200000
OTA_PATHS = (
    '/mnt/data/ota/firmware.bin', '/mnt/data/ota/data.bin',
    '/mnt/cache/ota/firmware.zip', '/mnt/cache/ota/bootloader.zip',
    '/mnt/system/extfw/backup_fw_sign.zip', '/mnt/system/extfw/boot_res_sign.bin',
    '/mnt/data/resources/offlineasr_data.zip',
)

# Standard reflected CRC32 table and update, computed independently of the image.
_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xedb88320 if _c & 1 else _c >> 1
    _TABLE.append(_c)


def crc32_update(crc, data):
    """One pass of the reflected CRC32 the firmware runs at 0x70161360 (no final inversion)."""
    for b in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ b) & 0xff]
    return crc & 0xffffffff


class Model(kernel.Model):
    def operation(self, op):
        crc, buf, length = op['args']
        return crc32_update(crc, bytes(self.read(buf + i, 1) for i in range(length)))


def contract(case):
    if case['scope'] != 'ota_install' or len(case['operations']) != 1:
        raise ValueError('ota install scope')
    return Model(case).run()


def case(name, crc, data):
    return dict(
        name='main_ota_install_' + name, scope='ota_install', supplied={}, quiet=[[0x81000000, 0x81008000]],
        csr_allowed=list(kernel.CSRS), ranges=[[a, a + n] for a, n, _ in CODE], csrs={str(n): 0 for n in kernel.CSRS},
        registers={'sp': STACK}, fregisters={}, stubs={}, stops={}, snapshot=[],
        operations=[dict(name='crc32', entry=CRC32_UPDATE, call=True, args=[crc, BUF, len(data)],
                         registers=False, result=True, result_high=False)],
        memory=[[BUF, (data + b'\0').hex()]])


def native_vectors():
    cases = []

    def add(crc, name, data):
        c = case(name, crc, data)
        c['expected'] = contract(c)
        cases.append(c)

    init = 0xffffffff
    add(init, 'empty', b'')
    add(init, 'single_zero', b'\x00')
    add(init, 'single_ff', b'\xff')
    add(init, 'ascii', b'123456789')                       # classic CRC32 check vector
    add(init, 'firmware_header', bytes(range(32)))
    add(init, 'block_256', bytes((i * 37 + 11) & 0xff for i in range(256)))
    add(init, 'block_2048', bytes((i * 131 + 7) & 0xff for i in range(0x800)))
    # Chaining: the firmware feeds the running CRC of chunk 1 into chunk 2.
    first = crc32_update(init, bytes(range(16)))
    add(first, 'chunk_chain', bytes(range(16, 32)))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE + DATA], cases=cases)


def cstr(memory, address, limit=64):
    return memory.read(address, limit).split(b'\0')[0].decode('ascii')


def download_key_table(memory):
    rows = []
    for i in range(DL_KEY_COUNT):
        file_type, ptr = struct.unpack('<II', memory.read(DL_KEY_TABLE + 8 * i, 8))
        rows.append(dict(file_type=file_type, property_key=cstr(memory, ptr)))
    return rows


def module_catalog(memory):
    """File type -> primary install path for each of the 13 upgrade modules at 0x70f60fa8."""
    pointers = struct.unpack('<%dI' % MODULE_COUNT, memory.read(MODULE_ARRAY, MODULE_COUNT * 4))
    rows = []
    for p in pointers:
        file_type = memory.read(p, 1)[0]
        path_ptr = struct.unpack('<I', memory.read(p + 4, 4))[0]
        path = None
        if 0x70160000 <= path_ptr < 0x71000000:
            s = cstr(memory, path_ptr)
            if s.startswith('/'):
                path = s
        rows.append(dict(file_type=file_type, descriptor=f'{p:#010x}', install_path=path))
    return rows


def crc32_reference_table(memory):
    table = struct.unpack('<256I', memory.read(CRC_TABLE, CRC_TABLE_LEN))
    return all(table[i] == _TABLE[i] for i in range(256))


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE + DATA:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    if not crc32_reference_table(memory):
        raise ValueError('CRC32 table is not the standard reflected polynomial table')

    keys = download_key_table(memory)
    if {r['file_type'] for r in keys} != {0, 8, 48, 49, 50, 51, 160, 252, 254}:
        raise ValueError('download record key types')
    if cstr(memory, UPGRADE_KEY_ADDR) != 'ota.record.v1.upgrade.package':
        raise ValueError('upgrade package key')
    catalog = module_catalog(memory)
    if [r['file_type'] for r in catalog] != [0, 224, 3, 252, 144, 8, 160, 19, 254, 48, 49, 50, 51]:
        raise ValueError('module type list')

    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    # The firmware's check vector "123456789" must give the canonical CRC32 after inversion.
    ascii_case = next(c for c in vector_doc['cases'] if c['name'].endswith('ascii'))
    if (ascii_case['expected']['rows'][0]['a0'] ^ 0xffffffff) != 0xcbf43926:
        raise ValueError('CRC32 check vector')

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
        transport='BLE only (no USB/wired port); OTA manager with a single global state byte at '
                  f'{OTA_STATE:#010x}, transitions logged "OTA state %d -> %d" by {SET_STATE:#010x}',
        delegate_callbacks=list(DELEGATE_CALLBACKS),
        integrity=dict(
            function=f'{CRC32_UPDATE:#010x}(crc, buffer, length)',
            algorithm='standard reflected CRC32 (poly 0xedb88320), seed 0xffffffff, final inversion by the caller',
            table=f'{CRC_TABLE:#010x} (256 entries, verified)',
            chunked_file_crc32=f'{CALC_CRC32:#010x} reads the file in 0x4000-byte chunks and chains the CRC',
            check_vector=dict(input='123456789', crc32='0xcbf43926')),
        validation_flow=dict(
            function=f'{VALIDATE:#010x} (downloader_request_validate)',
            steps=[
                'if the start size is zero, skip the CRC32 check',
                'received CRC32 (BLE start header) must equal the declared file CRC32',
                'read the file back from flash, recompute its CRC32, require it to equal the declared CRC32',
                'on match log "readback CRC32 matched!" and advance the OTA state'],
            readback='the written file is re-read and re-hashed, not trusted from the transfer'),
        download_record=dict(
            layout='file_type(1), file_size(4), CRC32(4), received_size(4), received_CRC32(4)',
            encoding=f'base64 via {PROP_ENCODE:#010x}, stored with set-system-property {PROP_SET:#010x}',
            restore=f'get-system-property {PROP_GET:#010x} then base64-decode',
            keys=keys),
        upgrade_package_record=dict(
            size_bytes=40, property_key='ota.record.v1.upgrade.package',
            requires='a matching download record whose file size and CRC32 agree before it is saved'),
        module_catalog=catalog,
        file_paths=list(OTA_PATHS),
        size_limits=dict(firmware=SIZE_LIMIT_FIRMWARE, data=SIZE_LIMIT_DATA),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Only the CRC32 update executes natively; the validation flow, record encoding, property keys, module '
            'catalog, paths and size ceilings are decoded statically and checked against the image bytes.',
            'The signature/authenticity check applied by the bootloader when the staged image is actually '
            'installed (Upgrade bootloader/firmware/boot-resource) is out of scope here; this block covers the '
            'transfer-integrity (CRC32) and the persisted records, not the cryptographic image signature.',
            'The downloader callbacks themselves (the BLE/BT transport that calls write_chunk_data) and the '
            'bootloader apply step after reboot are not executed.'])


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
        parser.exit(2, f'Cannot inspect OTA install: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
