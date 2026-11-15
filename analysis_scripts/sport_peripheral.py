#!/usr/bin/env python3
"""Sports-peripheral UUID tables and the Stryd cadence message layout.

The main firmware's ``bx_sport_peripheral`` module acts as a Bluetooth LE client
towards external sports sensors. Its UUID strings are reached through one
contiguous table of string pointers. This tool walks that table in the main and
factory-test images from an anchor string, checks whether each of the four
custom 128-bit UUIDs is referenced, and provides a host model of the two
20-byte message layouts that the firmware's characteristic handler reads from
the Stryd characteristic.

Field positions and widths come from the reviewed handler ``0x7039f5c2`` and its
byte-reader helpers (``u8``/``u16``/``u32``/``u64``, little endian). Field
meanings are not established and keep generic names. Nothing here connects to
a device or runs vendor code.
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import zipfile

IMAGES = {'main': ('META/firmware_sign.bin', 0x70160000),
          'factory': ('META/extfw/fct_test_sign.bin', 0x70000000)}
ANCHOR = '00001530-0000-3512-2118-0009af100700'
UUID_TEXT = re.compile(rb'(?:[0-9A-Fa-f]{4}(?:[0-9A-Fa-f]{2})?|'
                       rb'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
                       rb'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})')
CUSTOM = ('7e78aa18-72cd-d3b8-a81f-5b7e589bea0f', '7e78aa19-72cd-d3b8-a81f-5b7e589bea0f',
          'cc353442-be58-4ea2-876e-11d8d6976366', 'c551c36a-0377-4a29-9657-74ffb655a188')

# Reviewed from the main-image exports (see SPORT_PERIPHERAL.md).
SERVICE_CLASSIFIER = {'address': 0x7039f55a, 'returns': {
    '180a': 6, '180f': 1, '1818': 1, '1814': 1, CUSTOM[0]: 1}, 'otherwise': 0}
CHARACTERISTIC_CLASSIFIER = {'address': 0x7039f28c, 'returns': {
    '2a19': 1, '2a63': 1, '2a53': 1, CUSTOM[1]: 1}, 'otherwise': 0}
REVIEWED = ('7039f55a', '7039f28c', '7039f5c2', '7039f3c8', '7039ecf6',
            '7039ec4c', '703bd2c0', '703d01e4', '703d0418', '703d044a',
            '703d047e', '703d04b0')

STRYD_LAYOUTS = {
    0x32: (('type', 'B'), ('b1', 'B'), ('b2', 'B'), (None, 'B'), ('w1', 'H'),
           ('w2', 'H'), ('w3', 'H'), ('b3', 'B'), (None, 'B'), ('d1', 'I'),
           ('w4', 'H'), ('w5', 'H')),
    0x36: (('type', 'B'), (None, 'B'), ('w1', 'H'), ('w2', 'H'), ('w3', 'H'),
           ('w4', 'H'), ('w5', 'H'), (None, 'Q')),
}


def text_at(image, base, address):
    offset = address - base
    if not 0 <= offset < len(image):
        return None
    end = image.find(b'\0', offset, offset + 64)
    raw = image[offset:end] if end > offset else b''
    return raw.decode('ascii').lower() if UUID_TEXT.fullmatch(raw) else None


def string_address(image, base, text):
    for match in re.finditer(re.escape(text.encode()), image, re.I):
        if image[match.start() - 1] == 0 and image[match.end()] == 0:
            return base + match.start()
    return None


def pointer_refs(image, value):
    return [m.start() for m in re.finditer(re.escape(struct.pack('<I', value)), image)
            if m.start() % 4 == 0]


def uuid_table(image, base, anchor=ANCHOR):
    """The contiguous run of UUID-string pointers containing the anchor's pointer."""
    target = string_address(image, base, anchor)
    if target is None:
        raise ValueError('anchor string not found')
    refs = pointer_refs(image, target)
    if len(refs) != 1:
        raise ValueError(f'anchor referenced {len(refs)} times, expected once')
    def entry(offset):
        if not 0 <= offset <= len(image) - 4:
            return None
        return text_at(image, base, struct.unpack_from('<I', image, offset)[0])
    start = refs[0]
    while entry(start - 4):
        start -= 4
    end = refs[0]
    while entry(end + 4):
        end += 4
    return [{'slot': base + offset, 'uuid': entry(offset)}
            for offset in range(start, end + 4, 4)]


def classify(classifier, uuid):
    return classifier['returns'].get(uuid.lower(), classifier['otherwise'])


def decode_stryd(payload):
    """Model the firmware's read of one Stryd notification.

    Returns None for a message type the firmware ignores (anything other than
    0x32/0x36). Raises ValueError when the payload is shorter than the layout,
    where the firmware's reader sets its error flag and logs a parse failure.
    Trailing bytes beyond the layout are not read.
    """
    payload = bytes(payload)
    if not payload:
        raise ValueError('empty Stryd message')
    layout = STRYD_LAYOUTS.get(payload[0])
    if layout is None:
        return None
    fmt = '<' + ''.join(code for _, code in layout)
    size = struct.calcsize(fmt)
    if len(payload) < size:
        raise ValueError('Stryd message shorter than its layout')
    values = struct.unpack_from(fmt, payload)
    return {name: value for (name, _), value in zip(layout, values) if name}


def layout_sizes():
    return {f'0x{kind:02x}': struct.calcsize('<' + ''.join(c for _, c in fields))
            for kind, fields in STRYD_LAYOUTS.items()}


def inspect(archive):
    report = {'images': {}}
    for name, (member, base) in IMAGES.items():
        image = archive.read(member)
        table = uuid_table(image, base)
        present = {e['uuid'] for e in table}
        custom = {}
        for uuid in CUSTOM:
            address = string_address(image, base, uuid)
            custom[uuid] = {
                'string_address': address,
                'in_pointer_table': uuid in present,
                'pointer_references': len(pointer_refs(image, address)) if address else 0,
            }
        report['images'][name] = {
            'member': member, 'base': base,
            'sha256': hashlib.sha256(image).hexdigest(),
            'table_start': table[0]['slot'], 'table_entries': len(table),
            'table': [e['uuid'] for e in table], 'custom_uuids': custom}
    report['service_classifier'] = SERVICE_CLASSIFIER
    report['characteristic_classifier'] = CHARACTERISTIC_CLASSIFIER
    report['stryd_layout_bytes'] = layout_sizes()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=pathlib.Path,
                        help='local main-image export directory, to hash reviewed sources')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        report = inspect(archive)
    if args.decompiled:
        report['reviewed_source_sha256'] = {
            address: hashlib.sha256((args.decompiled / f'ram_{address}.c').read_bytes()).hexdigest()
            for address in REVIEWED}
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
