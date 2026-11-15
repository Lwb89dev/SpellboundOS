#!/usr/bin/env python3
"""Host model of observed MAX8617X FIFO framing and ordered register tables.

Derived from the bundled sensor driver, not a hardware specification. No SPI,
device access, register writes or vendor code execution are performed.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import zipfile

BASE = 0x80f62000
MEMBER = 'META/extfw/sensorhub@mhs003_sign.bin'
PRESETS = ((0x80fd920c, 80), (0x80fd92ac, 102), (0x80fd9378, 91),
           (0x80fd9430, 80), (0x80fd94d0, 58), (0x80fd9544, 69),
           (0x80fd95d0, 47), (0x80fd9630, 36))


def transfer_plan(status_03, status_04, frame_words, cached_words=0):
    """Mirror count/range/whole-frame checks before the observed FIFO read."""
    if not all(isinstance(v, int) and 0 <= v <= 255 for v in (status_03, status_04)):
        raise ValueError('status registers must be bytes')
    if not isinstance(frame_words, int) or not 1 <= frame_words <= 32:
        raise ValueError('frame word count must be 1..32')
    if not isinstance(cached_words, int) or not 0 <= cached_words <= 1000:
        raise ValueError('cached word count must be 0..1000')
    available = ((status_03 & 0xc0) << 2) | status_04
    if available >= 512 or cached_words + available > 1000:
        return {'action': 'flush', 'available_words': available, 'read_words': 0,
                'transfer_bytes': 0}
    words = frame_words * (available // frame_words)
    return {'action': 'read' if words else 'wait', 'available_words': available,
            'read_words': words, 'transfer_bytes': 2 + words * 4 if words else 0}


def decode_word(raw):
    if not isinstance(raw, int) or not 0 <= raw <= 0xffffffff:
        raise ValueError('FIFO word must be an unsigned 32-bit integer')
    sample = raw & 0xfffff
    return {'raw': raw, 'channel': (raw >> 29) & 3,
            'measurement': (raw >> 24) & 31,
            'sample': sample - 0x100000 if sample & 0x80000 else sample,
            'unclassified_bits_20_23': (raw >> 20) & 15,
            'unclassified_bit_31': raw >> 31}


def decode_response(data, frame_words, validate_starts=True):
    """The first two RX bytes are skipped, without assuming an echo value."""
    if not isinstance(frame_words, int) or not 1 <= frame_words <= 32:
        raise ValueError('frame word count must be 1..32')
    if len(data) < 2 or (len(data) - 2) % 4:
        raise ValueError('response must contain a two-byte prefix and whole words')
    count = (len(data) - 2) // 4
    if count >= 512 or count % frame_words:
        raise ValueError('response must contain bounded complete frames')
    entries = [decode_word(struct.unpack_from('>I', data, 2 + index * 4)[0])
               for index in range(count)]
    for index, entry in enumerate(entries):
        # Observed driver check applies only at each frame's first word and
        # when the driver's nonzero mode enables it. It does not validate all
        # channel sequences or reserved bits.
        if (validate_starts and index % frame_words == 0 and
                entry['measurement'] != 1 and entry['channel'] != 0):
            raise ValueError(f'frame-start check failed at word {index}')
    return entries


def register_table(data, address, count, base=BASE):
    offset = address - base
    if not 0 < count <= 1024 or offset < 0 or offset + count * 2 > len(data):
        raise ValueError('register table outside image or invalid count')
    raw = data[offset:offset + count * 2]
    return {'address': address, 'count': count, 'sha256': hashlib.sha256(raw).hexdigest(),
            'writes': [{'register': raw[index], 'value': raw[index + 1]}
                       for index in range(0, len(raw), 2)]}


def analyze(data):
    tables = [register_table(data, address, count) for address, count in PRESETS]
    return {'member': MEMBER, 'member_sha256': hashlib.sha256(data).hexdigest(),
            'image_base': BASE, 'fifo_reader': 0x80f74526,
            'irq_callback': 0x80f72f60, 'irq_dispatch': 0x80f63f6c,
            'irq_message_word': 0x601, 'status_registers': [3, 4],
            'fifo_tx_prefix_hex': '0880', 'bytes_per_word': 4,
            'wire_word_order': 'big-endian', 'cache_words': 1000,
            'fifo_reject_count_at_or_above': 512,
            'register_pair_writer': 0x80f731ec,
            'register_tables': [{k: v for k, v in table.items() if k != 'writes'} for table in tables],
            'summary': {'register_tables': len(tables),
                        'ordered_register_writes': sum(t['count'] for t in tables)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--tables-output', help='private ordered-table output; keep below ignored firmware/')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            data = archive.read(MEMBER)
        result = analyze(data)
        if args.tables_output:
            tables = [register_table(data, address, count) for address, count in PRESETS]
            pathlib.Path(args.tables_output).write_text(json.dumps(tables, indent=2, sort_keys=True) + '\n')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect optical FIFO: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
