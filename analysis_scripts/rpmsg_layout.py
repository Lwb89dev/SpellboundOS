#!/usr/bin/env python3
"""Initial rpmsg pool/queue layouts and a bounded independent header codec.

No shared memory is accessed on hardware. Queue roles depend on runtime mode.
Reserved header bytes must be supplied explicitly; native initialization of all
reserved bytes is not established, including the local token at offset 10.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_control_flow import pool_size
    from .zrpc_packets import MAIN, SENSOR, MAIN_HASH, SENSOR_HASH, uint, encode_data, encode_link, decode_channel
    from .zrpc_fragments import Reassembler, stock_channels
else:
    from sensorhub_memory import StartupMemory
    from zrpc_control_flow import pool_size
    from zrpc_packets import MAIN, SENSOR, MAIN_HASH, SENSOR_HASH, uint, encode_data, encode_link, decode_channel
    from zrpc_fragments import Reassembler, stock_channels

EXPORTS = (0x704ea184, 0x704e8f28, 0x704e9a48, 0x704ea8f2, 0x704eb4c0,
    0x707bf25e, 0x707bfa74, 0x707bffac, 0x707c024a, 0x707bfc0a,
    0x707bfcc4, 0x707bfe94, 0x707bfdf4, 0x707bff4c, 0x707c0442,
    0x707c0514, 0x707c06a2, 0x707bf746, 0x707bf982, 0x707bf9be)
BOUNDARY = (0x707bfb98, 0x707c03cc, 0x707c040c, 0x707bf672, 0x707bf678,
    0x707bfa00, 0x707bf67e, 0x704eb13a, 0x704e8e64, 0x704eb422,
    0x704eb476, 0x707bfb04, 0x707bfb88, 0x80d341d8, 0x704e8ea0, 0x704e9664)


def layout(base, count, payload, instance):
    uint(base, 32)
    uint(instance, 15)
    dimensions = pool_size(count, payload)
    if count < 2 or base % 16 or base + dimensions['total_bytes'] > 2**32:
        raise ValueError('invalid reviewed pool alignment, count or extent')
    n = count // 2
    queues = []
    for index in range(2):
        start = base + index * dimensions['ring_bytes']
        avail = start + n * 16
        used = (avail + 4 + n * 2 + 15) & ~15
        queues.append(dict(queue_id=instance * 2 + index, entries=n,
            descriptors=start, available=avail, used=used, used_end=used + 4 + n * 8,
            master_role='rx' if index == 0 else 'tx',
            remote_role='tx' if index == 0 else 'rx'))
    return dict(base=base, instance=instance, buffer_count=count, payload_bytes=payload,
        **dimensions, queues=queues, buffers=base + 2 * dimensions['ring_bytes'],
        end=base + dimensions['total_bytes'])


def encode_rpmsg(payload, *, source, destination, reserved, flags=0):
    if not isinstance(payload, bytes) or len(payload) > 65535:
        raise ValueError('invalid rpmsg payload')
    return struct.pack('<IIIHH', uint(source, 32), uint(destination, 32),
        uint(reserved, 32), len(payload), uint(flags, 16)) + payload


def decode_rpmsg(data):
    if not isinstance(data, bytes) or len(data) < 16:
        raise ValueError('truncated rpmsg header')
    source, destination, reserved, size, flags = struct.unpack_from('<IIIHH', data)
    if len(data) != 16 + size:
        raise ValueError('rpmsg packet length mismatch')
    return dict(source=source, destination=destination, reserved=reserved,
                flags_raw=flags, payload=data[16:])


def evidence(archive, decompiled, language):
    main, sensor = archive.read(MAIN), archive.read(SENSOR)
    if hashlib.sha256(main).hexdigest() != MAIN_HASH or hashlib.sha256(sensor).hexdigest() != SENSOR_HASH:
        raise ValueError('requires reviewed OTA images')
    source = (language / 'andestar_v5.instr.sinc').read_bytes()
    if hashlib.sha256(source).hexdigest() != 'b88e19a2ed21e641c683a1780aa739e1d9662106234a02b37fb4e949b4827a03':
        raise ValueError('requires corrected BBS language source')
    sources = {f'{group}/{a:08x}.c': hashlib.sha256((decompiled / group / f'{a:08x}.c').read_bytes()).hexdigest()
        for group, addresses in (('runtime-zrpc-bbs', EXPORTS), ('runtime-rpmsg-boundary', BOUNDARY)) for a in addresses}
    sender = (decompiled / 'runtime-zrpc-bbs/704ea184.c').read_text()
    receiver = (decompiled / 'runtime-zrpc-bbs/704e9a48.c').read_text()
    delivery = (decompiled / 'runtime-zrpc-bbs/704e8f28.c').read_text()
    checks = dict(sender_bit2_nonzero='(bVar1 & 4) != 0' in sender,
        receiver_more_bit_nonzero='(pbVar9 + 8) & 2) != 0' in receiver,
        delivery_crc_bit_clear='(param_1 + 3) & 2) == 0' in delivery)
    if not all(checks.values()):
        raise ValueError('corrected export predicates differ from reviewed forms')
    m = StartupMemory(main, 0x70160000, 0x270, 4, 0x2a0, 2)
    pools = []
    for index in range(3):
        identifier, base, count, payload = struct.unpack('<4I', m.read(0x70c0e8f4 + index * 16, 16))
        pools.append(layout(base, count, payload, identifier))
    examples = []
    for size in (35, 32):
        payload = bytes(range(size))
        packets = stock_channels(payload, mtu=40, source=2, destination=1,
            request=7, session=9, module=2)
        receiver = Reassembler()
        result = None
        for packet in packets:
            result = receiver.feed(packet)
        examples.append(dict(payload_size=size, link_mtu=40, channel_packets=len(packets),
            sequence=[decode_channel(p)['sequence'] for p in packets],
            more=[decode_channel(p)['bit1_raw'] for p in packets],
            delivered_matches=result == payload, remains_pending=receiver.state is not None))
    channel = encode_data(bytes.fromhex('10060000'), source=2, destination=1,
                          flags=2, request=7, session=9, module=2)
    return dict(main_sha256=MAIN_HASH, sensor_sha256=SENSOR_HASH,
        repaired_source_sha256=hashlib.sha256(source).hexdigest(),
        compiled_language_sha256=hashlib.sha256((language / 'andestar_v5.sla').read_bytes()).hexdigest(),
        corrected_predicates=checks, source_sha256=sources, pools=pools,
        synthetic_fragment_examples=examples,
        synthetic_rpmsg_process_hex=encode_rpmsg(encode_link(channel, checksum=True),
            source=1, destination=0, reserved=0).hex(),
        synthetic_scope='Chosen fields and explicit zero reserved word; not captured native bytes.',
        rpmsg_header_bytes=16, native_buffer_token_offset=10,
        endpoint_roles='local address is role 0/1; destination is inverse; runtime role is not observed',
        receive_ownership='endpoint callback return 1 retains; other values release',
        channel_bit2='forces queue selector 2; send worker scans queues 2, 1, 0',
        limitations=['Fresh targeted main exports only; remaining corpus and sensor exports need review.',
            'No live endpoints, cache coherency, vring operation or buffer ownership observed.',
            'Header decoder is strict; it excludes native allocation and error behavior.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    parser.add_argument('--language', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = evidence(archive, args.decompiled, args.language)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect rpmsg: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
