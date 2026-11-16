#!/usr/bin/env python3
"""Reviewed IPC notice/IRQ arithmetic and offline volatile-MMIO evidence.

These functions never access hardware. Counter, route and notification models
are bounded interpretations, not a driver, scheduler or register emulator.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN, SENSOR, MAIN_HASH, SENSOR_HASH, uint
else:
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN, SENSOR, MAIN_HASH, SENSOR_HASH, uint

TARGETS = (0x707bf7e0, 0x707bf926, 0x707bf746, 0x707bf710, 0x707bf72c,
    0x707bfa04, 0x707bfb32, 0x707c07a4, 0x707c0726, 0x707c03cc,
    0x707c040c, 0x707c06f8, 0x707c0780, 0x707bf982, 0x707bf9be,
    0x80d35bcc, 0x80d35c1c, 0x80d35c6c, 0x80d35d28, 0x80d35d44,
    0x80d453d4, 0x80d45464, 0x707bf66c, 0x707bf672, 0x707bf678, 0x707bfa00)
SENSOR_TARGETS = (0x80fa6a40, 0x80fa6ad6, 0x80fa6c7a, 0x80fa6bec,
    0x80fa6a26, 0x80fa6a0a, 0x80fa6cce, 0x80fa6d06, 0x80fa7ad8, 0x80fa7a5a)
WINDOWS = ((0x90008000, 0x1000), (0x91000000, 0x1000),
           (0xe4000000, 0x4000), (0xe6000000, 0x1000))


def queue_token(queue_id):
    return uint(queue_id, 5) + 1


def receive_notice(role, word):
    uint(role, 1)
    uint(word, 32)
    register = 0x9000807c if role == 0 else 0x90008074
    if role == 0 and word == 0xff:
        return dict(register=register, queue=None, steps=['echo_ack', 'exception_path'])
    if not 1 <= word <= 32:
        raise ValueError('notice would enter the native queue-index guard')
    return dict(register=register, queue=word - 1, steps=['dispatch', 'echo_ack'])


def irq_bank(irq):
    if type(irq) is not int or not 0 <= irq <= 0x52:
        raise ValueError('invalid untagged external IRQ')
    return dict(address=0xe4002000 + (irq >> 5) * 4, mask=1 << (irq & 31))


def critical_step(count, *, enter):
    if type(count) is not int or not 0 <= count <= 0x7fffffff or type(enter) is not bool:
        raise ValueError('invalid bounded critical-section state')
    if (enter and count == 0x7fffffff) or (not enter and count == 0):
        raise ValueError('critical-section overflow or unbalanced exit')
    updated = count + (1 if enter else -1)
    action = 'disable' if enter and count == 0 else 'enable' if not enter and updated == 0 else None
    return dict(count=updated, irq_action=action)


def should_notify(*, added, available_index, used_flags=0, event_index=None):
    for value in (added, available_index, used_flags):
        uint(value, 16)
    if event_index is None:
        return not bool(used_flags & 1)
    uint(event_index, 16)
    return added > ((available_index - 1 - event_index) & 0xffff)


def wait_expired(start, now):
    """Compare already-scaled reader values; raw counter snapshots need /1000 first."""
    uint(start, 64)
    uint(now, 64)
    return ((now - start) & 0xffffffffffffffff) >= 1000


def evidence(archive, decompiled, language):
    main, sensor = archive.read(MAIN), archive.read(SENSOR)
    if hashlib.sha256(main).hexdigest() != MAIN_HASH or hashlib.sha256(sensor).hexdigest() != SENSOR_HASH:
        raise ValueError('requires reviewed OTA images')
    language_source = (language / 'andestar_v5.instr.sinc').read_bytes()
    if hashlib.sha256(language_source).hexdigest() != 'b88e19a2ed21e641c683a1780aa739e1d9662106234a02b37fb4e949b4827a03':
        raise ValueError('requires the corrected BBS language')
    m = StartupMemory(main, 0x70160000, 0x270, 4, 0x2a0, 2)
    s = StartupMemory(sensor)
    groups = (('runtime-rpmsg-doorbell', (0x707bf7e0, 0x707bf926)),
              ('runtime-rpmsg-mmio', TARGETS), ('runtime-sensor-doorbell', SENSOR_TARGETS))
    hashes = {f'{group}/{a:08x}.c': hashlib.sha256((decompiled / group / f'{a:08x}.c').read_bytes()).hexdigest()
              for group, addresses in groups for a in addresses}
    baseline = (decompiled / 'runtime-rpmsg-doorbell/707bf7e0.c').read_text()
    wake = (decompiled / 'runtime-rpmsg-mmio/707bf7e0.c').read_text()
    sensor_wake = (decompiled / 'runtime-sensor-doorbell/80fa6ad6.c').read_text()
    irq = (decompiled / 'runtime-rpmsg-mmio/707bf926.c').read_text()
    checks = dict(baseline_loses_mode_register='90008000' not in baseline,
        main_restores_mode_writes=wake.count('Ram90008000 =') == 2,
        sensor_restores_mode_writes=sensor_wake.count('Ram90008000 =') == 2,
        exception_echo_ack_present='Ram9000807c = 0xff;' in irq,
        role_predicate_bytes_match=m.read(0x80d341d8, 14) == s.read(0x80fd2dec, 14))
    if not all(checks.values()):
        raise ValueError('reviewed volatile I/O evidence changed')
    fences = {}
    for address in (0x707bf66c, 0x707bf672, 0x707bf678):
        raw = m.read(address, 6)
        if raw != bytes.fromhex('0f1000008280'):
            raise ValueError('reviewed ordering hook bytes differ')
        fences[f'{address:08x}'] = hashlib.sha256(raw).hexdigest()
    return dict(main_sha256=MAIN_HASH, sensor_sha256=SENSOR_HASH,
        compiled_language_sha256=hashlib.sha256((language / 'andestar_v5.sla').read_bytes()).hexdigest(),
        source_sha256=hashes, reviewed_checks=checks,
        volatile_windows=[dict(base=base, size=size) for base, size in WINDOWS],
        irq=dict(number=0x10, handler=0x707bf926, register_callback=0x80d35c6c,
                 callback_table=0x70fe69c4, entries=32, **irq_bank(0x10)),
        notice_roles={'0': dict(send=0x90008070, busy=0x90008074, receive=0x9000807c),
                      '1': dict(send=0x90008078, busy=0x9000807c, receive=0x90008074)},
        queue_examples=[dict(queue=i, token=queue_token(i), role0=receive_notice(0, queue_token(i)),
                             role1=receive_notice(1, queue_token(i))) for i in range(6)],
        fence_i_hook_sha256=fences,
        mmio_timeout=dict(limit_raw=1000, timer=0x80d45464, counter_low=0xe6000000, counter_high=0xe6000004,
                          note='raw high/low/high snapshot then helper with divisor 1000; no physical time unit claimed'),
        limitations=['No device register access, interrupts, cache maintenance or wake transitions executed.',
            'Volatile windows are analysis metadata, not a complete hardware register specification.',
            'Models exclude scheduler, MMIO bus semantics and interrupt races; timer helper return types remain underspecified.'])


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
        parser.exit(2, f'Cannot inspect IPC doorbell: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
