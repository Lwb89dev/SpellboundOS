#!/usr/bin/env python3
"""Bounded offline timer/RTOS arithmetic; register values are synthetic inputs."""
import argparse
import hashlib
from itertools import islice
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN, MAIN_HASH, SENSOR, SENSOR_HASH, uint
else:
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN, MAIN_HASH, SENSOR, SENSOR_HASH, uint

MASK64 = 2**64 - 1
PERIOD = {'main': 1000, 'sensor': 33}
CALLBACK_BASE = {'main': 0x80c009f4, 'sensor': 0x80f15914}
TARGETS = {
    'main': (0x80d37e14,0x80d37f42,0x80d37fce,0x80d37eca,0x80d37e08,0x80d37fa6,
             0x80d3974e,0x80d454b8,0x702a2bb0),
    'sensor': (0x80f80e42,0x80f80f7c,0x80f81008,0x80f80f04,0x80f80e1c,0x80f80fe0,
               0x80f826e2,0x80f7b5e4,0x80f7b594,0x80f7e7b4,0x80fd2c3e),
}


def period(domain):
    if domain not in PERIOD:
        raise ValueError('unknown timer domain')
    return PERIOD[domain]


def timer_setup(raw, domain):
    uint(raw,64)
    tick = period(domain)
    compare, next_compare = (raw + tick) & MASK64, (raw + 2*tick) & MASK64
    return dict(compare=compare, next_compare=next_compare,
                writes=[(0xe6000008,compare & 0xffffffff),(0xe600000c,compare >> 32)])


def callback_record(domain, cause):
    period(domain)
    if type(cause) is not int or not 0 <= cause < 16: raise ValueError('outside reviewed hardware-cause table window')
    return CALLBACK_BASE[domain] + cause*16


def timer_interrupt(next_compare, mie, domain):
    uint(next_compare,64); uint(mie,32)
    return dict(writes=[(0xe6000008,0),(0xe600000c,next_compare >> 32),
                        (0xe6000008,next_compare & 0xffffffff)],
                mie_during=mie & ~0x80, mie_after=mie | 0x80,
                next_compare=(next_compare + period(domain)) & MASK64)


def stable_aon(samples):
    """Native low/high/low/high agreement, host bound 128 attempts."""
    for low, high, again_low, again_high in islice(samples,128):
        for word in (low,high,again_low,again_high): uint(word,32)
        if low == again_low and high == again_high:
            return high << 32 | low
    raise ValueError('no stable complete pair within the host bound')


def suspend_alarm_ticks(expected_idle, margin):
    """Reviewed u32 (idle-margin)<<15 then /1000, before native alarm calls."""
    uint(expected_idle,32)
    if expected_idle <= 3 or type(margin) is not int or margin not in (1,3):
        raise ValueError('excluded native short-idle branch or invalid margin')
    return (((expected_idle - margin) << 15) & 0xffffffff) // 1000


def resume_tick_estimate(elapsed_aon):
    """RV64 low product then shift, with the resulting RTOS count kept in u32."""
    uint(elapsed_aon,64)
    return (((elapsed_aon * 1000) & MASK64) >> 15) & 0xffffffff


def evidence(archive, decompiled, validations):
    result = dict(domains={}, limitations=[
        'Intervals and conversions are compiled contracts, not measured oscillator rates.',
        'Same numeric MMIO address across images does not prove shared physical counter identity.',
        'Prefixes stop before IRQ registration/scheduler calls; no live interrupt or wakeup tested.',
        'Tickless exports still have wide-register/type artifacts; selected formulas are checked in raw instructions.',
        'Suspension writes the counter itself; raw counter continuity/monotonicity is not guaranteed.',
        'AON host bound is 128 attempts; native reader has no such bound.'])
    for domain, member, expected, setup, isr, aon, table in (
        ('main',MAIN,MAIN_HASH,0x80d37e14,0x80d37f42,0x702a2bb0,0x80c009f4),
        ('sensor',SENSOR,SENSOR_HASH,0x80f80e42,0x80f80f7c,0x80f7e7b4,0x80f15914)):
        data = archive.read(member)
        if hashlib.sha256(data).hexdigest() != expected: raise ValueError('requires reviewed OTA images')
        m = StartupMemory(data,0x70160000,0x270,4,0x2a0,2) if domain == 'main' else StartupMemory(data)
        records = [struct.unpack('<4I',m.read(callback_record(domain,i),16)) for i in range(16)]
        if records[7][0] != isr: raise ValueError('reviewed trap table entry differs')
        raw_report = (validations / f'rtos-timer-{domain}-validation.json').read_bytes()
        execution = json.loads(raw_report)
        if (execution['domain'] != domain or execution['period_raw'] != period(domain)
                or execution['setup_cases'] != 13 or execution['isr_prefix_cases'] != 26
                or execution['aon_snapshot_cases'] != 3 or execution['dispatch_cases'] != 3
                or execution['hardware_execution'] is not False):
            raise ValueError('unexpected native-prefix validation report')
        folder = decompiled / f'runtime-rtos-timer-{domain}-fixed'
        exports = {f'{a:08x}.c': hashlib.sha256((folder / f'{a:08x}.c').read_bytes()).hexdigest()
                   for a in TARGETS[domain]}
        dispatcher = 0x80d35b10 if domain == 'main' else 0x80fd3d18
        ranges = ((setup,0x62 if domain == 'sensor' else 0x52),(isr,0x4a),(aon,0x1e),(table,256),(dispatcher,0x14))
        result['domains'][domain] = dict(image_sha256=expected, period_raw=period(domain),
            compare_registers=[0xe6000008,0xe600000c], counter_registers=[0xe6000000,0xe6000004],
            aon_registers=[0x910012f8,0x910012fc], initial_callback_table=table,
            callback_stride=16, dispatcher=dispatcher,
            initial_callbacks={str(i):dict(callback=row[0],argument=row[1],unclassified_words=list(row[2:]))
                               for i,row in enumerate(records) if any(row)},
            initial_callback_entry_7=records[7][0], export_sha256=exports,
            byte_range_sha256={f'{a:08x}_{n:x}':hashlib.sha256(m.read(a,n)).hexdigest() for a,n in ranges},
            validation_sha256=hashlib.sha256(raw_report).hexdigest(), validation=execution,
            setup_examples=[dict(raw=n,**timer_setup(n,domain)) for n in (0,0xffffffff,MASK64)],
            interrupt_example=timer_interrupt(0xffffffff,0,domain))
    result['aon_reader_bytes_match'] = (result['domains']['main']['byte_range_sha256']['702a2bb0_1e']
                                       == result['domains']['sensor']['byte_range_sha256']['80f7e7b4_1e'])
    result['suspend_examples'] = [dict(expected_idle=n,margin=margin,alarm_ticks=suspend_alarm_ticks(n,margin))
                                  for n in (4,10,1000,131073,0xffffffff) for margin in (1,3)]
    result['resume_examples'] = [dict(elapsed_aon=n,rtos_ticks=resume_tick_estimate(n))
                                 for n in (0,32,33,32768,2**32,2**64-1)]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled',type=Path,required=True)
    parser.add_argument('--validations',type=Path,required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = evidence(archive,args.decompiled,args.validations)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:
        parser.exit(2,f'Cannot inspect RTOS timer: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__ == '__main__': main()
