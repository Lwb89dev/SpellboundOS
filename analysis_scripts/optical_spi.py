#!/usr/bin/env python3
"""Bounded host contracts for the selected optical SPI adapter and polling HAL.

No electrical mode labels, live bus speed or successful sensor operation are
inferred from register words. Poll status words are separate supplied inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .clock_cache import pll_rate
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import SENSOR, SENSOR_HASH, uint
else:
    from clock_cache import pll_rate
    from sensorhub_memory import StartupMemory
    from zrpc_packets import SENSOR, SENSOR_HASH, uint

TARGETS = (0x80f7eb60,0x80f7ed84,0x80f7ee38,0x80f7eecc,0x80f7b36c,0x80f7b3a0,
    0x80f7b3d0,0x80f7b3b8,0x80f7e884,0x80f7e890,0x80f7e89c,0x80f7e8e4,
    0x80f89552,0x80f898ae,0x80f897bc,0x80f7ff0e,0x80f7fdda,0x80f63360,0x80f76ae6)


def spi_source_rate(bus, selection_word, *, pll_a=None, pll_b=None):
    if type(bus) is not int or bus not in (0,1): raise ValueError('only reviewed sensor SPI buses 0/1')
    uint(selection_word,32)
    mode=(selection_word >> (12+2*bus)) & 3
    return 48000000 if mode < 2 else pll_rate(pll_b if mode == 2 else pll_a)


def adapter_config(frequency, flags):
    uint(frequency,32); uint(flags,32)
    return dict(frequency=frequency, low_control_bits=3 if flags & 6 else 0, width_field=8)


def hardware_config(source_rate, frequency, flags, old_word, extra_mode=0):
    for v in (source_rate,frequency,flags,old_word): uint(v,32)
    uint(extra_mode,8)
    config = adapter_config(frequency,flags)
    divider = 0
    if frequency:
        ratio = source_rate // frequency
        divider = (ratio >> 1) - 1 if ratio > 1 else ratio
    return dict(control=(0x1004 if extra_mode else 0x100c) | config['low_control_bits'],
                configuration=(old_word & 0xff800000) | (7 << 16) | divider,
                enable_mask=0x18d)


def poll_round(tx_remaining, rx_remaining, statuses, elapsed, timeout):
    """One bounded full-duplex loop iteration, excluding actual data register I/O."""
    if any(type(n) is not int or not 0 <= n <= 4096 for n in (tx_remaining,rx_remaining)):
        raise ValueError('remaining counts outside the bounded host model')
    if len(statuses) != 3: raise ValueError('need separate busy, TX and RX status words')
    for word in statuses: uint(word,32)
    uint(elapsed,64); uint(timeout,32)
    if tx_remaining == 0 and rx_remaining == 0:
        return dict(tx_remaining=0,rx_remaining=0,outcome='complete_at_entry')
    if not statuses[0] & 4:
        if statuses[1] & 2 and tx_remaining: tx_remaining -= 1
        if statuses[2] & 0x3f0 and rx_remaining: rx_remaining -= 1
    return dict(tx_remaining=tx_remaining,rx_remaining=rx_remaining,
                outcome='timeout' if elapsed > timeout else 'continue')


def adapter_result(hal_result):
    uint(hal_result,32)
    return 2 if hal_result else 0


def delay_argument(argument):
    """Native delay-wrapper argument to the cycle-based micro-unit helper."""
    return (uint(argument,32) * 1000) & 0xffffffff


def scheduler_delay_argument(argument):
    uint(argument,32)
    return argument if argument == 0xffffffff or argument < 0x418938 else 0x418937


def evidence(archive, decompiled, validation):
    data = archive.read(SENSOR)
    if hashlib.sha256(data).hexdigest() != SENSOR_HASH: raise ValueError('requires reviewed sensor image')
    m = StartupMemory(data)
    board = struct.unpack('<3I',m.read(0x80f1533c,12))
    bus = struct.unpack('<3I',m.read(0x80f15348,12))
    ops = struct.unpack('<5I',m.read(0x80f1589c,20))
    if board[:2] != (0x91003000,0x200) or bus[2] != 0x90004000 or ops != (0x80f7b36c,0x80f7b2b8,0x80f7b3d0,0x80f7b3b8,0x80f7b3a0):
        raise ValueError('reviewed optical bus records differ')
    exports = {f'{a:08x}.c':hashlib.sha256((decompiled / f'{a:08x}.c').read_bytes()).hexdigest() for a in TARGETS}
    raw_report=validation.read_bytes(); execution=json.loads(raw_report)
    if (execution['adapter_config_cases']!=11 or execution['forwarding_return_cases']!=12
            or execution['hardware_execution'] is not False or execution['hal_execution'] is not False):
        raise ValueError('unexpected native adapter validation report')
    return dict(sensor_sha256=SENSOR_HASH, export_sha256=exports,
        validation_sha256=hashlib.sha256(raw_report).hexdigest(),validation=execution,
        bus=dict(name=m.string(bus[0]), register_base=bus[2],chip_select_gpio_bank=board[0],
                 chip_select_mask=board[1],adapter_ops=list(ops),clock_gate_register=0x90008008,
                 clock_gate_mask=4,source_selection_register=0x90008000,source_selection_bits=[12,13],
                 clock_lock_register=0x900080b0),
        byte_range_sha256={f'{a:08x}_{n:x}':hashlib.sha256(m.read(a,n)).hexdigest()
                          for a,n in ((0x80f7b36c,0x34),(0x80f1533c,24),(0x80f1589c,20),
                                      (0x80f7ed84,0xb4),(0x80f7ee38,0x94),(0x80f7eecc,0xb8),
                                      (0x80f7b36c,0x7c))},
        probe_config=dict(frequency_field=8000000,flags=0x801,dma_byte=0,
                          adapter=adapter_config(8000000,0x801)),
        synthetic_48mhz_register_example=hardware_config(48000000,8000000,0x801,0),
        poll_contract=dict(status_offset=0x0c,busy_mask=4,tx_mask=2,rx_mask=0x3f0,
                           data_offset=0x18,timeout_hal_result=3,adapter_error=2,public_error=-14,
                           timeout_predicate='unsigned64(now_reader-start_reader) > timeout',
                           completion='entry check before polling; timeout after data movement'),
        delay_paths=dict(active=0x80f63360,scheduler=0x80f7ff0e,probe_active_argument=7,
                         retry_scheduler_argument=10,scheduler_clamp=0x418937),
        limitations=['Compiled SPI clock requests/control bits are not measured bus timing or electrical mode proof.',
            'Same numeric counter address in main/sensor images does not establish shared physical time.',
            'DMA paths, bus locking, GPIO routing, native memory lifetime and concurrency are not emulated.',
            'A timeout may follow final-byte data movement; transfer and probe success remain unobserved.',
            'Public transfer wrapper returns zero for absent operation callbacks; zero alone does not prove data movement.',
            'The adapter forces width field 8 and collapses flags & 6 to 0 or 3; other flags are not decoded here.',
            'The low-level init result and probe SPI-init result are discarded by selected callers.',
            'Scheduler delay clamp helper includes diagnostics/assertion paths; only its returning path is modeled.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive'); parser.add_argument('--decompiled',type=Path,required=True)
    parser.add_argument('--validation',type=Path,required=True)
    args=parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive: report=evidence(archive,args.decompiled,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:
        parser.exit(2,f'Cannot inspect optical SPI: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__ == '__main__': main()
