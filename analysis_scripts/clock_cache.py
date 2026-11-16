#!/usr/bin/env python3
"""Bounded host models for selected clock and cache-control native paths.

Register words are caller-supplied synthetic inputs. No clock rate, cache line
progress, timer frequency or coherency is measured or changed on a device.
"""
import argparse
import hashlib
from itertools import islice
import json
from pathlib import Path
import re
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN, MAIN_HASH, uint
else:
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN, MAIN_HASH, uint

TARGETS = (0x80d45464, 0x80d4548c, 0x80d4549c, 0x80d454b0, 0x80d413a8,
    0x80d41338, 0x80d412a8, 0x80d412f0, 0x80d453d4, 0x70945b3c,
    0x707bf7e0, 0x701637ec, 0x7029fea0, 0x7029ff04, 0x7029ff68, 0x7029fe74)
CALLERS = (0x702a01c0, 0x702a0264, 0x702a02a0, 0x702a0338)


def stable_counter(samples):
    """Return the first stable high/low/high sample, bounded to 128 attempts."""
    for high, low, again in islice(samples, 128):
        for value in (high, low, again):
            uint(value, 32)
        if high == again:
            return high << 32 | low
    raise ValueError('no stable counter snapshot within host bound')


def pll_rate(word):
    uint(word, 32)
    divider = word >> 21 & 7
    if not word & (1 << 27):
        factor = word >> 24 & 15
        if factor in (1, 2):
            factor += 1
        divider *= factor
    if divider == 0:
        raise ValueError('zero PLL divider excluded from the host model')
    return (((word >> 16 & 31) + 32) * 48000000) // divider


def cpu_rate(role, config, *, pll_a=None, pll_b=None):
    uint(role, 1)
    uint(config, 32)
    mode = config & 3
    source = 48000000 if mode < 2 else pll_rate(pll_b if mode == 2 else pll_a)
    if role == 1:
        return source if config & 0x100 else source // (((config >> 4 & 15) + 1) * 2)
    return source if config & 0x1000000 else source // ((config >> 4 & 15) + 2)


def delay_cycle_target(rate, argument):
    uint(rate, 32)
    uint(argument, 32)
    return ((rate // 1000000) * argument) & 0xffffffff


def cache_contract(start, size, *, enabled, command):
    uint(start, 32)
    uint(size, 32)
    if type(enabled) is not bool or command not in (0, 1, 2):
        raise ValueError('invalid cache gate or range command')
    if start == 0 or start & 0x80000000:
        return dict(path='skip_signed_nonpositive')
    if not enabled:
        return dict(path='fence_only')
    return dict(path='cctl', begin=start & ~31, end=(start + size) & 0xffffffff,
                command=command, minimum_commands=1,
                progress='hardware CSR readback; no software line stride emulated')


def evidence(archive, decompiled, andes_source):
    data = archive.read(MAIN)
    if hashlib.sha256(data).hexdigest() != MAIN_HASH:
        raise ValueError('requires the reviewed main image')
    reference = andes_source.read_bytes()
    if hashlib.sha256(reference).hexdigest() != '6794d2076944f533d8acdd0f5e74eb7e1b3b9e326ea4a627efc9309749acd720':
        raise ValueError('requires the reviewed Zephyr v4.2.0 Andes cache driver')
    names = ('CCTL_L1D_VA_INVAL', 'CCTL_L1D_VA_WB', 'CCTL_L1D_VA_WBINVAL', 'CCTL_L1D_WBINVAL_ALL')
    commands = {name: int(re.search(rb'#define\s+' + name.encode() + rb'\s+(\d+)', reference)[1]) for name in names}
    if list(commands.values()) != [0, 1, 2, 6]:
        raise ValueError('cache reference commands differ')
    groups = (('runtime-clock-cache', TARGETS), ('runtime-clock-cache-followup', CALLERS))
    hashes = {f'{group}/{a:08x}.c': hashlib.sha256((decompiled / group / f'{a:08x}.c').read_bytes()).hexdigest()
              for group, addresses in groups for a in addresses}
    reader = (decompiled / 'runtime-clock-cache/80d45464.c').read_text()
    helper = (decompiled / 'runtime-clock-cache/70945b3c.c').read_text()
    startup = (decompiled / 'runtime-clock-cache/701637ec.c').read_text()
    cache = (decompiled / 'runtime-clock-cache/7029fea0.c').read_text()
    checks = dict(reader_returns_wide='ulonglong' in reader and 'return uVar4;' in reader,
        startup_separate_cache_enables='Csreg07ca = uVar3 | 2;' in startup and 'Csreg07ca = uVar3 | 1;' in startup,
        cache_command_and_readback='Csreg07cc = 1;' in cache and 'uVar1 = Csreg07cb;' in cache,
        helper_still_partially_undecoded='halt_baddata' in helper)
    if not all(checks.values()):
        raise ValueError('reviewed export state differs; update analysis explicitly')
    memory = StartupMemory(data, 0x70160000, 0x270, 4, 0x2a0, 2)
    return dict(main_sha256=MAIN_HASH, source_sha256=hashes, reviewed_checks=checks,
        reference=dict(url='https://github.com/zephyrproject-rtos/zephyr/blob/v4.2.0/drivers/cache/cache_andes.c',
                       sha256=hashlib.sha256(reference).hexdigest(), commands=commands),
        clock_registers=dict(role0_config=0x9a000000, role1_config=0x90008000,
                             pll_a=0x91000214, pll_b=0x9100021c, compiled_reference=48000000),
        clock_examples=dict(fallback_role0=cpu_rate(0, 0), fallback_role1=cpu_rate(1, 0),
            bypass_role0=cpu_rate(0, 0x1000000), bypass_role1=cpu_rate(1, 0x100)),
        cache_routines={'7029fea0': 'writeback by address, command 1',
            '7029ff04': 'writeback/invalidate by address, command 2',
            '7029ff68': 'invalidate by address, command 0', '7029fe74': 'writeback/invalidate all, command 6'},
        shared_pool_contract=[dict(base=base, contract=cache_contract(base, 64, enabled=True, command=1))
                              for base in (0x80f00000, 0x80f05000, 0x80f0a000)],
        instruction_range_sha256={f'{a:08x}_{n:x}': hashlib.sha256(memory.read(a, n)).hexdigest()
            for a, n in ((0x80d45464, 0x26), (0x80d4548c, 0x10), (0x80d4549c, 0x12),
                         (0x7029fea0, 0x60), (0x701637ec, 0x14))},
        remaining_undecoded_example=dict(address=0x70945bd4, bytes_hex=memory.read(0x70945bd4, 4).hex()),
        limitations=['Synthetic register inputs; no actual clock rate or elapsed duration measured.',
            'Wide arithmetic helper remains partly undecoded; timer scaling/physical units are not closed.',
            'Range guard explains software behavior at shared addresses, not physical cacheability or coherency.',
            'Zero PLL divider excluded; cache CSR progress and device command completion not emulated.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    parser.add_argument('--andes-source', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = evidence(archive, args.decompiled, args.andes_source)
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect clock/cache: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
