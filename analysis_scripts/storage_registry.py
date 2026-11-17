#!/usr/bin/env python3
"""Native registry population and lazy EFTL contracts over the original tables.

NAND/disk initializers, heap, geometry discovery and EFTL read data are supplied.
The original image does not execute on a watch and no flash is accessed.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH, digest, image_memory
    from .storage_map import STATIC_RANGES, extract
else:
    from recovery_validator import BOOT_HASH, digest, image_memory
    from storage_map import STATIC_RANGES, extract

ROOT = Path(__file__).resolve().parents[1]
FACTS = ROOT / 'analysis/storage-map.json'
HEAP = 0x81220000
TABLE = 0x80d805c0
PARTS = 0x80c33a38
CONFIG = dict(setup=0x80c24106, device=0x80c23bd0, find=0x80c23cee,
              owners=0x80c24140, partition=0x80c24340, lazy=0x80c231d6,
              read=0x80c23252, alloc=0x80c1a308, compare=0x80c2e5e8,
              logger=0x80c1cd7a, lazy_logger=0x80c1cc90,
              geometry=0x80c02298, ftl_read=0x80c0219a)
RANGES = STATIC_RANGES[1:] + ((0x80c23252, 0x4e),)
TARGETS = tuple(CONFIG[k] for k in ('setup', 'device', 'find', 'owners', 'partition', 'lazy', 'read')) + (0x80c231b2, 0x80c229ec)
LOGS = {0x80c3bf58: 'owner_allocation_error', 0x80c3bfa0: 'owner_missing',
        0x80c3bfcc: 'partition_start_error', 0x80c3ba80: 'eftl_deferred',
        0x80c3b9b8: 'sftl_deferred', 0x80c3ba98: 'eftl_ready'}


def u32(value): return value & 0xffffffff
def i32(value): return (value & 0x7fffffff) - (value & 0x80000000)


def facts():
    return json.loads(FACTS.read_bytes())['storage']


class Model:
    def __init__(self, case):
        self.c = case; self.f = facts(); self.actions = []; self.allocs = 0
        self.dev_ready = case['device_ready']; self.part_ready = case['partition_ready']
        seeded = self.dev_ready or case['mode'] == 'find'
        self.dev_table = TABLE if seeded else 0; self.dev_count = 5 if seeded else 0
        self.part_table = PARTS if self.part_ready else 0; self.part_count = 16 if self.part_ready else 0
        self.outer_table = 0; self.outer_count = 0; self.heap = HEAP if case['owners_present'] else 0
        fill = 0x55555555 if self.heap else 0xa5a5a5a5
        self.owners = [fill] * 16
        self.capacities = list(case['capacities']); self.blocks = [0x20000] * 3 + [0x1000] * 2
        self.eftl_ready = case['eftl_ready']; self.buffer = bytearray(b'\xa5' * 1024)

    def device(self):
        if self.dev_ready: return 0
        self.dev_table = TABLE; self.dev_count = 5
        for i, row in enumerate(self.f['devices']):
            if i in (0, 1, 3):
                result = self.c['driver_result'] if i == self.c['driver_fail_index'] else 0
                self.actions.append(f'initialize:{i}:{result}')
                if result: return u32(result)
            else: self.actions.append('log:' + ('eftl_deferred' if i == 2 else 'sftl_deferred'))
        self.dev_ready = True; return 0

    def find(self, query):
        self.actions.append('find:' + query)
        for i, row in enumerate(self.f['devices']):
            current = 'absent' if i == self.c['missing_device_index'] else row['name']
            if current == query: return row['address']
        return 0

    def partition(self):
        if self.part_ready: return 0
        self.part_table = PARTS; self.part_count = 16
        if not self.heap:
            self.allocs += 1; ok = self.allocs != self.c['alloc_fail_at']
            self.actions.append('alloc:64:' + str(int(ok)))
            if not ok: self.actions.append('log:owner_allocation_error'); return 0xffffffff
            self.heap = HEAP
        for i, row in enumerate(self.f['partitions']):
            owner = self.find(row['backend'])
            if not owner: self.actions.append('log:owner_missing'); continue
            slot = next(j for j, d in enumerate(self.f['devices']) if d['address'] == owner)
            offset = self.c['partition_offset'] if i == self.c['modified_partition'] else row['offset']
            if i32(self.capacities[slot]) <= i32(offset):
                self.actions.append('log:partition_start_error'); self.part_count = 0; return 0xffffffff
            self.owners[i] = owner
        self.part_ready = True; return 0

    def lazy(self):
        if self.eftl_ready: return
        self.actions.append('geometry:' + str(self.c['geometry_result']))
        if self.c['geometry_result'] < 0: return
        g = self.c['geometry']; block = u32(g[0] * g[1])
        self.blocks[2] = block; self.capacities[2] = u32((g[2] - g[3]) * block)
        self.eftl_ready = True; self.actions.append('log:eftl_ready')

    def run(self):
        rows = []
        for _ in range(self.c['repeat']):
            mode = self.c['mode']
            if mode == 'device': result = self.device()
            elif mode == 'partition': result = self.partition()
            elif mode == 'setup':
                result = self.device()
                if not result: result = self.partition()
                if result: result = 0xffffffff
                else: self.outer_table = TABLE; self.outer_count = 5
            elif mode == 'find': result = self.find(self.c['query'])
            elif mode in ('lazy', 'read'):
                self.lazy(); result = None
                if mode == 'read':
                    if not self.eftl_ready: result = 0xfffffff2
                    else:
                        n = self.c['size']; result = self.c['read_result']
                        self.actions.append(f'ftl_read:{self.c["offset"]}:{n}:{result}')
                        if result >= 0:
                            count = min(result, n)
                            self.buffer[:count] = bytes((self.c['offset'] + j * 7) & 255 for j in range(count))
                        result = u32(result)
            else: raise ValueError('registry mode')
            rows.append(dict(returned=result, device_ready=int(self.dev_ready), device_table=self.dev_table,
                device_count=self.dev_count, partition_ready=int(self.part_ready), partition_table=self.part_table,
                partition_count=self.part_count, outer_table=self.outer_table, outer_count=self.outer_count,
                owner_pointer=self.heap, owners=list(self.owners) if self.heap else None,
                owner_backing_sha256=digest(struct.pack('<16I', *self.owners)),
                capacities=list(self.capacities), blocks=list(self.blocks), eftl_ready=int(self.eftl_ready),
                buffer_sha256=digest(self.buffer)))
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if not 1 <= case['repeat'] <= 2 or not 0 <= case['size'] <= 512: raise ValueError('probe bounds')
    if case['mode'] in ('partition', 'find') and not case['device_ready']: raise ValueError('device registry required')
    return Model(case).run()


def native_vectors():
    cases = []
    def add(name, mode='setup', **changes):
        c = dict(name=name, mode=mode, repeat=1, device_ready=mode in ('partition', 'find'), partition_ready=False,
            owners_present=False, missing_device_index=-1, driver_fail_index=-1, driver_result=-14, alloc_fail_at=0,
            capacities=[0x7fffffff] * 5, modified_partition=-1, partition_offset=0, partition_span=0x40000,
            query='eftl', eftl_ready=False, geometry=[64, 2048, 128, 4], geometry_result=0,
            offset=32, size=32, read_result=32) | changes
        c['expected'] = contract(c); cases.append(c)
    add('setup_original'); add('setup_repeat', repeat=2)
    add('setup_alloc_error', alloc_fail_at=1); add('setup_alloc_retry', alloc_fail_at=1, repeat=2)
    for index in (0, 1, 3): add(f'setup_driver_{index}_error', driver_fail_index=index)
    add('device_original', 'device'); add('device_backend_status', 'device', driver_fail_index=1, driver_result=-9)
    add('device_already_ready', 'device', device_ready=True)
    add('partition_original', 'partition'); add('partition_existing_owners', 'partition', owners_present=True)
    add('partition_already_ready', 'partition', partition_ready=True, owners_present=True)
    add('partition_missing_owner', 'partition', missing_device_index=2)
    add('partition_missing_stale_owner', 'partition', missing_device_index=2, owners_present=True)
    add('partition_capacity_equal', 'partition', capacities=[0x7fffffff,0x7fffffff,0x40000,0x7fffffff,0x7fffffff])
    add('partition_signed_offset', 'partition', modified_partition=5, partition_offset=0x80000000)
    add('partition_span_not_checked', 'partition', modified_partition=5, partition_span=0xffff0000)
    add('find_original', 'find'); add('find_missing', 'find', query='missing')
    add('lazy_original', 'lazy'); add('lazy_repeat', 'lazy', repeat=2)
    add('lazy_error', 'lazy', geometry_result=-14); add('lazy_positive_status', 'lazy', geometry_result=1)
    add('lazy_already_ready', 'lazy', eftl_ready=True)
    add('lazy_arithmetic_wrap', 'lazy', geometry=[65536,65536,128,4])
    add('lazy_reserved_underflow', 'lazy', geometry=[64,2048,1,4])
    add('read_lazy', 'read'); add('read_lazy_error', 'read', geometry_result=-1)
    add('read_already_ready', 'read', eftl_ready=True)
    add('read_short', 'read', read_result=7); add('read_backend_error', 'read', read_result=-9)
    return dict(schema=1, cases=cases)


def evidence(archive, decompiled, vectors, validation):
    expected = native_vectors(); execution = json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes()) != expected: raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count'] != len(expected['cases']) or len(execution['cases']) != len(expected['cases']): raise ValueError('case count')
    for row, case in zip(execution['cases'], expected['cases']):
        if row['name'] != case['name'] or row['observed'] != case['expected'] or not 0 < row['steps'] <= 100000: raise ValueError('native mismatch/bound')
    memory = image_memory(archive)
    if extract(memory) != facts(): raise ValueError('original storage facts differ')
    return dict(boot_sha256=BOOT_HASH, storage_facts_sha256=digest(FACTS.read_bytes()),
        vectors_sha256=digest(vectors.read_bytes()), validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}': digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c': digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution, native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Original registry/device tables execute with supplied NAND/nandraw/disk initialization and heap services.',
            'Actual deferred EFTL/SFTL initializers and lazy EFTL geometry arithmetic execute; geometry discovery and EFTL read results/data are supplied.',
            'Missing-owner, signed-start and unchecked-span cases are bounded emulator fixtures, not observed physical failures.',
            'Physical NAND capacity, FTL translation, persistence, electrical behavior, recovery and full boot remain unproven.'])


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'): p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output: a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n'); return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)): p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z: report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e: p.exit(2,f'Cannot inspect storage registry: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__ == '__main__': main()
