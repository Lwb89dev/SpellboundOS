#!/usr/bin/env python3
"""Original registered storage read/bounds through ready EFTL and NAND/QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_qspi_stack as eftl
else:
    import eftl_qspi_stack as eftl

read=eftl.read
qspi=eftl.qspi
ROOT=Path(__file__).resolve().parents[1]
FACTS=ROOT/'analysis/storage-map.json'
TABLE=0x8130b100
OWNERS=0x8130b000
BACKEND=0x8130b600
EXTRA_RANGES=((0x80c24446,188),(0x80c24218,296))
RANGES=eftl.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
DATA_RANGES=eftl.dispatch.DATA_RANGES+((0x80c33a38,960),(0x80d80fb8,76))


def facts():return json.loads(FACTS.read_bytes())['storage']
def selected(c):return next((i,r) for i,r in enumerate(facts()['partitions']) if r['name']==c['storage_name'])
def table_bytes(c):
    data=bytearray(b''.join(r['name'].encode().ljust(24,b'\0')+r['backend'].encode().ljust(24,b'\0')+
        struct.pack('<3I',r['offset'],r['declared_span'],r['unclassified_word_38']) for r in facts()['partitions']))
    if c['storage_span']>=0:struct.pack_into('<I',data,selected(c)[0]*60+52,c['storage_span'])
    return data
def backend_bytes(c):
    p=next(r for r in facts()['devices'] if r['name']=='eftl');keys=('initialize','read','program','erase','rewrite','deinitialize','unclassified_40','unclassified_44','ioctl')
    return p['name'].encode().ljust(24,b'\0')+struct.pack('<13I',p['initial_base_word'],c['storage_capacity'],p['initial_block_word'],p['initial_word_24'],*(p['callbacks'][k] for k in keys))
def owners_bytes(c):
    index,_=selected(c)
    return struct.pack('<16I',*(BACKEND if r['backend']=='eftl' and not(c['storage_owner_missing'] and i==index) else 0 for i,r in enumerate(facts()['partitions'])))


class Model(eftl.Model):
    def __init__(self,c):super().__init__(c);self.storage_calls=0
    def storage_read(self):
        c=self.c;handle=c['storage_handle']
        if handle!='normal' or c['storage_null_output']:
            line=0xd0 if handle=='null' else 0xd1 if c['storage_null_output'] else 0x7d if handle=='below' else 0x7e
            self.actions.append('storage_diagnostic:'+str(line));self.stopped=dict(kind='assertion',owner=0x80c3c378 if line>=0xd0 else 0x80c3c340,line=line);return None
        _,p=selected(c)
        if c['storage_owner_missing']:self.actions.append('log:storage_no_owner');return -1
        span=c['storage_span'] if c['storage_span']>=0 else p['declared_span']
        span=span or ((c['storage_capacity']-p['offset'])&0xffffffff)
        if c['storage_offset']>=span:self.actions.append('log:storage_bounds');return -1
        count=min(c['storage_size'],span-c['storage_offset']);address=p['offset']+c['storage_offset']
        self.actions.append(f'storage_backend_read:{address}:{count}');self.storage_calls+=1
        old_count,old_offset=c['count'],c['offset'];c['count']=count;c['offset']=address
        value=self.mapped();c['count'],c['offset']=old_count,old_offset
        if not self.stopped and value<0:self.actions.append('log:storage_read_error')
        return value
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        value=self.storage_read();result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads,
            argument_hex=self.argument.hex(),driver_calls=self.dispatches,scratch_sha256=qspi.digest(self.scratch),
            eftl_context_hex=eftl.context(c).hex(),mapping_hex=struct.pack('<8H',*c['mapping']).hex(),
            storage_backend_calls=self.storage_calls,storage_table_sha256=qspi.digest(table_bytes(c)),
            storage_backend_sha256=qspi.digest(backend_bytes(c)),storage_owners_sha256=qspi.digest(owners_bytes(c)))
        return result


def contract(c):
    if c['mode']!='platform_storage' or c['dispatch_operation']!='storage_read' or not c['native_storage']:raise ValueError('storage entry')
    if c['storage_name'] not in ('nvms','envbak','recovery') or c['storage_handle'] not in ('normal','null','below','above'):raise ValueError('selected storage backing')
    if not 0<=c['storage_offset']<=0xffffffff or not 0<=c['storage_size']<=0xffffffff or not -1<=c['storage_span']<=1048576 or not 0<=c['storage_capacity']<=1048576:raise ValueError('storage bounds')
    _,p=selected(c);span=c['storage_span'] if c['storage_span']>=0 else p['declared_span'];span=span or ((c['storage_capacity']-p['offset'])&0xffffffff)
    count=min(c['storage_size'],max(0,span-c['storage_offset']))
    if count>64:raise ValueError('bounded storage output')
    if c['storage_offset']<span and count and p['offset']+c['storage_offset']+count>1048576:raise ValueError('EFTL map backing')
    probe=c|dict(mode='platform_eftl',dispatch_operation='eftl_map',offset=0,count=0)
    eftl.contract(probe)
    return Model(c).run()


def native_vectors():
    base=eftl.native_vectors()['cases'][0];cases=[]
    def add(name,**changes):
        c=base|dict(name=name,mode='platform_storage',native_storage=True,dispatch_operation='storage_read',
            storage_name='nvms',storage_handle='normal',storage_null_output=False,storage_owner_missing=False,
            storage_offset=16,storage_size=32,storage_span=-1,storage_capacity=1048576)|changes
        c['expected']=contract(c);cases.append(c)
    add('storage_nvms');add('storage_envbak',storage_name='envbak');add('storage_recovery',storage_name='recovery')
    add('storage_end_clamp',storage_offset=262144-8);add('storage_request_overflow_clamp',storage_offset=262144-8,storage_size=0xffffffff)
    add('storage_at_end',storage_offset=262144);add('storage_after_end',storage_offset=262145)
    add('storage_zero',storage_size=0);add('storage_zero_at_end',storage_offset=262144,storage_size=0)
    add('storage_derived_span',storage_span=0);add('storage_derived_end',storage_span=0,storage_offset=1048576-8)
    add('storage_small_span',storage_span=64,storage_offset=60,storage_size=64)
    add('storage_owner_missing',storage_owner_missing=True)
    for handle in ('null','below','above'):add('storage_handle_'+handle,storage_handle=handle)
    add('storage_null_output',storage_null_output=True)
    add('storage_unmapped',mapping=[65535]*8)
    add('storage_gap_after_prefix',storage_offset=131064,mapping=[3,65535,4,65535,2,0,5,6])
    add('storage_lower_error',driver_state='root_missing');add('storage_fast_bypass',driver_state='root_missing',fast=True)
    add('storage_ecc_error',responses=[32],fast=True)
    add('storage_two_pages',storage_offset=2040);add('storage_deferred',defer_reinit=True)
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    original=expected['cases'][0]
    if table_bytes(original)!=memory.read(0x80c33a38,960):raise ValueError('partition table differs')
    if backend_bytes(original|dict(storage_capacity=0x7fffffff))!=memory.read(0x80d80fb8,76):raise ValueError('backend table differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual registered storage read/bounds and original EFTL callback execute through ready map/page/partition/driver/BBT/NAND/QSPI with selected DMA.',
            'Original registry/backend rows are cloned; owner bindings, ready mapping, runtime capacity/span variants, RTOS and peripheral inputs are authored.',
            'Fixtures select nvms/envbak/recovery and at most 64 delivered bytes; broader registry lifetime, storage writes/repair, physical persistence/restoration/boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect storage/EFTL stack: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
