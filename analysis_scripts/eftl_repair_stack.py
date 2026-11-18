#!/usr/bin/env python3
"""Original bad marking and bounded zero-prefix EFTL relocation through NAND."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_readback_stack as rb
else:
    import eftl_readback_stack as rb

mutation=rb.mutation
qspi=rb.qspi
read=rb.read
EXTRA_RANGES=((0x80c01b6e,540),(0x80c0290c,48),(0x80c29126,192))
RANGES=rb.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)


class Model(rb.Model):
    def __init__(self,c):super().__init__(c);self.allocations=0
    def nand_program(self,page,blocking):
        c=self.c;page=self.map(page)
        if page is None:self.actions.append('log:page_result');return -150
        if c['guard'] and page<512:self.actions.extend(('log:page_guard','log:page_result'));return -250
        if self.bus(6)[0]:return None
        column=4096 if c['plane'] and page&64 else 0
        original=self.buffer;self.buffer=self.scratch;failed,_=self.bus(0x32,column,2,2112,0,3,True,not blocking);self.buffer=original
        if failed or self.bus(0x10,page,3)[0]:return None
        status=self.poll(2000)
        if status is None:return None
        if status&8:self.actions.append('log:page_result');return -102
        return 0
    def marker_page(self,page):
        page=self.map(page)
        if page is None:raise ValueError('marker mapping fixture')
        if self.bus(6)[0]:return None
        original=self.buffer;self.buffer=bytearray(512);failed,_=self.bus(0x32,2048,2,2,0,3,True);self.buffer=original
        if failed or self.bus(0x10,page,3)[0]:return None
        status=self.poll(2000)
        if status is None:return None
        if status&8:self.actions.append('log:page_result');return -102
        return 0
    def mark_absolute(self,block):
        for i in range(3):
            status=self.marker_page(block*64+i)
            if self.stopped:return None
            if status:self.actions.append('log:bad_mark_error');return -2
        self.actions.append('log:bad_mark_set');return 0
    def chip_query(self,query,arg):
        if query!=11:return super().chip_query(query,arg)
        self.actions.append('chip_ioctl:11');status=self.mark_absolute(struct.unpack_from('<I',arg)[0])
        if status and not self.stopped:self.actions.append('log:chip_error')
        return status
    def mark(self,pbn):
        if self.c['fast']:return self.mark_absolute(pbn+self.c['fast_base']//64)
        return self.partition_ioctl(11,bytearray(struct.pack('<I',pbn)))
    def find_block(self,pbn):
        for _ in range(9):
            if pbn!=65535:
                if self.flags[pbn]&1:self.actions.append('log:eftl_block_bad')
                else:
                    status=self.erase_block(pbn)
                    if self.stopped:return None
                    if not status:self.flags[pbn]&=1;return pbn
                    self.actions.append('log:eftl_erase_bad');self.mark(pbn)
                    if self.stopped:return None
                    self.flags[pbn]|=1
            pbn=next((i for i,v in enumerate(self.flags) if v==254),65535)
            if pbn==65535:self.actions.append('log:eftl_map_full');return 65535
        raise ValueError('bounded free selection')
    def repair(self,logical,old,prefix):
        self.flags[old]|=1;new=self.find_block(65535)
        if self.stopped:return None
        if new!=65535 and prefix:
            self.allocations+=1;self.actions.append('repair_alloc:2112:0')
            if not self.c['repair_alloc_fail']:raise ValueError('prefix-copy repair deferred')
            self.stopped=dict(kind='assertion',owner=0x80c3436c,line=0xa3);return None
        self.actions.append('log:eftl_retire_old');self.mark(old)
        if self.stopped:return None
        self.flags[old]=1;return -1 if new==65535 else new
    def map_write(self,address,payload):
        if address%2048:self.actions.append('log:eftl_write_alignment');return -1
        if not payload:return 0
        logical,within=divmod(address//2048,64);pbn=self.mapping[logical];n=len(payload)
        self.actions.append(f'write_input:{n}:'+qspi.digest(payload));self.scratch[:n]=payload
        self.actions.append(f'write_fill:{n}:{2048-n}');self.scratch[n:2048]=b'\xff'*(2048-n)
        if within==0:
            pbn=self.find_block(pbn)
            if self.stopped:return None
        if pbn!=65535:
            metadata=struct.pack('<H',logical)+bytes([69,(logical%256+logical//256+69)&255])
            self.actions.append('write_fill:2048:64');self.scratch[2048:]=b'\xff'*64;self.scratch[2068:2072]=metadata
            for _ in range(4):
                if within<self.flags[pbn]>>1:self.actions.append('log:eftl_sequence_error');break
                self.flags[pbn]=(self.flags[pbn]&1)|(((within+1)*2)&255)
                value=self.program_page(pbn*64+within)
                if self.stopped:return None
                if value:self.actions.append('log:eftl_program_failed')
                elif self.c['write_readback']:
                    value,got=self.readback(pbn*64+within)
                    if self.stopped:return None
                    if value:self.actions.append('log:eftl_readback_io_failed')
                    elif not self.check_metadata(got):
                        self.actions.extend(('log:eftl_readback_check_failed','log:eftl_write_failed'));return -2
                if not value:
                    if within==0:self.mapping[logical]=pbn
                    return n
                self.actions.append('log:eftl_repair_start');new=self.repair(logical,pbn,within)
                if self.stopped:return None
                if new<0:break
                self.actions.append('log:eftl_repair_selected');pbn=new
            else:raise ValueError('bounded write relocation')
        self.actions.append('log:eftl_write_failed');return -2
    def storage_mutation(self):
        if self.c['repair_entry']:return self.repair(self.c['repair_logical'],self.c['repair_old'],self.c['repair_prefix'])
        return super().storage_mutation()
    def run(self):
        result=super().run();result['rows'][0]['repair_allocations']=self.allocations;return result


def contract(c):
    if not c['native_repair'] or c['repair_old']!=3 or c['repair_logical']!=0 or c['repair_prefix'] not in (0,1):raise ValueError('repair entry backing')
    if c['storage_name']!='nvms' or c['storage_offset'] not in (0,2048):raise ValueError('selected repair logical block')
    if not c['responses'] or len(c['responses'])>8 or any(v not in (0,4,8,32) for v in c['responses']):raise ValueError('bounded repair statuses')
    prefix=c['repair_prefix'] if c['repair_entry'] else c['storage_offset']//2048
    if prefix and 254 in c['write_flags'] and not c['repair_alloc_fail']:raise ValueError('prefix copy deferred')
    rb.contract(c|dict(native_repair=False,responses=[0],write_readback=False))
    return Model(c).run()


def native_vectors():
    base=rb.native_vectors()['cases'][0];cases=[]
    def add(name,**changes):
        flags=[1]*8;flags[3]=0
        c=base|dict(name=name,native_repair=True,repair_entry=False,repair_logical=0,repair_old=3,repair_prefix=0,
            repair_alloc_fail=False,write_readback=False,fast=True,write_flags=flags)|changes
        c['expected']=contract(c);cases.append(c)
    add('program_no_free',responses=[8,0]);add('program_no_free_generic',responses=[8,0],fast=False)
    add('program_no_free_mark_failure',responses=[8])
    add('program_relocate_zero_prefix',storage_offset=0,responses=[0,8,0],write_flags=[1,1,1,0,1,254,1,1])
    add('program_relocate_generic',storage_offset=0,responses=[0,8,0],fast=False,write_flags=[1,1,1,0,1,254,1,1])
    add('program_prefix_alloc_failure',responses=[8,0],write_flags=[1,1,1,0,1,254,1,1],repair_alloc_fail=True)
    add('erase_failed_no_free',storage_offset=0,responses=[4,0])
    add('erase_failed_reselect',storage_offset=0,responses=[4,0],write_flags=[1,1,1,0,1,254,1,1])
    add('erase_failed_mark_failed_reselect',storage_offset=0,responses=[4,8,0],write_flags=[1,1,1,0,1,254,1,1])
    add('erase_all_candidates_fail',storage_offset=0,responses=[4],write_flags=[1,1,1,0,1,254,1,1])
    add('readback_io_no_free',responses=[0,32,0],write_readback=True)
    add('readback_io_alloc_failure',responses=[0,32,0],write_readback=True,repair_alloc_fail=True,write_flags=[1,1,1,0,1,254,1,1])
    add('logical_erase_relocate',storage_offset=0,mutation_operation='erase',responses=[0,8,0],write_flags=[1,1,1,0,1,254,1,1])
    add('rewrite_relocate',storage_offset=0,mutation_operation='rewrite',responses=[0,8,0],write_flags=[1,1,1,0,1,254,1,1])
    add('repair_direct_no_free',repair_entry=True)
    add('repair_direct_no_free_generic',repair_entry=True,fast=False)
    add('repair_direct_free',repair_entry=True,write_flags=[1,1,1,0,1,254,1,1])
    add('repair_direct_mark_failure',repair_entry=True,responses=[8])
    add('repair_direct_free_mark_failure',repair_entry=True,responses=[0,8],write_flags=[1,1,1,0,1,254,1,1])
    add('repair_generic_mark_failure',repair_entry=True,responses=[8],fast=False)
    add('repair_generic_free_mark_failure',repair_entry=True,responses=[0,8],fast=False,write_flags=[1,1,1,0,1,254,1,1])
    add('repair_direct_alloc_failure',repair_entry=True,repair_prefix=1,repair_alloc_fail=True,write_flags=[1,1,1,0,1,254,1,1])
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in mutation.storage.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual bad marking, erase reselection and zero-prefix relocation execute through original upper/EFTL/NAND/bus/QSPI; prefix allocation failure executes to its assertion.',
            'Maps/flags/statuses, cache data, RTOS/peripherals and leaf services are authored; allocation is supplied only as failure.',
            'Successful earlier-page copying, recursive prefix migration, full repair atomicity, physical bad marking/persistence/restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL repair stack: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
